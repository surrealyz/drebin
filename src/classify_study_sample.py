#! /usr/bin/env python

import argparse
from collections import defaultdict
import CommonModules as CM
import os
from FileListClassification import FileListClassificationSamples

def parse_args():
    parser = argparse.ArgumentParser(description='Train on one month / year, test on each month after.')
    parser.add_argument('--start_year', type=int, help='The start year. e.g., 2012', required=True)
    parser.add_argument('--train_one_month', action='store_true')
    parser.add_argument('--feature_type', type=str, choices=['mldroid_drebin', 'drebin', \
            'mldroid_drebin_asn', 'drebin_asn', \
            'ccs_drebin', 'ccs_drebin_apigraph', \
            'apigraph', 'reduced_apigraph', 'reduced_apigraph_keeptwo'], help='choose the type of features to train on.', required=True)
    parser.add_argument('--model_path', type=str, help='model path. e.g., models/20210625/20210625_exp1_drebin_train2012_monthlytest.pkl', required=True)
    return parser.parse_args()

def main(args):
    SaveModelName = args.model_path
    FeatureOption = True
    
    if args.feature_type == 'drebin':
        data_path = '/space1/android'
        ListFileFunc = CM.ListDataFiles
    elif args.feature_type == 'drebin_asn':
        data_path = '/space1/android'
        ListFileFunc = CM.ListASNDataFiles
    elif args.feature_type == 'mldroid_drebin':
        data_path = '/space1/mldroid_drebin'
        ListFileFunc = CM.ListDataFiles
    elif args.feature_type == 'mldroid_drebin_asn':
        data_path = '/space1/mldroid_drebin'
        ListFileFunc = CM.ListASNDataFiles
    elif args.feature_type == 'apigraph':
        data_path = '/space1/android'
        ListFileFunc = CM.ListAgFiles
    elif args.feature_type == 'reduced_apigraph':
        data_path = '/space1/mldroid_drebin'
        ListFileFunc = CM.ListAgFiles
    elif args.feature_type == 'reduced_apigraph_keeptwo':
        data_path = '/space1/mldroid_drebin_keeptwo'
        ListFileFunc = CM.ListAgFiles
    elif args.feature_type == 'ccs_drebin':
        data_path = '/space1/ccs_drebin'
        ListFileFunc = CM.ListDataFiles
    elif args.feature_type == 'ccs_drebin_apigraph':
        data_path = '/space1/ccs_drebin'
        ListFileFunc = CM.ListAgFiles
    else:
        exit()

    # read analyze_sdkver.tsv
    fname_minsdkver = {}
    firstline = True
    with open('analyze_sdkver.tsv', 'r') as f:
        for line in f:
            if firstline:
                firstline = False
                continue
            date, packageName, versionCode, versionName, minSdkVersion, targetSdkVersion, maxSdkVersion, label, XmlFile = line.rstrip().split('\t')
            data_fname = XmlFile.rsplit('.xml', 1)[0].split('/', 3)[-1] + '.data'
            fname_minsdkver[data_fname] = minSdkVersion

    MalPath = os.path.join(data_path, 'malware/%d' % args.start_year)
    GoodPath = os.path.join(data_path, 'benign/%d' % args.start_year)
 
    if args.train_one_month:
        # one month
        train_dir_list = ['01']
    else:
        # one year
        train_dir_list = os.listdir(MalPath)

    TrainMalSamples = []
    TrainGoodSamples = []
    for curdir in train_dir_list:
        TrainMalDir = os.path.join(MalPath, curdir)
        TrainMalSamples.extend(ListFileFunc(TrainMalDir))
    for curdir in train_dir_list:
        TrainGoodDir = os.path.join(GoodPath, curdir)
        TrainGoodSamples.extend(ListFileFunc(TrainGoodDir))
    FileListClassificationSamples(SaveModelName, TrainMalSamples, TrainGoodSamples, TrainMalSamples, TrainGoodSamples, FeatureOption, None, 30)

    # get known versions in training
    train_versions = set([])
    for sample in TrainGoodSamples + TrainMalSamples:
        sample = sample.split('/', 3)[-1]
        ver = fname_minsdkver[sample]
        train_versions.add(ver)
 
    if args.train_one_month:
        start = args.start_year
    else:
        start = args.start_year + 1
    for year in range(start, 2019):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            test_month = '%s-%s' % (year, month)
            MalDir = os.path.join(data_path, 'malware/%s/%s' % (year, month))
            GoodDir = os.path.join(data_path, 'benign/%s/%s'% (year, month))
            print(MalDir, GoodDir)
            TestMalSamples = ListFileFunc(MalDir)
            TestGoodSamples = ListFileFunc(GoodDir)
            fp_samples, fn_samples, fp_scores, fn_scores = FileListClassificationSamples(None, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, SaveModelName, 30)
            print(fp_scores)
            print('fp_scores: mean {:.4f}, var {:.4f}, min {:.4f}, max {:.4f}'.format(fp_scores.mean(), fp_scores.var(), fp_scores.min(), fp_scores.max()))
            print(fn_scores)
            print('fn_scores: mean {:.4f}, var {:.4f}, min {:.4f}, max {:.4f}\n'.format(fn_scores.mean(), fn_scores.var(), fn_scores.min(), fn_scores.max()))
            
            
            """
            # get the total count for each verion per month
            ver_cnt = defaultdict(lambda: 0)
            for sample in TestMalSamples + TestGoodSamples:
                sample = sample.split('/', 3)[-1]
                ver = fname_minsdkver[sample]
                ver_cnt[ver] += 1
            # get the min sdk ver of fp, fn samples
            fp_by_ver = defaultdict(lambda: 0)
            fn_by_ver = defaultdict(lambda: 0)
            for sample in fp_samples:
                sample = sample.split('/', 3)[-1]
                ver = fname_minsdkver[sample]
                fp_by_ver[ver] += 1
            for sample in fn_samples:
                sample = sample.split('/', 3)[-1]
                ver = fname_minsdkver[sample]
                fn_by_ver[ver] += 1
            # get the rate within each ver for fp, fn
            for ver, fp_cnt in fp_by_ver.items():
                new = ver not in train_versions
                ver_total = ver_cnt[ver]
                ver_rate = fp_cnt / float(ver_total)
                print('VerFP\t%s\t%s\t%s\t%s\t%d' % (test_month, new, ver, ver_rate, fp_cnt))
            for ver, fn_cnt in fn_by_ver.items():
                new = ver not in train_versions
                ver_total = ver_cnt[ver]
                ver_rate = fn_cnt / float(ver_total)
                print('VerFN\t%s\t%s\t%s\t%s\t%d' % (test_month, new, ver, ver_rate, fn_cnt))
            """



if __name__ == "__main__":
    global args
    args = parse_args()
    main(args)
