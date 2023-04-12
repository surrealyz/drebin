#! /usr/bin/env python

import argparse
import CommonModules as CM
import os
from FileListClassification import FileListClassification

def parse_args():
    parser = argparse.ArgumentParser(description='Train on 201501, test on each month after.')
    parser.add_argument('--start_year', type=int, help='The start year. e.g., 2012', required=True)
    parser.add_argument('--train_one_month', action='store_true')
    parser.add_argument('--feature_type', type=str, choices=['mldroid_drebin', 'drebin', \
            'mldroid_drebin_asn', 'drebin_asn', \
            'mldroid_drebin_reduced', \
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
    elif args.feature_type == 'mldroid_drebin_reduced':
        data_path = '/space1/mldroid_drebin_reduced'
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

    #MalPath = os.path.join(data_path, 'malware/2015/01')
    #GoodPath = os.path.join(data_path, 'benign/2015/01')
 
    MalPath = os.path.join(data_path, 'malware/%d' % args.start_year)
    GoodPath = os.path.join(data_path, 'benign/%d' % args.start_year)
    
    TrainMalSamples = []
    TrainGoodSamples = []
    #TrainMalSamples.extend(ListFileFunc(MalPath))
    #TrainGoodSamples.extend(ListFileFunc(GoodPath))
    #"""

    if args.train_one_month:
        train_dir_list = ['01']
    else:
        # one year
        train_dir_list = os.listdir(MalPath)

    for curdir in train_dir_list:
        TrainMalDir = os.path.join(MalPath, curdir)
        TrainMalSamples.extend(ListFileFunc(TrainMalDir))
    
    for curdir in train_dir_list:
        TrainGoodDir = os.path.join(GoodPath, curdir)
        TrainGoodSamples.extend(ListFileFunc(TrainGoodDir))
    #"""
    FileListClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TrainMalSamples, TrainGoodSamples, FeatureOption, None, 30)

    if args.train_one_month:
        start = args.start_year
    else:
        start = args.start_year + 1
    for year in range(start, 2019):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if year == args.start_year and midx == 0:
                continue
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            MalDir = os.path.join(data_path, 'malware/%s/%s' % (year, month))
            GoodDir = os.path.join(data_path, 'benign/%s/%s'% (year, month))
            print(MalDir, GoodDir)
            TestMalSamples = ListFileFunc(MalDir)
            TestGoodSamples = ListFileFunc(GoodDir)
            FileListClassification(None, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, SaveModelName, 30)
    
    return

if __name__ == "__main__":
    global args
    args = parse_args()
    main(args)
