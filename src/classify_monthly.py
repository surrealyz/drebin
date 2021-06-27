#! /usr/bin/env python

import argparse
import CommonModules as CM
import os
from FileListClassification import FileListClassification

def parse_args():
    parser = argparse.ArgumentParser(description='Train on 2012, test on each month after.')
    parser.add_argument('--feature_type', type=str, choices=['reduced_drebin', 'drebin', \
            'reduced_drebin_asn', 'drebin_asn', \
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
    elif args.feature_type == 'reduced_drebin':
        data_path = '/space1/mldroid_drebin'
        ListFileFunc = CM.ListDataFiles
    elif args.feature_type == 'reduced_drebin_asn':
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

    MalPath = os.path.join(data_path, 'malware/2012')
    GoodPath = os.path.join(data_path, 'benign/2012')
    
    TrainMalSamples = []
    TrainGoodSamples = []
    for curdir in os.listdir(MalPath):
        #for curdir in ['01']:
        TrainMalDir = os.path.join(MalPath, curdir)
        TrainMalSamples.extend(ListFileFunc(TrainMalDir))
    for curdir in os.listdir(GoodPath):
        #for curdir in ['01']:
        TrainGoodDir = os.path.join(GoodPath, curdir)
        TrainGoodSamples.extend(ListFileFunc(TrainGoodDir))
    FileListClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TrainMalSamples, TrainGoodSamples, FeatureOption, None, 30)

    for year in range(2013, 2015):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
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
