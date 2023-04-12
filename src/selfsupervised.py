#! /usr/bin/env python

import argparse
import CommonModules as CM
import numpy as np
import os
import pickle
from FileListClassification import FileListClassification, IncrementalClassification, TargetScoreClassification, SelfSupervised

def parse_args():
    parser = argparse.ArgumentParser(description='Train on 2012, maintain a target model performance for every month afterwards.')
    parser.add_argument('--feature_type', type=str, choices=['reduced_drebin', 'drebin', \
            'reduced_drebin_asn', 'drebin_asn', \
            'ccs_drebin', 'ccs_drebin_apigraph', \
            'apigraph', 'reduced_apigraph', 'reduced_apigraph_keeptwo'], help='choose the type of features to train on.', required=True)
    parser.add_argument('--f1', type=float, help='target F1 score', required=False)
    parser.add_argument('--model_path', type=str, help='model path. e.g., models/20210627/20210627_train2012_al_0.98_ccs_drebin.pkl', required=True)
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


    MalPath = '/space1/android/malware/2015'
    GoodPath = '/space1/android/benign/2015'
    
    #"""
    TrainMalSamples = []
    TrainGoodSamples = []
    #for curdir in os.listdir(MalPath):
    for curdir in ['01']:
        TrainMalDir = os.path.join(MalPath, curdir)
        TrainMalSamples.extend(ListFileFunc(TrainMalDir))
    #for curdir in os.listdir(GoodPath):
    for curdir in ['01']:
        TrainGoodDir = os.path.join(GoodPath, curdir)
        TrainGoodSamples.extend(ListFileFunc(TrainGoodDir))
    FileListClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TrainMalSamples, TrainGoodSamples, FeatureOption, None, 30)
    #"""

    # load previous TrainMalSamples and TrainGoodSamples
    #TrainMalSamples = pickle.load(open(SaveModelName.split('.pkl')[0]+'_TrainMalSamples.pkl', 'rb'))
    #TrainGoodSamples = pickle.load(open(SaveModelName.split('.pkl')[0]+'_TrainGoodSamples.pkl', 'rb'))
    
    TrainSamples = TrainMalSamples + TrainGoodSamples
    Train_Mal_labels = np.ones(len(TrainMalSamples))
    Train_Good_labels = np.empty(len(TrainGoodSamples))
    Train_Good_labels.fill(-1)
    y_train = np.concatenate((Train_Mal_labels, Train_Good_labels), axis=0)

    for year in range(2015, 2019):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if year == 2015 and midx == 0:
                continue
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            MalDir = '/space1/android/malware/%s/%s' % (year, month)
            GoodDir = '/space1/android/benign/%s/%s' % (year, month)
            print(MalDir, GoodDir)
            TestMalSamples = ListFileFunc(MalDir)
            TestGoodSamples = ListFileFunc(GoodDir)
            TestSamples = TestMalSamples + TestGoodSamples
            Test_Mal_labels = np.ones(len(TestMalSamples))
            Test_Good_labels = np.empty(len(TestGoodSamples))
            Test_Good_labels.fill(-1)
            y_test = np.concatenate((Test_Mal_labels, Test_Good_labels), axis=0)
            TrainSamples, y_train = SelfSupervised(None, TrainSamples, y_train, TestSamples, y_test, FeatureOption, SaveModelName, 30, year, month)

    # save the last TrainMalSamples TrainGoodSamples
    #pickle.dump(TrainMalSamples, open(SaveModelName.split('.pkl')[0]+'_TrainMalSamples.pkl', 'wb'))
    #pickle.dump(TrainGoodSamples, open(SaveModelName.split('.pkl')[0]+'_TrainGoodSamples.pkl', 'wb'))

    return

if __name__ == "__main__":
    global args
    args = parse_args()
    main(args)
