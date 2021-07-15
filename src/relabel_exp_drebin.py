#! /usr/bin/env python

import CommonModules as CM
import os
import pickle
from FileListClassification import FileListClassification, IncrementalClassification, TargetScoreClassification

def main():
    SaveModelName = 'models/20210627/20210627_al_drebin_0.98.pkl'
    #SaveModelName = 'models/20210626/20210626_exp5_al_drebin.pkl'
    #SaveModelName = 'models/20210626/20210626_exp6_al_drebin.pkl'
    FeatureOption = True
    MalPath = '/space1/android/malware/2012/'
    GoodPath = '/space1/android/benign/2012/'
    
    #"""
    TrainMalSamples = []
    TrainGoodSamples = []
    for curdir in os.listdir(MalPath):
        TrainMalDir = os.path.join(MalPath, curdir)
        TrainMalSamples.extend(CM.ListDataFiles(TrainMalDir))
    for curdir in os.listdir(GoodPath):
        TrainGoodDir = os.path.join(GoodPath, curdir)
        TrainGoodSamples.extend(CM.ListDataFiles(TrainGoodDir))
    FileListClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TrainMalSamples, TrainGoodSamples, FeatureOption, None, 30)
    #"""

    # load previous TrainMalSamples and TrainGoodSamples
    #TrainMalSamples = pickle.load(open(SaveModelName.split('.pkl')[0]+'_TrainMalSamples.pkl', 'rb'))
    #TrainGoodSamples = pickle.load(open(SaveModelName.split('.pkl')[0]+'_TrainGoodSamples.pkl', 'rb'))

    for year in range(2013, 2019):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if year == 2014 and m == 9:
                pickle.dump(TrainMalSamples, open(SaveModelName.split('.pkl')[0]+'_TrainMalSamples.pkl', 'wb'))
                pickle.dump(TrainGoodSamples, open(SaveModelName.split('.pkl')[0]+'_TrainGoodSamples.pkl', 'wb'))
                return
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            MalDir = '/space1/android/malware/%s/%s' % (year, month)
            GoodDir = '/space1/android/benign/%s/%s' % (year, month)
            print(MalDir, GoodDir)
            TestMalSamples = CM.ListDataFiles(MalDir)
            TestGoodSamples = CM.ListDataFiles(GoodDir)
            TargetScoreClassification(None, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, SaveModelName, 30, year, month, 0.98)
            #TargetScoreClassification(None, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, SaveModelName, 30, year, month, 0.95)
            #TargetScoreClassification(None, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, SaveModelName, 30, year, month, 0.9)
    
    # save the last TrainMalSamples TrainGoodSamples
    pickle.dump(TrainMalSamples, open(SaveModelName.split('.pkl')[0]+'_TrainMalSamples.pkl', 'wb'))
    pickle.dump(TrainGoodSamples, open(SaveModelName.split('.pkl')[0]+'_TrainGoodSamples.pkl', 'wb'))

    return

if __name__ == "__main__":
    main()
