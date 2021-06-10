#! /usr/bin/env python

import CommonModules as CM
import os
from FileListClassification import FileListClassification

def main():
    #SaveModelName = 'models/20210610_exp2_train2012.pkl'
    SaveModelName = 'models/20210610_exp0.pkl'
    FeatureOption = True
    MalPath = '/space1/android/malware/2012/'
    GoodPath = '/space1/android/benign/2012/'

    TrainMalSamples = []
    TrainGoodSamples = []
    #for curdir in os.listdir(MalPath):
    for curdir in ['01']:
        TrainMalDir = os.path.join(MalPath, curdir)
        TrainMalSamples.extend(CM.ListDataFiles(TrainMalDir))
    #for curdir in os.listdir(GoodPath):
    for curdir in ['01']:
        TrainGoodDir = os.path.join(GoodPath, curdir)
        TrainGoodSamples.extend(CM.ListDataFiles(TrainGoodDir))
    FileListClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TrainMalSamples, TrainGoodSamples, FeatureOption, None, 30)

    for year in range(2012, 2014):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if year == 2012 and m == 1:
                continue
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            MalDir = '/space1/android/malware/%s/%s' % (year, month)
            GoodDir = '/space1/android/benign/%s/%s' % (year, month)
            print(MalDir, GoodDir)
            TestMalSamples = CM.ListDataFiles(MalDir)
            TestGoodSamples = CM.ListDataFiles(GoodDir)
            FileListClassification(None, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, SaveModelName, 30)
    
    return

if __name__ == "__main__":
    main()
