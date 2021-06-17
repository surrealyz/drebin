#! /usr/bin/env python

import CommonModules as CM
import os
from FileListClassification import FileListClassification, IncrementalClassification

def main():
    SaveModelName = 'models/20210617_exp0_apigraph_train2012.pkl'
    FeatureOption = True
    MalPath = '/space1/android/malware/2012/'
    GoodPath = '/space1/android/benign/2012/'

    TrainMalSamples = []
    TrainGoodSamples = []
    for curdir in os.listdir(MalPath):
        TrainMalDir = os.path.join(MalPath, curdir)
        TrainMalSamples.extend(CM.ListAgFiles(TrainMalDir))
    for curdir in os.listdir(GoodPath):
        TrainGoodDir = os.path.join(GoodPath, curdir)
        TrainGoodSamples.extend(CM.ListAgFiles(TrainGoodDir))
    FileListClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TrainMalSamples, TrainGoodSamples, FeatureOption, None, 30)

    for year in range(2013, 2017):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            MalDir = '/space1/android/malware/%s/%s' % (year, month)
            GoodDir = '/space1/android/benign/%s/%s' % (year, month)
            print(MalDir, GoodDir)
            TestMalSamples = CM.ListAgFiles(MalDir)
            TestGoodSamples = CM.ListAgFiles(GoodDir)
            IncrementalClassification(None, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, SaveModelName, 30, year, month)
    
    return

if __name__ == "__main__":
    main()
