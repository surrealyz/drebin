#! /usr/bin/env python

import CommonModules as CM
import multiprocessing as mp
import os
import psutil, argparse, logging
import pickle

def main():
    for year in range(2012, 2019):
        for month in ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12']:
            MalDir = '/space1/android/malware/%s/%s' % (year, month)
            GoodDir = '/space1/android/benign/%s/%s' % (year, month)
            print(MalDir, GoodDir)
            ApkFileList = []
            for ApkDirectoryPath in [MalDir, GoodDir]:
                ApkFileList.extend(CM.ListApkFiles(ApkDirectoryPath))
            for ApkFile in ApkFileList:
                data_fname = os.path.splitext(ApkFile)[0] + ".data"
                ag_fname = os.path.splitext(ApkFile)[0] + ".ag"
                if not CM.FileExist(data_fname):
                    # remove the corresponding ag_fname
                    cmd = 'rm %s' % ag_fname
                    print(cmd)
                    os.system(cmd)

    return

if __name__ == "__main__":
    main()
