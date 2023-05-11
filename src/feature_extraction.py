#! /usr/bin/env python

from GetApkData import GetApkData
from RandomClassification import RandomClassification
from HoldoutClassification import HoldoutClassification
import psutil, argparse, logging

logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger('main.stdout')

def main():
    NCpuCores = psutil.cpu_count()

    # for year in range(2012, 2019):
    for year in range(2019, 2022):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            # MalDir = '/space1/android/malware/%s/%s' % (year, month)
            # GoodDir = '/space1/android/benign/%s/%s' % (year, month)
            MalDir = '/data2/yizheng/android/malware/%s/%s' % (year, month)
            GoodDir = '/data2/yizheng/android/benign/%s/%s' % (year, month)
            print(MalDir, GoodDir)
            GetApkData(NCpuCores-8, MalDir, GoodDir)

    return
    
if __name__ == "__main__":
    main()
