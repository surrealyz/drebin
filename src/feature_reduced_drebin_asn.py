#! /usr/bin/env python

import CommonModules as CM
import multiprocessing as mp
import os
import psutil, argparse, logging
import pickle
import re
from network_info import *

logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger('main.stdout')

def ProcessingData(DataDirectoryPath, data_fname, new_fname):
    ni = NetworkInfo()
    fout = open(new_fname, 'w')
    with open(data_fname, 'r') as f:
        for line in f:
            feat_type, name = line.rstrip('\n').split('_', 1)
            if feat_type == 'URLDomainList':
                # ignore non IPs
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", name):
                    info = ni.ip_lookup(name)
                    new_name = 'ASN%s' % info.asn
                    fout.write('%s_%s\n' % (feat_type, new_name))
                else:
                    fout.write(line)
            else:
                fout.write(line)
    return new_fname, True

def main():
    NCpuCores = psutil.cpu_count()

    for year in range(2012, 2019):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            MalDir = '/space1/mldroid_drebin/malware/%s/%s' % (year, month)
            GoodDir = '/space1/mldroid_drebin/benign/%s/%s' % (year, month)
            print(MalDir, GoodDir)
            DataFileList = []
            for DataDirectoryPath in [MalDir, GoodDir]:
                DataFileList.extend(CM.ListDataFiles(DataDirectoryPath))

            pool = mp.Pool(NCpuCores)
            ProcessingResults = []
            ScheduledTasks = []
            ProgressBar = CM.ProgressBar()
            for DataFile in DataFileList:
                data_fname = DataFile
                new_fname = os.path.splitext(DataFile)[0] + ".asndata"
                if True:
                    DataDirectoryPath = os.path.split(DataFile)[0]
                    ScheduledTasks.append(DataFile)
                    ProcessingResults = pool.apply_async(ProcessingData, args=(DataDirectoryPath, data_fname, new_fname),
                                                         callback=ProgressBar.CallbackForProgressBar)
            pool.close()
            if (ProcessingResults):
                ProgressBar.DisplayProgressBar(ProcessingResults, len(ScheduledTasks), type="hour")
            pool.join()


    return
    
if __name__ == "__main__":
    main()
