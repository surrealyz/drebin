#! /usr/bin/env python

import CommonModules as CM
import multiprocessing as mp
import os
import psutil, argparse, logging
import pickle

logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger('main.stdout')

def ProcessingData(DataDirectoryPath, data_fname, tmp_fname):
    fout = open(tmp_fname, 'w')
    with open(data_fname, 'r') as f:
        for line in f:
            feat_type, name = line.rstrip('\n').split('_', 1)
            if feat_type == 'RestrictedApiList':
                continue
            elif feat_type == 'SuspiciousApiList':
                if name[0] == 'L':
                    api_name = name[1:].replace('/', '.').replace(';->', '.')
                else:
                    api_name = name.replace('/', '.')
                fout.write('%s_%s\n' % (feat_type, api_name))
            elif feat_type in ['ServiceList', 'BroadcastReceiverList', 'IntentFilterList', 'ActivityList']:
                continue
            elif feat_type == 'URLDomainList':
                continue
            else:
                fout.write(line)
    cmd = 'mv %s %s' % (tmp_fname, data_fname)
    os.system(cmd)
    return data_fname, True

def main():
    NCpuCores = psutil.cpu_count()

    for year in range(2012, 2015):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            MalDir = '/space1/ccs_drebin/malware/%s/%s' % (year, month)
            GoodDir = '/space1/ccs_drebin/benign/%s/%s' % (year, month)
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
                tmp_fname = os.path.splitext(DataFile)[0] + ".newdata"
                if True:
                    DataDirectoryPath = os.path.split(DataFile)[0]
                    ScheduledTasks.append(DataFile)
                    ProcessingResults = pool.apply_async(ProcessingData, args=(DataDirectoryPath, data_fname, tmp_fname),
                                                         callback=ProgressBar.CallbackForProgressBar)
            pool.close()
            if (ProcessingResults):
                ProgressBar.DisplayProgressBar(ProcessingResults, len(ScheduledTasks), type="hour")
            pool.join()


    return
    
if __name__ == "__main__":
    main()
