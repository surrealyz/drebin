#! /usr/bin/env python

import CommonModules as CM
import multiprocessing as mp
import os
import psutil, argparse, logging
import pickle

logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger('main.stdout')

def ProcessingDataForApiGraph(ApkDirectoryPath, data_fname, ag_fname, method_cluster_mapping, cluster_api_mapping):
    api_feat = set([])
    fout = open(ag_fname, 'w')
    with open(data_fname, 'r') as f:
        for line in f:
            feat_type, name = line.rstrip('\n').split('_', 1)
            if feat_type in ['SuspiciousApiList', 'RestrictedApiList']:
                if name[0] == 'L':
                    api_name = name[1:].replace('/', '.').replace(';->', '.')
                else:
                    api_name = name.replace('/', '.')
                cluster_id = method_cluster_mapping.get(api_name, None)
                if cluster_id != None:
                    new_name = cluster_api_mapping[cluster_id]
                    api_feat.add('%s_%s' % (feat_type, new_name))
                else:
                    fout.write(line)
            else:
                fout.write(line)
    for new_name in api_feat:
        fout.write('%s\n' % new_name)
    fout.close()

    return ag_fname, True

def main():
    NCpuCores = psutil.cpu_count()

    # read the cluster files
    method_cluster_mapping = pickle.load(open('/home/yz/code/APIGraph/src/res/method_cluster_mapping_2000.pkl', 'rb'))
    cluster_api_mapping = pickle.load(open('/home/yz/code/APIGraph/src/res/cluster_api_mapping_2000.pkl', 'rb'))

    for year in range(2014, 2015):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if year == 2014 and m != 9:
                continue
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            MalDir = '/space1/android/malware/%s/%s' % (year, month)
            GoodDir = '/space1/android/benign/%s/%s' % (year, month)
            print(MalDir, GoodDir)
            ApkFileList = []
            for ApkDirectoryPath in [MalDir, GoodDir]:
                ApkFileList.extend(CM.ListApkFiles(ApkDirectoryPath))

            pool = mp.Pool(NCpuCores)
            ProcessingResults = []
            ScheduledTasks = []
            ProgressBar = CM.ProgressBar()
            for ApkFile in ApkFileList:
                data_fname = os.path.splitext(ApkFile)[0] + ".data"
                ag_fname = os.path.splitext(ApkFile)[0] + ".ag"
                #if CM.FileExist(ag_fname):
                #    pass
                #else:
                if not CM.FileExist(data_fname):
                    pass
                else:
                    ApkDirectoryPath = os.path.split(ApkFile)[0]
                    ScheduledTasks.append(ApkFile)
                    ProcessingResults = pool.apply_async(ProcessingDataForApiGraph, args=(ApkDirectoryPath, data_fname, ag_fname, method_cluster_mapping, cluster_api_mapping),
                                                         callback=ProgressBar.CallbackForProgressBar)
            pool.close()
            if (ProcessingResults):
                ProgressBar.DisplayProgressBar(ProcessingResults, len(ScheduledTasks), type="hour")
            pool.join()


    return
    
if __name__ == "__main__":
    main()
