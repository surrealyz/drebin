#! /usr/bin/env python

import CommonModules as CM
import multiprocessing as mp
import os
import psutil, argparse, logging
import pickle

from xml.dom import minidom #mini Document Object Model for XML

def ProcessingData(XmlFile):
    with open(XmlFile, 'r') as f:
        label = XmlFile.split('/space1/android/')[1].split('/')[0]
        Dom = minidom.parse(f)
        DomCollection = Dom.documentElement
        
        basic = Dom.firstChild
        if basic.hasAttribute("android:versionCode"):
            versionCode = basic.getAttribute("android:versionCode")
        else:
            versionCode = None
        if basic.hasAttribute("android:versionName"):
            versionName = basic.getAttribute("android:versionName")
        else:
            versionName = None
        if basic.hasAttribute("package"):
            packageName = basic.getAttribute("package")
        else:
            packageName = None

        DomSdk = DomCollection.getElementsByTagName("uses-sdk")
        if DomSdk == []:
            minSdkVersion, targetSdkVersion, maxSdkVersion = None, None, None
        for item in DomSdk:
            if item.hasAttribute("android:minSdkVersion"):
                minSdkVersion = item.getAttribute("android:minSdkVersion")
            else:
                minSdkVersion = None
            if item.hasAttribute("android:targetSdkVersion"):
                targetSdkVersion = item.getAttribute("android:targetSdkVersion")
            else:
                targetSdkVersion = None
            if item.hasAttribute("android:maxSdkVersion"):
                maxSdkVersion = item.getAttribute("android:maxSdkVersion")
            else:
                maxSdkVersion = None
        fields = (packageName, versionCode, versionName, minSdkVersion, targetSdkVersion, maxSdkVersion, label, XmlFile)
    return fields

def main():
    NCpuCores = psutil.cpu_count()
    
    fout = open('analyze_sdkver_pt2.tsv', 'w')
    for year in range(2015, 2019):
        month_list = list(range(1, 13))
        for midx, m in enumerate(month_list):
            if year == 2015 and m <= 5:
                continue
            if midx < 9:
                month = '0%s' % m
            else:
                month = str(m)
            MonthStr = '%s-%s' % (year, month)
            MalDir = '/space1/android/malware/%s/%s' % (year, month)
            GoodDir = '/space1/android/benign/%s/%s' % (year, month)
            print(MalDir, GoodDir)
            XmlFileList = []
            for ApkDirectoryPath in [MalDir, GoodDir]:
                XmlFileList.extend(CM.ListXmlFiles(ApkDirectoryPath))

            pool = mp.Pool(NCpuCores)
            ProcessingResults = []
            ScheduledTasks = []
            ProgressBar = CM.ProgressBar()
            for XmlFile in XmlFileList:
                #data_fname = os.path.splitext(XmlFile)[0] + ".data"
                #if not CM.FileExist(data_fname):
                #    pass
                #else:
                if True:
                    ApkDirectoryPath = os.path.split(XmlFile)[0]
                    ScheduledTasks.append(XmlFile)
                    result_obj = pool.apply_async(ProcessingData, args=(XmlFile,),
                                                         callback=ProgressBar.CallbackForProgressBar)
                    ProcessingResults.append(result_obj)
            pool.close()
            if (result_obj):
                ProgressBar.DisplayProgressBar(result_obj, len(ScheduledTasks), type="hour")
            pool.join()
            for fields in ProcessingResults:
                fout.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' % (tuple([MonthStr] +  [item.encode('ascii', 'ignore') if item != None else item for item in fields.get()])))

    fout.close()

    return


if __name__ == "__main__":
    main()
