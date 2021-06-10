import numpy as np
import time
import scipy.sparse
import CommonModules as CM
import sys
from sklearn.feature_extraction.text import TfidfVectorizer as TF
from sklearn.svm import LinearSVC
from sklearn.model_selection import GridSearchCV
from sklearn import metrics
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
import logging
from joblib import dump, load
import json, os
#from pprint import pprint

logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger('HoldoutClf.stdout')
Logger.setLevel("INFO")

def f1_score(precision, recall):
    return 2*precision*recall/float(precision+recall)

def get_model_stats(y, y_pred):
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    #print(tp, tn, fp, fn)
    acc = (tp+tn)/float(tp+tn+fp+fn)
    fpr = fp/float(fp+tn)
    tpr = tp/float(tp+fn)
    tnr = tn/float(fp+tn)
    fnr = fn/float(fn+tp)
    precision = tp/float(tp+fp)
    recall = tp/float(tp+fn)
    return tpr, tnr, fpr, fnr, acc, precision, f1_score(precision, tpr)

def FileListClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, Model, NumTopFeats):
    # step 1: creating feature vector
    Logger.debug("Loading Malware and Goodware Sample Data for training and testing")
    AllTestSamples = TestMalSamples + TestGoodSamples
    Logger.info("Loaded Samples")

    FeatureVectorizer = TF(input="filename", tokenizer=lambda x: x.split('\n'), token_pattern=None,
                           binary=FeatureOption)
    x_train = FeatureVectorizer.fit_transform(TrainMalSamples + TrainGoodSamples)
    x_test = FeatureVectorizer.transform(TestMalSamples + TestGoodSamples)

    # label training sets malware as 1 and goodware as -1
    Train_Mal_labels = np.ones(len(TrainMalSamples))
    Train_Good_labels = np.empty(len(TrainGoodSamples))
    Train_Good_labels.fill(-1)
    y_train = np.concatenate((Train_Mal_labels, Train_Good_labels), axis=0)
    Logger.info("Training Label array - generated")

    # label testing sets malware as 1 and goodware as -1
    Test_Mal_labels = np.ones(len(TestMalSamples))
    Test_Good_labels = np.empty(len(TestGoodSamples))
    Test_Good_labels.fill(-1)
    y_test = np.concatenate((Test_Mal_labels, Test_Good_labels), axis=0)
    Logger.info("Testing Label array - generated")

    # step 2: train the model
    Logger.info("Perform Classification with SVM Model")
    Parameters= {'C': [0.001, 0.01, 0.1, 1, 10, 100, 1000]}

    T0 = time.time()
    if not Model:
        Clf = GridSearchCV(LinearSVC(), Parameters, cv= 5, scoring= 'f1', n_jobs=-1 )
        SVMModels= Clf.fit(x_train, y_train)
        Logger.info("Processing time to train and find best model with GridSearchCV is %s sec." %(round(time.time() -T0, 2)))
        BestModel= SVMModels.best_estimator_
        Logger.info("Best Model Selected : {}".format(BestModel))
        TrainingTime = round(time.time() - T0,2)
        print "The training time for random split classification is %s sec." % (TrainingTime)
        print "Save the model to %s" % SaveModelName
        dump(BestModel, SaveModelName)
    else:
        BestModel = load(Model)
        TrainingTime = 0

    # step 4: Evaluate the best model on test set
    # y_pred is predicted class label
    y_pred = BestModel.predict(x_test)
    TestingTime = round(time.time() - TrainingTime - T0,2)
    tpr, tnr, fpr, fnr, acc, precision, f1 = get_model_stats(y_test, y_pred)
    print('Model Performance\tTPR\tTNR\tFPR\tFNR\tACC\tPREC\tF1')
    print('Model Performance\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n' % \
	    (tpr, tnr, fpr, fnr, acc, precision, f1))
    sys.stdout.flush()
    #print(metrics.classification_report(y_test,
    #                                    y_pred, labels=[1, -1],
    #                                    target_names=['Malware', 'Goodware']))

    return y_train, y_test, y_pred, TrainingTime, TestingTime
