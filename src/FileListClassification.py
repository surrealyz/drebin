import numpy as np
import time
import scipy.sparse
import CommonModules as CM
import sys
from sklearn.feature_extraction.text import TfidfVectorizer as TF
from sklearn.calibration import CalibratedClassifierCV
from sklearn.svm import LinearSVC
from sklearn.model_selection import GridSearchCV
from sklearn import metrics
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
import logging
from joblib import dump, load
import json, os
from scipy.sparse import vstack

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

def sort_index(pred_scores):
    confidence = [(idx, abs(score)) for idx, score in enumerate(pred_scores)]
    sorted_conf = sorted(confidence, key=lambda x:x[1])
    return sorted_conf

def get_wrong_samples(y_test, y_pred, y_proba, test_samples):
    # FP samples: y_test = -1, y_pred = 1
    # FN samples: y_test = 1, y_pred = -1
    # tuple, e.g, (array([0, 1]),)
    fp_indices = np.where((y_test == -1) & (y_pred == 1))
    fn_indices = np.where((y_test == 1) & (y_pred == -1))
    return test_samples[fp_indices], test_samples[fn_indices], y_proba[fp_indices][:, 1], y_proba[fn_indices][:, 0]

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

def FileListClassificationSamples(SaveModelName, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, Model, NumTopFeats):
    # step 1: creating feature vector
    Logger.debug("Loading Malware and Goodware Sample Data for training and testing")
    AllTestSamples = TestMalSamples + TestGoodSamples
    Logger.info("Loaded Samples")

    FeatureVectorizer = TF(input="filename", tokenizer=lambda x: x.split('\n'), token_pattern=None,
                           binary=FeatureOption)
    x_train = FeatureVectorizer.fit_transform(TrainMalSamples + TrainGoodSamples)
    x_test = FeatureVectorizer.transform(TestMalSamples + TestGoodSamples)
    test_samples = np.array(TestMalSamples + TestGoodSamples)

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
        """
        Clf = GridSearchCV(LinearSVC(), Parameters, cv= 5, scoring= 'f1', n_jobs=-1 )
        SVMModels= Clf.fit(x_train, y_train)
        Logger.info("Processing time to train and find best model with GridSearchCV is %s sec." %(round(time.time() -T0, 2)))
        BestModel= SVMModels.best_estimator_
        Logger.info("Best Model Selected : {}".format(BestModel))
        """
        clf = CalibratedClassifierCV(LinearSVC())
        clf.fit(x_train, y_train)
        BestModel = clf
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
    y_proba = BestModel.predict_proba(x_test)
    TestingTime = round(time.time() - TrainingTime - T0,2)
    tpr, tnr, fpr, fnr, acc, precision, f1 = get_model_stats(y_test, y_pred)
    print('Model Performance\tTPR\tTNR\tFPR\tFNR\tACC\tPREC\tF1')
    print('Model Performance\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n' % \
	    (tpr, tnr, fpr, fnr, acc, precision, f1))
    sys.stdout.flush()
    #print(metrics.classification_report(y_test,
    #                                    y_pred, labels=[1, -1],
    #                                    target_names=['Malware', 'Goodware']))

    fp_samples, fn_samples, fp_scores, fn_scores = get_wrong_samples(y_test, y_pred, y_proba, test_samples)
    return fp_samples, fn_samples, fp_scores, fn_scores

def IncrementalClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, Model, NumTopFeats, year, month):
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
    
    len_sample = (x_test.shape[0]) / 100
    # count the number of additional labeled samples for this month
    label_num = 0
    while Model != None and f1 < 0.98 and x_test.shape[0] > 0:
        print('F1: %f Try to label more samples...' % f1)
        len_test_mal = len(TestMalSamples)
        len_test_ben = len(TestGoodSamples)
        # step 5: incrementally label 1% from the test set, move them to the training set
        # TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples
        pred_scores = BestModel.decision_function(x_test)
        # sort pred_scores and x_test from least confident to most confident
        sorted_conf = sort_index(pred_scores)
        # sample 1% from the test set
        if len(sorted_conf) >= len_sample:
            sample_indices = [x[0] for x in sorted_conf[:len_sample]]
        else:
            sample_indices = [x[0] for x in sorted_conf]
        label_num += len(sample_indices)
        NewModelName = '%s+%s-%s+%s.pkl' % (Model.split('.pkl')[0], year, month, label_num)
        remove_mal = []
        remove_ben = []
        for idx in sample_indices:
            if idx < len_test_mal:
                # malicious label
                TrainMalSamples.append(TestMalSamples[idx])
                remove_mal.append(TestMalSamples[idx])
            else:
                idx -= len_test_mal
                # benign label
                TrainGoodSamples.append(TestGoodSamples[idx])
                remove_ben.append(TestGoodSamples[idx])
        for item in remove_mal:
            TestMalSamples.remove(item)
        for item in remove_ben:
            TestGoodSamples.remove(item)

        x_train = FeatureVectorizer.fit_transform(TrainMalSamples + TrainGoodSamples)
        if len(sorted_conf) >= len_sample:
            x_test = FeatureVectorizer.transform(TestMalSamples + TestGoodSamples)
        else:
            x_test = None

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

        # step 6: train the model
        Logger.info("Perform Classification with SVM Model")
        Parameters= {'C': [0.001, 0.01, 0.1, 1, 10, 100, 1000]}

        T0 = time.time()
        Clf = GridSearchCV(LinearSVC(), Parameters, cv= 5, scoring= 'f1', n_jobs=-1 )
        SVMModels= Clf.fit(x_train, y_train)
        Logger.info("Processing time to train and find best model with GridSearchCV is %s sec." %(round(time.time() -T0, 2)))
        BestModel= SVMModels.best_estimator_
        Logger.info("Best Model Selected : {}".format(BestModel))
        TrainingTime = round(time.time() - T0,2)
        print "The training time is %s sec." % (TrainingTime)
        print "Save the retrained model to %s" % NewModelName
        dump(BestModel, NewModelName)
        
        if x_test != None:
            # step 7: Evaluate the best model on test set
            # y_pred is predicted class label
            y_pred = BestModel.predict(x_test)
            TestingTime = round(time.time() - TrainingTime - T0,2)
            tpr, tnr, fpr, fnr, acc, precision, f1 = get_model_stats(y_test, y_pred)
            print('Model Performance\tTPR\tTNR\tFPR\tFNR\tACC\tPREC\tF1')
            print('Model Performance\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n' % \
                    (tpr, tnr, fpr, fnr, acc, precision, f1))
            sys.stdout.flush()

    if label_num != 0:
        print "Save the retrained model to %s" % Model
        dump(BestModel, Model)

    return y_train, y_test, y_pred, TrainingTime, TestingTime


def TargetScoreClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, Model, NumTopFeats, year, month, target_score):
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
    
    len_sample = (x_test.shape[0]) / 100
    # count the number of additional labeled samples for this month
    label_num = 0
    while Model != None and f1 < target_score and x_test.shape[0] > 0:
        print('F1: %f Try to label more samples...' % f1)
        len_test_mal = len(TestMalSamples)
        len_test_ben = len(TestGoodSamples)
        # step 5: incrementally label 1% from the test set, move them to the training set
        # TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples
        pred_scores = BestModel.decision_function(x_test)
        # sort pred_scores and x_test from least confident to most confident
        sorted_conf = sort_index(pred_scores)
        # sample 1% from the test set
        if len(sorted_conf) >= len_sample:
            sample_indices = [x[0] for x in sorted_conf[:len_sample]]
        else:
            sample_indices = [x[0] for x in sorted_conf]
        label_num += len(sample_indices)
        NewModelName = '%s+%s-%s+%s.pkl' % (Model.split('.pkl')[0], year, month, label_num)
        remove_mal = []
        remove_ben = []
        for idx in sample_indices:
            if idx < len_test_mal:
                # malicious label
                TrainMalSamples.append(TestMalSamples[idx])
                remove_mal.append(TestMalSamples[idx])
            else:
                idx -= len_test_mal
                # benign label
                TrainGoodSamples.append(TestGoodSamples[idx])
                remove_ben.append(TestGoodSamples[idx])
        for item in remove_mal:
            TestMalSamples.remove(item)
        for item in remove_ben:
            TestGoodSamples.remove(item)

        x_train = FeatureVectorizer.fit_transform(TrainMalSamples + TrainGoodSamples)
        if len(sorted_conf) >= len_sample:
            x_test = FeatureVectorizer.transform(TestMalSamples + TestGoodSamples)
        else:
            x_test = None

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

        # step 6: train the model
        Logger.info("Perform Classification with SVM Model")
        Parameters= {'C': [0.001, 0.01, 0.1, 1, 10, 100, 1000]}

        T0 = time.time()
        Clf = GridSearchCV(LinearSVC(), Parameters, cv= 5, scoring= 'f1', n_jobs=-1 )
        SVMModels= Clf.fit(x_train, y_train)
        Logger.info("Processing time to train and find best model with GridSearchCV is %s sec." %(round(time.time() -T0, 2)))
        BestModel= SVMModels.best_estimator_
        Logger.info("Best Model Selected : {}".format(BestModel))
        TrainingTime = round(time.time() - T0,2)
        print "The training time is %s sec." % (TrainingTime)
        print "Save the retrained model to %s" % NewModelName
        dump(BestModel, NewModelName)
        
        if x_test != None:
            # step 7: Evaluate the best model on test set
            # y_pred is predicted class label
            y_pred = BestModel.predict(x_test)
            TestingTime = round(time.time() - TrainingTime - T0,2)
            tpr, tnr, fpr, fnr, acc, precision, f1 = get_model_stats(y_test, y_pred)
            print('Model Performance\tTPR\tTNR\tFPR\tFNR\tACC\tPREC\tF1')
            print('Model Performance\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n' % \
                    (tpr, tnr, fpr, fnr, acc, precision, f1))
            sys.stdout.flush()

    if label_num != 0:
        print "Save the retrained model to %s" % Model
        dump(BestModel, Model)

    return y_train, y_test, y_pred, TrainingTime, TestingTime

def SelfSupervised(SaveModelName, TrainSamples, y_train, TestSamples, y_test, FeatureOption, Model, NumTopFeats, year, month):
    # step 1: creating feature vector
    Logger.debug("Loading Malware and Goodware Sample Data for training and testing")
    Logger.info("Loaded Samples")

    FeatureVectorizer = TF(input="filename", tokenizer=lambda x: x.split('\n'), token_pattern=None,
                           binary=FeatureOption)
    x_train = FeatureVectorizer.fit_transform(TrainSamples)
    x_test = FeatureVectorizer.transform(TestSamples)

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

    # step 3: Evaluate the best model on test set
    # y_pred is predicted class label
    y_pred = BestModel.predict(x_test)
    TestingTime = round(time.time() - TrainingTime - T0,2)
    tpr, tnr, fpr, fnr, acc, precision, f1 = get_model_stats(y_test, y_pred)
    print('Model Performance\tTPR\tTNR\tFPR\tFNR\tACC\tPREC\tF1')
    print('Model Performance\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n' % \
	    (tpr, tnr, fpr, fnr, acc, precision, f1))
    sys.stdout.flush()

    # step 4: add all these samples to the training set
    print('Use prediction to label %d more samples...' % x_test.shape[0])
    
    TrainSamples.extend(TestSamples)
    x_train = FeatureVectorizer.fit_transform(TrainSamples)
    y_train = np.concatenate((y_train, y_pred), axis=0)
    
    # step 5: retrain the model
    Logger.info("Perform Classification with SVM Model")
    Parameters= {'C': [0.001, 0.01, 0.1, 1, 10, 100, 1000]}

    T0 = time.time()
    Clf = GridSearchCV(LinearSVC(), Parameters, cv= 5, scoring= 'f1', n_jobs=-1 )
    SVMModels= Clf.fit(x_train, y_train)
    Logger.info("Processing time to train and find best model with GridSearchCV is %s sec." %(round(time.time() -T0, 2)))
    BestModel= SVMModels.best_estimator_
    Logger.info("Best Model Selected : {}".format(BestModel))
    TrainingTime = round(time.time() - T0,2)
    print "The training time is %s sec." % (TrainingTime)
    print "Save the retrained model to %s" % Model
    dump(BestModel, Model)

    return TrainSamples, y_train

def RangeClassification(SaveModelName, TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples, FeatureOption, Model, NumTopFeats, year, month, low_score, target_score):
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
    
    len_sample = (x_test.shape[0]) / 100
    # count the number of additional labeled samples for this month
    label_num = 0
    if f1 < low_score:
        while Model != None and x_test.shape[0] > 0 and f1 < target_score:
            print('F1: %f Try to label more samples...' % f1)
            len_test_mal = len(TestMalSamples)
            len_test_ben = len(TestGoodSamples)
            # step 5: incrementally label 1% from the test set, move them to the training set
            # TrainMalSamples, TrainGoodSamples, TestMalSamples, TestGoodSamples
            pred_scores = BestModel.decision_function(x_test)
            # sort pred_scores and x_test from least confident to most confident
            sorted_conf = sort_index(pred_scores)
            # sample 1% from the test set
            if len(sorted_conf) >= len_sample:
                sample_indices = [x[0] for x in sorted_conf[:len_sample]]
            else:
                sample_indices = [x[0] for x in sorted_conf]
            label_num += len(sample_indices)
            NewModelName = '%s+%s-%s+%s.pkl' % (Model.split('.pkl')[0], year, month, label_num)
            remove_mal = []
            remove_ben = []
            for idx in sample_indices:
                if idx < len_test_mal:
                    # malicious label
                    TrainMalSamples.append(TestMalSamples[idx])
                    remove_mal.append(TestMalSamples[idx])
                else:
                    idx -= len_test_mal
                    # benign label
                    TrainGoodSamples.append(TestGoodSamples[idx])
                    remove_ben.append(TestGoodSamples[idx])
            for item in remove_mal:
                TestMalSamples.remove(item)
            for item in remove_ben:
                TestGoodSamples.remove(item)

            x_train = FeatureVectorizer.fit_transform(TrainMalSamples + TrainGoodSamples)
            if len(sorted_conf) >= len_sample:
                x_test = FeatureVectorizer.transform(TestMalSamples + TestGoodSamples)
            else:
                x_test = None

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

            # step 6: train the model
            Logger.info("Perform Classification with SVM Model")
            Parameters= {'C': [0.001, 0.01, 0.1, 1, 10, 100, 1000]}

            T0 = time.time()
            Clf = GridSearchCV(LinearSVC(), Parameters, cv= 5, scoring= 'f1', n_jobs=-1 )
            SVMModels= Clf.fit(x_train, y_train)
            Logger.info("Processing time to train and find best model with GridSearchCV is %s sec." %(round(time.time() -T0, 2)))
            BestModel= SVMModels.best_estimator_
            Logger.info("Best Model Selected : {}".format(BestModel))
            TrainingTime = round(time.time() - T0,2)
            print "The training time is %s sec." % (TrainingTime)
            print "Save the retrained model to %s" % NewModelName
            dump(BestModel, NewModelName)
            
            if x_test != None:
                # step 7: Evaluate the best model on test set
                # y_pred is predicted class label
                y_pred = BestModel.predict(x_test)
                TestingTime = round(time.time() - TrainingTime - T0,2)
                tpr, tnr, fpr, fnr, acc, precision, f1 = get_model_stats(y_test, y_pred)
                print('Model Performance\tTPR\tTNR\tFPR\tFNR\tACC\tPREC\tF1')
                print('Model Performance\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n' % \
                        (tpr, tnr, fpr, fnr, acc, precision, f1))
                sys.stdout.flush()

    if label_num != 0:
        print "Save the retrained model to %s" % Model
        dump(BestModel, Model)

    return y_train, y_test, y_pred, TrainingTime, TestingTime
