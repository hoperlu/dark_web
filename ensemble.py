import numpy as np
from keras.models import Sequential
from keras.layers.core import Dense,Dropout,Activation
from keras.optimizers import Adam
from keras import regularizers
from keras.callbacks import EarlyStopping
import keras.backend.tensorflow_backend as K
from sklearn.model_selection import KFold
import tensorflow as tf
import my_tools
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
import xgboost as xgb
from sklearn.svm import LinearSVC

def build_true_predict_labels(label_true,label_pred,f_name):
	'''
	建立能用來畫confusionmatrix的txt檔
	但跟my_tools裡的不同，這個地輸入是label_true(類行為串列)跟label_pred(類行為串列)
	'''
	label_true_temp=label_true.copy()
	label_pred_temp=label_pred.copy()
	for index in range(len(label_pred)):
		label_pred_temp[index]=str(label_pred_temp[index])
		label_true_temp[index]=str(label_true_temp[index])
	true_predict_labels=''
	true_predict_labels+=' '.join(label_true_temp)+'\n'+' '.join(label_pred_temp)+'\n'
	f=open(f_name,'wt',encoding='big5')
	f.write(true_predict_labels)
	f.close()

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
gpu_options = tf.GPUOptions(per_process_gpu_memory_fraction = 0.1)
session = tf.Session(config = tf.ConfigProto(gpu_options = gpu_options))
K.set_session(session)

#用總資料的90%資料做training, 10%testing
mirror_test=0
del_types=[]
del_features=[0,1,3,6,9,10,11,16,21,26,31,43,44,55,56]
number=0.9
pcap_type='tor'
zeros=1
retrans=0
timeout=60
max_num_pkts=50
raw_data=np.genfromtxt('CSV_scapy/{}/timeout_flows_zeros={}_retrans={}_timeout={}_max_num_pkts={}.csv'.format(pcap_type,zeros,retrans,timeout,max_num_pkts),dtype=None,delimiter=',',encoding='utf8')
mode='duplicate_data_percentage'
mirror_train=0
flows=my_tools.FLOWS(raw_data,del_types,del_features,number,mode,mirror_train,mirror_test)
(training_data,label)=flows.build_training_data()
(testing_data,label_true)=flows.build_testing_data()
label_true=flows.label_transformer(label_true)

#用90%資料中的(n_splits-1)/n_splits訓練dnn, random_forest, xgb, svm, 
#用90%資料剩下的1/n_splits做validate, 同時當ensemble的training data(要做oversampling)
n_splits=10
kf=KFold(n_splits=n_splits,shuffle=True)
for train_index, validate_index in kf.split(training_data):
	(training_data_train,label_train)=flows.build_training_data_train(training_data[train_index],label[train_index])
	(training_data_validate,label_validate)=(training_data[validate_index].copy(),label[validate_index].copy())
	(training_data_validate,label_validate)=flows.build_training_data_train(training_data_validate,label_validate)
	label_train=flows.label_transformer(label_train)
	label_validate=flows.label_transformer(label_validate)

	model_rf=RandomForestClassifier(n_estimators=100,criterion='gini', max_depth=None, min_samples_split=2, min_samples_leaf=1, 
		min_weight_fraction_leaf=0.0, max_features='auto', max_leaf_nodes=None, min_impurity_decrease=0.0, min_impurity_split=None, 
		bootstrap=True, oob_score=False, n_jobs=1, random_state=None, verbose=0, warm_start=False, class_weight=None)
	model_rf=model_rf.fit(training_data_train,label_train)
	label_pred_rf=flows.label_transformer(list(model_rf.predict(training_data_validate)))

	dtrain=xgb.DMatrix(training_data_train,label=label_train)
	dvalidate=xgb.DMatrix(training_data_validate,label=label_validate)
	param = {'eta':0.9,'gamma':0,'max_depth':6,'min_child_weight':1,'subsample':1,'objective':'multi:softprob','num_class':8-len(del_types),'nthread':4}
	evallist = [(dtrain, 'train'),(dvalidate, 'eval')]
	model_xgb=xgb.train(param,dtrain,300,evallist,early_stopping_rounds=2,verbose_eval=False)
	label_pred_xgb=model_xgb.predict(dvalidate,ntree_limit=model_xgb.best_ntree_limit)
	
	model_svm=LinearSVC()
	model_svm.fit(training_data_train,label_train)
	label_pred_svm=flows.label_transformer(list(model_svm.predict(training_data_validate)))

	label_train=flows.label_transformer(label_train)
	label_validate=flows.label_transformer(label_validate)
	training_data_train=flows.normalization(training_data_train)
	training_data_validate=flows.normalize_with_given_mean_std(training_data_validate)
	model_dense=Sequential()
	model_dense.add(Dense(256,activation='relu',batch_input_shape=(None,training_data_train.shape[1])))
	model_dense.add(Dropout(0.5))
	model_dense.add(Dense(256,activation='relu'))
	model_dense.add(Dropout(0.5))
	model_dense.add(Dense(256,activation='relu'))
	model_dense.add(Dropout(0.5))
	model_dense.add(Dense(256,activation='relu'))
	model_dense.add(Dropout(0.5))
	model_dense.add(Dense(256,activation='relu'))
	model_dense.add(Dropout(0.5))
	model_dense.add(Dense(128,activation='relu'))
	model_dense.add(Dropout(0.5))
	model_dense.add(Dense(32,activation='relu'))
	model_dense.add(Dropout(0.5))
	model_dense.add(Dense(units=8-len(del_types),activation='softmax'))
	model_dense.compile(loss='categorical_crossentropy',optimizer='Adam',metrics=['categorical_accuracy'])
	model_dense.fit(x=training_data_train,y=label_train,batch_size=400,epochs=3000,verbose=0,validation_data=(training_data_validate,label_validate),
		callbacks=[EarlyStopping(patience=2,restore_best_weights=True)])
	label_pred_dense=model_dense.predict(training_data_validate)
	break

#用90%資料剩下的10%(佔總資料的9%)訓練ensemble model, 這其中有10%(佔總資料的0.9%)拿去做validate
training_data_ensemble=np.append(label_pred_dense,label_pred_rf,1)
training_data_ensemble=np.append(training_data_ensemble,label_pred_xgb,1)
training_data_ensemble=np.append(training_data_ensemble,label_pred_svm,1)
#training_data_ensemble=np.append(training_data_ensemble,training_data_validate,1)
model=Sequential()
model.add(Dense(32,activation='relu',batch_input_shape=(None,training_data_ensemble.shape[1])))
#model.add(Dropout(0.5))
model.add(Dense(32,activation='relu'))
model.add(Dense(32,activation='relu'))
model.add(Dense(32,activation='relu'))
#model.add(Dropout(0.5))
model.add(Dense(16,activation='relu'))
#model.add(Dropout(0.5))
model.add(Dense(units=8-len(del_types),activation='softmax'))
model.compile(loss='categorical_crossentropy',optimizer='Adam',metrics=['categorical_accuracy'])
model.fit(x=training_data_ensemble,y=label_validate,batch_size=400,epochs=3000,verbose=0,validation_split=0.1,
	callbacks=[EarlyStopping(patience=2,restore_best_weights=True)])

#test testing data
label_pred_rf=list(model_rf.predict(testing_data))
build_true_predict_labels(label_true,label_pred_rf,'ensemble_txt/{}/random_forest_true_predict_labels.txt'.format(pcap_type))
label_pred_rf=flows.label_transformer(label_pred_rf)
dtest=xgb.DMatrix(testing_data)
label_pred_xgb=model_xgb.predict(dtest,ntree_limit=model_xgb.best_ntree_limit)
label_pred_svm=list(model_svm.predict(testing_data))
build_true_predict_labels(label_true,label_pred_svm,'ensemble_txt/{}/svm_true_predict_labels.txt'.format(pcap_type))
label_pred_svm=flows.label_transformer(label_pred_svm)
testing_data=flows.normalize_with_given_mean_std(testing_data)
label_pred_dense=model_dense.predict(testing_data)
testing_data=np.append(label_pred_dense,label_pred_rf,1)
testing_data=np.append(testing_data,label_pred_xgb,1)
testing_data=np.append(testing_data,label_pred_svm,1)
#testing_data=np.append(testing_data,testing_data,1)
label_pred_ensemble=model.predict(testing_data)
label_pred_dense=flows.label_transformer(label_pred_dense)
build_true_predict_labels(label_true,label_pred_dense,'ensemble_txt/{}/dense_true_predict_labels.txt'.format(pcap_type))
label_pred_xgb=flows.label_transformer(label_pred_xgb)
build_true_predict_labels(label_true,label_pred_xgb,'ensemble_txt/{}/xgb_true_predict_labels.txt'.format(pcap_type))
label_pred_ensemble=flows.label_transformer(label_pred_ensemble)
build_true_predict_labels(label_true,label_pred_ensemble,'ensemble_txt/{}/ensemble_true_predict_labels.txt'.format(pcap_type))

