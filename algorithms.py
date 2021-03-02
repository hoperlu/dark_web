import numpy as np
from keras.models import Sequential
from keras.layers.core import Dense,Dropout,Activation
from keras.optimizers import Adam
from keras import regularizers
from keras.callbacks import EarlyStopping
import keras.backend.tensorflow_backend as K
from sklearn.model_selection import KFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn import tree
import xgboost as xgb
import tensorflow as tf
import lightgbm as lgb
from catboost import CatBoostClassifier, Pool
import my_tools
import os

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
gpu_options = tf.compat.v1.GPUOptions(per_process_gpu_memory_fraction = 0.1)
session = tf.compat.v1.Session(config = tf.compat.v1.ConfigProto(gpu_options = gpu_options))
K.set_session(session)
'''
#use 10-fold to find the best parameters
mirror_test=0
del_types=[]
del_features=[0,1,3,6,7,9,10,11,16,21,26,31,36,43,44,55,56]#[0,1,4,5,7,8,9,10,21,26,31]+[index for index in range(11,21)]+[index for index in range(36,65+256)]
number=1
pcap_type='tor'
cross_validate_result=''
algorithm='dt' #'dense','random_forest','knn','xgb','svm','cat','lgb','dt'
f=open('{}_out.txt'.format(algorithm),'wt',encoding='big5')
print(algorithm)
mirror_train=0
zeros=1
retrans=0
mode='duplicate_data_percentage'
max_num_pkts=1000
timeout=0
#for zeros in (0,1):
for timeout in (0,10,15,30,60,120):
#for max_num_pkts in (5,10,20,50,100,250,500,1000):
	raw_data=np.genfromtxt('CSV_scapy/{}/timeout_flows_zeros={}_retrans={}_timeout={}_max_num_pkts={}.csv'.format(pcap_type,zeros,retrans,timeout,max_num_pkts),dtype=None,delimiter=',',encoding='utf8')
	#for mode in ('duplicate_data_percentage','percentage'):
		#for mirror_train in (0,1):
	flows=my_tools.FLOWS(raw_data,del_types,del_features,number,mode,mirror_train,mirror_test)
	(training_data,label)=flows.build_training_data()
	#(testing_data,label_true)=flows.build_testing_data()

	n_splits=10
	kf=KFold(n_splits=n_splits,shuffle=True)
	total_acc=0
	total_recall=0
	avg_precision=0
	tenfold_validate_label_true=[]
	tenfold_validate_label_pred=[]
	for train_index, validate_index in kf.split(training_data):
		(training_data_train,label_train)=flows.build_training_data_train(training_data[train_index],label[train_index])
		(training_data_validate,label_validate)=(np.delete(training_data[validate_index],del_features,1),label[validate_index].copy())
		if algorithm=='dense':
			training_data_train=flows.normalization(training_data_train)
			training_data_validate=flows.normalize_with_given_mean_std(training_data_validate)
			model=Sequential()
			model.add(Dense(256,activation='relu',batch_input_shape=(None,training_data_train.shape[1])))
			model.add(Dropout(0.5))
			model.add(Dense(256,activation='relu'))
			model.add(Dropout(0.5))
			model.add(Dense(256,activation='relu'))
			model.add(Dropout(0.5))
			model.add(Dense(256,activation='relu'))
			model.add(Dropout(0.5))
			model.add(Dense(256,activation='relu'))
			model.add(Dropout(0.5))
			model.add(Dense(128,activation='relu'))
			model.add(Dropout(0.5))
			model.add(Dense(32,activation='relu'))
			model.add(Dropout(0.5))
			model.add(Dense(units=8-len(del_types),activation='softmax'))
			model.compile(loss='categorical_crossentropy',optimizer='Adam',metrics=['categorical_accuracy'])
			model.fit(x=training_data_train,y=label_train,batch_size=400,epochs=3000,verbose=0,validation_data=(training_data_validate,label_validate),
				callbacks=[EarlyStopping(patience=2,restore_best_weights=True),my_tools.my_tensorboard('dense_txt/{}/{}_{}_{}_{}_{}_{}_{}_tensorboard.txt'.format(pcap_type,mode,mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts))])
			label_pred=flows.label_transformer(model.predict(training_data_validate))
			label_validate=flows.label_transformer(label_validate)
		if algorithm=='random_forest':
			label_train=flows.label_transformer(label_train)
			label_validate=flows.label_transformer(label_validate)
			model=RandomForestClassifier(n_estimators=100,criterion='gini', max_depth=None, min_samples_split=2, min_samples_leaf=1, 
				min_weight_fraction_leaf=0.0, max_features='auto', max_leaf_nodes=None, min_impurity_decrease=0.0, min_impurity_split=None, 
				bootstrap=True, oob_score=False, n_jobs=1, random_state=None, verbose=0, warm_start=False, class_weight=None)
			model=model.fit(training_data_train,label_train)
			label_pred=model.predict(training_data_validate)
		if algorithm=='knn':
			label_train=flows.label_transformer(label_train)
			label_validate=flows.label_transformer(label_validate)
			model=KNeighborsClassifier()
			model=model.fit(training_data_train,label_train)
			label_pred=model.predict(training_data_validate)
		if algorithm=='xgb':
			label_train=flows.label_transformer(label_train)
			label_validate=flows.label_transformer(label_validate)
			dtrain=xgb.DMatrix(training_data_train,label=label_train)
			dvalidate=xgb.DMatrix(training_data_validate,label=label_validate)
			param = {'eta':0.9,'gamma':0,'max_depth':6,'min_child_weight':1,'subsample':1,'objective':'multi:softprob','num_class':8-len(del_types),'nthread':4}
			evallist = [(dtrain, 'train'),(dvalidate, 'eval')]
			model=xgb.train(param,dtrain,300,evallist,early_stopping_rounds=2,verbose_eval=False)
			dtest=xgb.DMatrix(training_data_validate)
			label_pred=flows.label_transformer(model.predict(dtest,ntree_limit=model.best_ntree_limit))
		if algorithm=='svm':
			label_train=flows.label_transformer(label_train)
			label_validate=flows.label_transformer(label_validate)
			model=LinearSVC()
			model.fit(training_data_train,label_train)	
			label_pred=model.predict(training_data_validate)
		if algorithm=='lgb':
			label_train=flows.label_transformer(label_train)
			label_validate=flows.label_transformer(label_validate)
			dtrain=lgb.Dataset(training_data_train,label=label_train,params={'verbose': -1})
			dvalidate=lgb.Dataset(training_data_validate,label=label_validate,params={'verbose': -1})
			param={'objective':'multiclass','num_class':8-len(del_types),'verbose': -1}#multiclassova cross_entropy cross_entropy_lambda
			model=lgb.train(param,dtrain,valid_sets=[dvalidate],early_stopping_rounds=2)
			label_pred=flows.label_transformer(model.predict(training_data_validate))
		if algorithm=='cat':
			label_train=flows.label_transformer(label_train)
			label_validate=flows.label_transformer(label_validate)
			model=CatBoostClassifier(loss_function='MultiClass',logging_level='Silent',early_stopping_rounds=2)
			model.fit(training_data_train,label_train,eval_set=(training_data_validate,label_validate))
			label_pred=flows.label_transformer(model.predict(training_data_validate))
		if algorithm=='dt':
			label_train=flows.label_transformer(label_train)
			label_validate=flows.label_transformer(label_validate)
			model=tree.DecisionTreeClassifier()
			model=model.fit(training_data_train,label_train)
			label_pred=model.predict(training_data_validate)
		acc=0
		recall=0
		precision=0
		recalls=[[0,0] for index in range(8-len(del_types))]
		precisions=[[0,0] for index in range(8-len(del_types))]
		for index in range(len(label_validate)):
			precisions[label_pred[index]][1]+=1
			recalls[label_validate[index]][1]+=1
			if label_validate[index]==label_pred[index]:
				recalls[label_validate[index]][0]+=1
				precisions[label_validate[index]][0]+=1
				acc+=1
		nan_count=0
		for term in recalls:
			try:
				recall+=term[0]/term[1]
			except:
				nan_count+=1
		for term in precisions:
			if term[1]==0:
				avg_precision='nan'
				break
			else:
				precision+=term[0]/term[1]
		else:
			avg_precision+=precision/len(precisions)
		total_acc+=acc/len(label_validate)
		total_recall+=recall/(len(recalls)-nan_count)
		tenfold_validate_label_true.extend(label_validate)
		tenfold_validate_label_pred.extend(label_pred)
		if avg_precision=='nan':
			break
	try:
		avg_precision/=n_splits
	except:
		pass
	cross_validate_result+=str(pcap_type)+'_'+str(mode)+'_'+str(mirror_train)+'_'+str(mirror_test)+'_'+str(zeros)+'_'+str(retrans)+'_'+str(timeout)+'_'+str(max_num_pkts)+' '+str(total_acc/n_splits)+' '+str(total_recall/n_splits)+' '+str(avg_precision)+'\n'

	true_predict_labels=''
	for index in range(len(tenfold_validate_label_true)):
		tenfold_validate_label_true[index]=str(tenfold_validate_label_true[index])
		tenfold_validate_label_pred[index]=str(tenfold_validate_label_pred[index])
	true_predict_labels+=' '.join(tenfold_validate_label_true)+'\n'+' '.join(tenfold_validate_label_pred)+'\n'
	f2=open('{}_txt/{}/10_fold_{}_{}_{}_{}_{}_{}_{}_true_predict_labels.txt'.format(algorithm,pcap_type,mode,mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts),'wt',encoding='big5')
	f2.write(true_predict_labels)
	f2.close()
f.write(cross_validate_result)
f.close()
'''

#parameters have been determined, no 10-fold
mirror_test=0
del_types=[]
del_features=[0,1,3,6,7,9,10,11,16,21,26,31,36,43,44,55,56]#[0,1,4,5,7,8,9,10,21,26,31]+[index for index in range(11,21)]+[index for index in range(36,65+256)]
number=0.9
pcap_type='tor'
mirror_train=0
zeros=1
retrans=0
mode='duplicate_data_percentage'
timeout=30
max_num_pkts=1000
algorithm='cat'
#for timeout in (10,15,30,60,120):
#for max_num_pkts in (0,5,10,20,50,100,250,500,1000):
raw_data=np.genfromtxt('CSV_scapy/{}/timeout_flows_zeros={}_retrans={}_timeout={}_max_num_pkts={}.csv'.format(pcap_type,zeros,retrans,timeout,max_num_pkts),dtype=None,delimiter=',',encoding='utf8')
#for algorithm in ('dense','random_forest','knn','xgb','cat','lgb','svm','dt'):
flows=my_tools.FLOWS(raw_data,del_types,del_features,number,mode,mirror_train,mirror_test)
(training_data,label)=flows.build_training_data()
(testing_data,label_true)=flows.build_testing_data()

n_splits=10
kf=KFold(n_splits=n_splits,shuffle=True)
testing_label_true=[]
testing_label_pred=[]
for train_index, validate_index in kf.split(training_data):
	(training_data_train,label_train)=flows.build_training_data_train(training_data[train_index],label[train_index])
	(training_data_validate,label_validate)=(np.delete(training_data[validate_index],del_features,1),label[validate_index].copy())
	if algorithm=='dense':
		training_data_train=flows.normalization(training_data_train)
		training_data_validate=flows.normalize_with_given_mean_std(training_data_validate)
		testing_data=flows.normalize_with_given_mean_std(testing_data)
		model=Sequential()
		model.add(Dense(256,activation='relu',batch_input_shape=(None,training_data_train.shape[1])))
		model.add(Dropout(0.5))
		model.add(Dense(256,activation='relu'))
		model.add(Dropout(0.5))
		model.add(Dense(256,activation='relu'))
		model.add(Dropout(0.5))
		model.add(Dense(256,activation='relu'))
		model.add(Dropout(0.5))
		model.add(Dense(256,activation='relu'))
		model.add(Dropout(0.5))
		model.add(Dense(128,activation='relu'))
		model.add(Dropout(0.5))
		model.add(Dense(32,activation='relu'))
		model.add(Dropout(0.5))
		model.add(Dense(units=8-len(del_types),activation='softmax'))
		model.compile(loss='categorical_crossentropy',optimizer='Adam',metrics=['categorical_accuracy'])
		model.fit(x=training_data_train,y=label_train,batch_size=400,epochs=3000,verbose=0,validation_data=(training_data_validate,label_validate),
			callbacks=[EarlyStopping(patience=2,restore_best_weights=True),my_tools.my_tensorboard('dense_txt/{}/{}_{}_{}_{}_{}_{}_{}_tensorboard.txt'.format(pcap_type,mode,mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts))])
		label_pred=flows.label_transformer(model.predict(testing_data))
	if algorithm=='random_forest':
		label_train=flows.label_transformer(label_train)
		label_validate=flows.label_transformer(label_validate)
		model=RandomForestClassifier(n_estimators=100,criterion='gini', max_depth=None, min_samples_split=2, min_samples_leaf=1, 
			min_weight_fraction_leaf=0.0, max_features='auto', max_leaf_nodes=None, min_impurity_decrease=0.0, min_impurity_split=None, 
			bootstrap=True, oob_score=False, n_jobs=1, random_state=None, verbose=0, warm_start=False, class_weight=None)
		model=model.fit(training_data_train,label_train)
		label_pred=model.predict(testing_data)
		#print(list(model.feature_importances_))
	if algorithm=='knn':
		label_train=flows.label_transformer(label_train)
		label_validate=flows.label_transformer(label_validate)
		model=KNeighborsClassifier()
		model=model.fit(training_data_train,label_train)
		label_pred=model.predict(testing_data)
	if algorithm=='xgb':
		label_train=flows.label_transformer(label_train)
		label_validate=flows.label_transformer(label_validate)
		print(training_data_train.shape)
		dtrain=xgb.DMatrix(training_data_train,label=label_train)
		dvalidate=xgb.DMatrix(training_data_validate,label=label_validate)
		param = {'eta':0.9,'gamma':0,'max_depth':6,'min_child_weight':1,'subsample':1,'objective':'multi:softprob','num_class':8-len(del_types),'nthread':4}
		evallist = [(dtrain, 'train'),(dvalidate, 'eval')]
		model=xgb.train(param,dtrain,300,evallist,early_stopping_rounds=2,verbose_eval=False)
		dtest=xgb.DMatrix(testing_data)
		label_pred=flows.label_transformer(model.predict(dtest,ntree_limit=model.best_ntree_limit))
	if algorithm=='svm':
		label_train=flows.label_transformer(label_train)
		label_validate=flows.label_transformer(label_validate)
		model=LinearSVC()
		model.fit(training_data_train,label_train)	
		label_pred=model.predict(testing_data)
	if algorithm=='lgb':
		label_train=flows.label_transformer(label_train)
		label_validate=flows.label_transformer(label_validate)
		dtrain=lgb.Dataset(training_data_train,label=label_train,params={'verbose':0})
		dvalidate=lgb.Dataset(training_data_validate,label=label_validate,params={'verbose':0})
		param={'objective':'multiclass','num_class':8-len(del_types),'verbose':0}#multiclassova cross_entropy cross_entropy_lambda
		model=lgb.train(param,dtrain,valid_sets=[dvalidate],early_stopping_rounds=2)
		label_pred=flows.label_transformer(model.predict(testing_data))
		model.save_model('lgb_model.txt')
	if algorithm=='cat':
		label_train=flows.label_transformer(label_train)
		label_validate=flows.label_transformer(label_validate)
		model=CatBoostClassifier(loss_function='MultiClass',logging_level='Silent',early_stopping_rounds=2)
		model.fit(training_data_train,label_train,eval_set=(training_data_validate,label_validate))
		#dtest=Pool()
		label_pred=flows.label_transformer(model.predict(testing_data))
		#直接在server秀出model acc
		acc=0
		label_true=flows.label_transformer(label_true)
		for index in range(len(label_pred)):
			if label_true[index]==label_pred[index]:
				acc+=1
		print(acc/len(label_true))
		label_true=flows.label_transformer(label_true)
	if algorithm=='dt':
		label_train=flows.label_transformer(label_train)
		label_validate=flows.label_transformer(label_validate)
		model=tree.DecisionTreeClassifier()
		model=model.fit(training_data_train,label_train)
		label_pred=model.predict(testing_data)
	label_true=flows.label_transformer(label_true)
	testing_label_true.extend(label_true)
	testing_label_pred.extend(label_pred)
	break

true_predict_labels=''
for index in range(len(testing_label_true)):
	testing_label_true[index]=str(testing_label_true[index])
	testing_label_pred[index]=str(testing_label_pred[index])
true_predict_labels+=' '.join(testing_label_true)+'\n'+' '.join(testing_label_pred)+'\n'
f2=open('{}_txt/{}/{}_{}_{}_{}_{}_{}_{}_true_predict_labels.txt'.format(algorithm,pcap_type,mode,mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts),'wt',encoding='big5')
f2.write(true_predict_labels)
f2.close()
print('algorithm {} is finished'.format(algorithm))
