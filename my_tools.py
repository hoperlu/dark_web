import numpy as np
from random import sample
from keras.layers import Input,Dense,Dropout
from keras.models import Model
from keras.optimizers import Adam
from keras.callbacks import EarlyStopping,ModelCheckpoint,Callback,LearningRateScheduler
import keras.backend.tensorflow_backend as K
from imblearn.over_sampling import SMOTE,ADASYN,RandomOverSampler

'''
變數命名規則
raw_data:跟原csv檔有一樣的行數列數,第一列是行的名稱(ex. source IP/port, flow duration/IAT mean/IAT max, etc.)
processed_data:去掉前4行,最後一行仍是label,第一列仍是行的名稱(ex. flow duration/IAT mean/IAT max, etc.)
feeding_data:可餵進model的data(每行每列都是數字feature)
'''
class FLOWS():
	def __init__(self,raw_data,del_types,del_features,number,mode,mirror_train,mirror_test):
		self.processed_data=np.delete(raw_data,[0,1,2,3],1)
		self.feature_count=self.processed_data.shape[1]-1
		self.del_types=del_types.copy()
		self.del_features=del_features.copy()
		self.number=number
		self.mode=mode
		self.mirror_train=mirror_train
		self.mirror_test=mirror_test
		self.types=['AUDIO','BROWSING','CHAT','FILE-TRANSFER','MAIL','P2P','VIDEO','VOIP']
		for type_ in self.del_types:
			self.types.remove(type_)
		self.feature_name=self.processed_data[0]
		self.group_of_types=self.build_group_of_types()
		self.number_for_each_type=self.build_number_for_each_type()

	def build_group_of_types(self):
		#回傳字典group_of_types, 其key是類型名稱,value為list,list中每個值代表raw_data中的row的index
		group_of_types={}
		for type_ in self.types:
			group_of_types[type_]=[]
		label_column=self.processed_data.shape[1]-1
		for row_index in range(1,len(self.processed_data)):
			type_=self.processed_data[row_index,label_column]
			if type_ in self.types:
				group_of_types[type_].append(row_index)			
		return group_of_types
	
	def build_number_for_each_type(self):
		'''
		回傳一字典, key為type名稱, value為該type要取幾筆data
		當mode=
		'constant', number為constant,每種type都取 number 筆data
		'min_type_percentage', number為percentage,假設數目最少的type有A筆data,則每種type都取 int(A*number) 筆data
		其他:number為percentage,每種type都取 int(該type的data數目*number) 筆data
		'''
		number_for_each_type={}
		if self.mode=='constant':
			for type_ in self.types:
				number_for_each_type[type_]=self.number	
		else:
			for type_ in self.types:
				number_for_each_type[type_]=int(len(self.group_of_types[type_])*self.number)
			if self.mode=='min_type_percentage':
				min_number=number_for_each_type[self.types[0]]
				for type_ in self.types:
					if number_for_each_type[type_]<min_number:
						min_number=number_for_each_type[type_]
				for type_ in self.types:
					number_for_each_type[type_]=min_number
		return number_for_each_type
	
	def append_mirror_flow(self,feeding_data_input,label_input):
		#回傳附加了mirror-flow的feeding_data
		pairs=[]
		for index in range(len(self.feature_name)):
			if 'Fwd to Bwd'==self.feature_name[index]:
				fwd_to_bwd_index=index
				continue
			if 'Bwd to Fwd'==self.feature_name[index]:
				bwd_to_fwd_index=index
				continue
			if 'Fwd' in self.feature_name[index] or 'fwd' in self.feature_name[index]:
				for index2 in range(len(self.feature_name)):
					if ('Bwd' in self.feature_name[index2] or 'bwd' in self.feature_name[index2]) and (self.feature_name[index2].replace('bwd','fwd')==self.feature_name[index] or self.feature_name[index2].replace('Bwd','Fwd')==self.feature_name[index]):
						pairs.append((index,index2))
						break
		try:
			pairs.append((fwd_to_bwd_index,bwd_to_fwd_index))
		except:
			pass
		feeding_data=feeding_data_input.copy()
		temp_feeding_data=feeding_data.copy()
		for pair in pairs:
			temp=temp_feeding_data[:,pair[0]].copy()
			temp_feeding_data[:,pair[0]]=temp_feeding_data[:,pair[1]]
			temp_feeding_data[:,pair[1]]=temp
		feeding_data=np.append(feeding_data,temp_feeding_data,0)
		label=np.append(label_input,label_input,0)
		return (feeding_data,label)
	
	def build_training_data(self):
		'''
		此函式回傳feeding_data(numpy.ndarray,size=(feeding_data數,feature數)) 和 label(numpy.ndarray,size=(feeding_data
		數,type數)),並用self.selected_row_for_testing_data紀錄那些會被用來當testing data的row的row_index,
		此attribute紀錄的row_index跟processed_data的row_index完全一樣，而processed_data的row_index又跟raw_data的一樣
		'''
		selected_row_for_testing_data=[]   #將會成為attribute,紀錄哪些row是testing data
		total_length=0
		for type_ in self.types:
			selected_row_for_testing_data.extend(self.group_of_types[type_])
			total_length+=self.number_for_each_type[type_]
		feeding_data=np.zeros((total_length,self.feature_count))
		label=np.zeros((total_length,len(self.types)))
		offset=0
		for type_ in self.types:
			selected_row_indices=sample(self.group_of_types[type_],self.number_for_each_type[type_])
			feeding_data[offset:offset+self.number_for_each_type[type_]]=self.processed_data[selected_row_indices,:self.feature_count]
			label[offset:offset+self.number_for_each_type[type_],self.types.index(type_)]=1.0
			for index in selected_row_indices:
				selected_row_for_testing_data.remove(index)
			offset+=self.number_for_each_type[type_]
		self.selected_row_for_testing_data=selected_row_for_testing_data
		return (feeding_data,label)
	
	def build_training_data_train(self,training_data,label):
		'''
		training_data為feeding_data, label則是其相對應的label(為array)
		mode=
		'constant':每種type都同樣挑 number 筆data當training data
		'percentage':每種type都各自挑 int(該type數量*number) 筆data當training data
		'min_type_percentage':undersampling. 假設data數量最少的type有A筆data, 則每種type都取 int(A*number) 筆data
		'duplicate_data_percentage':oversampling. resample all classes but the majority class
		'smote':oversampling
		'adasyn':oversampling
		self.mirror_train=0:沒有mirror_flow, mirror_train=1:有mirror_flow
		'''
		training_data_train=training_data.copy()
		label_train=label.copy()
		if self.mode=='constant' or self.mode=='percentage' or self.mode=='min_type_percentage':
			pass
		elif self.mode=='duplicate_data_percentage':
			randomoversampler=RandomOverSampler()
			label_train=self.label_transformer(label_train)
			(training_data_train,label_train)=randomoversampler.fit_sample(training_data_train,label_train)
			label_train=list(label_train)
			label_train=self.label_transformer(label_train)
		elif self.mode=='smote':
			smote=SMOTE(ratio='all',k_neighbors=5)
			label_train=self.label_transformer(label_train)
			(training_data_train,label_train)=smote.fit_sample(training_data_train,label_train)
			label_train=list(label_train)
			label_train=self.label_transformer(label_train)
		elif self.mode=='adasyn':
			adasyn=ADASYN(ratio='all')
			label_train=self.label_transformer(label_train)
			(training_data_train,label_train)=adasyn.fit_sample(training_data_train,label_train)
			label_train=list(label_train)
			label_train=self.label_transformer(label_train)
		else:
			raise ValueError(('unkown value of mode:\'{}\', mode shoud be either \'constant\', \'percentage\', \'min_type_percentage\', '
				'\'duplicate_data_percentage\', \'smote\' or \'adasyn\'\n').format(self.mode))
		if self.mirror_train:
			(training_data_train,label_train)=self.append_mirror_flow(training_data_train,label_train)
		training_data_train=np.delete(training_data_train,self.del_features,1)
		return training_data_train,label_train
	
	def label_transformer(self,label):
		#當label為list, 將其轉成np array, 當label為np array, 將其轉成list
		if type(label)==type([]):
			new_label=np.zeros((len(label),len(self.types)))
			for index in range(len(label)):
				new_label[index,label[index]]=1.0
		else:
			try:
				new_label=np.argmax(label,1)
			except:
				new_label=label.copy()
			new_label=list(new_label)
		return new_label
	
	def normalization(self,feeding_data_input):
		#回傳經過normalize的feeding_data
		feeding_data=feeding_data_input.copy()
		mean_std=[]
		for col_index in range(feeding_data.shape[1]):
			mean=feeding_data[:,col_index].mean()
			std=feeding_data[:,col_index].std()
			mean_std.append((mean,std))
			if std>0:
				feeding_data[:,col_index]=(feeding_data[:,col_index]-mean)/std
			elif std==0:
				feeding_data[:,col_index]=0
			else:
				print('warning!!! std<0')
		self.mean_std=mean_std
		return feeding_data
	
	def build_testing_data(self,source=None):
		'''
		回傳feeding_data(numpy.ndarray,size=(feeding_data數,feature數)) 和 label(numpy.ndarray,size=(feeding_data數,type數))
		如果變數source是None,只從self.raw_data中挑在self.selected_row_for_testing_data的那幾筆當feeding_data
		否則,用source這個csv檔裡的所有data建立testing data
		if mirror_flow==1,testing data中加入mirror flow, ==0不加
		'''
		if source==None:
			feeding_data=self.processed_data[self.selected_row_for_testing_data,:self.feature_count].astype(float)
			label=np.zeros((len(self.selected_row_for_testing_data),len(self.types)))
			for index in range(len(self.selected_row_for_testing_data)):
				label[index,self.types.index(self.processed_data[self.selected_row_for_testing_data[index],self.feature_count])]=1.0
		else:
			feeding_data=np.delete(np.genfromtxt(source,dtype=None,delimiter=',',encoding='utf8'),[0,1,2,3],1)
			feeding_data=np.delete(feeding_data,[0],0)
			label=np.zeros((len(feeding_data),self.feature_count))
			for index in range(len(feeding_data)):
				label[index,self.types.index(feeding_data[index,self.feature_count])]=1.0
			feeding_data=np.delete(feeding_data,[self.feature_count],1).astype(float)
		if self.mirror_test:
			(feeding_data,label)=self.append_mirror_flow(feeding_data,label)
		feeding_data=np.delete(feeding_data,self.del_features,1)
		return (feeding_data,label)
	
	def normalize_with_given_mean_std(self,feeding_data_input):
		#回傳normalize後的feeding_data
		feeding_data=feeding_data_input.copy()
		for col_index in range(feeding_data.shape[1]):
			mean=self.mean_std[col_index][0]
			std=self.mean_std[col_index][1]
			if std>0:
				feeding_data[:,col_index]=(feeding_data[:,col_index]-mean)/std
			elif std==0:
				feeding_data[:,col_index]=0
		return feeding_data

	def build_true_predict_labels(self,testing_data,label_true,f_name,model):
		#建立能用來畫confusionmatrix的txt檔
		label_true_temp=label_true.copy()
		true_predict_labels=''
		label_pred=model.predict(testing_data)
		if type(label_pred)!=type([]):
			label_pred=self.label_transformer(label_pred)
		if type(label_true_temp)!=type([]):
			label_true_temp=self.label_transformer(label_true_temp)
		for row_index in range(len(label_pred)):
			label_true_temp[row_index]=str(label_true_temp[row_index])
			label_pred[row_index]=str(label_pred[row_index])
		true_predict_labels+=' '.join(label_true_temp)+'\n'+' '.join(label_pred)+'\n'
		f=open(f_name,'wt',encoding='big5')
		f.write(true_predict_labels)
		f.close()

def feature_refinement(feeding_data):
	#回傳用autoencoder/TSNE對normalized data降維後的結果
	input_data=Input(shape=(feeding_data.shape[1],))
	encoded=Dense(286,activation='relu')(input_data)
	encoded=Dense(276,activation='relu')(encoded)
	encoded=Dense(266,activation='relu')(encoded)
	encoded=Dense(256,activation='relu')(encoded)

	decoded=Dense(266,activation='relu')(decoded)
	decoded=Dense(276,activation='relu')(decoded)
	decoded=Dense(286,activation='relu')(decoded)
	decoded=Dense(feeding_data.shape[1],activation='relu')(decoded)
	encoder=Model(input=input_data,output=encoded)
	autoencoder=Model(input=input_data,output=decoded)
	autoencoder.compile(optimizer='Adam',loss='mse',metrics=['acc'])
	autoencoder.fit(feeding_data,feeding_data,epochs=1000,batch_size=400,callbacks=[EarlyStopping(monitor='loss',patience=2)])
	encoder.save('dimension_reduction.h5')
	feeding_data=encoder.predict(feeding_data)
	return feeding_data

def whether_specific_types(processed_data,specific_types,number_for_each_type):
	'''
	回傳feeding_data和其對應label
	specific_types為串列,若某type在specific_types中,其label=1,否則為0
	'''
	other_types=['AUDIO','BROWSING','CHAT','FILE-TRANSFER','MAIL','P2P','VIDEO','VOIP']
	temp_number_for_each_type=number_for_each_type.copy()
	for type_ in specific_types:
		other_types.remove(type_)
	(specific_feeding_data,label)=build_training_data(processed_data,group_of_types,number_for_each_type,del_types)
	label=[1 for index in range(len(label))]
	f=open('selected_row_for_testing_data.txt','rt',encoding='big5')
	temp_text=f.read()
	f.close()
	f=open('selected_row_for_testing_data_specific.txt','wt',encoding='big5')
	f.write(temp_text)
	f.close()  #避免selected_row_for_testing_data被蓋掉
	(other_feeding_data,other_label)=build_training_data(processed_data,group_of_types,number_for_each_type,del_types)
	other_label=[0 for index in range(len(other_label))]
	feeding_data=np.append(specific_feeding_data,other_feeding_data,0)
	label.extend(other_label)
	return (feeding_data,label)

class my_earlystopping(Callback):
	'''
	當val_acc超過百分之多少,馬上停止訓練,並回傳當前learning rate
	'''
	def __init__(self,threshould):
		super().__init__()
		self.threshould=threshould
	def on_epoch_end(self, epoch, logs=None):
		acc = logs['categorical_accuracy']
		if acc>self.threshould:
			self.model.stop_training = True
			
class my_tensorboard(Callback):
	'''
	紀錄acc, val_acc, loss, val_loss, 並將結果存入tensorboard.txt
	'''
	def __init__(self,f_name=''):
		super().__init__()
		self.f_name=f_name
		self.tensorboard_string=''
	def on_epoch_end(self, epoch, logs=None):
		val_loss=logs['val_loss']
		val_categorical_accuracy=logs['val_categorical_accuracy']
		loss=logs['loss']
		categorical_accuracy=logs['categorical_accuracy']
		self.tensorboard_string+='{} {} {} {}\n'.format(val_loss,val_categorical_accuracy,loss,categorical_accuracy)
	def on_train_end(self, logs=None):
		self.tensorboard_string+='\n'
		f=open(self.f_name,'wt',encoding='big5')
		f.write(self.tensorboard_string)
		f.close()
