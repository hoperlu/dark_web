import os
import numpy as np
#import pickle
#import scapy.all as sc
#import xgboost as xgb
import lightgbm as lgb
import matplotlib.pyplot as plt

def order_acc(target,log):
	log=log.split('\n')
	log=log[:-1]
	for index in range(len(log)):
		log[index]=log[index].split(' ')
	keys={}
	for index in range(len(log)):
		keys[log[index][target]]=index
	keys_list=sorted(keys.keys())
	#for index in range(len(log)): #this for loop is for xgb only
	#	log[index][1]=1-float(log[index][1])
	for index in range(len(keys_list)-6,len(keys_list)):
		print(log[keys[keys_list[index]]])
'''
#pcap_type,mode,mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts
f=open('lgb_out.txt','rt')
log=f.read()
f.close()
order_acc(2,log) #1是acc 2是recall 3是precision
'''
'''
#畫original feature跟proposed feature的結果比較
plt.clf()
max_num_pkts=0
for timeout in (10,15,30,60,120):
	for algorithm in {'dense':'DNN','random_forest':'RF','knn':'KNN','xgb':'XGB','cat':'CAT','lgb':'LGB','dt':'DT'}:
'''
'''
#統計各種type有多少flow
#for timeout in (10,15,30,60,120):
timeout=0
raw_data=np.genfromtxt('CSV_scapy/tor/timeout_flows_zeros=1_retrans=0_timeout={}_max_num_pkts=0.csv'.format(timeout),dtype=None,delimiter=',',encoding='utf8')
counter={'AUDIO':0,'BROWSING':0,'CHAT':0,'FILE-TRANSFER':0,'MAIL':0,'P2P':0,'VIDEO':0,'VOIP':0}
for index in range(1,len(raw_data)):
	counter[raw_data[index,-1]]+=1
print(timeout,counter)
'''
'''
#tor有哪些src sport dst dport pairs
raw_data=np.genfromtxt('CSV_scapy/tor/timeout_flows_zeros=1_retrans=0_timeout=0_max_num_pkts=0.csv',dtype=None,delimiter=',',encoding='utf8')
a=[]
for index in range(1,len(raw_data)):
	a.append((raw_data[index,0],raw_data[index,1],raw_data[index,2],raw_data[index,3]))
a=set(a)
for term in a:
	print(term)
print(len(a))
'''
'''
#xgb feature importance
model=xgb.Booster({'nthread': 4})  # init model
model.load_model('xgb.model')  # load data
figure=xgb.plot_importance(model,max_num_features=40)
plt.show()
'''

#lgb feature importance
model=lgb.Booster(model_file='lgb_model.txt')
figure=lgb.plot_importance(model,max_num_features=40)
plt.show()

'''
#pcap檔更名
types=['AUDIO','BROWSING','CHAT','FILETRANSFER','MAIL','P2P','VIDEO','VOIP']
for filename in os.listdir('Pcaps/nonTor'):
	for type_ in types:
		if type_ in filename.upper():
			if type_=='FILETRANSFER':
				new_name='FILE-TRANSFER_'+filename
			else:
				new_name=type_+'_'+filename
			break
	else:
		new_name='XX_'+filename
	os.rename('Pcaps/nonTor/{}'.format(filename),'Pcaps/nonTor/{}'.format(new_name))
'''
'''
#pcap檔更名
for folder in os.listdir('Pcaps/tor/google'):
	for filename in os.listdir('Pcaps/tor/google/{}'.format(folder)):
		new_name=filename.replace('tor','BROWSING')
		os.rename('Pcaps/tor/google/{}/{}'.format(folder,filename),'Pcaps/tor/google/{}/{}'.format(folder,new_name))
'''
