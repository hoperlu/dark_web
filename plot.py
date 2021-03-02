from sklearn.metrics import confusion_matrix
import itertools
import matplotlib.pyplot as plt
import numpy as np
import os

pcap_type='tor' #'tor','unb'
machine_learning_method='svm'#'dense','random_forest','knn','xgb','svm','cat','lgb','dt'
del_types=[] 
for pcap_type in ('tor','unb'):
	for machine_learning_method in ('dense','random_forest','knn','xgb','svm','lgb','dt'):
		for filename in os.listdir('C:/myfiles/paper_survey/dark_web/{}_txt/{}'.format(machine_learning_method,pcap_type)):
			if '_tensorboard.txt' in filename:
				try:
					[mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts]=filename[:filename.index('.')].split('_')[-7:-1]
					mode=('_').join(filename[:filename.index('.')].split('_')[:-7])	
				except:
					pass
				f2=open('{}_txt/{}/{}'.format(machine_learning_method,pcap_type,filename),'rt',encoding='big5')
				#以下開始畫tensorboard
				line=f2.readline()
				val_loss_list=[]
				val_acc_list=[]
				loss_list=[]
				acc_list=[]
				while line!='\n':
					line=line.split(' ')
					line=[float(x) for x in line]
					val_loss_list.append(line[0])
					val_acc_list.append(line[1])
					loss_list.append(line[2])
					acc_list.append(line[3])
					line=f2.readline()
				x_coordinate=[x for x in range(len(acc_list))]
				plt.plot(x_coordinate,val_acc_list)
				plt.plot(x_coordinate,acc_list)
				plt.tight_layout()
				try:
					plt.savefig('{}_fig/{}/{}_{}_{}_{}_{}_{}_{}_acc.png'.format(machine_learning_method,pcap_type,mode,mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts))
				except:
					plt.savefig('{}_fig/{}/{}_acc.png'.format(machine_learning_method,pcap_type,filename[:filename.index('_')]))
				plt.clf()
				plt.plot(x_coordinate,val_loss_list)
				plt.plot(x_coordinate,loss_list)
				plt.tight_layout()
				try:
					plt.savefig('{}_fig/{}/{}_{}_{}_{}_{}_{}_{}_loss.png'.format(machine_learning_method,pcap_type,mode,mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts))
				except:
					plt.savefig('{}_fig/{}/{}_loss.png'.format(machine_learning_method,pcap_type,filename[:filename.index('_')]))
				plt.clf()
				f2.close()
			if '_true_predict_labels.txt' in filename:
				try:
					[mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts]=filename[:filename.index('.')].split('_')[-9:-3]
					mode=('_').join(filename[:filename.index('.')].split('_')[:-9])
				except:
					pass
				f=open('{}_txt/{}/{}'.format(machine_learning_method,pcap_type,filename),'rt',encoding='big5')
				plt.clf()
				types=['AUDIO','BROWSING','CHAT','FILE-TRANSFER','MAIL','P2P','VIDEO','VOIP']
				for type_ in del_types:
					types.remove(type_)
				label_true=f.readline()
				label_true=label_true.split()
				label_pred=f.readline()
				label_pred=label_pred.split()
				for index in range(len(label_true)):
					label_true[index]=int(label_true[index])
					label_pred[index]=int(label_pred[index])

				acc=0
				for index in range(len(label_true)):
					if label_true[index]==label_pred[index]:
						acc+=1
				acc/=len(label_pred)

				recall=0
				#cm=confusion_matrix(label_true,label_pred)
				#cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
				cm=confusion_matrix(label_true,label_pred,normalize='true')
				cm=cm.astype('float')
				plt.imshow(cm,interpolation='nearest',cmap=plt.cm.Blues)#, cmap=plt.cm.jet)
				plt.colorbar()
				tick_marks=np.arange(len(types))
				plt.xticks(tick_marks,['AUD','BRO','CHAT','FT','MAIL','P2P','VID','VOIP'],rotation=0)
				plt.yticks(tick_marks,types)
				thresh=cm.max()/2.
				for i,j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
					plt.text(j,i,'{:.2f}'.format(cm[i, j]), horizontalalignment="center",color="black" if cm[i, j]<thresh else "white")
					if i==j:
						recall+=cm[i,j]
				plt.ylabel('True label')
				recall/=8-len(del_types)
				#plt.xlabel('Predicted label\nacc={:.4f},recall={:.4f}\n'.format(acc,recall))
				#plt.tight_layout()

				precisions_recalls=[[],[],[]]
				for index in range(len(types)):
					TP=0
					TP_plus_FP=0
					TP_plus_FN=0
					for index2 in range(len(label_pred)):
						if label_pred[index2]==index:
							TP_plus_FP+=1
						if label_true[index2]==index:
							TP_plus_FN+=1
						if label_true[index2]==index and label_pred[index2]==index:
							TP+=1
					try:
						precisions_recalls[0].append('{:.2f}'.format(TP/TP_plus_FP))
					except:
						precisions_recalls[0].append('nan')
					try:
						precisions_recalls[1].append('{:.2f}'.format(TP/TP_plus_FN))
					except:
						precisions_recalls[1].append('nan')
				for index in range(len(precisions_recalls[0])):
					try:
						precisions_recalls[2].append('{:.2f}'.format(2*float(precisions_recalls[0][index])*float(precisions_recalls[1][index])/(float(precisions_recalls[0][index])+float(precisions_recalls[1][index]))))
					except:
						precisions_recalls[2].append('nan')
				precisions_recalls_table=plt.table(cellText=precisions_recalls,rowLabels=('precision','recall','f1-score'),colLabels=types,loc='top',cellLoc='middle')
				precisions_recalls_table.set_fontsize(8)
				precisions_recalls_table.auto_set_column_width(range(8))
				precision=0
				try:
					for term in precisions_recalls[0]:
						precision+=float(term)
					precision/=len(precisions_recalls[0])
					plt.xlabel('Predicted label\ntotal_acc={:.4f}, avg_recall={:.4f}, avg_precision={:.4f}\n'.format(acc,recall,precision))
				except:
					plt.xlabel('Predicted label\nacc={:.4f},recall={:.4f},precision=nan\n'.format(acc,recall))
				plt.tight_layout()
				plt.subplots_adjust(top=0.8)
				try:
					plt.savefig('{}_fig/{}/confusionmatrix_{}_{}_{}_{}_{}_{}_{}.png'.format(machine_learning_method,pcap_type,mode,mirror_train,mirror_test,zeros,retrans,timeout,max_num_pkts))
				except:
					plt.savefig('{}_fig/{}/confusionmatrix_{}.png'.format(machine_learning_method,pcap_type,filename[:filename.index('_')]))
				plt.clf()
				f.close()
