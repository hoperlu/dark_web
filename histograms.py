import numpy as np
import pickle
import scapy.all as sc
import matplotlib.pyplot as plt

def del_short_flows(timeout_flows):
	'''
	只要fwd bwd中有一個方向的pkt數目不到2，就刪除該flow
	'''
	count=0
	index=0
	while index<len(timeout_flows):
		count_fwd=0
		count_bwd=0
		for pkt in timeout_flows[index]['packets']:
			if pkt['dir']=='>':
				count_fwd+=1
			else:
				count_bwd+=1
			if count_fwd>1 and count_bwd>1:
				index+=1
				break
		else:
			#print(timeout_flows[index])
			del timeout_flows[index]
			count+=1
	print('delete {} flows'.format(count))
	print('there are total {} flows'.format(len(timeout_flows)))

def truncate_flows(temp_flows,timeout,max_num_pkts):
	'''
	此函式回傳經過timeout和max_num_pkts切割過的timeout_flows
	timeout限制了每個flow的duration, =0代表不限制，超過的會變成另個項
	max_num_pkts限制每個flow最多有幾個pkt，=0代表不限制，超過的會變成另個項
	'''
	timeout_flows=[]
	for flow in temp_flows:
		base_index=0
		for index in range(1,len(flow['packets'])):
			if timeout:
				if flow['packets'][index]['time']-flow['packets'][base_index]['time']>timeout:
					timeout_flows.append({'src':flow['src'],'dst':flow['dst'],'sport':flow['sport'],'dport':flow['dport'],'label':flow['label'],'filename':flow['filename'],'fwd_ttl':flow['fwd_ttl'],'bwd_ttl':flow['bwd_ttl'],'packets':flow['packets'][base_index:index]})
					base_index=index
			if max_num_pkts:
				if index-base_index==max_num_pkts:
					timeout_flows.append({'src':flow['src'],'dst':flow['dst'],'sport':flow['sport'],'dport':flow['dport'],'label':flow['label'],'filename':flow['filename'],'fwd_ttl':flow['fwd_ttl'],'bwd_ttl':flow['bwd_ttl'],'packets':flow['packets'][base_index:index]})
					base_index=index
		timeout_flows.append({'src':flow['src'],'dst':flow['dst'],'sport':flow['sport'],'dport':flow['dport'],'label':flow['label'],'filename':flow['filename'],'fwd_ttl':flow['fwd_ttl'],'bwd_ttl':flow['bwd_ttl'],'packets':flow['packets'][base_index:]})
	del_short_flows(timeout_flows)
	return timeout_flows
'''
#統計每種type的flow數
#for pcap_type in('tor','nonTor'):
pcap_type='tor'
for zeros in (0,1):
	for retrans in (0,1):
		for timeout in (0,5,10,15,30,60,120):
			for max_num_pkts in (0,10,50,250,500,1000):
				#list每項分別代表: 總flow數, duration, IAT, pkts/flow, pkts/BCD, bytes/pkt, bytes/BCD
				types_count={'AUDIO':0,'BROWSING':0,'CHAT':0,'FILE-TRANSFER':0,'MAIL':0,'P2P':0,'VIDEO':0,'VOIP':0}
				raw_data=np.genfromtxt('CSV_scapy/{}/timeout_flows_zeros={}_retrans={}_timeout={}_max_num_pkts={}.csv'.format(pcap_type,zeros,retrans,timeout,max_num_pkts),dtype=None,delimiter=',',encoding='utf8')
				for index in range(1,len(raw_data)):
					types_count[raw_data[index,-1]]+=1
				print(pcap_type,zeros,retrans,timeout,max_num_pkts)
				print(types_count)

'''
'''
histogram, 用來比較固定參數時，相同feature(IAT, BCD_pkts or BCD_bytes)不同type的統計差異，
x軸為每個IAT/pkts_BCD/bytes_BCD占了該flow總IAT/BCD_pkts/BCD_bytes數的百分比，
y軸為該type所有flow對應x軸的count除以該type總flow數後的結果
'''
'''
pcap_type='tor'  #'tor','nonTor'
zeros=1  #0,1
retrans=0  #0,1
f=open('{}_timeout_flows_zeros={}_retrans={}_timeout=0_max_num_pkts=0.pickle'.format(pcap_type,zeros,retrans),'rb')
timeout_flows=pickle.load(f)
f.close()
timeout=15  #0,5,10,15,30,60,120
max_num_pkts=0  #0,10,50,250,500,1000
print(pcap_type,zeros,retrans,timeout,max_num_pkts)
new_timeout_flows=truncate_flows(timeout_flows,timeout,max_num_pkts)
types_count={'AUDIO':0,'BROWSING':0,'CHAT':0,'FILE-TRANSFER':0,'MAIL':0,'P2P':0,'VIDEO':0,'VOIP':0}
types_IAT={'AUDIO':[],'BROWSING':[],'CHAT':[],'FILE-TRANSFER':[],'MAIL':[],'P2P':[],'VIDEO':[],'VOIP':[]}
types_pkts_BCD={'AUDIO':[],'BROWSING':[],'CHAT':[],'FILE-TRANSFER':[],'MAIL':[],'P2P':[],'VIDEO':[],'VOIP':[]}
types_bytes_BCD={'AUDIO':[],'BROWSING':[],'CHAT':[],'FILE-TRANSFER':[],'MAIL':[],'P2P':[],'VIDEO':[],'VOIP':[]}					
for index in range(len(new_timeout_flows)):
	types_count[new_timeout_flows[index]['label']]+=1
	total_IAT=0
	total_pkts=len(new_timeout_flows[index]['packets'])
	total_bytes=0
	base_flow_time=None
	for pkt in new_timeout_flows[index]['packets']:
		if base_flow_time!=None:
			total_IAT+=pkt['time']-base_flow_time
		total_bytes+=pkt['num_bytes']
		base_flow_time=pkt['time']
	base_flow_time=None
	flow_pkts_continuous=0
	flow_bytes_continuous=0
	last_dir=None
	for pkt in new_timeout_flows[index]['packets']:
		if base_flow_time!=None: #代表當前pkt不是第一個封包
			types_IAT[new_timeout_flows[index]['label']].append((pkt['time']-base_flow_time)/total_IAT)
			if last_dir!=pkt['dir']:
				types_pkts_BCD[new_timeout_flows[index]['label']].append(flow_pkts_continuous/total_pkts)
				flow_pkts_continuous=0
				types_bytes_BCD[new_timeout_flows[index]['label']].append(flow_bytes_continuous/total_bytes)
				flow_bytes_continuous=0
		base_flow_time=pkt['time']
		last_dir=pkt['dir']
		flow_pkts_continuous+=1
		flow_bytes_continuous+=pkt['num_bytes']
	types_pkts_BCD[new_timeout_flows[index]['label']].append(flow_pkts_continuous/total_pkts)
	types_bytes_BCD[new_timeout_flows[index]['label']].append(flow_bytes_continuous/total_bytes)
for type_ in types_count:
	plt.clf()
	plt.hist(types_IAT[type_], 50, density=True, facecolor='g', alpha=0.75)
	plt.xlabel('percentage of IAT')
	plt.ylabel('count after normalize')
	plt.title('histogram of IAT of {}'.format(type_))
	plt.savefig('histogram/IAT_{}_{}_{}_{}_{}_{}.png'.format(pcap_type,zeros,retrans,timeout,max_num_pkts,type_))
	plt.clf()
	plt.hist(types_pkts_BCD[type_], 50, density=True, facecolor='g', alpha=0.75)
	plt.xlabel('percentage of pkts_BCD')
	plt.ylabel('count after normalize')
	plt.title('histogram of pkts_BCD of {}'.format(type_))
	plt.savefig('histogram/pkts_BCD_{}_{}_{}_{}_{}_{}.png'.format(pcap_type,zeros,retrans,timeout,max_num_pkts,type_))
	plt.clf()
	plt.hist(types_bytes_BCD[type_], 50, density=True, facecolor='g', alpha=0.75)
	plt.xlabel('percentage of bytes_BCD')
	plt.ylabel('count after normalize')
	plt.title('histogram of bytes_BCD of {}'.format(type_))
	plt.savefig('histogram/bytes_BCD_{}_{}_{}_{}_{}_{}.png'.format(pcap_type,zeros,retrans,timeout,max_num_pkts,type_))
'''

pcap_type='tor'
zeros=1
retrans=0
timeout=15
max_num_pkts=0
raw_data=np.genfromtxt('CSV_scapy/{}/timeout_flows_zeros={}_retrans={}_timeout={}_max_num_pkts={}.csv'.format(pcap_type,zeros,retrans,timeout,max_num_pkts),dtype=None,delimiter=',',encoding='utf8')
types_byte_dist={'AUDIO':np.array([0 for index in range(256)]),'BROWSING':np.array([0 for index in range(256)]),'CHAT':np.array([0 for index in range(256)]),'FILE-TRANSFER':np.array([0 for index in range(256)]),'MAIL':np.array([0 for index in range(256)]),'P2P':np.array([0 for index in range(256)]),'VIDEO':np.array([0 for index in range(256)]),'VOIP':np.array([0 for index in range(256)])}
for index in range(1,len(raw_data)):
	types_byte_dist[raw_data[index,-1]]+=raw_data[index,-257:-1].astype(int)
for type_ in types_byte_dist:
	types_byte_dist[type_]=types_byte_dist[type_]/types_byte_dist[type_].sum()
for type_ in types_byte_dist:
	plt.clf()
	plt.bar([index for index in range(256)],types_byte_dist[type_])
	plt.savefig('histogram/bytes_dist_{}_{}_{}_{}_{}_{}.png'.format(pcap_type,zeros,retrans,timeout,max_num_pkts,type_))
