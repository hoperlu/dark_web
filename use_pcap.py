#python3.6.7 scapy2.4.0
import scapy.all as sc
import os
import pickle
import numpy as np
from decimal import Decimal

def sniff_pkts_shield(pcap_type,all_packets,filename,captured,abandoned):
	'''
	紀錄每個符合pcap_type的封包
	讓之後的build_flows能建立timeout_flows
	all_packets為一字典，key為pkt.time，value為一串列，
	串列中每項為一字典(因為可能有些pkt的time是相同的，故需要串列)，一個字典儲存一個pkt的各種資訊
	captured/abandoned為字典，key是type的名稱，value是該type被captured/abandoned的封包累積了幾個
	'''
	def sniff_pkts(pkt):
		if 'tor' in pcap_type:
			if 'TCP' in pkt:
				byte_dist=[0 for index in range(256)]
				for term in bytes(pkt['TCP'].payload):
					byte_dist[term]+=1
				captured[filename[:filename.index('_')]]+=1
				if sum(byte_dist)!=len(pkt['TCP'].payload):
					print('warning!!! sum(byte_dist)!=len(pkt["TCP"].payload)')
				if pkt.time not in all_packets:
					all_packets[pkt.time]=[{'src':pkt['IP'].src,'dst':pkt['IP'].dst,'sport':pkt['TCP'].sport,'dport':pkt['TCP'].dport,'label':filename[:filename.index('_')],'filename':filename,'ttl':pkt.ttl,'flags':str(pkt['TCP'].flags),'seq':pkt['TCP'].seq,'num_bytes':len(pkt['TCP'].payload),'byte_dist':byte_dist}]
				else:
					all_packets[pkt.time].append({'src':pkt['IP'].src,'dst':pkt['IP'].dst,'sport':pkt['TCP'].sport,'dport':pkt['TCP'].dport,'label':filename[:filename.index('_')],'filename':filename,'ttl':pkt.ttl,'flags':str(pkt['TCP'].flags),'seq':pkt['TCP'].seq,'num_bytes':len(pkt['TCP'].payload),'byte_dist':byte_dist})
			else:
				abandoned[filename[:filename.index('_')]]+=1
		elif 'nonTor' in pcap_type:
			if 'TCP' in pkt:
				byte_dist=[0 for index in range(256)]
				for term in bytes(pkt['TCP'].payload):
					byte_dist[term]+=1
				captured[filename[:filename.index('_')]]+=1
				if sum(byte_dist)!=len(pkt['TCP'].payload):
					print('warning!!! sum(byte_dist)!=len(pkt["TCP"].payload)')
				if pkt.time not in all_packets:
					all_packets[pkt.time]=[{'src':pkt['IP'].src,'dst':pkt['IP'].dst,'sport':pkt['TCP'].sport,'dport':pkt['TCP'].dport,'label':filename[:filename.index('_')],'filename':filename,'ttl':pkt.ttl,'flags':str(pkt['TCP'].flags),'seq':pkt['TCP'].seq,'num_bytes':len(pkt['TCP'].payload),'byte_dist':byte_dist}]
				else:
					all_packets[pkt.time].append({'src':pkt['IP'].src,'dst':pkt['IP'].dst,'sport':pkt['TCP'].sport,'dport':pkt['TCP'].dport,'label':filename[:filename.index('_')],'filename':filename,'ttl':pkt.ttl,'flags':str(pkt['TCP'].flags),'seq':pkt['TCP'].seq,'num_bytes':len(pkt['TCP'].payload),'byte_dist':byte_dist})
			else:
				abandoned[filename[:filename.index('_')]]+=1
		else:
			print('pcap_type error')
	return sniff_pkts

def build_flows(timeout_flows,all_packets,zeros,retrans):
	'''
	用傳入的字典all_packets建立flow
	zeros, binary, 建立的flow是否要包含payload長度為0的封包 0為否 1為是
	retrans, binary, 建立的flow是否要包含重傳的封包 0為否 1為是
	temp/timeout_flows為一串列，其中每項都是代表一個flow的字典，字典的key包含
	src, dst, sport, dport, label, filename, fwd_ttl, bwd_ttl, seq, packets, 前8者為string，
	seq是list，代表最近曾經出現過的封包的sequence number(至多1000個)
	packets是list, list中每項為一字典，代表該flow中每個封包，key有time, dir(> fwd, < bwd), num_bytes(of payload),
	'''
	temp_flows=[]
	time_indices=sorted(all_packets.keys())
	for time_index in time_indices:
		for pkt in all_packets[time_index]:
			#iterate直到找到該pkt屬於的flow，沒找到就繼續iterate下個flow
			index=0
			while index<len(temp_flows):
				if pkt['src']==temp_flows[index]['src'] and pkt['dst']==temp_flows[index]['dst'] and pkt['sport']==temp_flows[index]['sport'] and pkt['dport']==temp_flows[index]['dport']:
					directon='>'
					if temp_flows[index]['fwd_ttl']!=pkt['ttl']:
						print('warning!!! temp_flows[index]["fwd_ttl"]!=pkt["ttl"]')
				elif pkt['src']==temp_flows[index]['dst'] and pkt['dst']==temp_flows[index]['src'] and pkt['sport']==temp_flows[index]['dport'] and pkt['dport']==temp_flows[index]['sport']:
					directon='<'
					if 'bwd_ttl' not in temp_flows[index].keys():
						temp_flows[index]['bwd_ttl']=pkt['ttl']
					elif temp_flows[index]['bwd_ttl']!=pkt['ttl']:
						print('warning!!! temp_flows[index]["bwd_ttl"]!=pkt["ttl"]')
				else:
					index+=1
					continue
				if 'F' in pkt['flags']:
					if not (zeros==0 and pkt['num_bytes']==0) and not (retrans==0 and pkt['seq'] in temp_flows[index]['seq']):
						temp_flows[index]['packets'].append({'time':time_index,'dir':directon,'num_bytes':pkt['num_bytes']})
						temp_flows[index]['byte_dist'].append(pkt['byte_dist'].copy())
					timeout_flows.append(temp_flows[index].copy())
					del temp_flows[index]
					break
				else:
					if not (zeros==0 and pkt['num_bytes']==0) and not (retrans==0 and pkt['seq'] in temp_flows[index]['seq']):
						temp_flows[index]['packets'].append({'time':time_index,'dir':directon,'num_bytes':pkt['num_bytes']})
						temp_flows[index]['byte_dist'].append(pkt['byte_dist'].copy())
					temp_flows[index]['seq']=temp_flows[index]['seq'][-999:]
					temp_flows[index]['seq'].append(pkt['seq'])
					if 'S' in pkt['flags'] and 'A' not in pkt['flags']:
						print('warning!!! "S" in middle of the flow')
					break
			else: #若iterate完還是找不到，進入else建立一個新的flow
				if 'F' not in pkt['flags']:
					if not (zeros==0 and pkt['num_bytes']==0):
						temp_flows.append({'src':pkt['src'],'dst':pkt['dst'],'sport':pkt['sport'],'dport':pkt['dport'],'label':pkt['label'],'filename':pkt['filename'],'fwd_ttl':pkt['ttl'],'seq':[pkt['seq']],'packets':[{'time':time_index,'dir':'>','num_bytes':pkt['num_bytes']}],'byte_dist':[pkt['byte_dist'].copy()]})
					else:
						temp_flows.append({'src':pkt['src'],'dst':pkt['dst'],'sport':pkt['sport'],'dport':pkt['dport'],'label':pkt['label'],'filename':pkt['filename'],'fwd_ttl':pkt['ttl'],'seq':[pkt['seq']],'packets':[],'byte_dist':[]})
	timeout_flows.extend(temp_flows)

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
					byte_dist=[0 for index2 in range(256)]
					for index2 in range(base_index,index):
						for index3 in range(256):
							byte_dist[index3]+=flow['byte_dist'][index2][index3]
					timeout_flows.append({'src':flow['src'],'dst':flow['dst'],'sport':flow['sport'],'dport':flow['dport'],'label':flow['label'],'filename':flow['filename'],'fwd_ttl':flow['fwd_ttl'],'bwd_ttl':flow['bwd_ttl'],'packets':flow['packets'][base_index:index],'byte_dist':byte_dist})
					'''
					fwd_byte_dist=[0 for index2 in range(256)]
					bwd_byte_dist=[0 for index2 in range(256)]
					for index2 in range(base_index,index):
						if flow['packets'][index]['dir']=='>':
							for index3 in range(256):
								fwd_byte_dist[index3]+=flow['byte_dist'][index2][index3]
						elif flow['packets'][index]['dir']=='<':
							for index3 in range(256):
								bwd_byte_dist[index3]+=flow['byte_dist'][index2][index3]
						else:
							print('warning!!! wrong value of directon')
					timeout_flows.append({'src':flow['src'],'dst':flow['dst'],'sport':flow['sport'],'dport':flow['dport'],'label':flow['label'],'filename':flow['filename'],'fwd_ttl':flow['fwd_ttl'],'bwd_ttl':flow['bwd_ttl'],'packets':flow['packets'][base_index:index],'fwd_byte_dist':fwd_byte_dist,'bwd_byte_dist':bwd_byte_dist})
					'''
					base_index=index
			if max_num_pkts:
				if index-base_index==max_num_pkts:
					byte_dist=[0 for index2 in range(256)]
					for index2 in range(base_index,index):
						for index3 in range(256):
							byte_dist[index3]+=flow['byte_dist'][index2][index3]
					timeout_flows.append({'src':flow['src'],'dst':flow['dst'],'sport':flow['sport'],'dport':flow['dport'],'label':flow['label'],'filename':flow['filename'],'fwd_ttl':flow['fwd_ttl'],'bwd_ttl':flow['bwd_ttl'],'packets':flow['packets'][base_index:index],'byte_dist':byte_dist})
					'''
					fwd_byte_dist=[0 for index2 in range(256)]
					bwd_byte_dist=[0 for index2 in range(256)]
					for index2 in range(base_index,index):
						if flow['packets'][index]['dir']=='>':
							for index3 in range(256):
								fwd_byte_dist[index3]+=flow['byte_dist'][index2][index3]
						elif flow['packets'][index]['dir']=='<':
							for index3 in range(256):
								bwd_byte_dist[index3]+=flow['byte_dist'][index2][index3]
						else:
							print('warning!!! wrong value of directon')
					timeout_flows.append({'src':flow['src'],'dst':flow['dst'],'sport':flow['sport'],'dport':flow['dport'],'label':flow['label'],'filename':flow['filename'],'fwd_ttl':flow['fwd_ttl'],'bwd_ttl':flow['bwd_ttl'],'packets':flow['packets'][base_index:index],'fwd_byte_dist':fwd_byte_dist,'bwd_byte_dist':bwd_byte_dist})
					'''
					base_index=index
		byte_dist=[0 for index2 in range(256)]
		for index2 in range(base_index,len(flow['packets'])):
			for index3 in range(256):
				byte_dist[index3]+=flow['byte_dist'][index2][index3]
		timeout_flows.append({'src':flow['src'],'dst':flow['dst'],'sport':flow['sport'],'dport':flow['dport'],'label':flow['label'],'filename':flow['filename'],'fwd_ttl':flow['fwd_ttl'],'bwd_ttl':flow['bwd_ttl'],'packets':flow['packets'][base_index:],'byte_dist':byte_dist})
		'''
		fwd_byte_dist=[0 for index2 in range(256)]
		bwd_byte_dist=[0 for index2 in range(256)]
		for index2 in range(base_index,len(flow['packets'])):
			if flow['packets'][index]['dir']=='>':
				for index3 in range(256):
					fwd_byte_dist[index3]+=flow['byte_dist'][index2][index3]
			elif flow['packets'][index]['dir']=='<':
				for index3 in range(256):
					bwd_byte_dist[index3]+=flow['byte_dist'][index2][index3]
			else:
				print('warning!!! wrong value of directon')
		timeout_flows.append({'src':flow['src'],'dst':flow['dst'],'sport':flow['sport'],'dport':flow['dport'],'label':flow['label'],'filename':flow['filename'],'fwd_ttl':flow['fwd_ttl'],'bwd_ttl':flow['bwd_ttl'],'packets':flow['packets'][base_index:],'fwd_byte_dist':fwd_byte_dist,'bwd_byte_dist':bwd_byte_dist})
		'''
	del_short_flows(timeout_flows)
	return timeout_flows

def calculate_features(packets,byte_dist):
	#回傳需要用packets計算的特徵. IAT=inter-arrival time, BCD=before change direction
	flow_duration=packets[-1]['time']-packets[0]['time'] #flow的持續時間
	flow_pkts=len(packets) #整個flow有幾個pkt
	fwd_pkts=0 #fwd方向有幾個pkt
	bwd_pkts=0 #bwd方向有幾個pkt
	flow_bytes_mean=0 #平均每個pkt的num_byte是多少
	flow_bytes_mean2=0 #每個pkt的num_byte平方的平均，用來算pkt的num_byte的std
	flow_bytes_max=None #flow的所有pkt中，payload擁有最多byte的pkt的payload的byte數
	flow_bytes_min=None
	fwd_bytes_mean=0 #平均每個fwd方向的pkt有幾個byte
	fwd_bytes_mean2=0
	fwd_bytes_max=None #flow的fwd方向的所有pkt中，payload擁有最多byte的pkt的payload的byte數
	fwd_bytes_min=None
	bwd_bytes_mean=0 #平均每個bwd方向的pkt有幾個byte
	bwd_bytes_mean2=0
	bwd_bytes_max=None #flow的bwd方向的所有pkt中，payload擁有最多byte的pkt的payload的byte數
	bwd_bytes_min=None
	base_flow_time=None #當迭代到第k個pkt, 儲存第k-1個pkt的.time以計算IAT
	flow_IAT_mean=0
	flow_IAT_mean2=0
	flow_IAT_max=None
	flow_IAT_min=None
	base_fwd_time=None #當迭代到fwd方向的第k個pkt, 儲存fwd方向的第k-1個pkt的.time以計算IAT
	fwd_IAT_mean=0
	fwd_IAT_mean2=0
	fwd_IAT_max=None
	fwd_IAT_min=None
	base_bwd_time=None #當迭代到bwd方向的第k個pkt, 儲存bwd方向的第k-1個pkt的.time以計算IAT
	bwd_IAT_mean=0
	bwd_IAT_mean2=0
	bwd_IAT_max=None
	bwd_IAT_min=None
	exchange_dir_count=0 #計算整個flow方向總共變了幾次
	fwd_to_bwd=0 #counter，數fwd變換到bwd的次數
	bwd_to_fwd=0 #counter，數bwd變換到fwd的次數
	flow_pkts_continuous=0 #連續同方向的pkt已經出現幾個
	flow_pkts_BCD_mean=0 #每次換方向前，平均有幾個byte
	flow_pkts_BCD_mean2=0
	flow_pkts_BCD_max=None
	flow_pkts_BCD_min=None
	fwd_pkts_continuous=0 #連續的fwd pkt已經出現幾個
	fwd_pkts_BCD_mean=0 #fwd方向的pkt換成bwd方向時，平均傳了幾個pkt
	fwd_pkts_BCD_mean2=0
	fwd_pkts_BCD_max=None
	fwd_pkts_BCD_min=None
	bwd_pkts_continuous=0 #連續的bwd pkt已經出現幾個
	bwd_pkts_BCD_mean=0 #bwd方向的pkt換成bwd方向時，平均傳了幾個pkt
	bwd_pkts_BCD_mean2=0
	bwd_pkts_BCD_max=None
	bwd_pkts_BCD_min=None
	flow_bytes_continuous=0 #儲存目前已出現幾個同方向的byte
	flow_bytes_BCD_mean=0 #每次換方向前，平均有幾個byte
	flow_bytes_BCD_mean2=0
	flow_bytes_BCD_max=None
	flow_bytes_BCD_min=None
	fwd_bytes_continuous=0 #儲存目前已出現幾個fwd方向的byte
	fwd_bytes_BCD_mean=0 #fwd方向的pkt換成bwd方向時，平均傳了幾個byte
	fwd_bytes_BCD_mean2=0
	fwd_bytes_BCD_max=None
	fwd_bytes_BCD_min=None
	bwd_bytes_continuous=0 #儲存目前已出現幾個bwd方向的byte
	bwd_bytes_BCD_mean=0 #bwd方向的pkt換成fwd方向時，平均傳了幾個byte
	bwd_bytes_BCD_mean2=0
	bwd_bytes_BCD_max=None
	bwd_bytes_BCD_min=None
	last_dir=None #儲存上個pkt的方向
	for pkt in packets:
		if pkt['dir']=='>':
			fwd_pkts+=1
			fwd_bytes_mean+=pkt['num_bytes']
			fwd_bytes_mean2+=pkt['num_bytes']**2
			if fwd_bytes_max==None:
				fwd_bytes_max=pkt['num_bytes']
			elif pkt['num_bytes']>fwd_bytes_max:
				fwd_bytes_max=pkt['num_bytes']
			if fwd_bytes_min==None:
				fwd_bytes_min=pkt['num_bytes']
			elif pkt['num_bytes']<fwd_bytes_min:
				fwd_bytes_min=pkt['num_bytes']
			if base_fwd_time!=None:
				if pkt['time']-base_fwd_time<0:
					print('warning!!!!!! pkt["time"]-base_fwd_time<0')
				fwd_IAT_mean+=pkt['time']-base_fwd_time
				fwd_IAT_mean2+=(pkt['time']-base_fwd_time)**2
				if fwd_IAT_max==None:
					fwd_IAT_max=pkt['time']-base_fwd_time
				elif fwd_IAT_max<pkt['time']-base_fwd_time:
					fwd_IAT_max=pkt['time']-base_fwd_time
				if fwd_IAT_min==None:
					fwd_IAT_min=pkt['time']-base_fwd_time
				elif fwd_IAT_min>pkt['time']-base_fwd_time:
					fwd_IAT_min=pkt['time']-base_fwd_time
			base_fwd_time=pkt['time']
			fwd_pkts_continuous+=1
			fwd_bytes_continuous+=pkt['num_bytes']
			if last_dir=='<':
				bwd_to_fwd+=1
				bwd_pkts_BCD_mean+=bwd_pkts_continuous
				bwd_pkts_BCD_mean2+=bwd_pkts_continuous**2
				if bwd_pkts_BCD_max==None:
					bwd_pkts_BCD_max=bwd_pkts_continuous
				elif bwd_pkts_continuous>bwd_pkts_BCD_max:
					bwd_pkts_BCD_max=bwd_pkts_continuous
				if bwd_pkts_BCD_min==None:
					bwd_pkts_BCD_min=bwd_pkts_continuous
				elif bwd_pkts_continuous<bwd_pkts_BCD_min:
					bwd_pkts_BCD_min=bwd_pkts_continuous
				bwd_pkts_continuous=0
				bwd_bytes_BCD_mean+=bwd_bytes_continuous
				bwd_bytes_BCD_mean2+=bwd_bytes_continuous**2
				if bwd_bytes_BCD_max==None:
					bwd_bytes_BCD_max=bwd_bytes_continuous
				elif bwd_bytes_continuous>bwd_bytes_BCD_max:
					bwd_bytes_BCD_max=bwd_bytes_continuous
				if bwd_bytes_BCD_min==None:
					bwd_bytes_BCD_min=bwd_bytes_continuous
				elif bwd_bytes_continuous<bwd_bytes_BCD_min:
					bwd_bytes_BCD_min=bwd_bytes_continuous
				bwd_bytes_continuous=0
		if pkt['dir']=='<':
			bwd_pkts+=1
			bwd_bytes_mean+=pkt['num_bytes']
			bwd_bytes_mean2+=pkt['num_bytes']**2
			if bwd_bytes_max==None:
				bwd_bytes_max=pkt['num_bytes']
			elif pkt['num_bytes']>bwd_bytes_max:
				bwd_bytes_max=pkt['num_bytes']
			if bwd_bytes_min==None:
				bwd_bytes_min=pkt['num_bytes']
			elif pkt['num_bytes']<bwd_bytes_min:
				bwd_bytes_min=pkt['num_bytes']
			if base_bwd_time!=None:
				if pkt['time']-base_bwd_time<0:
					print('warning!!!!!! pkt["time"]-base_bwd_time<0')
				bwd_IAT_mean+=pkt['time']-base_bwd_time
				bwd_IAT_mean2+=(pkt['time']-base_bwd_time)**2
				if bwd_IAT_max==None:
					bwd_IAT_max=pkt['time']-base_bwd_time
				elif bwd_IAT_max<pkt['time']-base_bwd_time:
					bwd_IAT_max=pkt['time']-base_bwd_time
				if bwd_IAT_min==None:
					bwd_IAT_min=pkt['time']-base_bwd_time
				elif bwd_IAT_min>pkt['time']-base_bwd_time:
					bwd_IAT_min=pkt['time']-base_bwd_time
			base_bwd_time=pkt['time']
			bwd_pkts_continuous+=1
			bwd_bytes_continuous+=pkt['num_bytes']
			if last_dir=='>':
				fwd_to_bwd+=1
				fwd_pkts_BCD_mean+=fwd_pkts_continuous
				fwd_pkts_BCD_mean2+=fwd_pkts_continuous**2
				if fwd_pkts_BCD_max==None:
					fwd_pkts_BCD_max=fwd_pkts_continuous
				elif fwd_pkts_continuous>fwd_pkts_BCD_max:
					fwd_pkts_BCD_max=fwd_pkts_continuous
				if fwd_pkts_BCD_min==None:
					fwd_pkts_BCD_min=fwd_pkts_continuous
				elif fwd_pkts_continuous<fwd_pkts_BCD_min:
					fwd_pkts_BCD_min=fwd_pkts_continuous
				fwd_pkts_continuous=0
				fwd_bytes_BCD_mean+=fwd_bytes_continuous
				fwd_bytes_BCD_mean2+=fwd_bytes_continuous**2
				if fwd_bytes_BCD_max==None:
					fwd_bytes_BCD_max=fwd_bytes_continuous
				elif fwd_bytes_continuous>fwd_bytes_BCD_max:
					fwd_bytes_BCD_max=fwd_bytes_continuous
				if fwd_bytes_BCD_min==None:
					fwd_bytes_BCD_min=fwd_bytes_continuous
				elif fwd_bytes_continuous<fwd_bytes_BCD_min:
					fwd_bytes_BCD_min=fwd_bytes_continuous
				fwd_bytes_continuous=0
		flow_bytes_mean+=pkt['num_bytes']
		flow_bytes_mean2+=pkt['num_bytes']**2
		if flow_bytes_max==None:
			flow_bytes_max=pkt['num_bytes']
		elif pkt['num_bytes']>flow_bytes_max:
			flow_bytes_max=pkt['num_bytes']
		if flow_bytes_min==None:
			flow_bytes_min=pkt['num_bytes']
		elif pkt['num_bytes']<flow_bytes_min:
			flow_bytes_min=pkt['num_bytes']
		if base_flow_time!=None: #代表當前pkt不是第一個封包
			if pkt['time']-base_flow_time<0:
				print('warning!!!!!! pkt["time"]-base_flow_time<0')
			flow_IAT_mean+=pkt['time']-base_flow_time
			flow_IAT_mean2+=(pkt['time']-base_flow_time)**2
			if flow_IAT_max==None:
				flow_IAT_max=pkt['time']-base_flow_time
			elif flow_IAT_max<pkt['time']-base_flow_time:
				flow_IAT_max=pkt['time']-base_flow_time
			if flow_IAT_min==None:
				flow_IAT_min=pkt['time']-base_flow_time
			elif flow_IAT_min>pkt['time']-base_flow_time:
				flow_IAT_min=pkt['time']-base_flow_time
			if last_dir!=pkt['dir']:
				exchange_dir_count+=1
				flow_pkts_BCD_mean+=flow_pkts_continuous
				flow_pkts_BCD_mean2+=flow_pkts_continuous**2
				if flow_pkts_BCD_max==None:
					flow_pkts_BCD_max=flow_pkts_continuous
				elif flow_pkts_continuous>flow_pkts_BCD_max:
					flow_pkts_BCD_max=flow_pkts_continuous
				if flow_pkts_BCD_min==None:
					flow_pkts_BCD_min=flow_pkts_continuous
				elif flow_pkts_continuous<flow_pkts_BCD_min:
					flow_pkts_BCD_min=flow_pkts_continuous
				flow_pkts_continuous=0
				flow_bytes_BCD_mean+=flow_bytes_continuous
				flow_bytes_BCD_mean2+=flow_bytes_continuous**2
				if flow_bytes_BCD_max==None:
					flow_bytes_BCD_max=flow_bytes_continuous
				elif flow_bytes_continuous>flow_bytes_BCD_max:
					flow_bytes_BCD_max=flow_bytes_continuous
				if flow_bytes_BCD_min==None:
					flow_bytes_BCD_min=flow_bytes_continuous
				elif flow_bytes_continuous<flow_bytes_BCD_min:
					flow_bytes_BCD_min=flow_bytes_continuous
				flow_bytes_continuous=0
		base_flow_time=pkt['time']
		last_dir=pkt['dir']
		flow_pkts_continuous+=1
		flow_bytes_continuous+=pkt['num_bytes']
	flow_bytes=flow_bytes_mean #flow共有多少bytes
	if flow_bytes!=sum(byte_dist):
		print('warning!!!!! flow_bytes!=sum(byte_dist)')
	fwd_bytes=fwd_bytes_mean #fwd方向共有多少bytes
	bwd_bytes=bwd_bytes_mean #bwd方向共有多少bytes
	flow_IAT=flow_IAT_mean #flow的IAT總時數
	fwd_IAT=fwd_IAT_mean #fwd方向的IAT總時數
	bwd_IAT=bwd_IAT_mean #bwd方向的IAT總時數
	flow_bytes_mean/=flow_pkts
	flow_bytes_mean2/=flow_pkts
	fwd_bytes_mean/=fwd_pkts
	fwd_bytes_mean2/=fwd_pkts
	bwd_bytes_mean/=bwd_pkts
	bwd_bytes_mean2/=bwd_pkts
	flow_IAT_mean/=flow_pkts-1
	flow_IAT_mean2/=flow_pkts-1
	fwd_IAT_mean/=fwd_pkts-1
	fwd_IAT_mean2/=fwd_pkts-1
	bwd_IAT_mean/=bwd_pkts-1
	bwd_IAT_mean2/=bwd_pkts-1
	if last_dir=='>': #因為最後一個fwd方向的pkt, 沒有下一個bwd方向的pkt去觸發fwd_pkts_BCD_mean+=fwd_pkts_continuous等動作
		fwd_pkts_BCD_mean+=fwd_pkts_continuous
		fwd_pkts_BCD_mean2+=fwd_pkts_continuous**2
		if fwd_pkts_BCD_max==None:
			fwd_pkts_BCD_max=fwd_pkts_continuous
		elif fwd_pkts_continuous>fwd_pkts_BCD_max:
			fwd_pkts_BCD_max=fwd_pkts_continuous
		if fwd_pkts_BCD_min==None:
			fwd_pkts_BCD_min=fwd_pkts_continuous
		elif fwd_pkts_continuous<fwd_pkts_BCD_min:
			fwd_pkts_BCD_min=fwd_pkts_continuous
		fwd_bytes_BCD_mean+=fwd_bytes_continuous
		fwd_bytes_BCD_mean2+=fwd_bytes_continuous**2
		if fwd_bytes_BCD_max==None:
			fwd_bytes_BCD_max=fwd_bytes_continuous
		elif fwd_bytes_continuous>fwd_bytes_BCD_max:
			fwd_bytes_BCD_max=fwd_bytes_continuous
		if fwd_bytes_BCD_min==None:
			fwd_bytes_BCD_min=fwd_bytes_continuous
		elif fwd_bytes_continuous<fwd_bytes_BCD_min:
			fwd_bytes_BCD_min=fwd_bytes_continuous
	if last_dir=='<': #因為最後一個bwd方向的pkt, 沒有下一個fwd方向的pkt去觸發bwd_pkts_BCD_mean+=bwd_pkts_continuous等動作
		bwd_pkts_BCD_mean+=bwd_pkts_continuous
		bwd_pkts_BCD_mean2+=bwd_pkts_continuous**2
		if bwd_pkts_BCD_max==None:
			bwd_pkts_BCD_max=bwd_pkts_continuous
		elif bwd_pkts_continuous>bwd_pkts_BCD_max:
			bwd_pkts_BCD_max=bwd_pkts_continuous
		if bwd_pkts_BCD_min==None:
			bwd_pkts_BCD_min=bwd_pkts_continuous
		elif bwd_pkts_continuous<bwd_pkts_BCD_min:
			bwd_pkts_BCD_min=bwd_pkts_continuous
		bwd_bytes_BCD_mean+=bwd_bytes_continuous
		bwd_bytes_BCD_mean2+=bwd_bytes_continuous**2
		if bwd_bytes_BCD_max==None:
			bwd_bytes_BCD_max=bwd_bytes_continuous
		elif bwd_bytes_continuous>bwd_bytes_BCD_max:
			bwd_bytes_BCD_max=bwd_bytes_continuous
		if bwd_bytes_BCD_min==None:
			bwd_bytes_BCD_min=bwd_bytes_continuous
		elif bwd_bytes_continuous<bwd_bytes_BCD_min:
			bwd_bytes_BCD_min=bwd_bytes_continuous
	flow_pkts_BCD_mean+=flow_pkts_continuous #因為最後一個pkt, 沒有下一個跟它相反方向的pkt去觸發flow_pkts_BCD_mean+=flow_pkts_continuous等動作
	flow_pkts_BCD_mean2+=flow_pkts_continuous**2
	if flow_pkts_continuous>flow_pkts_BCD_max:
		flow_pkts_BCD_max=flow_pkts_continuous
	if flow_pkts_continuous<flow_pkts_BCD_min:
		flow_pkts_BCD_min=flow_pkts_continuous
	flow_bytes_BCD_mean+=flow_bytes_continuous
	flow_bytes_BCD_mean2+=flow_bytes_continuous**2
	if flow_bytes_continuous>flow_bytes_BCD_max:
		flow_bytes_BCD_max=flow_bytes_continuous
	if flow_bytes_continuous<flow_bytes_BCD_min:
		flow_bytes_BCD_min=flow_bytes_continuous
	if fwd_pkts_BCD_mean!=fwd_pkts:
		print('fwd_pkts_BCD_mean!=fwd_pkts')
	if bwd_pkts_BCD_mean!=bwd_pkts:
		print('bwd_pkts_BCD_mean!=bwd_pkts')
	if fwd_bytes_BCD_mean!=fwd_bytes:
		print('fwd_bytes_BCD_mean!=fwd_bytes')
	if bwd_bytes_BCD_mean!=bwd_bytes:
		print('bwd_bytes_BCD_mean!=bwd_bytes')
	if flow_pkts_BCD_mean!=flow_pkts:
		print('flow_pkts_BCD_mean!=flow_pkts')
	if flow_bytes_BCD_mean!=flow_bytes:
		print('flow_bytes_BCD_mean!=flow_bytes')
	if bwd_to_fwd==fwd_to_bwd+1:
		fwd_groups=bwd_to_fwd
		bwd_groups=bwd_to_fwd
	elif bwd_to_fwd==fwd_to_bwd:
		if last_dir=='>':
			fwd_groups=fwd_to_bwd+1
			bwd_groups=bwd_to_fwd
		else:
			fwd_groups=fwd_to_bwd
			bwd_groups=bwd_to_fwd+1
	elif bwd_to_fwd+1==fwd_to_bwd:
		fwd_groups=fwd_to_bwd
		bwd_groups=fwd_to_bwd
	else:
		print('warning!!! bwd_to_fwd={}, fwd_to_bwd={}'.format(bwd_to_fwd,fwd_to_bwd))
	fwd_pkts_BCD_mean/=fwd_groups
	bwd_pkts_BCD_mean/=bwd_groups
	fwd_bytes_BCD_mean/=fwd_groups
	bwd_bytes_BCD_mean/=bwd_groups
	fwd_pkts_BCD_mean2/=fwd_groups
	bwd_pkts_BCD_mean2/=bwd_groups
	fwd_bytes_BCD_mean2/=fwd_groups
	bwd_bytes_BCD_mean2/=bwd_groups
	flow_pkts_BCD_mean/=exchange_dir_count+1
	flow_bytes_BCD_mean/=exchange_dir_count+1
	flow_pkts_BCD_mean2/=exchange_dir_count+1
	flow_bytes_BCD_mean2/=exchange_dir_count+1
	if fwd_groups+bwd_groups!=exchange_dir_count+1:
		print('warning!!! fwd_groups+bwd_groups!=exchange_dir_count+1')
	if exchange_dir_count!=fwd_to_bwd+bwd_to_fwd:
		print('warning!!!  exchange_dir_count!=fwd_to_bwd+bwd_to_fwd')
	if flow_pkts!=fwd_pkts+bwd_pkts:
		print('warning!!! flow_pkts!=fwd_pkts+bwd_pkts')
	if flow_bytes!=fwd_bytes+bwd_bytes:
		print('warning!!! flow_bytes!=fwd_bytes+bwd_bytes')
	if flow_pkts_BCD_max!=max(fwd_pkts_BCD_max,bwd_pkts_BCD_max):
		print('warning!!! flow_pkts_BCD_max!=max(fwd_pkts_BCD_max,bwd_pkts_BCD_max)')
	if flow_bytes_BCD_max!=max(fwd_bytes_BCD_max,bwd_bytes_BCD_max):
		print('warning!!! flow_bytes_BCD_max!=max(fwd_bytes_BCD_max,bwd_bytes_BCD_max)')
	if flow_pkts_BCD_min!=min(fwd_pkts_BCD_min,bwd_pkts_BCD_min):
		print('warning!!! flow_pkts_BCD_min!=min(fwd_pkts_BCD_min,bwd_pkts_BCD_min)')
	if flow_bytes_BCD_min!=min(fwd_bytes_BCD_min,bwd_bytes_BCD_min):
		print('warning!!! flow_bytes_BCD_min!=min(fwd_bytes_BCD_min,bwd_bytes_BCD_min)')
	return [
		flow_duration,
		flow_pkts,fwd_pkts,bwd_pkts,
		flow_bytes,flow_bytes_mean,float(flow_bytes_mean2-flow_bytes_mean**2)**(1/2),flow_bytes_max,flow_bytes_min,
		fwd_bytes,fwd_bytes_mean,float(fwd_bytes_mean2-fwd_bytes_mean**2)**(1/2),fwd_bytes_max,fwd_bytes_min,
		bwd_bytes,bwd_bytes_mean,float(bwd_bytes_mean2-bwd_bytes_mean**2)**(1/2),bwd_bytes_max,bwd_bytes_min,
		flow_IAT,flow_IAT_mean,float(flow_IAT_mean2-flow_IAT_mean**2)**(1/2),flow_IAT_max,flow_IAT_min,
		fwd_IAT,fwd_IAT_mean,float(fwd_IAT_mean2-fwd_IAT_mean**2)**(1/2),fwd_IAT_max,fwd_IAT_min,
		bwd_IAT,bwd_IAT_mean,float(bwd_IAT_mean2-bwd_IAT_mean**2)**(1/2),bwd_IAT_max,bwd_IAT_min,	
		exchange_dir_count,fwd_to_bwd,bwd_to_fwd,fwd_groups,bwd_groups,
		flow_pkts_BCD_mean,float(flow_pkts_BCD_mean2-flow_pkts_BCD_mean**2)**(1/2),flow_pkts_BCD_max,flow_pkts_BCD_min,
		fwd_pkts_BCD_mean,float(fwd_pkts_BCD_mean2-fwd_pkts_BCD_mean**2)**(1/2),fwd_pkts_BCD_max,fwd_pkts_BCD_min,
		bwd_pkts_BCD_mean,float(bwd_pkts_BCD_mean2-bwd_pkts_BCD_mean**2)**(1/2),bwd_pkts_BCD_max,bwd_pkts_BCD_min,
		flow_bytes_BCD_mean,float(flow_bytes_BCD_mean2-flow_bytes_BCD_mean**2)**(1/2),flow_bytes_BCD_max,flow_bytes_BCD_min,
		fwd_bytes_BCD_mean,float(fwd_bytes_BCD_mean2-fwd_bytes_BCD_mean**2)**(1/2),fwd_bytes_BCD_max,fwd_bytes_BCD_min,
		bwd_bytes_BCD_mean,float(bwd_bytes_BCD_mean2-bwd_bytes_BCD_mean**2)**(1/2),bwd_bytes_BCD_max,bwd_bytes_BCD_min
		]+byte_dist
'''
#extract flows from pcap files
#sc.load_layer('tls')
#for pcap_type in('tor','nonTor'):
pcap_type='tor'
retrans=0
for zeros in (0,1):
	#for retrans in (0,1):
	print(pcap_type,zeros,retrans)
	timeout_flows=[]
	captured={'AUDIO':0,'BROWSING':0,'CHAT':0,'FILE-TRANSFER':0,'MAIL':0,'P2P':0,'VIDEO':0,'VOIP':0}
	abandoned={'AUDIO':0,'BROWSING':0,'CHAT':0,'FILE-TRANSFER':0,'MAIL':0,'P2P':0,'VIDEO':0,'VOIP':0}
	for filename in os.listdir('Pcaps/{}'.format(pcap_type)):
		all_packets={}
		sc.sniff(offline='Pcaps/{}/{}'.format(pcap_type,filename),store=0,prn=sniff_pkts_shield(pcap_type,all_packets,filename,captured,abandoned))
		build_flows(timeout_flows,all_packets,zeros,retrans)
	del_short_flows(timeout_flows)
	print(captured)
	print(abandoned)
	f=open('{}_timeout_flows_zeros={}_retrans={}_timeout=0_max_num_pkts=0.pickle'.format(pcap_type,zeros,retrans),'wb')
	pickle.dump(timeout_flows,f)
	f.close()
'''
'''
truncate flows have timeout=0, max_num_pkts=0, and then create csv
IAT=inter-arrival time
BCD=before change direction
嘗試去掉能從其他特徵推算出的特徵( ex. flow IAT/size max/min, 因為這其實就是max/min(fwd IAT/size max/min, bwd IAT/size max/min))
'''
first_row=(
	'Source IP','Source Port','Destination IP','Destination Port','Fwd TTL','Bwd TTL',
	'Flow Duration',
	'Flow Packets','Fwd Packets','Bwd Packets',
	'Flow Bytes','Flow Bytes/Pkt Mean','Flow Bytes/Pkt Std','Flow Bytes/Pkt Max','Flow Bytes/Pkt Min',
	'Fwd Bytes','Fwd Bytes/Pkt Mean','Fwd Bytes/Pkt Std','Fwd Bytes/Pkt Max','Fwd Bytes/Pkt Min',
	'Bwd Bytes','Bwd Bytes/Pkt Mean','Bwd Bytes/Pkt Std','Bwd Bytes/Pkt Max','Bwd Bytes/Pkt Min',
	'Flow IAT','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min',
	'Fwd IAT','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Fwd IAT Min',
	'Bwd IAT','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Bwd IAT Min',
	'Exchange Direction Count','Fwd to Bwd','Bwd to Fwd','Fwd Groups','Bwd Groups',
	'Flow Packets BCD Mean','Flow Packets BCD Std','Flow Packets BCD Max','Flow Packets BCD Min',
	'Fwd Packets BCD Mean','Fwd Packets BCD Std','Fwd Packets BCD Max','Fwd Packets BCD Min',
	'Bwd Packets BCD Mean','Bwd Packets BCD Std','Bwd Packets BCD Max','Bwd Packets BCD Min',
	'Flow Bytes BCD Mean','Flow Bytes BCD Std','Flow Bytes BCD Max','Flow Bytes BCD Min',
	'Fwd Bytes BCD Mean','Fwd Bytes BCD Std','Fwd Bytes BCD Max','Fwd Bytes BCD Min',
	'Bwd Bytes BCD Mean','Bwd Bytes BCD Std','Bwd Bytes BCD Max','Bwd Bytes BCD Min',
	'byte_dist_0', 'byte_dist_1', 'byte_dist_2', 'byte_dist_3', 'byte_dist_4', 'byte_dist_5', 'byte_dist_6', 'byte_dist_7', 'byte_dist_8', 'byte_dist_9', 'byte_dist_10', 'byte_dist_11', 'byte_dist_12', 'byte_dist_13', 'byte_dist_14', 'byte_dist_15', 'byte_dist_16', 'byte_dist_17', 'byte_dist_18', 'byte_dist_19', 'byte_dist_20', 'byte_dist_21', 'byte_dist_22', 'byte_dist_23', 'byte_dist_24', 'byte_dist_25', 'byte_dist_26', 'byte_dist_27', 'byte_dist_28', 'byte_dist_29', 'byte_dist_30', 'byte_dist_31', 'byte_dist_32', 'byte_dist_33', 'byte_dist_34', 'byte_dist_35', 'byte_dist_36', 'byte_dist_37', 'byte_dist_38', 'byte_dist_39', 'byte_dist_40', 'byte_dist_41', 'byte_dist_42', 'byte_dist_43', 'byte_dist_44', 'byte_dist_45', 'byte_dist_46', 'byte_dist_47', 'byte_dist_48', 'byte_dist_49', 'byte_dist_50', 'byte_dist_51', 'byte_dist_52', 'byte_dist_53', 'byte_dist_54', 'byte_dist_55', 'byte_dist_56', 'byte_dist_57', 'byte_dist_58', 'byte_dist_59', 'byte_dist_60', 'byte_dist_61', 'byte_dist_62', 'byte_dist_63', 'byte_dist_64', 'byte_dist_65', 'byte_dist_66', 'byte_dist_67', 'byte_dist_68', 'byte_dist_69', 'byte_dist_70', 'byte_dist_71', 'byte_dist_72', 'byte_dist_73', 'byte_dist_74', 'byte_dist_75', 'byte_dist_76', 'byte_dist_77', 'byte_dist_78', 'byte_dist_79', 'byte_dist_80', 'byte_dist_81', 'byte_dist_82', 'byte_dist_83', 'byte_dist_84', 'byte_dist_85', 'byte_dist_86', 'byte_dist_87', 'byte_dist_88', 'byte_dist_89', 'byte_dist_90', 'byte_dist_91', 'byte_dist_92', 'byte_dist_93', 'byte_dist_94', 'byte_dist_95', 'byte_dist_96', 'byte_dist_97', 'byte_dist_98', 'byte_dist_99', 'byte_dist_100', 'byte_dist_101', 'byte_dist_102', 'byte_dist_103', 'byte_dist_104', 'byte_dist_105', 'byte_dist_106', 'byte_dist_107', 'byte_dist_108', 'byte_dist_109', 'byte_dist_110', 'byte_dist_111', 'byte_dist_112', 'byte_dist_113', 'byte_dist_114', 'byte_dist_115', 'byte_dist_116', 'byte_dist_117', 'byte_dist_118', 'byte_dist_119', 'byte_dist_120', 'byte_dist_121', 'byte_dist_122', 'byte_dist_123', 'byte_dist_124', 'byte_dist_125', 'byte_dist_126', 'byte_dist_127', 'byte_dist_128', 'byte_dist_129', 'byte_dist_130', 'byte_dist_131', 'byte_dist_132', 'byte_dist_133', 'byte_dist_134', 'byte_dist_135', 'byte_dist_136', 'byte_dist_137', 'byte_dist_138', 'byte_dist_139', 'byte_dist_140', 'byte_dist_141', 'byte_dist_142', 'byte_dist_143', 'byte_dist_144', 'byte_dist_145', 'byte_dist_146', 'byte_dist_147', 'byte_dist_148', 'byte_dist_149', 'byte_dist_150', 'byte_dist_151', 'byte_dist_152', 'byte_dist_153', 'byte_dist_154', 'byte_dist_155', 'byte_dist_156', 'byte_dist_157', 'byte_dist_158', 'byte_dist_159', 'byte_dist_160', 'byte_dist_161', 'byte_dist_162', 'byte_dist_163', 'byte_dist_164', 'byte_dist_165', 'byte_dist_166', 'byte_dist_167', 'byte_dist_168', 'byte_dist_169', 'byte_dist_170', 'byte_dist_171', 'byte_dist_172', 'byte_dist_173', 'byte_dist_174', 'byte_dist_175', 'byte_dist_176', 'byte_dist_177', 'byte_dist_178', 'byte_dist_179', 'byte_dist_180', 'byte_dist_181', 'byte_dist_182', 'byte_dist_183', 'byte_dist_184', 'byte_dist_185', 'byte_dist_186', 'byte_dist_187', 'byte_dist_188', 'byte_dist_189', 'byte_dist_190', 'byte_dist_191', 'byte_dist_192', 'byte_dist_193', 'byte_dist_194', 'byte_dist_195', 'byte_dist_196', 'byte_dist_197', 'byte_dist_198', 'byte_dist_199', 'byte_dist_200', 'byte_dist_201', 'byte_dist_202', 'byte_dist_203', 'byte_dist_204', 'byte_dist_205', 'byte_dist_206', 'byte_dist_207', 'byte_dist_208', 'byte_dist_209', 'byte_dist_210', 'byte_dist_211', 'byte_dist_212', 'byte_dist_213', 'byte_dist_214', 'byte_dist_215', 'byte_dist_216', 'byte_dist_217', 'byte_dist_218', 'byte_dist_219', 'byte_dist_220', 'byte_dist_221', 'byte_dist_222', 'byte_dist_223', 'byte_dist_224', 'byte_dist_225', 'byte_dist_226', 'byte_dist_227', 'byte_dist_228', 'byte_dist_229', 'byte_dist_230', 'byte_dist_231', 'byte_dist_232', 'byte_dist_233', 'byte_dist_234', 'byte_dist_235', 'byte_dist_236', 'byte_dist_237', 'byte_dist_238', 'byte_dist_239', 'byte_dist_240', 'byte_dist_241', 'byte_dist_242', 'byte_dist_243', 'byte_dist_244', 'byte_dist_245', 'byte_dist_246', 'byte_dist_247', 'byte_dist_248', 'byte_dist_249', 'byte_dist_250', 'byte_dist_251', 'byte_dist_252', 'byte_dist_253', 'byte_dist_254', 'byte_dist_255',
	'label'
	)

pcap_type='tor'
#for pcap_type in('tor','nonTor'):
retrans=0
for zeros in (0,1):
	#for retrans in (0,1):
	f=open('{}_timeout_flows_zeros={}_retrans={}_timeout=0_max_num_pkts=0.pickle'.format(pcap_type,zeros,retrans),'rb')
	timeout_flows=pickle.load(f)
	f.close()
	for timeout in (0,10,15,30,60,120):
		for max_num_pkts in (0,5,10,20,50,100,250,500,1000):
			if 'timeout_flows_zeros={}_retrans={}_timeout={}_max_num_pkts={}.csv'.format(zeros,retrans,timeout,max_num_pkts) not in os.listdir('CSV_scapy/{}'.format(pcap_type)):
				print(pcap_type,zeros,retrans,timeout,max_num_pkts)
				new_timeout_flows=truncate_flows(timeout_flows,timeout,max_num_pkts)
				csv=np.empty((1+len(new_timeout_flows),len(first_row)),object)
				csv[0]=first_row
				for index in range(len(new_timeout_flows)):
					csv[index+1,0]=new_timeout_flows[index]['src']
					csv[index+1,1]=new_timeout_flows[index]['sport']
					csv[index+1,2]=new_timeout_flows[index]['dst']
					csv[index+1,3]=new_timeout_flows[index]['dport']
					csv[index+1,4]=new_timeout_flows[index]['fwd_ttl']
					csv[index+1,5]=new_timeout_flows[index]['bwd_ttl']
					csv[index+1][6:len(first_row)-1]=calculate_features(new_timeout_flows[index]['packets'],new_timeout_flows[index]['byte_dist'])
					csv[index+1,len(first_row)-1]=new_timeout_flows[index]['label']
				np.savetxt('CSV_scapy/{}/timeout_flows_zeros={}_retrans={}_timeout={}_max_num_pkts={}.csv'.format(pcap_type,zeros,retrans,timeout,max_num_pkts),csv,fmt='%s',delimiter=',')
