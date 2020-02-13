#!/usr/bin/env python
import scapy.all as scapy
import argparse
import re
import time
uname=""
pas=""
K=0
L=0
M=0
a=0
count=1
SrcIP=[]
Dst=[]
packet_count=0
time_dict={}
def login_uname(packet):
	global uname
	packet_list=list(map(str,packet.split("|")))
	if("Raw" in packet and "dport=telnet" in packet):
		if(len(packet_list)==5):
			if(packet_list[3][12]!=" " and packet_list[3][12]!="\\"):
				uname+=str(packet_list[3][12])
def login_pass(packet):
	global pas
	packet_list=list(map(str,packet.split("|")))
	if("Raw" in packet and "dport=telnet" in packet):
		if(len(packet_list)==5):
			if(packet_list[3][12]!=" " and packet_list[3][12]!="\\"):
				pas+=str(packet_list[3][12])
def file_write(uname,pas):
	global K
	auth_details={"root":["xc3511","vizxv","admin","888888","xmhdipc","default","juantech","123456","54321","(none)","root","12345","pass","1111","666666","password","1234","klv123","klv1234","Zte521","hi3518","jvbzd","anko","zlxx.","7ujMko0vizxv","7ujMko0admin","system","ikwb","dreambox","user","realtek","00000000"],"admin":["admin","password","(none)","admin1234","smcadmin","1111","1111111","1234","12345","54321","123456","7ujMko0admin","pass","meinsm"],"support":["support"],"Administrator":["admin"],"service":["service"],"supervisor":["supervisor"],"guest":["guest","1234","12345"],"admin1":["password"],"administrator":["1234"],"666666":["666666"],"888888":["888888"],"ubnt":["ubnt"],"tech":["tech"],"mother":["fucker"]}
	a="UserName: "+uname+" "+"Password: "+pas
	#print(a)
	if(uname in auth_details):
		if(pas in auth_details[uname]):
			print("UserName: "+uname+" with "+"Password: "+pas+" combination is vulnerable, so try a complex combination to secure your system from Mirai attack")
	with open("credentials.txt","w") as f:
		f.write(a)
	K=0
def packet_counter(src,dst):
	global SrcIP
	global count
	global Dst
	global M
	M=0
	if(dst not in Dst):
		Dst.append(dst)
	else:
		count+=1
	if(src not in SrcIP):
		SrcIP.append(src)
	if(count>4):
		print("Warning...: SYN flood over IP: "+str(Dst)+" by these/this IP: "+str(Dst)+" and packet count is "+str(count))
def calculate_time(time,name):
	global L
	L=0
	global time_dict
	if(name not in time_dict):
		time_dict[name]=time
	else:
		a=time-time_dict[name]
		time_dict[name]=time
		print("Time between two Logins of "+name+" user is :"+str(a))
def timer(time):
	global packet_count
	global a
	packet_count+=1
	if(packet_count==1):
		a=time
		a+=10
	if(time>a):
		print("No of packet's per 10 seconds are ",packet_count)
		packet_count=0

def pack(packet):
	global K
	global L
	global M
	global uname
	global pas
	global time_dict
	start_packet_time=time.time()
	timer(start_packet_time)
	packet=packet.summary
	packet=str(packet)
	packet_list=list(map(str,packet.split("|")))
	print(packet_list[3])
	if("login:" in packet and "Last" not in packet):
		K=1
	elif("Password" in packet):
		K=2
	elif("Last login" in packet):
		K=3
		print("*******Now this username:",uname," and password: ",pas," is trying to login")
		start_time=time.time()
	elif("ack=0" in packet or "syn=0" in packet):
		M=4
	if("Login incorrect" in packet):
		print("Now this username:",uname," and password: ",pas," is trying to login")
		uname=""
		pas=""
	if(K==1):
		login_uname(packet)
	elif(K==2):
		login_pass(packet)
	elif(K==3):
		file_write(uname,pas)
		#calculate_time(start_time,uname)
		uname=""
		pas=""
	"""if(M==4):
		a=list(map(str,packet_list[1].split()))
		packet_counter(a[11],a[12])"""
def sniff():
	scapy.sniff(filter='tcp and port 23', iface="eth0",prn=pack)
sniff()