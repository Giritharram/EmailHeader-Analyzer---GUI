from dataclasses import replace
from email.parser import BytesParser, Parser
from email.policy import default
import re

sh=[]
rh=[]
pu=[]
tl=[]

with open('sample.txt', 'rb') as fp:
	
	headers = BytesParser(policy=default).parse(fp)
	a = str(headers).split('Received: ')
	

	def sender_host(a):
		print("-------------------------------------------------------------")
		print("			Sender_host		")
		print("-------------------------------------------------------------")
		print("\n")
		for i in a:
			tmp = i.split('by')
			sh.append(tmp[0].replace("\n",""))
		del sh[0]
		for i in sh:
			print(i.strip("from "))
		print("\n")

	def received_host(a):
		print("-------------------------------------------------------------")
		print("			Received_host		")
		print("-------------------------------------------------------------")
		for i in a:
			t = i.replace("\n",'')
			tmp = re.split('by |with|id |\n', t)
			try:
				rh.append(tmp[1])
			except:
				print("")
		for i in rh:
			print(i)
		print("\n")

	def protocol_used(a):
		print("-------------------------------------------------------------")
		print("			Protocol Used		")
		print("-------------------------------------------------------------")
		for i in a:
			t = i.replace("\n",'')
			tmp = re.split('by|with|id|;|\n', t)
			try:
				pu.append(tmp[2])
			except:
				print("")
		for i in pu:
			print(i.strip(" "))
		print("\n")
	
	def time_stamp(a):
		print("-------------------------------------------------------------")
		print("			Time Stamp		")
		print("-------------------------------------------------------------")
		for i in a:
			t = i.replace("\n",'')
			tmp = re.split('; |X-|\n', t)
			try:
				tl.append(tmp[1])
			except:
				print("")
		for i in tl:
			print(i)
		print("\n")
		print(tl)

	sender_host(a)
	received_host(a)
	protocol_used(a)
	time_stamp(a)