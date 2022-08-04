from dataclasses import replace
from email.parser import BytesParser, Parser
from email.policy import default
import re
import os
import sys


sh=[]
rh=[]
pu=[]
tl=[]
l = ['Message-ID: <','Subject: ','From: ','Reply-To: ','To: ','pradeep']

with open('sample.txt', 'rb') as fp:

	headers = BytesParser(policy=default).parse(fp)
	#For Received headers
	a = str(headers).split('Received: ')		
	
	def sender_host(a):	
		for i in a:
			tmp = i.split('by')
			try:
				sh.append(tmp[0].replace("\n",""))
			except:
				None
		del sh[0]
		l = []
		for i in sh:
			t = i.strip("from ")
			print(t)
		print("\n")
		
	
	def received_host(a):
		for i in a:
			t = i.replace("\n",'')
			tmp = re.split('by |with|id |\n', t)
			try:
				rh.append(tmp[1])
			except:
				None
		for i in rh:
			print(i)
			
		

	def protocol_used(a):
		for i in a:
			t = i.replace("\n",'')
			tmp = re.split('by|with|id|;|\n', t)
			try:
				pu.append(tmp[2])
			except:
				None

		for i in pu:
			print(i.strip(" "))
		print("\n")
	
	def time_stamp(a):
		
		for i in a:
			t = i.replace("\n",'')
			tmp = re.split('; |X-|\n', t)
			try:
				tl.append(tmp[1])
			except:
				None
		for i in tl:
			print(i)
		print("\n")
	
	def summary(b):
		try:
			tmp = str(headers).split(b)
		except:
			None
		try:
			a = tmp[1]
		except:
			None
		d = list(a.split("\n"))
		try:
			print('{} {}'.format(b,d[0]))
		except:
			None

	def X_headers():
		with open('sample.txt', 'rb') as fp:
			for i in fp:
				a = str(i).strip("b'")
				b = a.split('X-')
				try:
					print("X-"+b[1].replace('\\n','').replace('\\r',''))
				except:
					None

	

	if __name__ == "__main__":
		# sys.stdout = open('a.txt','wt')

		# print("-------------------------------------------------------------")
		# print("			Sender_host		")
		# print("-------------------------------------------------------------")
		# sender_host(a)
		

		# print("-------------------------------------------------------------")
		# print("			Received_host		")
		# print("-------------------------------------------------------------")
		# received_host(a)

		# print("\n")
		# print("-------------------------------------------------------------")
		# print("			 No of Hops			")
		# print("-------------------------------------------------------------")
		# print("         		   ",len(rh))
		
		# print("\n")
		# print("-------------------------------------------------------------")
		# print("			Protocol Used		")
		# print("-------------------------------------------------------------")
		# protocol_used(a)
		
		# print("-------------------------------------------------------------")
		# print("			Time Stamp		")
		# print("-------------------------------------------------------------")
		# time_stamp(a)

		# print("-------------------------------------------------------------")
		# print("			Summary		")
		# print("-------------------------------------------------------------")
		for i in l:
			if i in str(headers):
				summary(i)
			else:
				print("Header Not Found!")
		print("\n")
		
		# print("-------------------------------------------------------------")
		# print("			X-Headers		")
		# print("-------------------------------------------------------------")
		# X_headers()
		


