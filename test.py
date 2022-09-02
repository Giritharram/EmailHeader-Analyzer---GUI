from dataclasses import replace
from email.parser import BytesParser, Parser
from email.policy import default
import re

sh=[]
rh=[]
pu=[]
tl=[]
a = []
ls = ['Message-ID: ','Subject: ','From: ','Reply-To: ','To: ','Date: ']

lo = ['Accept-Language: ','Approved: ','ARC-Authentication-Results: ','ARC-Message-Signature: ','ARC-Seal: ','Archive: ','Archived-At: ','Authentication-Results: ','Auto-Submitted: ','Bcc: ','Body: ','Cancel-Key: ','Cancel-Lock: ','Cc: ','Comments: ','Alternate-Recipient: ','Autoforwarded: ','Autosubmitted: ','Content-Alternative: ','Content-Description: ','Content-Disposition: ','Content-Duration: ','Content-features: ','Content-ID: ','Content-Identifier: ','Content-Language: ','Content-Location: ','Content-MD5: ','Content-Return: ','Content-Transfer-Encoding: ','Content-Translation-Type: ','Content-Type: ','Control: ','Conversion: ','Conversion-With-Loss: ','DL-Expansion-History: ','Deferred-Delivery: ','Delivery-Date: ','Discarded-X400-IPMS-Extensions: ','Discarded-X400-MTS-Extensions: ','Disclose-Recipients: ','Disposition-Notification-Options: ','Disposition-Notification-To: ','Distribution: ','DKIM-Signature: ','Downgraded-Final-Recipient: ','Downgraded-In-Reply-To: ','Downgraded-Message-Id: ','Downgraded-Original-Recipient: ','Downgraded-References: ','Encoding: ','Encrypted: ','Expires: ','Expiry-Date: ','Followup-To: ','Generate-Delivery-Report: ','Importance: ','In-Reply-To: ','Incomplete-Copy: ','Injection-Date: ','Injection-Info: ','Keywords: ','Language: ','Latest-Delivery-Time: ','Lines: ','List-Archive: ','List-Help: ','List-ID: ','List-Owner: ','List-Owner: ','List-Subscribe: ','List-Unsubscribe: ','List-Unsubscribe-Post: ','Message-Context: ','Message-ID: ','Message-Type: ','MIME-Version: ','MMHS-Exempted-Address: ','MMHS-Extended-Authorisation-Info: ','MMHS-Subject-Indicator-Codes: ','MMHS-Handling-Instructions: ','MMHS-Message-Instructions: ','MMHS-Codress-Message-Indicator: ','MMHS-Originator-Reference: ','MMHS-Primary-Precedence: ','MMHS-Copy-Precedence: ',
'MMHS-Message-Type: ','MMHS-Other-Recipients-Indicator-To: ','MMHS-Other-Recipients-Indicator-CC: ','MMHS-Acp127-Message-Identifier: ','MMHS-Originator-PLAD: ','MT-Priority: ','Newsgroups: ','Obsoletes: ','Organization: ','Original-Encoded-Information-Types: ','Original-From: ','Original-Message-ID: ','Original-Recipient: ','Original-Sender: ','Originator-Return-Address: ','Original-Subject: ','Path: ','PICS-Label: ','Posting-Version: ','Prevent-NonDelivery-Report: ','Priority: ','Received-SPF: ','References: ','Relay-Version: ','Reply-By: ','Require-Recipient-Valid-Since: ','Resent-Bcc: ','Resent-Cc: ','Resent-Date: ','Resent-From: ','Resent-Message-ID: ','Resent-Reply-To: ','Resent-Sender: ','Resent-To: ','Return-Path: ','Sender: ','Sensitivity: ','Solicitation: ','Summary: ','Supersedes: ','TLS-Report-Domain: ','TLS-Required: ','TLS-Report-Submitter: ','User-Agent: ','VBR-Info: ','VBR-Info: ','X400-Content-Identifier: ','X400-Content-Return: ','X400-Content-Type: ','X400-MTS-Identifier: ','X400-Originator: ','X400-Received: ','X400-Recipients: ','X400-Trace: ','Xref: ']

def flatten(l):
    fl=[]
    for i in l:
        if type(i) is list:
            for item in i:
                fl.append(item)
        else:
            fl.append(i)
    return fl

with open('sample.txt', 'rb') as fp:

	headers = BytesParser(policy=default).parse(fp)
	#For Received headers
	a = str(headers).split('Received: ')		
	
	def sender_host(p=a):
		snd_host = []	
		for i in p:
			tmp = i.split('by')
			try:
				sh.append(tmp[0].replace("\n",""))
			except:
				None
		del sh[0]
		l = []
		for i in sh:
			t = i.strip("from")
			snd_host.append(t)
		snd_host.reverse()
		return snd_host
		
	
	def received_host(p=a):
		for i in p:
			t = i.replace("\n",'')
			tmp = re.split('by |with|id |\n', t)
			try:
				rh.append(tmp[1])
			except:
				None
		rh.reverse()
		return rh
			
		

	def protocol_used(p=a):
		for i in p:
			# pro_used=[]
			t = i.replace("\n",'')
			tmp = re.split('with|id|\n', t)
			try:
				pu.append(tmp[1])
			except:
				None
		pu.reverse()
		return pu
	
	def time_stamp(p=a):
		time_st = []
		for i in a:
			t = i.replace("\n",'').replace('  ','')
			tmp = re.split(';|X-|\n', t)
			try:
				tl.append(tmp[1])
			except:
				None
		for i in tl:
			try:
				t = i.split(')')
				time_st.append(t[0]+')')
			except:
				None
		time_st.reverse()
		return time_st
	
	def no_of_hops():
		hops = []
		for i in range(len(rh)+1):
			hops.append(i)
		del hops[0]
		return hops

	def summary(b):
		try:
			tmp = str(headers).replace('\\n','').split(b)
		except:
			None
		try:
			a = tmp[1]
		except:
			None
		d = list(a.split("\n"))
		try:
			r = d[0]
		except:
			None
		return r

	def otherheaders(b):
		with open('sample.txt','rb') as fp:
			for i in fp:
				z = str(i).strip("b'")
				try:
					tmp =str(z).replace('\\n','').split(b)
				except:
					None
				try:
					a = tmp[1]
				except:
					None
			return a

	def call_summary():
		call_sum = []
		for i in ls:
			if i in str(headers):
				call_sum.append(i+summary(i))
		return call_sum


	def call_otherheaders():
		tmp = []
		for i in lo:
			if i in str(headers):
				tmp.append(i+otherheaders(i))
		r = flatten(tmp)		
		return r

	def X_headers():
		with open('sample.txt', 'rb') as fp:
			tmp = []
			for i in fp:
				a = str(i).strip("b'")
				b = a.split('X-')
				try:
					tmp.append("X-"+b[1].replace('\\n','').replace('\\r',''))
				except:
					None
			return tmp

	def combine_Xh_and_Oh():
		t1 = call_otherheaders()
		t2 = X_headers()
		t3 = t1+t2
		f = flatten(t3)
		return f

		# hdr = []
		# hdr_val = []
		# for i in f:
		# 	e = i.split(':')
		# 	try:
		# 		if len(e[0])>4:
		# 			hdr.append(e[0])
		# 	except:
		# 		None
		# 	try:
		# 		hdr_val.append(e[1])
		# 	except:
		# 		None
		# print(len(hdr))
		# print(len(hdr_val))


	# if __name__ == "__main__":


	# 	print("-------------------------------------------------------------")
	# 	print("			Sender_host		")
	# 	print("-------------------------------------------------------------")
	# 	print(sender_host())
	# 	print('\n')
		

	# 	print("-------------------------------------------------------------")
	# 	print("			Received_host		")
	# 	print("-------------------------------------------------------------")
	# 	print(received_host())
		
	# 	print("\n")
	# 	print("-------------------------------------------------------------")
	# 	print("			 No of Hops			")
	# 	print("-------------------------------------------------------------")
	# 	print(no_of_hops())
		
	# 	print("\n")
	# 	print("-------------------------------------------------------------")
	# 	print("			Protocol Used		")
	# 	print("-------------------------------------------------------------")
	# 	print(protocol_used())
		
	# 	print("-------------------------------------------------------------")
	# 	print("			Time Stamp		")
	# 	print("-------------------------------------------------------------")
	# 	print(time_stamp())
	# 	print('\n')

	# 	print("-------------------------------------------------------------")
	# 	print("			Summary		")
	# 	print("-------------------------------------------------------------")
	# 	print(call_summary())
		
	# 	print("-------------------------------------------------------------")
	# 	print("			Other-Headers		")
	# 	print("-------------------------------------------------------------")
	# 	print(combine_Xh_and_Oh())
		


