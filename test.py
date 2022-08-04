from dataclasses import replace
from email.parser import BytesParser, Parser
from email.policy import default
import re



sh=[]
rh=[]
pu=[]
tl=[]

ls = ['Message-ID: ','Subject: ','From: ','Reply-To: ','To: ','Date: ']

lo = ['Accept-Language: ','Approved: ','ARC-Authentication-Results: ','ARC-Message-Signature: ','ARC-Seal: ','Archive: ','Archived-At: ','Authentication-Results: ','Auto-Submitted: ','Bcc: ','Body: ','Cancel-Key: ','Cancel-Lock: ','Cc: ','Comments: ','Alternate-Recipient: ','Autoforwarded: ','Autosubmitted: ','Content-Alternative: ','Content-Description: ','Content-Disposition: ','Content-Duration: ','Content-features: ','Content-ID: ','Content-Identifier: ','Content-Language: ','Content-Location: ','Content-MD5: ','Content-Return: ','Content-Transfer-Encoding: ',
'Content-Translation-Type: ','Content-Type: ','Control: ','Conversion: ','Conversion-With-Loss: ','DL-Expansion-History: ','Deferred-Delivery: ','Delivery-Date: ','Discarded-X400-IPMS-Extensions: ','Discarded-X400-MTS-Extensions: ','Disclose-Recipients: ','Disposition-Notification-Options: ','Disposition-Notification-To: ','Distribution: ','DKIM-Signature: ','Downgraded-Final-Recipient: ','Downgraded-In-Reply-To: ','Downgraded-Message-Id: ','Downgraded-Original-Recipient: ','Downgraded-References: ','Encoding: ','Encrypted: ','Expires: ','Expiry-Date: ','Followup-To: ','Generate-Delivery-Report: ',
'Importance: ','In-Reply-To: ','Incomplete-Copy: ','Injection-Date: ','Injection-Info: ','Keywords: ','Language: ','Latest-Delivery-Time: ','Lines: ','List-Archive: ','List-Help: ','List-ID: ','List-Owner: ','List-Owner: ','List-Subscribe: ','List-Unsubscribe: ','List-Unsubscribe-Post: ','Message-Context: ','Message-ID: ','Message-Type: ','MIME-Version: ','MMHS-Exempted-Address: ','MMHS-Extended-Authorisation-Info: ','MMHS-Subject-Indicator-Codes: ','MMHS-Handling-Instructions: ','MMHS-Message-Instructions: ','MMHS-Codress-Message-Indicator: ','MMHS-Originator-Reference: ','MMHS-Primary-Precedence: ','MMHS-Copy-Precedence: ',
'MMHS-Message-Type: ','MMHS-Other-Recipients-Indicator-To: ','MMHS-Other-Recipients-Indicator-CC: ','MMHS-Acp127-Message-Identifier: ','MMHS-Originator-PLAD: ','MT-Priority: ','Newsgroups: ','Obsoletes: ','Organization: ','Original-Encoded-Information-Types: ','Original-From: ','Original-Message-ID: ','Original-Recipient: ','Original-Sender: ','Originator-Return-Address: ','Original-Subject: ','Path: ','PICS-Label: ','Posting-Version: ','Prevent-NonDelivery-Report: ','Priority: ','Received-SPF: ','References: ','Relay-Version: ','Reply-By: ','Require-Recipient-Valid-Since: ','Resent-Bcc: ','Resent-Cc: ','Resent-Date: ','Resent-From: ',
'Resent-Message-ID: ','Resent-Reply-To: ','Resent-Sender: ','Resent-To: ','Return-Path: ','Sender: ','Sensitivity: ','Solicitation: ','Summary: ','Supersedes: ','TLS-Report-Domain: ','TLS-Required: ','TLS-Report-Submitter: ','User-Agent: ','VBR-Info: ','VBR-Info: ','X400-Content-Identifier: ','X400-Content-Return: ','X400-Content-Type: ','X400-MTS-Identifier: ','X400-Originator: ','X400-Received: ','X400-Recipients: ','X400-Trace: ','Xref: ']


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
	
	def call_summary():
		for i in ls:
			if i in str(headers):
				summary(i)
		print("\n")

	def call_otherheaders():
		for i in lo:
			if i in str(headers):
				summary(i)

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


		print("-------------------------------------------------------------")
		print("			Sender_host		")
		print("-------------------------------------------------------------")
		sender_host(a)
		

		print("-------------------------------------------------------------")
		print("			Received_host		")
		print("-------------------------------------------------------------")
		received_host(a)

		print("\n")
		print("-------------------------------------------------------------")
		print("			 No of Hops			")
		print("-------------------------------------------------------------")
		print("         		   ",len(rh))
		
		print("\n")
		print("-------------------------------------------------------------")
		print("			Protocol Used		")
		print("-------------------------------------------------------------")
		protocol_used(a)
		
		print("-------------------------------------------------------------")
		print("			Time Stamp		")
		print("-------------------------------------------------------------")
		time_stamp(a)

		print("-------------------------------------------------------------")
		print("			Summary		")
		print("-------------------------------------------------------------")
		call_summary()
		
		print("-------------------------------------------------------------")
		print("			Other-Headers		")
		print("-------------------------------------------------------------")
		call_otherheaders()
		X_headers()
		


