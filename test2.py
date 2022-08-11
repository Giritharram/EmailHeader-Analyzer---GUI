from dataclasses import replace
from email.parser import BytesParser, Parser
from email.policy import default
import re


ls = ['Message-ID: <','Subject: ','From: ','Reply-To: ','To: ']

lo = ['Received-SPF: ','Accept-Language: ','Approved: ','ARC-Authentication-Results: ','ARC-Message-Signature: ','ARC-Seal: ','Archive: ','Archived-At: ','Authentication-Results: ','Auto-Submitted: ','Bcc: ','Body: ','Cancel-Key: ','Cancel-Lock: ','Cc: ','Comments: ','Alternate-Recipient: ','Autoforwarded: ','Autosubmitted: ','Content-Alternative: ','Content-Description: ','Content-Disposition: ','Content-Duration: ','Content-features: ','Content-ID: ','Content-Identifier: ','Content-Language: ','Content-Location: ','Content-MD5: ','Content-Return: ','Content-Transfer-Encoding: ',
'Content-Translation-Type: ','Content-Type: ','Control: ','Conversion: ','Conversion-With-Loss: ','DL-Expansion-History: ','Deferred-Delivery: ','Delivery-Date: ','Discarded-X400-IPMS-Extensions: ','Discarded-X400-MTS-Extensions: ','Disclose-Recipients: ','Disposition-Notification-Options: ','Disposition-Notification-To: ','Distribution: ','DKIM-Signature: ','Downgraded-Final-Recipient: ','Downgraded-In-Reply-To: ','Downgraded-Message-Id: ','Downgraded-Original-Recipient: ','Downgraded-References: ','Encoding: ','Encrypted: ','Expires: ','Expiry-Date: ','Followup-To: ','Generate-Delivery-Report: ',
'Importance: ','In-Reply-To: ','Incomplete-Copy: ','Injection-Date: ','Injection-Info: ','Keywords: ','Language: ','Latest-Delivery-Time: ','Lines: ','List-Archive: ','List-Help: ','List-ID: ','List-Owner: ','List-Owner: ','List-Subscribe: ','List-Unsubscribe: ','List-Unsubscribe-Post: ','Message-Context: ','Message-ID: ','Message-Type: ','MIME-Version: ','MMHS-Exempted-Address: ','MMHS-Extended-Authorisation-Info: ','MMHS-Subject-Indicator-Codes: ','MMHS-Handling-Instructions: ','MMHS-Message-Instructions: ','MMHS-Codress-Message-Indicator: ','MMHS-Originator-Reference: ','MMHS-Primary-Precedence: ','MMHS-Copy-Precedence: ',
'MMHS-Message-Type: ','MMHS-Other-Recipients-Indicator-To: ','MMHS-Other-Recipients-Indicator-CC: ','MMHS-Acp127-Message-Identifier: ','MMHS-Originator-PLAD: ','MT-Priority: ','Newsgroups: ','Obsoletes: ','Organization: ','Original-Encoded-Information-Types: ','Original-From: ','Original-Message-ID: ','Original-Recipient: ','Original-Sender: ','Originator-Return-Address: ','Original-Subject: ','Path: ','PICS-Label: ','Posting-Version: ','Prevent-NonDelivery-Report: ','Priority: ','References: ','Relay-Version: ','Reply-By: ','Require-Recipient-Valid-Since: ','Resent-Bcc: ','Resent-Cc: ','Resent-Date: ','Resent-From: ',
'Resent-Message-ID: ','Resent-Reply-To: ','Resent-Sender: ','Resent-To: ','Return-Path: ','Sender: ','Sensitivity: ','Solicitation: ','Summary: ','Supersedes: ','TLS-Report-Domain: ','TLS-Required: ','TLS-Report-Submitter: ','User-Agent: ','VBR-Info: ','VBR-Info: ','X400-Content-Identifier: ','X400-Content-Return: ','X400-Content-Type: ','X400-MTS-Identifier: ','X400-Originator: ','X400-Received: ','X400-Recipients: ','X400-Trace: ','Xref: ']




def summary(b):
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
        try:
            print('{} {}'.format(b,a))
        except:
            None
    
    # def summary(b):
    #     try:
    #         tmp = str(fp).split(b) 
    #     except:
    #         None
    #     try:
    #         a = tmp[1]
    #     except:
    #         None
    #     d = list(a.split("\n"))
        
    #     try:
    #         print('{} {}'.format(b,d[0]))

    #     except:
    #         None

with open('sample.txt','rb') as fp:
    headers = BytesParser(policy=default).parse(fp)
    for i in lo:
        if i in str(headers):
            summary(i)

    
        
# from os import remove
# import re
# ips = []
# lts= []
# fli = []

# with open('sample.txt', 'r') as file:
#     fi = file.readlines()
#     re_ip = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

# for line in fi:
#     ip = re.findall(re_ip,line)
#     ips.append(ip)

# res = list(filter(None,ips))

# for i in res:
#     if len(i) > 1:
#         lts.append(i[0])
#         lts.append(i[1])
#     else:
#         lts.append(i)

# for i in lts:
#     if type(i) is str:
#         fli.append(list(i.split(" ")))
#     else:
#         fli.append(i)

# for i in fli:
#     print(i)




import requests
from bs4 import BeautifulSoup
ip_add = '5.2.72.226'
api_key = "0016029bda9f2888c76cd394c44f3ab11ee24ddc092c81523060f2294fe29e0a"
r = requests.get("https://www.virustotal.com/api/v3/ip-address/%s" % ip_add, headers={'User-agent': 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0','x-apikey': '%s' % api_key}).json()

dict_web = r['data']['attributes']['last_analysis_results']
tot_engine_c=0
tot_detect_c=0
result_eng = []
eng_name = []
count_harmless = 0
for i in dict_web:
    tot_engine_c = 1 + tot_engine_c
    if dict_web[i]['category'] == "malicios" or dict_web[i]['category'] == "suspicious":
        result_eng.append(dict_web[i]["result"])
        eng_name.append(dict_web[i]["engine_name"])
        tot_detect_c = 1 + tot_detect_c
res = []
for i in result_eng:
    if i not in res:
        res.append(i)

result_eng = res
if tot_detect_c > 0:
    print("The %s was rated for" % ip_add + str(result_eng)[1:-1] + " on " + str(tot_detect_c) + " engines out of " + str(tot_engine_c) + "engines. The reported engines are:" + str(eng_name)[1:-1] + '.')
else:
    print("The IP %s " %ip_add + "has been marked harmless")

# import requests

# url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

# params = {'apikey':'0016029bda9f2888c76cd394c44f3ab11ee24ddc092c81523060f2294fe29e0a','ip':'5.2.72.226'}

# response = requests.get(url, params=params)

# print(response.json())

            