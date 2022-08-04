from dataclasses import replace
from email.parser import BytesParser, Parser
from email.policy import default
import re


ls = ['Message-ID: <','Subject: ','From: ','Reply-To: ','To: ']

lo = ['Accept-Language: ','Approved: ','ARC-Authentication-Results: ','ARC-Message-Signature: ','ARC-Seal: ','Archive: ','Archived-At: ','Authentication-Results: ','Auto-Submitted: ','Bcc: ','Body: ','Cancel-Key: ','Cancel-Lock: ','Cc: ','Comments: ','Alternate-Recipient: ','Autoforwarded: ','Autosubmitted: ','Content-Alternative: ','Content-Description: ','Content-Disposition: ','Content-Duration: ','Content-features: ','Content-ID: ','Content-Identifier: ','Content-Language: ','Content-Location: ','Content-MD5: ','Content-Return: ','Content-Transfer-Encoding: ',
'Content-Translation-Type: ','Content-Type: ','Control: ','Conversion: ','Conversion-With-Loss: ','DL-Expansion-History: ','Deferred-Delivery: ','Delivery-Date: ','Discarded-X400-IPMS-Extensions: ','Discarded-X400-MTS-Extensions: ','Disclose-Recipients: ','Disposition-Notification-Options: ','Disposition-Notification-To: ','Distribution: ','DKIM-Signature: ','Downgraded-Final-Recipient: ','Downgraded-In-Reply-To: ','Downgraded-Message-Id: ','Downgraded-Original-Recipient: ','Downgraded-References: ','Encoding: ','Encrypted: ','Expires: ','Expiry-Date: ','Followup-To: ','Generate-Delivery-Report: ',
'Importance: ','In-Reply-To: ','Incomplete-Copy: ','Injection-Date: ','Injection-Info: ','Keywords: ','Language: ','Latest-Delivery-Time: ','Lines: ','List-Archive: ','List-Help: ','List-ID: ','List-Owner: ','List-Owner: ','List-Subscribe: ','List-Unsubscribe: ','List-Unsubscribe-Post: ','Message-Context: ','Message-ID: ','Message-Type: ','MIME-Version: ','MMHS-Exempted-Address: ','MMHS-Extended-Authorisation-Info: ','MMHS-Subject-Indicator-Codes: ','MMHS-Handling-Instructions: ','MMHS-Message-Instructions: ','MMHS-Codress-Message-Indicator: ','MMHS-Originator-Reference: ','MMHS-Primary-Precedence: ','MMHS-Copy-Precedence: ',
'MMHS-Message-Type: ','MMHS-Other-Recipients-Indicator-To: ','MMHS-Other-Recipients-Indicator-CC: ','MMHS-Acp127-Message-Identifier: ','MMHS-Originator-PLAD: ','MT-Priority: ','Newsgroups: ','Obsoletes: ','Organization: ','Original-Encoded-Information-Types: ','Original-From: ','Original-Message-ID: ','Original-Recipient: ','Original-Sender: ','Originator-Return-Address: ','Original-Subject: ','Path: ','PICS-Label: ','Posting-Version: ','Prevent-NonDelivery-Report: ','Priority: ','Received-SPF: ','References: ','Relay-Version: ','Reply-By: ','Require-Recipient-Valid-Since: ','Resent-Bcc: ','Resent-Cc: ','Resent-Date: ','Resent-From: ',
'Resent-Message-ID: ','Resent-Reply-To: ','Resent-Sender: ','Resent-To: ','Return-Path: ','Sender: ','Sensitivity: ','Solicitation: ','Summary: ','Supersedes: ','TLS-Report-Domain: ','TLS-Required: ','TLS-Report-Submitter: ','User-Agent: ','VBR-Info: ','VBR-Info: ','X400-Content-Identifier: ','X400-Content-Return: ','X400-Content-Type: ','X400-MTS-Identifier: ','X400-Originator: ','X400-Received: ','X400-Recipients: ','X400-Trace: ','Xref: ']


with open('sample.txt','rb') as fp:
    headers = BytesParser(policy=default).parse(fp)
    a = str(headers).split('Received: ')

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


    for i in lo:
        if i in str(headers):
            summary(i)
        
            