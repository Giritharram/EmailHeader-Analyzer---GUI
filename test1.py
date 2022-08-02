from cmath import exp
from dataclasses import replace
from email.parser import BytesParser, Parser
from email.policy import default
import re



with open('sample.txt','rb') as fp:
    headers = BytesParser(policy=default).parse(fp)
    a = str(headers)
    
    
    for i in a:
        print(i.replace('\n',''))
    # for i in fp:
    #     a = str(i).replace("Rec",' ')
    #     a = str(i).strip("b'")

        # try:
        #     b = a.replace('\\n','').replace('\\r','')
        #     t = b.replace('\n','')
        #     print(t)
        # except:
        #     None

        # try:
        #     [n for n in fp.readlines() if not n.startswith('Received:')]
        # except:
        #     None