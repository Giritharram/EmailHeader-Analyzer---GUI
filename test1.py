from cmath import exp
from dataclasses import replace
from email.parser import BytesParser, Parser
from email.policy import default
import re

sh=[]
rh=[]

with open('sample.txt','r') as fp:
    a1=[]
    for i in fp:
        a = str(i).split('Received: ')
        for i in a:
            tmp = re.split('from|by|with|id|;|X-|\n',i)
            del tmp[0]
            print(tmp)
            