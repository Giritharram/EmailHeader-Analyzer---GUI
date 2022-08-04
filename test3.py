from os import remove
import jellyfish

a1=[]
b1=[]
c1=[]



with open('sample.txt','r') as fp:
    for i in fp:
        a = str(i).replace('\n','')
        t = list(a.split(" "))
        f = list(filter(None,t))
        a1.append(f)    

with open('a.txt','r') as fa:
    for i in fa:
        a = str(i).replace('\n','')
        t = list(a.split(" "))
        f = list(filter(None,t))
        b1.append(f)

for i in b1:
    print(i)

# print(a1)
# print(b1)
# for i in a1[:]:
#     for k in b1[:]:
#             print(k)
#         # print(str(b1))

l = ['Message-ID: <','Subject: ','From: ','Reply-To: ','To: ','Received:','To:','Subject:','Reply-To:','Date:','From:']

# print(l)