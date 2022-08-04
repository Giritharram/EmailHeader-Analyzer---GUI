import os
from test import *

os.system("python3 test.py")

a1 = []
b1 = []
res= []

with open('sample.txt','r') as fp:
    for i in fp:
        a = str(i).replace('\n','')
        t = list(a.split(" "))
        f = list(filter(None,t))
        a1.append(f)
    # for i in a1:
    #     print(i)


with open('a.txt','r') as fa:
    for i in fa:
        a = str(i).replace('\n','')
        t = list(a.split(" "))
        f = list(filter(None,t))
        b1.append(f)


def flatten(t):
    fl=[]
    for i in t:
        if type(i) is list:
            for item in i:
                fl.append(item)
        else:
            fl.append(i)
    return fl


def rm_common(a,b):
    for i in a[:]:
        if i in b:
            a.remove(i)
    return a

# a = rm_common(a1,b1)
# print(a)

# a = flatten(a1)
# b = flatten(b1)
c = rm_common(a1,b1)

d = rm_common(c,l)
for i in d:
    res.append(i)
    
print(res)

# def re_headers(c):
#     a = ""
#     try:
#         for i in c:
#             li = i.remove(str(l))
#             res.append(li)            
#     except:
#         None
#     return res


# print(re_headers(c))
    
