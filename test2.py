# from pdb import pm
# import requests
# import re
# import socket

# ips = []
# lts = []
# fli = []
# fnl = []
# op  = []
# pmin = 21
# pmax = 500

# def flatten(l):
#     fl=[]
#     for i in l:
#         if type(i) is list:
#             for item in i:
#                 fl.append(item)
#         else:
#             fl.append(i)
#     return fl


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

# b = flatten(fli)


# res = set(b)

# fnl = list(set(res))


# for k in fnl:
#     url = ("https://www.virustotal.com/api/v3/ip_addresses/%s" % k)
#     headers = {
#         "Accept": "application/json",
#         "x-apikey": "0016029bda9f2888c76cd394c44f3ab11ee24ddc092c81523060f2294fe29e0a"
#     }
#     r = requests.get(url, headers=headers).json()
#     try:
#         dict_web = r['data']['attributes']['last_analysis_results']

#         tot_engine_c=0
#         tot_detect_c=0
#         result_eng = []
#         eng_name = []
#         count_harmless = 0
#         for i in dict_web:
#             tot_engine_c = 1 + tot_engine_c
#             if dict_web[i]['category'] == "malicious" or dict_web[i]['category'] == "suspicious":
#                 result_eng.append(dict_web[i]["result"])
#                 eng_name.append(dict_web[i]["engine_name"])
#                 tot_detect_c = 1 + tot_detect_c
#         res = []
#         for i in result_eng:
#             if i not in res:
#                 res.append(i)

#         result_eng = res
#         if tot_detect_c > 0:
#             print("The IP %s was rated for " % i + str(result_eng)[1:-1] + " on " + str(tot_detect_c) + " engines out of " + str(tot_engine_c) + " engines. \n")
#             print("The reported engines are: \n")
#             for i in eng_name:
#                 print(i)
#         else:
#             print("The IP %s   has been marked harmless" %k)
#     except:
#         None

# ip = '5.2.72.226'

# for port in range(pmin,pmax+1):
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(0.5)
#             s.connect((ip,port))
#             op.append(port)
#     except:
#         None

# for port in op:
#     print(f"Port {port} is open on {ip}.")
import re
import urllib
import urllib.request
dnwe = []
dnwht = []
dnwhts = []
# Get TLD database
resp = urllib.request.urlopen('http://data.iana.org/TLD/tlds-alpha-by-domain.txt')

# Create a reverse sorted list of TLD ('.com' must be before '.co')
tld = sorted([tld.strip().lower().decode('utf-8')
                  for tld in resp.readlines()[1:]], reverse=True)

# Compile the regex pattern
FQDN = re.compile(fr"([^\s]*\.(?:{'|'.join(tld)}))")


# Find all fqdn
with open('sample.txt') as fp:
    fqdn_list = []
    for line in fp.readlines():
        line = line.strip().lower()

        # Remove comments and blank lines
        if (len(line) == 0) or line.startswith('#'):
            continue
        # Extract FQDN
        fqdn = FQDN.findall(line)
        if fqdn:
            fqdn_list.append(fqdn[0])


# for i in fqdn_list:
    # if '=' in i and '"' not in i: 
    #     tmp1 = i.split('=')
        # print(tmp)
    # if 'http' in i:
    #     try:
    #         tmp2 = i.split('http:')
    #         try:
    #             dnwht.append('http:'+tmp2[1])
    #         except:
    #             None
    #     except:
    #         None
    # if 'https' in i:
    #     try:
    #         tmp2 = i.split('https')
    #         dnwhts.append('https'+tmp2[1])
    #     except:
    #         None
    # if len(i)>=10:
    #     print(i,"No")
    # print(i)

# print(dnwht)
# print('------')
# print(dnwhts)
# print(len(fqdn_list))

with open("sample.txt") as file:
        for line in file:
            urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', line)
            print(urls)
# a = str(fqdn_list).split()