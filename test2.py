import requests
import re
import nmap
import urllib
import urllib.request
import time
import whois
from test import *

mal_op = []
nonmal_op = []
mal_ip = []
nonmal_ip = []
maldomain=[]
nonmaldomain=[]


#function to extract ip address present in the sample.txt file
def extract_ip():
    ip_add = []
    lts = []
    fli = []
    fnl = []
    with open('sample.txt', 'r') as file:
        fi = file.readlines()
        re_ip = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for line in fi:
        if '127.0.0.1' in line:
            continue
        ip = re.findall(re_ip,line)
        ip_add.append(ip)

    res = list(filter(None,ip_add))

    for i in res:
        if len(i) > 1:
            lts.append(i[0])
            lts.append(i[1])
        else:
            lts.append(i)

    for i in lts:
        if type(i) is str:
            fli.append(list(i.split(" ")))
        else:
            fli.append(i)

    b = flatten(fli)

    fnl = list(set(b))
    return fnl


#function to extract domain names present in the sample.txt file
def extract_domain():
    fqdn_list = []
    tmp_domain = []
    domain_names = []

    resp = urllib.request.urlopen('http://data.iana.org/TLD/tlds-alpha-by-domain.txt')

    # Create a reverse sorted list of TLD ('.com' must be before '.co')
    tld = sorted([tld.strip().lower().decode('utf-8')
                    for tld in resp.readlines()[1:]], reverse=True)

    # Compile the regex pattern
    FQDN = re.compile(fr"([^\s]*\.(?:{'|'.join(tld)}))")


    # Find all fqdn
    with open('sample.txt') as fp:
        for line in fp.readlines():
            line = line.strip().lower()
            # Remove comments and blank lines
            if (len(line) == 0) or line.startswith('#'):
                continue
            # Extract FQDN
            fqdn = FQDN.findall(line)
            if fqdn:
                fqdn_list.append(fqdn[0])
    
    for i in fqdn_list:
        if 'http' not in i and ':' not in i and ';' not in i and '==' not in i:
            if '=' in i : 
                tmp1 = i.split('=')
                if len(tmp1)>0:
                    tmp_domain.append(tmp1[1])
                else:
                    tmp_domain.append(tmp1)
            if '<' in i : 
                tmp1 = i.split('<')
                tmp_domain.append(tmp1[1])

            if '(' in i : 
                tmp1 = i.split('(')
                tmp_domain.append(tmp1[1])

            if 'http' not in i and ':' not in i and ';' not in i and '==' not in i and '<' not in i and '(' not in i and '=' not in i and '-' not in i and '/' not in i and '%' not in i and i not in tmp_domain and len(i) > 7:
                tmp_domain.append(i)
    
    # domain_names = list(set(domain_names))
    for i in tmp_domain:
        if 'ppops' in i or 'google.com' in i or 'gmail.com' in i:
            continue
        if '@' in i:
            a = i.split('@')
            domain_names.append(a[1])
        else:
            domain_names.append(i)
    domain_names = list(set(domain_names))
    
    return domain_names

#function to extract URLs present in the sample.txt file
def extract_url():
    urllist = []    
    with open("sample.txt") as file:
            for line in file:
                if 'http' in line:
                    urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', line)
                    for i in urls:
                        if len(str(i)) > 12 and '.' in i:
                            urllist.append(str(i))
    urllist = list(set(urllist))
    return urllist


#function to find malicious IP from the extracted IPs from sample.txt file
def ip_info(lst):
    nmi = ['No IPs were found to be malicious']
    for k in lst:
        url = ("https://www.virustotal.com/api/v3/ip_addresses/%s" % k)
        headers = {
            "Accept": "application/json",
            "x-apikey": "ecb19838262d000479df6b9e09c58f5ce47832b20c7e4f55adfbc4238b16445b"
        }
        try:
            r = requests.get(url, headers=headers).json()
        
            dict_web = r['data']['attributes']['last_analysis_results']
            tot_engine_c=0
            tot_detect_c=0
            result_eng = []
            eng_name = []
            for i in dict_web:
                tot_engine_c = 1 + tot_engine_c
                if dict_web[i]['category'] == "malicious" or dict_web[i]['category'] == "suspicious":
                    result_eng.append(dict_web[i]["result"])
                    eng_name.append(dict_web[i]["engine_name"])
                    tot_detect_c = 1 + tot_detect_c
            res = []
            for i in result_eng:
                if i not in res:
                    res.append(i)
            result_eng = res

            if tot_detect_c > 0:
                mal_ip.append(k)
            else:
                nonmal_ip.append(k)
        
        except:
            None

    if len(mal_ip)>0:
        return mal_ip
    else:
        return nmi

#function to find open ports for the malicious IPs if exist
def ports(h):
    nm = nmap.PortScanner()
    host = h
    nm.scan(host, '20-1024')
    oport = []
    try:
        if nm[host].state() == 'up':
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        oport.append(port)
                        
    except:
        None
    
    return oport

# function to return open port result of a malicious IP if exist as a dictionary
def port_result():
    a = {}
    nmi = {"No IPs" :" were found to be malicious"}
    if len(mal_ip) > 0:
        for i in mal_ip:
            b=ports(i)
            a[i]=b
        return a
    else:
        return nmi

    
#function to find malicious URL from the extracted URLs from sample.txt file
def url_info(lst):
    malurl = []
    nonmalurl = []
    nmu = ['No URLs were found to be malicious']
    count = 0
    for k in lst:
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': 'ecb19838262d000479df6b9e09c58f5ce47832b20c7e4f55adfbc4238b16445b', 'resource':k }
            if count!=0 and count%4 == 0:
                time.sleep(62)
            count += 1
            try: 
                response = requests.get(url, params=params)
                r = response.json()
                print(r)
                print("--------------------------------------------------------------------------")
                if r['positives']>0:
                    malurl.append(k)
                else:
                    nonmalurl.append(k)
            except:
                None
    
    if len(malurl)>0:
        return malurl
    else:
        return nmu

#function to find malicious domain from the extracted domains from sample.txt file
def domain_info(lst):
    error_info = ["Error occured"]
    nmd = ['No domains were found to be malicious']
    count = 0
    print(lst)
    for k in lst:
        if count!=0 and count%4 == 0:
            time.sleep(62)
        count += 1
        print(count)
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey':'bcc1f94cc4ec1966f43a5552007d6c4fa3461cec7200f8d95053ebeeecc68afa','domain':k}
        try:
            r = requests.get(url, params=params).json()
            print(r)
            try:
                if r.get('detected_urls')[0].get('positives') > 0:
                    maldomain.append(k)
            except:
                nonmaldomain.append(k)
        except:
            None
    print(maldomain,'-malicious')
    print(nonmaldomain,'-nonmalicious')    
    
    if len(maldomain)>0:
        return maldomain
    else:
        return nmd

#function to find passivedns for the malicious IPs if exist
def ip_passivedns(lst):
    fli = {}
    nrf = ['No records found']
    nftb = ['No IPs were found to be malicious']
    errorinfo = ['Error Occured  or API Quota may have exceeded']
    if 'No IPs were found to be malicious' in lst:
        fli['']=nftb            
        return fli

    else:
        try:
            count = 0
            for k in lst:
                count += 1
                if count%4 == 0:
                    time.sleep(62)
                url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

                params = {'apikey':'ecb19838262d000479df6b9e09c58f5ce47832b20c7e4f55adfbc4238b16445b','ip':k}

                r = requests.get(url, params=params).json()

                print(k)
                print('***************')
                print(r['resolutions'])
                j = r['resolutions']
                print(len(j))
                if len(j) < 1:
                    fli[k]=nrf
                else:
                    fli[k]=j
                print('-------------')
            return fli
        except:
            fli['']=errorinfo
            return fli

#function to find whoisdata for malicious IPs and Domains if exist    
def whoisdata():
    mip=mal_ip
    mdomain=maldomain
    d = {}
    ndifm = {"No Domain or IP" :" were found to be malicious"}
    error_info = ['Error Occured']
    try:
        if len(mip) < 1 and len(mdomain) < 1:
            d['']=ndifm
            return d    
        else:
            k = mip+mdomain
            for i in k:
                w = whois.whois(i)
                d[i]=w
            return d
    except:
        d['']=error_info
        return d

