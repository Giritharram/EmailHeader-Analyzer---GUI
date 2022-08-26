import requests
import re
import nmap
import urllib
import urllib.request
from opentip.client import OpenTIP


mal_op = []
nonmal_op = []
mal_ip = []
nonmal_ip = []


def flatten(l):
    fl=[]
    for i in l:
        if type(i) is list:
            for item in i:
                fl.append(item)
        else:
            fl.append(i)
    return fl

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



def extract_domain():
    fqdn_list = []
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
                    domain_names.append(tmp1[1])
                else:
                    domain_names.append(tmp1)
            if '<' in i : 
                tmp1 = i.split('<')
                domain_names.append(tmp1[1])

            if '(' in i : 
                tmp1 = i.split('(')
                domain_names.append(tmp1[1])

            if 'http' not in i and ':' not in i and ';' not in i and '==' not in i and '<' not in i and '(' not in i and '=' not in i and '-' not in i and '/' not in i and '%' not in i and i not in domain_names and len(i) > 7:
                domain_names.append(i)
    
    domain_names = list(set(domain_names))
    return domain_names

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


def ip_info(lst):
    nmi = ['No IPs were found to be malicious']
    for k in lst:
        url = ("https://www.virustotal.com/api/v3/ip_addresses/%s" % k)
        headers = {
            "Accept": "application/json",
            "x-apikey": "0016029bda9f2888c76cd394c44f3ab11ee24ddc092c81523060f2294fe29e0a"
        }
        r = requests.get(url, headers=headers).json()
        try:
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
                # print("The IP %s was rated for " % k + str(result_eng)[1:-1] + " on " + str(tot_detect_c) + " engines out of " + str(tot_engine_c) + " engines. \n")
                # print("The reported engines are: \n")
                mal_ip.append(k)
                # for i in eng_name:
                #     print(i)
                # print("\n")
            else:
                # print("The IP %s   has been marked harmless" %k)
                nonmal_ip.append(k)
        
        except:
            None

    if len(mal_ip)>0:
        return mal_ip
    else:
        return nmi

def ports(h):
    nm = nmap.PortScanner()
    host = h
    nm.scan(host, '20-1024')
    oport = []
    # portst = []
    f = 'No open ports found'
    try:
        if nm[host].state() == 'up':
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    # lport.sort()
                    for port in lport:
                        oport.append(port)
                        # portst.append(nm[host][proto][port]['state'])
    except:
        return f
        
    return oport
    # if len(oport) > 0:
    #     print(oport,portst)
    

def domain_info():
    client = OpenTIP('uAQFmZvDTOW6pmyaB4M5Rg==')
    # for i in lst:
    a = client.get_verdict_by_ioc('domain', 'sibidharan.me')
    print(a)
    # if '"Zone":"Green"' in a or '"Zone":"Grey"' in a:
    #     print(a)
    # else:
    #     print(a)

def url_info(lst):
    client = OpenTIP('uAQFmZvDTOW6pmyaB4M5Rg==')
    for i in lst:
        a = client.get_verdict_by_ioc('url', i+'/')
        print(a)
        # if '"Zone":"Green"' in a or '"Zone":"Grey"' in a:
        #     None
        # else:
        #     print(a)



# print(mal_ip)

def port_result():
    a = {}
    for i in mal_ip:
        b=ports(i)
        a[i]=b
    return a
    # for i in z:
    #     print(i,type(i))

    # return flatten(a)
# print(port_result())
url_info(extract_url())

