from test import *
from test2 import *
# import re
from urllib import request
from flask import Flask, render_template, request
app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.route('/')
def result1():
   hop = no_of_hops()
   seh = sender_host()
   reh = received_host()
   protu = protocol_used()
   timst = time_stamp()
   sumry = call_summary()
   othehe = combine_Xh_and_Oh()
   return render_template('result1.html', no_of_hop=hop,sender_result=seh,received_result=reh,proto_used=protu,timestamp_result=timst,
   summary_result=sumry,otherheaders_result=othehe)

@app.route('/info')
def result2():
   mip = ip_info(extract_ip())
   noi = extract_ip()
   return render_template('result2.html',allips=noi,malipinfo=mip)

@app.route('/getip')
def result3():
   ipi = port_result()
   return render_template('result3.html',ipportscan=ipi)

if __name__ == '__main__':
   app.run(debug = True)

