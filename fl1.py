from test import *
from test2 import *
from flask import Flask, render_template
app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.route('/')
def result():
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
def result1():
   mip = malipinfo
   noi = extract_ip()
   return render_template('result2.html',allips=noi,malipinfo=mip)

# @app.route('/portscan')
# def result2():
#    if 
if __name__ == '__main__':
   app.run(debug = True)