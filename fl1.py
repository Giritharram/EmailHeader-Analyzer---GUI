from test import *
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
   return render_template('result.html', no_of_hop=hop,sender_result = seh,received_result = reh,proto_used=protu,timestamp_result=timst)

if __name__ == '__main__':
   app.run(debug = True)