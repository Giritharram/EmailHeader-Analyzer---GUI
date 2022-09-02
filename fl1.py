from test import *
from test2 import *
from werkzeug.utils import secure_filename
from urllib import request
from flask import *
import os

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['UPLOAD_FOLDER'] = ''
app.config['ALLOWED_EXTENSION'] = ['EML','TXT']
app.config['TXT_EXTENSION'] = ['TXT']

def allowed_file(filename):
    if not '.' in filename:
        return False
    ext = filename.rsplit('.',1)[1]

    if ext.upper() in app.config['ALLOWED_EXTENSION']:
        return True
    else:
        return False

def txtfile(filename):
    ext = filename.rsplit('.',1)[1]
    if ext.upper() in app.config['TXT_EXTENSION']:
        return True
    else:
        return False

@app.route('/home', methods=['GET', 'POST'])
def upload_image():
    if request.method == 'POST':
        if request.files:
            file = request.files['file']

            if file.filename == "":
                print("The file should have a filename")
                return redirect(request.url)

            if not allowed_file(file.filename):
                print("The file extension is not allowed")
                return redirect(request.url)
            else:
                if txtfile(file.filename):
                    file.filename = 'sample.txt'
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    return redirect('/headerresult')
                else:
                    file.filename = 'sample.txt'
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    return redirect('/headerresult')

    return render_template('test.html')

@app.route('/headerresult')
def result1():
   seh = sender_host()
   reh = received_host()
   hop = no_of_hops()
   protu = protocol_used()
   timst = time_stamp()
   sumry = call_summary()
   othehe = combine_Xh_and_Oh()
   return render_template('result1.html', no_of_hop=hop,sender_result=seh,received_result=reh,proto_used=protu,timestamp_result=timst,
   summary_result=sumry,otherheaders_result=othehe)

@app.route('/ipinfo')
def result2():
   mip = ip_info(extract_ip())
   noi = extract_ip()
   return render_template('result2.html',allips=noi,malipinfo=mip)

@app.route('/portinfo')
def result3():
   ipi = port_result()
   return render_template('result3.html',ipportscan=ipi)

@app.route('/urlinfo')
def result4():
   murl=url_info(extract_url())
   nou= extract_url()
   return render_template('result4.html',allurl=nou,malurlinfo=murl)

@app.route('/domaininfo')
def result5():
   mdomain=domain_info(extract_domain())
   nod= extract_domain()
   return render_template('result5.html',alldomain=nod,maldomaininfo=mdomain)

@app.route('/ippass')
def result6():
   ippass = ip_passivedns(ip_info(extract_ip()))
   return render_template('result6.html',ippassive=ippass)

@app.route('/whoisinfo')
def result7():
   whoisifo = whoisdata()
   return render_template('result7.html',whois_data=whoisifo)

if __name__ == '__main__':
   app.run(debug = True)

