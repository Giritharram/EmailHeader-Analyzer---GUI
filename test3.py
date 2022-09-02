import os
from pickle import FALSE
from flask import *
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = ''
app.config['ALLOWED_EXTENSION'] = ['EML','TXT']
app.config['EML_EXTENSION'] = ['EML']
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


@app.route('/test')
def test():
    t = 'hello'
    return t

@app.route('/fileupload', methods=['GET', 'POST'])
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
                    return redirect('/test')
                else:
                    file.filename = 'sample.txt'
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    return redirect('/test')

    return render_template('test.html')



if __name__ == '__main__':
   app.run(debug = True)