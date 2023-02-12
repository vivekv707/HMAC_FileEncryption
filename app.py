from flask import Flask,render_template,request,send_file
from cryptography.fernet import Fernet
import hmac
import hashlib
import io
import os



app = Flask(__name__)

@app.route('/',methods=['GET','POST'])
def index():
    if request.method == "POST":
        file = request.files['file']
        key = Fernet.generate_key()
        f = Fernet(key)
        data = file.read()
        ext = file.filename
        ext = ext.split('.')[1]
        name = "test_enc."
        name += ext
        enc = f.encrypt(data)
        with open(name, "wb") as fo:
            fo.write(enc) 
        
        digest_maker = hmac.new(key, enc, hashlib.sha256)
        second_digest_maker =  hmac.new(key,digest_maker.hexdigest().encode('utf-8'),hashlib.sha256)
        authcode = second_digest_maker.hexdigest()
        print(authcode)
        key = key.decode()
        return render_template('index.html',key=key,filename=name,hmacauth =authcode)
    else:
        return render_template('index.html',key="",filename="",hmacauth ="")

@app.route('/download/<filename>')
def download(filename):
    
    return_data = io.BytesIO()
    try:
        with open(filename, "rb") as fo:
            return_data.write(fo.read())
        return_data.seek(0)
    except:
        return render_template('index.html',error='You can download the file only once as they are not saved on the server')
    name = filename
    os.remove(filename)
    return send_file(return_data,mimetype='txt',as_attachment=True,download_name=name)


@app.route('/decrypt',methods=['GET','POST'])
def decrypt():
    if request.method == "POST":
        key = request.form['key']
        authcode = request.form['authcode']
        try:
            f = Fernet(key)
        except:
            return render_template('decrypt.html',error='Incorrect Key')
        file = request.files['file']
        ext = file.filename
        ext = ext.split('.')[1]
        name = 'test_dec.'
        name += ext
        data = file.read()
        digest_maker = hmac.new(key.encode('utf-8'), data, hashlib.sha256)
        second_digest_maker =  hmac.new(key.encode('utf-8'),digest_maker.hexdigest().encode('utf-8'),hashlib.sha256)
        authcodegen = second_digest_maker.hexdigest()
        integrity = False
        if authcode == authcodegen:
            integrity = True

        if integrity:
            with open(name, "wb") as fo:
                fo.write(f.decrypt(data)) 
            return render_template('decrypt.html',filename=name,integrity='Data integrity verified')
        else:
            return render_template('decrypt.html',error='Data Tampered')
        
    return render_template('decrypt.html')


    

if __name__ == "__main__":
    app.run(debug=True)