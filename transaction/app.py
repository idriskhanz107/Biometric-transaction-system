from flask import Flask, render_template, request, redirect, url_for, flash
from flask import Flask, render_template, request, redirect, session, g
import os
import cv2
import numpy as np
import sqlite3
import os
import hashlib
import json
import datetime
import os
from werkzeug.utils import secure_filename

from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import io



app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'


app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MODEL_FOLDER'] = 'models'

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

DATABASE = 'transactions.db'


def initialize_globals():
    g.my_variable = 0

# Register the function to run before the first request
@app.before_request
def before_request():
    initialize_globals()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
# Function to encrypt an image
def encrypt_image(image_path, key):
    # Open the image file
    with open(image_path, 'rb') as f:
        image_bytes = f.read()

    # Encrypt the image bytes
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.iv + cipher.encrypt(pad(image_bytes, AES.block_size))
    

    return encrypted_data

# Function to decrypt an image
def decrypt_image(encrypted_data, key):
    # Extract the initialization vector from the encrypted data
    iv = encrypted_data[:AES.block_size]
    encrypted_data = encrypted_data[AES.block_size:]

    # Decrypt the image bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    return decrypted_data

# Initialize SQLite database
def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE,
                        fname TEXT,
                        bal TEXT,
                        pinno TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER,
                        filename TEXT,
                        file_path TEXT,
                        timestamp TEXT,
                        hash TEXT,
                        key TEXT,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS blockchain (
                        block_index INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        previous_hash TEXT,
                        transactions TEXT,
                        nonce INTEGER
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS shared_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_id INTEGER,
                        recipient_id INTEGER,
                        FOREIGN KEY (file_id) REFERENCES files(id),
                        FOREIGN KEY (recipient_id) REFERENCES users(id)
                    )''')
        db.commit()

# Initialize database when the application starts
init_db()

def hash_block(block):
    return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

def create_genesis_block():
    return {
        'index': 0,
        'timestamp': str(datetime.datetime.now()),
        'previous_hash': '0',
        'transactions': [],
        'nonce': 0
    }

def proof_of_work(block):
    while True:
        block_hash = hash_block(block)
        if block_hash[:4] == '0000':
            return block_hash
        else:
            block['nonce'] += 1

def create_block(prev_block_hash, transactions):
    block = {
        'index': len(get_blockchain()),
        'timestamp': str(datetime.datetime.now()),
        'previous_hash': prev_block_hash,
        'transactions': transactions,
        'nonce': 0
    }
    proof_of_work(block)
    return block

def add_block(block):
    db = get_db()
    c = db.cursor()
    c.execute('''INSERT INTO blockchain (timestamp, previous_hash, transactions, nonce)
                 VALUES (?, ?, ?, ?)''', (block['timestamp'], block['previous_hash'], json.dumps(block['transactions']), block['nonce']))
    db.commit()

def get_blockchain():
    db = get_db()
    c = db.cursor()
    c.execute('''SELECT * FROM blockchain ORDER BY block_index ASC''')
    return c.fetchall()

# Function to check if a filename has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


    
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return redirect('/login')

    file = request.form['file']
    print(file)
    filename = int(file)
    print(filename)
    reciever=request.form['recipient']
    pc=request.form['pc']
    file_hash = hashlib.sha256(b"test").hexdigest()

    # Retrieve user id from session
    db = get_db()
    c = db.cursor()
    c.execute('''SELECT id,bal,pinno FROM users WHERE username = ?''', (session['username'],))
    data = c.fetchall()
    print(data[0])
    udata=data[0]
    uid=udata[0]
    bal=int(udata[1])
    pin=udata[2]
    if(pin==pc):
        if(bal>filename):
            c.execute('''INSERT INTO files (user_id, filename, file_path, timestamp, hash,key)VALUES (?, ?, ?, ?, ?,?)''', (reciever, filename, filename, str(datetime.datetime.now()), file_hash,file))
            db.commit()
            transaction = {
                'user_id': reciever,
                'transaction': filename,
                'timestamp': str(datetime.datetime.now()),
                'transaction_hash': file_hash
                }
            prev_block_hash = get_blockchain()[-1][2] if get_blockchain() else '0'
            block = create_block(prev_block_hash, [transaction])
            add_block(block)
            print("Transaction Successfull")
            #global ts
            g.my_variable=1
            return redirect(url_for('upload_file1', value="Transaction Successfull"))
        else:
            #global ts
            g.my_variable=2
            print("Low Balance")
            return redirect(url_for('upload_file1', value="Low Balance"))
        
    else:
        #global ts
        g.my_variable=3
        print("Transaction not Successfull")
        return redirect(url_for('upload_file1', value="Invalid Pin No"))

    return redirect('/upload1')



@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']

        db = get_db()
        c = db.cursor()
        c.execute('''SELECT * FROM users WHERE username = ? ''', (username))
        user = c.fetchone()
        if user:
            session['username'] = username
            session['fname'] = user[2]
            print(user[2])
            print(session['fname'])
            g.my_variable=0
            return redirect('/up')
        else:
            return render_template('login.html', message='Invalid username or password')
    return render_template('login.html', message='')


# Function to fetch shared files
def get_shared_files():
    db = get_db()
    c = db.cursor()
    c.execute('''SELECT files.id,files.filename, users.username, files.timestamp, files.hash,files.key
                 FROM files
                 INNER JOIN users ON files.user_id = users.id''')
    result = c.fetchall()
    #print(result)  # Debugging
    return result

# Route to display shared files
@app.route('/shared_files')
def shared_files():
    if 'username' not in session:
        return redirect('/login')
    
    files = get_shared_files()
    #print(files)  # Debugging
    return render_template('shared_files.html', files=files)


# Function to fetch blockchain details
def get_blockchain_details():
    db = get_db()
    c = db.cursor()
    c.execute('''SELECT * FROM blockchain''')
    return c.fetchall()

# Route to display blockchain details
@app.route('/blockchain_details')
def blockchain_details():
    if 'username' not in session:
        return redirect('/login')
    
    blockchain = get_blockchain_details()
    return render_template('blockchain_details.html', blockchain=blockchain)

def get_users():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT * FROM users')
    users = c.fetchall()
    #print(users)  # Debugging
    return users


# Function to fetch user id by username
def get_user_id(username):
    db = get_db()
    c = db.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if user:
        return user[0]
    return None

@app.route('/up')
def index1():
    ts=g.my_variable
    if ts==0:
        ts=0
        print(ts)
        return redirect(url_for('upload_file1', value=""))
    if ts==1:
        print(ts)
        return redirect(url_for('upload_file1', value="Transaction Successfull"))
    if ts==2:
        print(ts)
        return redirect(url_for('upload_file1', value="Transaction Not Successfull due to Balance"))
    if ts==3:
        print(ts)
        return redirect(url_for('upload_file1', value="Transaction Not Successfull due to PIN No"))

@app.route('/readfids')
def rfid():
    users = get_users()
    import time
    import serial
    SerialPort = serial.Serial("COM6", baudrate=9600, timeout=1)
    time.sleep(4)
    GDATA=''
    while(GDATA==''):
        GDATA=SerialPort.readline().decode()
        print("waiting for finger")
        print(GDATA)
        
        time.sleep(0.5)
    return render_template('upload.html', users=users,fid=GDATA)

@app.route('/readfids1')
def rfid1():
    #users = get_users()
    import time
    import serial
    SerialPort = serial.Serial("COM6", baudrate=9600, timeout=1)
    time.sleep(4)
    GDATA=''
    while(GDATA==''):
        GDATA=SerialPort.readline().decode()
        print("waiting for finger")
        print(GDATA)
        
        time.sleep(0.5)
    return render_template('login.html', fids=GDATA)

@app.route('/readfids2')
def rfid2():
    #users = get_users()
    import time
    import serial
    SerialPort = serial.Serial("COM6", baudrate=9600, timeout=1)
    time.sleep(4)
    GDATA=''
    while(GDATA==''):
        GDATA=SerialPort.readline().decode()
        print("waiting for finger")
        print(GDATA)
        
        time.sleep(0.5)
    return render_template('register.html', fids=GDATA)
    

@app.route('/upload1', methods=['GET', 'POST'])
def upload_file1():
    usd=session['fname']
    print(usd)
    if 'username' not in session:
        return redirect('/login')

    users = get_users()

    if request.method == 'POST':
        file = request.form['file']
        reciever=request.form['recipient']
        filename = reciever
        
        
        

        # Calculate hash of the file
        with open(file_path, 'rb') as f:
            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()

        # Retrieve user id from session
        user_id = get_user_id(session['username'])

        # Save file info to database
        db = get_db()
        c = db.cursor()
        
        #encrypted_data = encrypt_image(file_path, key)
        #print(encrypted_data)
        c.execute('''INSERT INTO files (user_id, filename, file_path, timestamp, hash)
                     VALUES (?, ?, ?, ?, ?)''', (user_id, encrypted_data, file_path, str(datetime.datetime.now()), file_hash))
        db.commit()

        # Share file with selected recipients
        recipients = request.form.getlist('recipients')
        for recipient_id in recipients:
            c.execute('''INSERT INTO shared_files (file_id, recipient_id) VALUES (?, ?)''', (c.lastrowid, recipient_id))
            db.commit()

        #return redirect('/')
        

    return render_template('upload.html', users=users,usd=usd)

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'username' not in session:
        return redirect('/login')

    # Fetch file path from the database using file_id
    db = get_db()
    c = db.cursor()
    c.execute('''SELECT file_path FROM files WHERE id = ?''', (file_id,))
    file_path = c.fetchone()[0]

    # Serve the file for download
    return send_file(file_path, as_attachment=True)


@app.route('/shared_files1')
def shared_files1():
    # Check if user is logged in
    if 'username' not in session:
        return redirect('/login')

    # Get user ID of the current user
    user_id = get_user_id(session['username'])
    if user_id is None:
        # Redirect to login if user ID not found
        return redirect('/login')

    try:
        # Fetch shared files for the current user
        db = get_db()
        c = db.cursor()
        c.execute('''SELECT files.id, files.filename 
                     FROM files 
                     INNER JOIN shared_files ON files.id = shared_files.file_id 
                     WHERE shared_files.recipient_id = ?''', (user_id,))
        shared_files = c.fetchall()
        db.close()

        # Log shared files
        app.logger.info(f"Shared files for user {session['username']}: {shared_files}")

        return render_template('shared_files.html', shared_files=shared_files)
    except Exception as e:
        # Log and handle exceptions
        app.logger.error(f"Error fetching shared files: {e}")
        return "An error occurred while fetching shared files. Please try again later."


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        fname = request.form['fname']
        bal = request.form['bal']
        pc = request.form['pc']
        db = get_db()
        c = db.cursor()
        c.execute('''INSERT INTO users (username, fname,bal,pinno) VALUES (?, ?,?,?)''', (username, fname,bal,pc))
        db.commit()
        return redirect('/')
    return render_template('register.html')


@app.route('/file_sharing')
def file_sharing():
    return render_template('upload.html')


@app.route('/test')
def test():
    return render_template('home.html')


if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True,host="0.0.0.0")


