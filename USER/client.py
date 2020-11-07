from collections import OrderedDict
from flask import Flask, jsonify, render_template, flash, redirect, url_for, request, session
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from passlib.hash import sha256_crypt
import binascii
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from flask_mysqldb import MySQL
from USER.appfun import *
from USER.forms import *
from functools import wraps

from datetime import timedelta

class Transaction:

    def __init__(self,sender_public_key,sender_private_key,recipient_public_key,amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount

    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount,
        })

    def sign_transaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    def key_verify(self):
        try:
            private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
            public_key = private_key.publickey()
            key = binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
            if key == self.sender_public_key:
                return True
            else:
                return False
        except ValueError:
            return False

    def recipient_key_verify(self):
        users = Table("users","username", "password", "public_key")
        user = users.getone("public_key", self.recipient_public_key)
        public_key = user.get('public_key')
        if public_key is None:
            return False
        else:
            return True


app = Flask(__name__,template_folder='template')
app.permanent_session_lifetime = timedelta(minutes=10)
app.secret_key = "secret"
app.config['MYSQL_HOST'] = 'localhost'

app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ""
app.config['MYSQL_DB'] = 'slcoin'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql_app = MySQL(app)

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return wrap

def is_logged_out(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            flash('You are already logged in.', 'danger')
            return redirect(url_for('dashboard'))
        else:
            return f(*args, **kwargs)
    return wrap

def log_in_user(username):
    users = Table("users","username", "password","public_key")
    user = users.getone('username', username)
    session['logged_in'] = True
    session['username'] = username
    session['public_key'] = user.get('public_key')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/key_wraning')
@is_logged_out
def key_wraning():
    return render_template('key_wraning.html')

@app.route('/register',methods=['GET','POST'])
@is_logged_out
def register():

    form = RegisterForm(request.form)
    users = Table("users","username","password","public_key")

    if request.method == 'POST' and form.validate():
        username = form.username.data
        public_key = form.public_key.data

        if isnewuser(username):
            password = sha256_crypt.encrypt(form.password.data)
            users.insert(username,password,public_key)
            log_in_user(username)
            return redirect(url_for('dashboard'))
        else:
            flash('User already exists', 'danger')
            return redirect(url_for('register'))
    if request.method == 'POST' and not form.validate():
        err=[]
        if len(form.username.errors) > 0:
            for i in range(len(form.username.errors)):
                err.append("username " + form.username.errors[i])
        if len(form.password.errors) > 0:
            for i in range(len(form.password.errors)):
                err.append("password " + form.password.errors[i])
        if len(form.confirm.errors) > 0:
            for i in range(len(form.confirm.errors)):
                err.append("confirm password " + form.confirm.errors[i])
        for i in range(len(err)):
            flash(err[i], 'danger')
    return render_template('register.html', form=form)

@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html',session = session)

@app.route("/login", methods=['GET','POST'])
@is_logged_out
def login():
    if request.method == 'POST':
        username = request.form['username']
        candidate = request.form['password']
        session.permanent = True
        users = Table("users","username","password","public_key")
        user = users.getone("username", username)
        accPass = user.get('password')

        if accPass is None:
            flash('Username "%s" not found.' %username,'danger')
            return redirect(url_for('login'))
        else:
            if sha256_crypt.verify(candidate, accPass):
                try:
                    private_key = RSA.importKey(binascii.unhexlify(request.form['private_key']))
                    public_key_gen = private_key.publickey()
                    public_key_gen2 = binascii.hexlify(public_key_gen.exportKey(format='DER')).decode('ascii')
                    if user.get('public_key') == public_key_gen2:
                        log_in_user(username)
                        return redirect(url_for('dashboard'))
                    else:
                        flash('Invalid private key.', 'danger')
                        return redirect(url_for('login'))
                except ValueError:
                    flash('Invalid private key.', 'danger')
                    return redirect(url_for('login'))
            else:
                flash('Invalid password.','danger')
                return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    flash('You have now logged out.','success')
    return redirect(url_for('login'))

@app.route('/transaction')
@is_logged_in
def transaction():
    return render_template('transaction.html',session = session)

@app.route('/buy')
@is_logged_in
def buy():
    return render_template('buy.html',session = session)

@app.route('/about')
@is_logged_in
def about():
    return render_template('About.html')

@app.route('/backup', methods=['GET','POST'])
@is_logged_in
def backup():
    return render_template('backup.html',session = session)

@app.route('/confirm_backup_key', methods=['POST'])
@is_logged_in
def confirm_backup_key():
    form = backupForm(request.form)
    if request.method == 'POST' and form.validate():
        recover_keys = Table("recover", "public_key","recover_public_key")
        recover_key = recover_keys.getone("public_key", form.backup_public_key.data)

        if recover_key.get('public_key') is None:
            try:
                private_key = RSA.importKey(binascii.unhexlify(form.backup_private_key.data))
                public_key_gen = private_key.publickey()
                public_key_gen2 = binascii.hexlify(public_key_gen.exportKey(format='DER')).decode('ascii')
                if form.backup_public_key.data == public_key_gen2:
                    key = RSA.importKey(binascii.unhexlify(form.backup_key.data))
                    key_gen = key.publickey()
                    key_gen2 = binascii.hexlify(key_gen.exportKey(format='DER')).decode('ascii')
                    recover_keys.insert(form.backup_public_key.data,key_gen2)
                    response = {'form': True,
                                'key_issue': True,
                                'private_key': True,
                                }
                else:
                    response = {'form': True,
                                'key_issue': True,
                                'private_key': False
                                }
            except ValueError:
                response = {'form': True,
                            'key_issue': True,
                            'private_key':False
                            }
        else:
            response = {'form': True,
                        'key_issue':False,
                        }
    else:
        response = {'form': False,
                    }
    return jsonify(response), 200

@app.route('/recover')
@is_logged_in
def recover():
    return render_template('recover.html')


@app.route('/buy_coin',methods=['POST'])
def buy_coin():
    form = BuyForm(request.form)

    if request.method == 'POST' and form.validate():
        transaction = Transaction("BPSC wallet", form.my_private_key.data,form.my_public_key.data, form.amount.data)
        try:
            private_key = RSA.importKey(binascii.unhexlify(form.my_private_key.data))
            public_key = private_key.publickey()
            key = binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
            if key == form.my_public_key.data:
                response = {'transaction': transaction.to_dict(),
                            'signature': transaction.sign_transaction(),
                            'key_verify': True,
                            'BuyForm': True,
                            }
            else:
                response = {'key_verify': False,
                            'BuyForm': True,
                            }
        except ValueError:
            response = {'key_verify': False,
                        'BuyForm': True,
                        }
    else:
        response = {'key_verify': False,
                    'BuyForm': False,
                    }

    return jsonify(response), 200


@app.route('/recover_account',methods=['POST'])
def recover_account():
    form = recoverform(request.form)
    if request.method == 'POST' and form.validate():
        try:
            private_key = RSA.importKey(binascii.unhexlify(form.new_private_key.data))
            public_key = private_key.publickey()
            key = binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
            if key == form.new_public_key.data:
                privatekey = True
            else:
                privatekey = False
        except ValueError:
            privatekey = False

        recover_keys = Table("recover", "public_key", "recover_public_key")
        recover_key = recover_keys.getone("public_key", form.old_public_key.data)
        if recover_key.get('public_key') is None:
            old_public_key = False
        else:
            old_public_key = True

        try:
            recover_key = RSA.importKey(binascii.unhexlify(form.recover_key.data))
            recoverpublic_key = recover_key.publickey()
            gen_recover_public_key = binascii.hexlify(recoverpublic_key.exportKey(format='DER')).decode('ascii')
            recover_key = recover_keys.getone("public_key", form.old_public_key.data)
            if gen_recover_public_key == recover_key.get('recover_public_key'):
                recoverkey = True
            else:
                recoverkey = False
        except ValueError:
            recoverkey = False

        if privatekey == True and old_public_key == True and recoverkey ==True:
            transaction = Transaction(form.old_public_key.data, form.new_private_key.data, form.new_public_key.data, request.form['balance'])

            response = {'transaction': transaction.to_dict(),
                        'signature': transaction.sign_transaction(),
                        'recover_form': True,
                        'privatekey': privatekey,
                        'old_public_key': old_public_key,
                        'recoverkey': recoverkey,
                        }
            users = Table("users","username", "password", "public_key")
            # user = users.deleteone("public_key", form.old_public_key.data)
            # recover_key = recover_keys.deleteone("public_key", form.old_public_key.data)
            return jsonify(response), 200

        response = {'recover_form': True,
                    'privatekey' :privatekey,
                    'old_public_key':old_public_key,
                    'recoverkey':recoverkey,
                    }
    else:
        response = {'recover_form': False,
                }
    return jsonify(response), 200
@app.route('/generate/transaction',methods=['POST'])
def generate_transaction():
    form = TransactionForm(request.form)

    if request.method == 'POST' and form.validate():
        transaction = Transaction(form.sender_public_key.data, form.sender_private_key.data, form.recipient_public_key.data, form.amount.data)
        if transaction.key_verify():
            if transaction.recipient_key_verify():
                response = {'transaction': transaction.to_dict(),
                            'signature': transaction.sign_transaction(),
                            'recipient_key_verify': True,
                            'key_verify': True,
                            'TransactionForm': True,
                            }
            else:
                response = {'recipient_key_verify': False,
                            'TransactionForm': True,
                            'key_verify': True,
                            }
        else:
            if transaction.recipient_key_verify():
                response = {'recipient_key_verify': True,
                            'key_verify': False,
                            'TransactionForm': True,
                            }
            else:
                response = {'recipient_key_verify': False,
                            'TransactionForm': True,
                            'key_verify': False,
                            }
    else:
        response = {'TransactionForm': False,
                }

    return jsonify(response), 200

@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii'),
    }

    return jsonify(response), 200

@app.route('/qrcode')
def qrcode():
    response = {
        'private_key': "aaaaaaa",
    }

    return jsonify(response), 200

def database():
    try:
        create_db_connection('localhost', 'root', "", 'slcoin')
    except:
        print("check database connection.")

if __name__ =='__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5005, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port
    database()
    app.run(host='127.0.0.1', port=port, debug=True)
