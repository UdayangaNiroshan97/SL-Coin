from flask import Flask ,jsonify, render_template ,request
from flask_cors import CORS
from time import time
from collections import OrderedDict
import binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import json
import hashlib
import requests
from urllib.parse import urlparse

class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.COUNT_TX = 0

        #create the genesis block
        self.create_block('00')

    #register node
    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    #block create
    def create_block(self,previous_hash):
        block = {'block_number': len(self.chain) + 1,
                 'timestamp': time(),
                 'transactions': self.transactions,
                 'previous_hash': previous_hash}

        self.transactions = []
        self.chain.append(block)
        return block

    #transaction user authentication
    def verify_transaction_signature(self, sender_public_key, signature, transaction):
        public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    #hash value genarate
    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()

    #block chain resolve conflicts
    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            try:
                response = requests.get('http://' + node + '/chain2')

                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except:
                continue

        if new_chain:
            self.chain = new_chain
            return True

        return False

    #check blockchain validity
    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            if block['previous_hash'] != self.hash(last_block):
                return False

            last_block = block
            current_index += 1

        return True

    #submit transaction to transaction list
    def submit_buy_transaction(self,sender_public_key,recipient_public_key,signature,amount):
        transaction = OrderedDict({'sender_public_key': sender_public_key,
                                   'recipient_public_key': recipient_public_key,
                                   'amount': amount})
        signature_verification=self.verify_transaction_signature(recipient_public_key, signature, transaction)
        if signature_verification:
            self.COUNT_TX +=1
            self.transactions.append(transaction)
            if self.COUNT_TX >0:
                last_block = self.chain[-1]
                previous_hash = self.hash(last_block)
                self.resolve_conflicts()
                block = self.create_block(previous_hash)
                for node in self.nodes:
                    try:
                        resolve_node = requests.get('http://' + node + '/nodes/resolve2')
                    except:
                        continue
                self.COUNT_TX = 0

            return len(self.chain)
        else:
            return False

    # submit transaction to transaction list
    def submit_transaction(self,sender_public_key,recipient_public_key,signature,amount):
        transaction = OrderedDict({'sender_public_key': sender_public_key,
                                   'recipient_public_key': recipient_public_key,
                                   'amount': amount})
        signature_verification=self.verify_transaction_signature(sender_public_key, signature, transaction)
        if signature_verification:
            self.COUNT_TX +=1
            self.transactions.append(transaction)
            if self.COUNT_TX >0:
                last_block = self.chain[-1]
                previous_hash = self.hash(last_block)
                self.resolve_conflicts()
                block = self.create_block( previous_hash)
                for node in self.nodes:
                    try:
                        resolve_node = requests.get('http://' + node + '/nodes/resolve2')
                    except:
                        continue
                self.COUNT_TX = 0

            return len(self.chain)
        else:
            return False


# instantiate the blockchain
blockchain = Blockchain()

app = Flask(__name__,template_folder='template')
CORS(app,supports_credentials=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/configure')
def configure():
    return render_template('configure.html')

@app.route('/transactions/get',methods=['GET'])
def get_transaction():
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200

@app.route('/chain2', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/add_coin', methods=['POST'])
def add_coin():
    values = request.form
    transaction_results = blockchain.submit_buy_transaction('BPSC WALLET',
                                                        values['buy_recipient_public_key'],
                                                        values['buy_signature'],
                                                        values['buy_amount'])
    if transaction_results == False:
        response = {'message': 'Invalid transaction/Signature'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to the block' + str(transaction_results)}
        return jsonify(response), 201

@app.route('/add_recover_balance', methods=['POST'])
def add_recover_balance():
    values = request.form
    transaction_results = blockchain.submit_buy_transaction(values['recover_public_key'],
                                                        values['public_key'],
                                                        values['recover_signature'],
                                                        values['recover_balance'])
    if transaction_results == False:
        response = {'message': 'Invalid transaction/Signature'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to the block' + str(transaction_results)}
        return jsonify(response), 201


@app.route('/transactions/new',methods=['POST'])
def new_transaction():
    values = request.form

    transaction_results = blockchain.submit_transaction(values['confirmation_sender_public_key'],
                                                        values['confirmation_recipient_public_key'],
                                                        values['transaction_signature'],
                                                        values['confirmation_amount'])
    if transaction_results == False :
        response = {'message':'Invalid transaction/Signature'}
        return jsonify(response),406
    else:
        response =  {'message':'Transaction will be added to the block'+str(transaction_results)}
        return jsonify(response),201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain,
        }
    return jsonify(response), 200

@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201

def configure_nodes():
    blockchain.register_node('127.0.0.1:5002')
    data = {'nodes': '127.0.0.1:' + str(port)}
    try:
        requests.post(url='http://127.0.0.1:5002/nodes/register', data=data)
        response = requests.get(url='http://127.0.0.1:5002/nodes/get')
        for node in response.json()['nodes']:
            if node == '127.0.0.1:' + str(port):
                continue
            elif node == '127.0.0.1:5000':
                continue
            else:
                blockchain.register_node(node)
        for node in blockchain.nodes:
            if node == '127.0.0.1:' + str(port):
                continue
            elif node == '127.0.0.1:5000':
                continue
            else:
                try:
                    requests.post(url='http://' + str(node) + '/nodes/register', data=data)
                except:
                    continue
    except:
        pass

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port
    app.secret_key = "secret123"
    configure_nodes()
    app.run(host='127.0.0.1', port=port, debug=True)
