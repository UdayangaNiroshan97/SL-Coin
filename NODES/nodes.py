from flask import Flask ,jsonify, render_template ,request
from flask_cors import CORS,cross_origin
from time import time
from collections import OrderedDict
import binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse


class Blockchain:

    def __init__(self):
        self.chain = []
        self.chain2 = []
        self.current_information = []
        self.chain3 = []
        self.nodes = set()

    #register nodes
    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    #hash value genarate
    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()

    #resolve conflicts
    def resolve_conflicts(self,chain_no):
        neighbours = self.nodes
        new_chain = None

        if chain_no == '1':

            max_length = len(self.chain)

            for node in neighbours:
                if node == '127.0.0.1:5001':
                    continue
                else:
                    try:
                        response = requests.get('http://' + node + '/chain')

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

        elif chain_no == '2':
            max_length = len(self.chain2)

            for node in neighbours:
                if node == '127.0.0.1:5000':
                    continue
                else:
                    try:
                        response = requests.get('http://' + node + '/chain2')

                        if response.status_code == 200:
                            length = response.json()['length']
                            chain2 = response.json()['chain']

                            if length > max_length and self.valid_chain(chain2):
                                max_length = length
                                new_chain = chain2
                    except:
                        continue

            if new_chain:
                self.chain2 = new_chain
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

    def new_information(self, information):
        self.current_information.append({'information': information })

    def new_block(self, previous_hash):
        block = {
            'index2': len(self.chain2) + 1,
            'timestamp': time(),
            'information': self.current_information,
            'previous_hash': previous_hash or self.hash(self.chain2[-1]),
        }

        # Reset the current list of transactions
        self.current_information = []

        self.chain2.append(block)
        return block


# instantiate the blockchain
blockchain = Blockchain()

# instantiate the node
app = Flask(__name__,template_folder='template')
CORS(app,supports_credentials=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/configure')
def configure():
    return render_template('configure.html')

@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/chain2', methods=['GET'])
def get_chain2():
    response = {
        'chain': blockchain.chain2,
        'length': len(blockchain.chain2),
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.chain3[-1]

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(previous_hash)

    response = {
        'message': "New Block Forged",
        'index2': block['index2'],
        'information': block['information'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/information/new', methods=['POST'])
def new_information():
    values = request.get_json()

    required = ['information']
    if not all(k in values for k in required):
        return 'Missing values', 400

    index = blockchain.new_information(values['information'])

    response = {'message': f'information will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts('1')

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

@app.route('/nodes/resolve2', methods=['GET'])
def consensus2():
    replaced = blockchain.resolve_conflicts('2')

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain2
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain2,
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
    if str(port) == '5002':
        pass
    else:
        blockchain.register_node('127.0.0.1:5002')
        try:
            data = {'nodes': '127.0.0.1:' + str(port)}
            requests.post(url='http://127.0.0.1:5002/nodes/register', data=data)
            response = requests.get(url='http://127.0.0.1:5002/nodes/get')
            for node in response.json()['nodes']:
                if node == '127.0.0.1:' + str(port):
                    continue
                else:
                    blockchain.register_node(node)
            for node in blockchain.nodes:
                if node == '127.0.0.1:' + str(port):
                    continue
                else:
                    try:
                        requests.post(url='http://' + str(node) + '/nodes/register', data=data)
                    except:
                        continue
        except:
            pass

    blockchain.resolve_conflicts('1')
    blockchain.resolve_conflicts('2')

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5002, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port
    app.secret_key = "secret123"
    configure_nodes()
    app.run(host='127.0.0.1', port=port, debug=True)

