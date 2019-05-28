import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import requests
from flask import Flask, jsonify, request
from hashlib import sha256
from threading import Thread
from time import sleep
import random
import secrets
import codecs
import keys
import curves
"""
Difficulty level : new_difficulty = old_difficulty X (2016 blocks X 10 minutes) / (the time took in minutes to mine the last 2016 blocks)
"""

# created at 5001
class BitcoinWallet:
    def __init__(self):
        self.POOL_SIZE = 256
        self.KEY_BYTES = 32
        self.CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)
        self.pool = [0] * self.POOL_SIZE
        self.pool_pointer = 0
        self.prng_state = None
        self.__init_pool()
        # FROM HERE ARE ADDED BY MÜRPHY
        self.private_key = 0
        self.address = 0
        self.public_key = 0
        self.bitcoin_left = 0
        
    @staticmethod
    def generate_address(self, private_key):
        public_key = BitcoinWallet.__private_to_public(private_key)
        address = BitcoinWallet.__public_to_address(public_key)
        self.public_key = public_key.decode("utf-8")
        return address
        
    @staticmethod
    def generate_compressed_address(private_key):
        public_key = BitcoinWallet.__private_to_compressed_public(private_key)
        address = BitcoinWallet.__public_to_address(public_key)
        return address
    
    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        # Get ECDSA public key
        key = keys.SigningKey.from_string(private_key_bytes, curve=curves.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Add bitcoin byte
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
        return public_key
    
    @staticmethod
    def __private_to_compressed_public(private_key):
        private_hex = codecs.decode(private_key, 'hex')
        # Get ECDSA public key
        key = ecdsa.SigningKey.from_string(private_hex, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Get X from the key (first half)
        key_string = key_hex.decode('utf-8')
        half_len = len(key_hex) // 2
        key_half = key_hex[:half_len]
        # Add bitcoin byte: 0x02 if the last digit is even, 0x03 if the last digit is odd
        last_byte = int(key_string[-1], 16)
        bitcoin_byte = b'02' if last_byte % 2 == 0 else b'03'
        public_key = bitcoin_byte + key_half
        return public_key
    
    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        # Run ripemd160 for the SHA256
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        # Add network byte
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
        # Double SHA256 to get checksum
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        # Concatenate public key and checksum to get the address
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        # Get the number of leading zeros and convert hex to decimal
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        # Convert hex to decimal
        address_int = int(address_hex, 16)
        # Append digits to the start of string
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        # Add '1' for each 2 leading zeros
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string

    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        # Get the number of leading zeros and convert hex to decimal
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        # Convert hex to decimal
        address_int = int(address_hex, 16)
        # Append digits to the start of string
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        # Add '1' for each 2 leading zeros
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string
    
    def seed_input(self, str_input):
        time_int = int(time())
        self.__seed_int(time_int)
        for char in str_input:
            char_code = ord(char)
            self.__seed_byte(char_code)
            
    def generate_key(self):
        big_int = self.__generate_big_int()
        big_int = big_int % (self.CURVE_ORDER - 1) # key < curve order
        big_int = big_int + 1 # key > 0
        key = hex(big_int)[2:]
        # Add leading zeros if the hex key is smaller than 64 chars
        key = key.zfill(self.KEY_BYTES * 2)
        return key

    def __init_pool(self):
        for i in range(self.POOL_SIZE):
            random_byte = secrets.randbits(8)
            self.__seed_byte(random_byte)
        time_int = int(time())
        self.__seed_int(time_int)

    def __seed_int(self, n):
        self.__seed_byte(n)
        self.__seed_byte(n >> 8)
        self.__seed_byte(n >> 16)
        self.__seed_byte(n >> 24)

    def __seed_byte(self, n):
        self.pool[self.pool_pointer] ^= n & 255
        self.pool_pointer += 1
        if self.pool_pointer >= self.POOL_SIZE:
            self.pool_pointer = 0
    
    def __generate_big_int(self):
        if self.prng_state is None:
            seed = int.from_bytes(self.pool, byteorder='big', signed=False)
            random.seed(seed)
            self.prng_state = random.getstate()
        random.setstate(self.prng_state)
        big_int = random.getrandbits(self.KEY_BYTES * 8)
        self.prng_state = random.getstate()
        return big_int

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)
        self.block_timer = 0
        self.difficulty = 3
        self.time_mined = 0
        self.length = 1
        self.target_length = 100
        self.start_time = time()
        self.POOL_SIZE = 256
        self.KEY_BYTES = 32
        self.CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)
        self.pool = [0] * self.POOL_SIZE
        self.pool_pointer = 0
        self.prng_state = None
        self.__init_pool()
        # FROM HERE ARE ADDED BY MÜRPHY
        self.private_key = 0
        self.address = 0
        self.public_key = 0
        self.bitcoin_left = 0
        
    @staticmethod
    def generate_address(self, private_key):
        public_key = self.__private_to_public(private_key)
        address = self.__public_to_address(public_key)
        self.public_key = public_key.decode("utf-8")
        return address
        
    @staticmethod
    def generate_compressed_address(private_key):
        public_key = BitcoinWallet.__private_to_compressed_public(private_key)
        address = BitcoinWallet.__public_to_address(public_key)
        return address
    
    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        # Get ECDSA public key
        key = keys.SigningKey.from_string(private_key_bytes, curve=curves.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Add bitcoin byte
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
        return public_key
    
    @staticmethod
    def __private_to_compressed_public(private_key):
        private_hex = codecs.decode(private_key, 'hex')
        # Get ECDSA public key
        key = ecdsa.SigningKey.from_string(private_hex, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Get X from the key (first half)
        key_string = key_hex.decode('utf-8')
        half_len = len(key_hex) // 2
        key_half = key_hex[:half_len]
        # Add bitcoin byte: 0x02 if the last digit is even, 0x03 if the last digit is odd
        last_byte = int(key_string[-1], 16)
        bitcoin_byte = b'02' if last_byte % 2 == 0 else b'03'
        public_key = bitcoin_byte + key_half
        return public_key
    
    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        # Run ripemd160 for the SHA256
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        # Add network byte
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
        # Double SHA256 to get checksum
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        # Concatenate public key and checksum to get the address
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        # Get the number of leading zeros and convert hex to decimal
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        # Convert hex to decimal
        address_int = int(address_hex, 16)
        # Append digits to the start of string
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        # Add '1' for each 2 leading zeros
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string

    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        # Get the number of leading zeros and convert hex to decimal
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        # Convert hex to decimal
        address_int = int(address_hex, 16)
        # Append digits to the start of string
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        # Add '1' for each 2 leading zeros
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string
    
    def seed_input(self, str_input):
        time_int = int(time())
        self.__seed_int(time_int)
        for char in str_input:
            char_code = ord(char)
            self.__seed_byte(char_code)
            
    def generate_key(self):
        big_int = self.__generate_big_int()
        big_int = big_int % (self.CURVE_ORDER - 1) # key < curve order
        big_int = big_int + 1 # key > 0
        key = hex(big_int)[2:]
        # Add leading zeros if the hex key is smaller than 64 chars
        key = key.zfill(self.KEY_BYTES * 2)
        return key

    def __init_pool(self):
        for i in range(self.POOL_SIZE):
            random_byte = secrets.randbits(8)
            self.__seed_byte(random_byte)
        time_int = int(time())
        self.__seed_int(time_int)

    def __seed_int(self, n):
        self.__seed_byte(n)
        self.__seed_byte(n >> 8)
        self.__seed_byte(n >> 16)
        self.__seed_byte(n >> 24)

    def __seed_byte(self, n):
        self.pool[self.pool_pointer] ^= n & 255
        self.pool_pointer += 1
        if self.pool_pointer >= self.POOL_SIZE:
            self.pool_pointer = 0
    
    def __generate_big_int(self):
        if self.prng_state is None:
            seed = int.from_bytes(self.pool, byteorder='big', signed=False)
            random.seed(seed)
            self.prng_state = random.getstate()
        random.setstate(self.prng_state)
        big_int = random.getrandbits(self.KEY_BYTES * 8)
        self.prng_state = random.getstate()
        return big_int
        
    def addblock_catcher(self):
        starter = time()
        while(1):
            if len(self.chain) != self.length:
                print('\n\n')
                print("")
                self.time_mined = time() - starter
                print("test value \n")
                test = len(self.chain)/self.time_mined
                print(test)
                print('\n mine number : \n')
                print(len(self.chain))
                print('time mined \n')
                print(self.time_mined)
                if (test < 5):
                    self.difficulty += 1
                    print('\n')
                    print('difficulty increasing')
                elif (test > 5):
                    self.difficulty -= 1
                    print('\n')
                    print('decreasing difficulty')
                # Right now difficulty setting isn't working because 
                # measuring the time part ain't working properly I suspect
                # I use average thing so maybe that's an issue..
                # First fix the time thing up there and then worry about minting scheudle
                print('\n')
                print(self.difficulty)
                print('\n')
                #print(self.time_mined)
                print('npnonon')
                print('\n\n')
                #self.difficulty = int(self.difficulty * len(self.chain) * 5000000000 /self.time_mined)
                
                self.length += 1
        

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block) 
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            sleep(1)
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                
                # Check if the length is longer and the chain is valid
#                if length > max_length and self.valid_chain(chain):
                if length > max_length :
   
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            sleep(1)
            return True

        return False
    
    def bring_current_transactions(self):
        #self.register_node('http://0.0.0.0:5004') # first register a static node
        #self.register_node('http://0.0.0.0:5005')
        # need to include node for transaction here
        neighbours = self.nodes
        for node in neighbours:
            sleep(3)
            response = requests.get(f'http://{node}/hear_transaction')
            print(response.json()['current_transactions'])
            self.current_transactions.extend(response.json()['current_transactions'])
            return True
            """
            print(response.json()['current_transactions'][0]['recipient'])
            sender = response.json()['current_transactions'][0]['sender']
            print(type(sender))
        # adds only one the first current_transaction right now
        # Need to fix so that it can include all the current_transactions
        # Need to figure a way out to delete current_transactions that was added somewhere
            if response.status_code == 200:
                sender = response.json()['current_transactions'][0]['sender']
                print(type(sender))
                recipient = response.json()['current_transactions'][0]['recipient']
                amount = response.json()['current_transactions'][0]['amount']
                #self.current_transactions.append({'sender':response.json()[0]['sender'], 'recipient':response.json()[0]['recipient'],
  # 'amount':response.json()[0]['amount']})
                #self.current_transactions.append({'sender':sender,'recipient':recipient,'amount':amount})
                
                # Delete the under line to stop transaction data pushed immeidately
                self.new_transaction(sender, recipient, amount)
                self.delete_current_transactions()
                print('transaction added')
                print('\n')
            """
            
            return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        #guess_hash = sha256(f'{last_proof}{proof}{last_hash}'.encode()).hexdigest()
        #I only need my last_proof
        if (len(self.chain) != 0):
            last_proof = self.chain[-1]['proof']
            previous_hash = previous_hash
            
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
  #      print('\n\n')
#        self.time_mined = time() - self.time_mined
#        print(self.time_mined)
 #       print('\n')
        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1
    
    def hear_sendtransact_answer(self):
        pass
        
    """
    def mine(self):
    # We run the proof of work algorithm to get the next proof...
        last_block = self.last_block
        proof = self.proof_of_work(last_block)
    
        # We must receive a reward for finding the proof.
        # The sender is "0" to signify that this node has mined a new coin.
        self.new_transaction(
            sender="0",
            recipient=node_identifier,
            amount=1,
        )
        last_hash = self.hash(last_block)
        last_proof = last_block['proof']
        previous_hash = sha256(f'{last_proof}{proof}{last_hash}'.encode()).hexdigest()
        # Forge the new Block by adding it to the chain
        previous_hash = self.hash(last_block)
        #guess_hash = sha256(f'{last_proof}{proof}{last_hash}'.encode()).hexdigest()
        if (previous_hash[:3] == "000"):
            block = self.new_block(proof, previous_hash)
    
        response = {
            'message': "New Block Forged",
            'index': block['index'],
            'transactions': block['transactions'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
        }
        return 0
        """
    def mass_mine_self(self):
        
        neighbours = self.nodes
        while (len(self.chain) != self.target_length):
            # We run the proof of work algorithm to get the next proof...
            #delete later
            #sleep(2)
            #delete later
            last_block = self.last_block
            response = self.proof_of_work(last_block)
            print(response)
            proof = response[1]
            #proof = self.proof_of_work(last_block)
            # We must receive a reward for finding the proof.
            # The sender is "0" to signify that this node has mined a new coin.
            self.bring_current_transactions()
            self.new_transaction(
                sender="0",
                recipient=node_identifier,
                amount=1,
            
            )
            
            # Forge the new Block by adding it to the chain
            previous_hash = response[0]
          #  self.bring_current_transactions()
            block = self.new_block(proof, previous_hash)
            for node in neighbours:
                requests.get(f'http://{node}/delete_current_transactions')
                sleep(2)
            if len(self.chain) == self.target_length:
                return 0
            
        #record_time_end = time()
        #record_time = record_time_end - record_time_start
        #print(record_time)
        return 0
        
    def mass_mine_two_withresolve(self): #register 5000 and 5001 node
        self.register_node('http://0.0.0.0:5000') # first register a static node
        self.register_node('http://0.0.0.0:5002')
      #  self.register_node('http://0.0.0.0:5004') # node for adding transactions
        t1 = Thread(target = self.mass_mine_self)
        t2 = Thread(target = self.consensus)
        t3 = Thread(target = self.addblock_catcher)
        t2.start()
        t1.start()
        t3.start()
        #print(list(blockchain.nodes))
      #  self.register_node('http://0.0.0.0:5002')
      #  blockchain.reigster_node('http://0.0.0.0:5003')
       # number = 0
     #   record_time_start = time()
    #    while (number_1 != 200 or number_2 != 200):
        #executor = ThreadPoolExecutor(max_workers = 2)
      #  t1 = Thread(target = self.mass_mine_self)
      #  t2 = Thread(target = self.consensus)
      #  t2.start()
      #  t1.start()
      #  while (len(self.chain) != 20): # number : number of nodes trying to mine
      #      pass
        if len(self.chain) == self.target_length:
            t1.join()
            t2.join()
            t3.join()
        return 1
    
    def consensus(self):
        while (len(self.chain) != self.target_length):
            self.resolve_conflicts()
        
    
    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """  

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        #while self.valid_proof(last_proof, proof, last_hash) is False:
        #    proof += 1
        while sha256(f'{last_proof}{proof}{last_hash}'.encode()).hexdigest()[:self.difficulty] != "00000000000000000000000000000000"[:self.difficulty]:
            proof += 1
#        while self.valid_proof(last_proof, proof, last_hash) is False:
#            proof += 1
        guess_hash = sha256(f'{last_proof}{proof}{last_hash}'.encode()).hexdigest()
        response = [guess_hash, proof]
        print(guess_hash)
        #sleep(1)
        return response
    

    @staticmethod
    def valid_proof(self, last_proof, proof, last_hash):
        """
        Validates the Proof
    
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.
                
        """
    
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
#        return guess_hash[:6] == "000000"
        return guess_hash[:self.difficulty] == "00000000000000000000000000000000"[:self.difficulty]
    
    def send_transaction(self, this_input):
        values = request.get_json()
        sender = 'test_sender'
        recipient = 'test_recipient'
        amount = this_input
        values = {'sender' : sender, 'recipient':recipient, 'amount':amount}
        print("worked here")
        print(values)
        print('\n')
        print(type(values))
        print('\n')
        #index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])
        """
        values comes in as:
        {'sender' : 'youngeun111', 'recipient': 'goeun111', 'amount': 55}
        so it's a dict
        """
        self.new_transaction(values['sender'], values['recipient'], values['amount'])
        #return jsonify(response), 201
        return 0
    
    def delete_current_transactions(self): # delete first value
        del self.current_transactions[:]
        print("deleted")
        return True
        
    def send_msg(self):
        self.register_node('http://0.0.0.0:5004')
        


# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/test_resolve', methods=['GET'])
def test_resolve():
    blockchain.consensus()
    return 0

@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200
"""

Note the 200 after the jsonify(response)/ call. 
This tells Flask that the status code of that page should be 200 which  
by default 200; assumed which translates to: all went well.

"""

# ADDED - BEGIN

@app.route('/mass_mine_self', methods=['GET']) 
def mass_mine_self():
    number = 0    
    record_time_start = time()
    while (number != 200):
        sleep(2)
        # We run the proof of work algorithm to get the next proof...
        last_block = blockchain.last_block
        proof = blockchain.proof_of_work(last_block)
    
        # We must receive a reward for finding the proof.
        # The sender is "0" to signify that this node has mined a new coin.
        blockchain.new_transaction(
            sender="0",
            recipient=node_identifier,
            amount=1,
        )
        
        # Forge the new Block by adding it to the chain
        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof, previous_hash)
        
        response = {
            'message': "New Block Forged",
            'index': block['index'],
            'transactions': block['transactions'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
        }
        number += 1
    record_time_end = time()
    record_time = record_time_end - record_time_start
    print(record_time)
    return jsonify(response), 200

@app.route('/mass_mine_three_nodes', methods=['GET']) 
def mass_mine_three_nodes(): #register 5000 and 5001 node
    blockchain.register_node('http://0.0.0.0:5001') # first register a static node
    #print(list(blockchain.nodes))
    blockchain.register_node('http://0.0.0.0:5002')
    blockchain.reigster_node('http://0.0.0.0:5003')
   # number = 0
    record_time_start = time()
#    while (number_1 != 200 or number_2 != 200):
    while (len(blockchain.chain) < 400): # number : number of nodes trying to mine
        # We run the proof of work algorithm to get the next proof...
        last_block = blockchain.last_block
        proof = blockchain.proof_of_work(last_block)
    
        # We must receive a reward for finding the proof.
        # The sender is "0" to signify that this node has mined a new coin.
        blockchain.new_transaction(
            sender="0",
            recipient=node_identifier,
            amount=1,
        )
        
        # Forge the new Block by adding it to the chain
        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof, previous_hash)
        
        response = {
            'message': "New Block Forged",
            'index': block['index'],
            'transactions': block['transactions'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
        }
        replaced = blockchain.resolve_conflicts()
    #    number += 1
    #    blockchain.resolve_conflicts()
    record_time_end = time()
    record_time = record_time_end - record_time_start
    print(record_time)
    
    return jsonify(response), 200

@app.route('/mass_mine_three_nodes2', methods=['GET'])
def mass_mine_three_nodes2():
    blockchain.mass_mine_two_withresolve()
    return 0


# ADDED - END

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'current transactions' : blockchain.current_transactions,
    }
    return jsonify(response), 200

# ADDED - START

def register_node_specific(url_input):
    values = url_input

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

# ADDED - END

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


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
            'chain': blockchain.chain
        }

    return jsonify(response), 200

@app.route('/bring_current_transactions', methods=['GET'])
def load_current_transcations():
    blockchain.bring_current_transactions()
    
@app.route('/hear_transaction', methods=['GET'])
def hear_transaction():
    response = {
            'chain' : blockchain.chain,
            'current_transactions': blockchain.current_transactions
            #'length': len(blockchain.current_transactions),
            }
    return jsonify(response), 200

@app.route('/send_transactions', methods=['GET'])
def send_transactions():
    this_input = 1
    blockchain.send_transaction(this_input)
    #return jsonify(response), 201
    return 0

@app.route('/hear_sendtransact_answer', methods=['GET'])
def hear_sendtransact_answer():
    blockchain.hear_sendtransact_answer()

@app.route('/delete_current_transactions', methods=['GET'])
def delete_current_transactions():
    blockchain.delete_current_transactions()

@app.route('/send_msg', methods=['GET'])
def send_msg():
    blockchain.send_msg()
    
@app.route('/get_difficulty', methods=['GET'])
def get_difficulty():
    response = { 'difficulty':blockchain.difficulty}
    return jsonify(response), 200

@app.route('/get_private_key', methods=['GET'])
def get_private_key():
    #wallet = BitcoinWallet()
    blockchain.seed_input('Truly random string. I rolled a dice and got 4.')
    blockchain.private_key = blockchain.generate_key()
    print('private key : ')
    print(blockchain.private_key)
    print('\n')
    blockchain.address = blockchain.generate_address(blockchain, blockchain.private_key)
    print('address : ')
    print(blockchain.address)
    print('\n public_key : ')
    print(blockchain.public_key)

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=5001)