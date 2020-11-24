#!/usr/bin/env python3

import argparse
import hashlib
import pickle
import shelve
import sys
import time

import base58
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Util.number import long_to_bytes

# ========================================


class Block:
    def __init__(self, transactions, prev_block_hash, prev_height):
        self.height = prev_height + 1
        self.prev_block_hash = prev_block_hash
        self.time = int(time.time())
        self.bits = 20
        self.transactions = transactions

        POW = ProofOfWork(self)
        nonce, hash_val = POW.run()
        self.hash = hash_val
        self.nonce = nonce

    @classmethod
    def genesis_block(cls, coinbase):
        return cls([coinbase], "", 0)

    def __str__(self):
        D = {"Height": self.height,
             "Prev Block Hash": self.prev_block_hash,
             "Time": self.time,
             "Hash": self.hash,
             "Nonce": self.nonce
             }
        return "\n".join([f"{k}: {v}" for k, v in D.items()])

    def hash_transactions(self):
        data = "".join([tx.id for tx in self.transactions])
        tx_hash = hashlib.sha256(data.encode()).hexdigest()
        return tx_hash


class Blockchain:
    def __init__(self, address=None):
        with shelve.open("blocks") as db:
            tip = db.get("l", None)
            if tip is None:
                print("No existing blockchain found. Creating a new one...")
                if address is None:
                    print("Please specify the address!")
                    sys.exit(1)
                genesis_coinbase_data = b"Genesis Block"
                cbtx = Transaction.coinbaseTX(address, genesis_coinbase_data)
                genesis = Block.genesis_block(cbtx)
                db[genesis.hash] = genesis
                db["l"] = genesis.hash
                tip = genesis.hash

        self.tip = tip

    def mine_block(self, transactions):
        for tx in transactions:
            if not self.verify_transaction(tx):
                raise ValueError("Invalid transaction")

        with shelve.open("blocks") as db:
            last_hash = db.get("l", None)
            last_block = db[last_hash]
            new_block = Block(transactions, last_hash, last_block.height)
            db[new_block.hash] = new_block
            db["l"] = new_block.hash
            self.tip = new_block.hash

    def find_unspent_transactions(self, pub_key_hash):
        unspentTXOs = list()
        spentTXOs = dict()

        current_hash = self.tip
        with shelve.open("blocks") as db:
            while current_hash:
                block = db[current_hash]
                for tx in block.transactions:
                    txid = tx.id.encode().hex()
                    for out_idx, vout in enumerate(tx.vouts):
                        if txid in spentTXOs and out_idx in spentTXOs[txid]:
                            continue

                        if vout.is_locked_with_key(pub_key_hash):
                            unspentTXOs.append(tx)

                    if not tx.is_coinbase():
                        for vin in tx.vins:
                            if vin.uses_key(pub_key_hash):
                                in_txid = vin.txid.encode().hex()
                                spentTXOs.setdefault(
                                    in_txid, set()).add(vin.vout)

                current_hash = block.prev_block_hash

        return unspentTXOs

    def findUTXO(self, pub_key_hash):
        UTXOs = list()
        unspentTXs = self.find_unspent_transactions(pub_key_hash)
        for tx in unspentTXs:
            for vout in tx.vouts:
                if vout.is_locked_with_key(pub_key_hash):
                    UTXOs.append(vout)

        return UTXOs

    def find_spendable_outputs(self, pub_key_hash, amount):
        unspent_outputs = dict()
        unspentTXs = self.find_unspent_transactions(pub_key_hash)
        accumulated = 0
        for tx in unspentTXs:
            txid = tx.id.encode().hex()
            for out_idx, out in enumerate(tx.vouts):
                if (out.is_locked_with_key(pub_key_hash) and
                        accumulated < amount):
                    accumulated += out.value
                    unspent_outputs.setdefault(txid, list()).append(out_idx)
                    if accumulated >= amount:
                        return accumulated, unspent_outputs

        return accumulated, unspent_outputs

    def find_transaction(self, txid):
        current_hash = self.tip
        with shelve.open("blocks") as db:
            while current_hash:
                block = db[current_hash]
                for tx in block.transactions:
                    if tx.id == txid:
                        return tx
                current_hash = block.prev_block_hash

        raise ValueError("Transaction is not found")

    def sign_transaction(self, tx, private_key):
        prevTXs = dict()

        for vin in tx.vins:
            prevTX = self.find_transaction(vin.txid)
            prevTXs[prevTX.id.encode().hex()] = prevTX

        tx.sign(private_key, prevTXs)

    def verify_transaction(self, tx):
        if tx.is_coinbase():
            return True

        prevTXs = dict()

        for vin in tx.vins:
            prevTX = self.find_transaction(vin.txid)
            prevTXs[prevTX.id.encode().hex()] = prevTX

        return tx.verify(prevTXs)

# ========================================


class ProofOfWork:
    def __init__(self, block):
        self.block = block
        self.target = 1 << (256 - block.bits)

    def prepare_data(self, nonce):
        block = self.block
        data = (block.prev_block_hash +
                block.hash_transactions() +
                hex(block.time)[2:] +
                hex(block.bits)[2:] +
                hex(nonce)[2:])
        return data

    def run(self):
        nonce = 0
        max_nonce = (1 << 63) - 1
        print("Mining a new block")
        while nonce < max_nonce:
            data = self.prepare_data(nonce)
            hash_val = hashlib.sha256(data.encode()).hexdigest()
            hash_int = int(hash_val, 16)
            if hash_int < self.target:
                print(hash_val)
                break
            else:
                nonce += 1
        print()

        return nonce, hash_val

    def validate(self):
        data = self.prepare_data(self.block.nonce)
        hash_val = hashlib.sha256(data.encode()).hexdigest()
        hash_int = int(hash_val, 16)

        return hash_int < self.target

# ========================================


class TXInput:
    def __init__(self, txid, vout, signature, pub_key):
        self.txid = txid
        self.vout = vout
        self.signature = signature
        self.pub_key = pub_key

    def uses_key(self, pub_key_hash):
        locking_hash = Util.hash_pub_key(self.pub_key)
        return locking_hash == pub_key_hash


class TXOutput:
    def __init__(self, value, address=None, pub_key_hash=None):
        self.value = value
        self.pub_key_hash = None

        if address is not None:
            self.lock(address)
            return

        if pub_key_hash is not None:
            self.pub_key_hash = pub_key_hash
            return

        raise ValueError("Both address and pub_key_hash are None")

    def lock(self, address):
        self.pub_key_hash = Util.address_to_pubkeyhash(address)

    def is_locked_with_key(self, pub_key_hash):
        return self.pub_key_hash == pub_key_hash


class Transaction:
    def __init__(self, txid, vins, vouts):
        self.id = txid
        self.vins = vins
        self.vouts = vouts

    @classmethod
    def coinbaseTX(cls, user_to, data=None):
        if data is None:
            data = f"Reward to '{user_to}'"
            data = data.encode()

        subsidy = 10

        txin = TXInput(b"", -1, None, data)
        txout = TXOutput(subsidy, user_to)
        tx = cls(None, [txin], [txout])
        tx.id = tx.hash()

        return tx

    def is_coinbase(self):
        return (len(self.vins) == 1 and
                self.vins[0].txid == b"" and
                self.vins[0].vout == -1)

    @classmethod
    def UTXOTransaction(cls, user_from, user_to, amount, blockchain):
        inputs = list()
        outputs = list()

        with shelve.open("wallets") as db:
            try:
                wallets = db["wallets"]
                wallet = wallets[user_from]
            except KeyError:
                print("ERROR: No such wallet!")
                sys.exit(1)

        pub_key_hash = Util.hash_pub_key(wallet.public_key)
        acc, valid_outputs = blockchain.find_spendable_outputs(
            pub_key_hash, amount)

        if acc < amount:
            print("ERROR: Not enough funds")
            sys.exit(1)

        for txid, outs in valid_outputs.items():
            txid = bytes.fromhex(txid).decode()
            for out in outs:
                inputs.append(TXInput(txid, out, None, wallet.public_key))

        outputs.append(TXOutput(amount, user_to))
        if acc > amount:
            outputs.append(TXOutput(acc - amount, user_from))

        tx = cls(None, inputs, outputs)
        tx.id = tx.hash()
        private_key = ECC.import_key(wallet.private_key.decode())
        blockchain.sign_transaction(tx, private_key)

        return tx

    def hash(self):
        return hashlib.sha256(pickle.dumps(self)).hexdigest()

    def sign(self, private_key, prevTXs):
        if self.is_coinbase():
            return

        tx_copy = self.trimmed_copy()

        for in_idx, vin in enumerate(tx_copy.vins):
            prevTX = prevTXs[vin.txid.encode().hex()]
            tx_copy.vins[in_idx].signature = None
            tx_copy.vins[in_idx].pub_key = prevTX.vouts[vin.vout].pub_key_hash
            tx_copy.id = tx_copy.hash()
            tx_copy.vins[in_idx].pub_key = None

            # sign
            h = SHA256.new(tx_copy.id.encode())
            signer = DSS.new(private_key, "fips-186-3")
            signature = signer.sign(h)

            self.vins[in_idx].signature = signature

    def verify(self, prevTXs):
        tx_copy = self.trimmed_copy()

        for in_idx, vin in enumerate(self.vins):
            prevTX = prevTXs[vin.txid.encode().hex()]
            tx_copy.vins[in_idx].signature = None
            tx_copy.vins[in_idx].pub_key = prevTX.vouts[vin.vout].pub_key_hash
            tx_copy.id = tx_copy.hash()
            tx_copy.vins[in_idx].pub_key = None

            pub_key = ECC.import_key(vin.pub_key.decode())
            h = SHA256.new(tx_copy.id.encode())
            verifier = DSS.new(pub_key, "fips-186-3")
            try:
                verifier.verify(h, vin.signature)
                return True
            except ValueError:
                return False

    def trimmed_copy(self):
        inputs = list()
        outputs = list()

        for vin in self.vins:
            inputs.append(TXInput(vin.txid, vin.vout, None, None))

        for vout in self.vouts:
            outputs.append(TXOutput(vout.value, pub_key_hash=vout.pub_key_hash))

        tx_copy = type(self)(self.id, inputs, outputs)

        return tx_copy

# ========================================


class Wallet:
    def __init__(self):
        private_key = ECC.generate(curve="P-256")
        public_key = private_key.public_key()
        self.private_key = private_key.export_key(format="PEM").encode()
        self.public_key = public_key.export_key(format="PEM").encode()

        with shelve.open("wallets") as db:
            wallets = db.get("wallets", dict())
            wallets[self.get_address().decode()] = self
            db["wallets"] = wallets

    def get_address(self):
        pub_key_hash = Util.hash_pub_key(self.public_key)

        version = bytes([0])
        versioned_payload = version + pub_key_hash
        checksum = Util.checksum(versioned_payload)

        full_payload = versioned_payload + checksum
        address = base58.b58encode(full_payload)

        return address


# ========================================

class Constant:
    address_checksum_len = 4


class Util:
    @staticmethod
    def hash_pub_key(pub_key):
        pub_sha256 = hashlib.sha256(pub_key).digest()
        ripemd160 = hashlib.new("ripemd160")
        ripemd160.update(pub_sha256)
        return ripemd160.digest()

    @staticmethod
    def checksum(payload):
        first_sha = hashlib.sha256(payload).digest()
        second_sha = hashlib.sha256(first_sha).digest()

        return second_sha[:Constant.address_checksum_len]

    @staticmethod
    def validate_address(address):
        pub_key_hash = base58.b58decode(address.encode())
        actual_checksum = pub_key_hash[-Constant.address_checksum_len:]
        version = pub_key_hash[0:1]
        pub_key_hash = pub_key_hash[1:-Constant.address_checksum_len]
        target_checksum = Util.checksum(version + pub_key_hash)
        return actual_checksum == target_checksum

    @staticmethod
    def address_to_pubkeyhash(address):
        return (
            base58.b58decode(address.encode())[1:-Constant.address_checksum_len]
        )

# ========================================


class CLI:
    def createwallet(self, args):
        wallet = Wallet()
        print("Your new address:", wallet.get_address().decode())

    def createblockchain(self, args):
        if args.address is None:
            print("Please specify the address!")
            return
        if not Util.validate_address(args.address):
            print("ERROR: Address is not valid")
            return
        Blockchain(args.address)
        print("Done!")

    def getbalance(self, args):
        if args.address is None:
            print("Please specify the address!")
            return
        if not Util.validate_address(args.address):
            print("ERROR: Address is not valid")
            return
        blockchain = Blockchain()
        pub_key_hash = Util.address_to_pubkeyhash(args.address)
        UTXOs = blockchain.findUTXO(pub_key_hash)
        balance = sum([out.value for out in UTXOs])
        print(f"Balance of '{args.address}': {balance}")

    def send(self, args):
        if (args.user_from is None or args.user_to is None or
                args.amount is None):
            print("Please specify from, to, and amount!")
            return
        blockchain = Blockchain()
        tx = Transaction.UTXOTransaction(
            args.user_from, args.user_to, args.amount, blockchain)
        cbtx = Transaction.coinbaseTX(args.user_from, b"")
        blockchain.mine_block([cbtx, tx])
        print("Success!")

    def printchain(self, args):
        with shelve.open("blocks") as db:
            current_hash = db.get("l", None)
            if current_hash is None:
                print("No blockchain yet. Please create one first!")
                return
            while current_hash:
                block = db[current_hash]
                print(block)
                POW = ProofOfWork(block)
                print("PoW:", POW.validate())
                print()
                current_hash = block.prev_block_hash

    def printblock(self, args):
        if args.height is None:
            print("Please specify the height!")
            return
        with shelve.open("blocks") as db:
            current_hash = db.get("l", None)
            if current_hash is None:
                print("No blockchain yet. Please create one first!")
                return
            while current_hash:
                block = db[current_hash]
                if block.height == args.height:
                    print(block)
                    POW = ProofOfWork(block)
                    print("PoW:", POW.validate())
                    return
                current_hash = block.prev_block_hash
        print("No block with such height found!")

# ========================================


if __name__ == '__main__':
    cli = CLI()

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparser = subparsers.add_parser("createwallet")
    subparser.set_defaults(func=cli.createwallet)

    subparser = subparsers.add_parser("createblockchain")
    subparser.add_argument("--address")
    subparser.set_defaults(func=cli.createblockchain)

    subparser = subparsers.add_parser("getbalance")
    subparser.add_argument("--address")
    subparser.set_defaults(func=cli.getbalance)

    subparser = subparsers.add_parser("send")
    subparser.add_argument("--from", dest="user_from")
    subparser.add_argument("--to", dest="user_to")
    subparser.add_argument("--amount", type=int)
    subparser.set_defaults(func=cli.send)

    subparser = subparsers.add_parser("printchain")
    subparser.set_defaults(func=cli.printchain)

    subparser = subparsers.add_parser("printblock")
    subparser.add_argument("--height", type=int)
    subparser.set_defaults(func=cli.printblock)

    args = parser.parse_args()
    args.func(args)
