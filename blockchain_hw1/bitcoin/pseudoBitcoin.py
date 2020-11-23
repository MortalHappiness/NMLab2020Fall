#!/usr/bin/env python3

import argparse
import hashlib
import pickle
import shelve
import time

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
                    exit(1)
                genesis_coinbase_data = "Genesis Block"
                cbtx = Transaction.coinbaseTX(address, genesis_coinbase_data)
                genesis = Block.genesis_block(cbtx)
                db[genesis.hash] = genesis
                db["l"] = genesis.hash
                tip = genesis.hash

        self.tip = tip

    def mine_block(self, transactions):
        with shelve.open("blocks") as db:
            last_hash = db.get("l", None)
            last_block = db[last_hash]
            new_block = Block(transactions, last_hash, last_block.height)
            db[new_block.hash] = new_block
            db["l"] = new_block.hash
            self.tip = new_block.hash

    def find_unspent_transactions(self, address):
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

                        if vout.can_be_unlocked_with(address):
                            unspentTXOs.append(tx)

                    if not tx.is_coinbase():
                        for vin in tx.vins:
                            if vin.can_unlock_output_with(address):
                                in_txid = vin.txid.encode().hex()
                                spentTXOs.setdefault(
                                    in_txid, set()).add(vin.vout)

                current_hash = block.prev_block_hash

        return unspentTXOs

    def findUTXO(self, address):
        UTXOs = list()
        unspentTXs = self.find_unspent_transactions(address)
        for tx in unspentTXs:
            for vout in tx.vouts:
                if vout.can_be_unlocked_with(address):
                    UTXOs.append(vout)

        return UTXOs

    def find_spendable_outputs(self, address, amount):
        unspent_outputs = dict()
        unspentTXs = self.find_unspent_transactions(address)
        accumulated = 0
        for tx in unspentTXs:
            txid = tx.id.encode().hex()
            for out_idx, out in enumerate(tx.vouts):
                if out.can_be_unlocked_with(address) and accumulated < amount:
                    accumulated += out.value
                    unspent_outputs.setdefault(txid, list()).append(out_idx)
                    if accumulated >= amount:
                        return accumulated, unspent_outputs

        return accumulated, unspent_outputs

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
    def __init__(self, txid, vout, script_sig):
        self.txid = txid
        self.vout = vout
        self.script_sig = script_sig

    def can_unlock_output_with(self, unlocking_data):
        return self.script_sig == unlocking_data


class TXOutput:
    def __init__(self, value, script_pub_key):
        self.value = value
        self.script_pub_key = script_pub_key

    def can_be_unlocked_with(self, unlocking_data):
        return self.script_pub_key == unlocking_data


class Transaction:
    def __init__(self, txid, vins, vouts):
        self.id = txid
        self.vins = vins
        self.vouts = vouts

    @classmethod
    def coinbaseTX(cls, user_to, data=None):
        if data is None:
            data = f"Reward to '{user_to}'"

        subsidy = 10

        txin = TXInput("", -1, data)
        txout = TXOutput(subsidy, user_to)
        tx = cls(None, [txin], [txout])
        tx.set_id()

        return tx

    def is_coinbase(self):
        return (len(self.vins) == 1 and
                self.vins[0].txid == "" and
                self.vins[0].vout == -1)

    @classmethod
    def UTXOTransaction(cls, user_from, user_to, amount, blockchain):
        inputs = list()
        outputs = list()

        acc, valid_outputs = blockchain.find_spendable_outputs(
            user_from, amount)

        if acc < amount:
            print("ERROR: Not enough funds")
            exit(1)

        for txid, outs in valid_outputs.items():
            txid = bytes.fromhex(txid).decode()
            for out in outs:
                inputs.append(TXInput(txid, out, user_from))

        outputs.append(TXOutput(amount, user_to))
        if acc > amount:
            outputs.append(TXOutput(acc - amount, user_from))

        tx = cls(None, inputs, outputs)
        tx.set_id()

        return tx

    def set_id(self):
        self.id = hashlib.sha256(pickle.dumps(self)).hexdigest()


# ========================================


class CLI:
    def createblockchain(self, args):
        if args.address is None:
            print("Please specify the address!")
            return
        Blockchain(args.address)
        print("Done!")

    def getbalance(self, args):
        if args.address is None:
            print("Please specify the address!")
            return
        blockchain = Blockchain()
        UTXOs = blockchain.findUTXO(args.address)
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
        blockchain.mine_block([tx])
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
