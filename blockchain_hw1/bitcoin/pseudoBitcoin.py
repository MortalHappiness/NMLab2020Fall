#!/usr/bin/env python3

import argparse
import hashlib
import shelve
import time

# ========================================


class ProofOfWork:
    def __init__(self, block):
        self.block = block
        self.target = 1 << (256 - block.bits)

    def prepare_data(self, nonce):
        block = self.block
        data = (block.prev_block_hash +
                block.data +
                hex(block.time)[2:] +
                hex(block.bits)[2:] +
                hex(nonce)[2:])
        return data

    def run(self):
        nonce = 0
        max_nonce = (1 << 63) - 1
        print(f'Mining the block containing "{self.block.data}"')
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


class Block:
    def __init__(self, data, prev_block_hash, prev_height):
        self.height = prev_height + 1
        self.prev_block_hash = prev_block_hash
        self.time = int(time.time())
        self.bits = 20
        self.data = data

        POW = ProofOfWork(self)
        nonce, hash_val = POW.run()
        self.hash = hash_val
        self.nonce = nonce

    @classmethod
    def genesis_block(cls):
        return cls("Genesis block", "", 0)

    def __str__(self):
        D = {"Height": self.height,
             "Prev Block Hash": self.prev_block_hash,
             "Time": self.time,
             "Data": self.data,
             "Hash": self.hash,
             "Nonce": self.nonce
             }
        return "\n".join([f"{k}: {v}" for k, v in D.items()])


class Blockchain:
    def __init__(self):
        with shelve.open("blocks") as db:
            try:
                tip = db["l"]
            except KeyError:
                genesis = Block.genesis_block()
                db[genesis.hash] = genesis
                db["l"] = genesis.hash
                tip = genesis.hash

        self.tip = tip

    def add_block(self, data):
        with shelve.open("blocks") as db:
            last_hash = db["l"]
            last_block = db[last_hash]
            new_block = Block(data, last_hash, last_block.height)
            db[new_block.hash] = new_block
            db["l"] = new_block.hash
            self.tip = new_block.hash


class CLI:
    blockchain = Blockchain()

    @classmethod
    def addblock(cls, args):
        if (args.transaction is None):
            print("Please specify the transaction!")
            return
        cls.blockchain.add_block(args.transaction)
        print("Success!")

    @classmethod
    def printchain(cls, args):
        with shelve.open("blocks") as db:
            current_hash = db["l"]
            while current_hash:
                block = db[current_hash]
                print(block)
                POW = ProofOfWork(block)
                print("PoW:", POW.validate())
                print()
                current_hash = block.prev_block_hash

    @classmethod
    def printblock(cls, args):
        if (args.height is None):
            print("Please specify the height!")
            return
        with shelve.open("blocks") as db:
            current_hash = db["l"]
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
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparser = subparsers.add_parser("addblock")
    subparser.add_argument("--transaction")
    subparser.set_defaults(func=CLI.addblock)

    subparser = subparsers.add_parser("printchain")
    subparser.set_defaults(func=CLI.printchain)

    subparser = subparsers.add_parser("printblock")
    subparser.add_argument("--height", type=int)
    subparser.set_defaults(func=CLI.printblock)

    args = parser.parse_args()
    args.func(args)
