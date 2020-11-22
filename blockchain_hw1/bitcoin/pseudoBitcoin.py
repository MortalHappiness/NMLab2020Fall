#!/usr/bin/env python3

import argparse
import hashlib
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


class Blockchain:
    def __init__(self):
        self.blocks = [Block.genesis_block()]

    def add_block(self, data):
        prev_block = self.blocks[-1]
        new_block = Block(data, prev_block.hash, prev_block.height)
        self.blocks.append(new_block)


# ========================================


def addblock(args):
    pass


def printchain(args):
    pass


def printblock(args):
    pass


# ========================================


if __name__ == '__main__':
    blockchain = Blockchain()
    blockchain.add_block("123 456")
    blockchain.add_block("hello")

    for block in blockchain.blocks:
        print("Prev. hash:", block.prev_block_hash)
        print("Data:", block.data)
        print("Hash:", block.hash)
        POW = ProofOfWork(block)
        print("PoW:", POW.validate())
        print()

    exit()

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparser = subparsers.add_parser("addblock")
    subparser.add_argument("--transaction")
    subparser.set_defaults(func=addblock)

    subparser = subparsers.add_parser("printchain")
    subparser.set_defaults(func=printchain)

    subparser = subparsers.add_parser("printblock")
    subparser.add_argument("--height", type=int)
    subparser.set_defaults(func=printblock)

    args = parser.parse_args()
    args.func(args)
