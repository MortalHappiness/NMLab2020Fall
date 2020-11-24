# HW1 - Pseudo Bitcoin

## Prerequisites

Run the following command to install prerequisites

```shell
pip install -r requirements.txt
```

## Usage

1. Create wallet

```shell
python pseudoBitcoin.py createwallet
```

This will create a new wallet and print the address.

2. Create Blockchain

```shell
python pseudoBitcoin.py createblockchain --address <address>
```

Create a new blockchain, reward to the specified address.

3. Get Balance

```shell
python pseudoBitcoin.py getbalance --address <address>
```

Get the balance of the specified address.

4. Send

```shell
python pseudoBitcoin.py send --from <from> --to <to> --amount <amount>
```

Send bitcoin from address `<from>` to address `<to>` with amount `<amount>`.

5. Print Blockchain

```shell
python pseudoBitcoin.py printchain
```

Print the blockchain.

6. Print Block

```shell
python pseudoBitcoin.py printblock --height <height>
```

Print the block with the specified height.

## Functionalities implemented

Block, Blockchain, Proof-of-Work, Database, Client, UTXO model, Sign & Verify, Mining reward, Merkle tree.
