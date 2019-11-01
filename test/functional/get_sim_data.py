#! /usr/bin/env python3

import random

from test_framework.authproxy import AuthServiceProxy
from decimal import Decimal

rpc = AuthServiceProxy("http://__cookie__:c7a01a4665500e722eb208556ad1deaa564d5c55c454f34a54e892a033957c73@127.0.0.1:8332")

def get_txout_value(txid, vout):
    tx = rpc.getrawtransaction(txid, 1)
    return tx['vout'][vout]['value']

lines_written = 0;

with open('sim_data.csv'.format(), "w+") as f:
    target_balance = 0
    funder_balance = 14000
    while lines_written < 10000:
        block_num = random.randint(500000, 600000)
        block = rpc.getblock(rpc.getblockhash(block_num), 2)
        print("block {}".format(block_num))

        for i in range(1, len(block['tx'])):
            tx = block['tx'][i]
            if lines_written % 500 == 0:
                print(lines_written)
            fee = 0
            for input in tx['vin']:
                fee += get_txout_value(input['txid'], input['vout'])
            for output in tx['vout']:
                fee -= output['value']
            feerate = fee / (Decimal(tx['vsize']) / 1000)
            for output in tx['vout']:
                val = output['value']
                if val == 0:
                    continue
                is_out = random.choices([True, False], [2, 1])[0]
                if is_out:
                    if target_balance - val > fee:
                        target_balance -= val
                        funder_balance += val
                        f.write("-{},{:.8f}\n".format(val, feerate))
                        lines_written += 1
                    else:
                        is_out = False
                if not is_out:
                    if funder_balance - val > fee:
                        target_balance += val
                        funder_balance -= val
                        f.write("{},{:.8f}\n".format(val, feerate))
                        lines_written += 1
                    else:
                        target_balance -= val
                        funder_balance += val
                        f.write("-{},{:.8f}\n".format(val, feerate))
                        lines_written += 1
