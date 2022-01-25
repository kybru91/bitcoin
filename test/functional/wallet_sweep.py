#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the sweep RPC command."""

from decimal import Decimal, getcontext

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

class WalletSweepTest(BitcoinTestFramework):
    def set_test_params(self):
        getcontext().prec=10
        self.num_nodes = 1
        self.setup_clean_chain = True

    def assert_tx_has_output(self, tx, addr, value=None ):
        for output in tx["decoded"]["vout"]:
            if addr == output["scriptPubKey"]["address"] and value is None or value == output["value"]:
                return
        raise AssertionError("Output to {} not present or wrong amount".format(addr))

    def assert_balance_swept_completely(self, tx, balance):
        output_sum = sum([o["value"] for o in tx["decoded"]["vout"]])
        assert_equal(output_sum, balance + tx["fee"])
        assert_equal(0, self.wallet.getbalances()["mine"]["trusted"]) # wallet is empty

    def generate_initial_utxos(self, amounts):
        for a in amounts:
            self.def_wallet.sendtoaddress(self.wallet.getnewaddress(), a)
        self.generate(self.nodes[0], 1)
        assert_greater_than(self.wallet.getbalances()["mine"]["trusted"], 0)

    def clean_up(self):
        if 0 < self.wallet.getbalances()["mine"]["trusted"]:
            self.wallet.sweep([self.return_addr_remainder])

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def sweep_two_utxos(self):
        self.log.info("Testing basic sweep case without specific amounts")
        self.generate_initial_utxos([10, 11])
        wallet_balance_before_sweep = self.wallet.getbalances()["mine"]["trusted"]

        sweep_tx_receipt = self.wallet.sweep([self.return_addr_remainder])
        self.generate(self.nodes[0], 1)
        assert_equal(0, self.wallet.getbalances()["mine"]["trusted"]) # wallet is empty

        assert_equal(sweep_tx_receipt["complete"], True)
        tx_from_wallet = self.wallet.gettransaction(txid = sweep_tx_receipt["txid"], verbose = True)

        assert_equal(len(tx_from_wallet["decoded"]["vout"]), 1)
        output = tx_from_wallet["decoded"]["vout"][0]
        assert_equal(output["value"], wallet_balance_before_sweep + tx_from_wallet["fee"]) # fee is negative
        assert_equal(output["scriptPubKey"]["address"], self.return_addr_remainder)

    def sweep_to_two_outputs(self):
        self.log.info("Testing sweep where one output has specified amount")
        self.generate_initial_utxos([8, 13])
        wallet_balance_before_sweep = self.wallet.getbalances()["mine"]["trusted"]

        sweep_tx_receipt = self.wallet.sweep([{self.return_addr_with_amount: 5}, self.return_addr_remainder])
        self.generate(self.nodes[0], 1)
        assert_equal(0, self.wallet.getbalances()["mine"]["trusted"]) # wallet is empty

        assert_equal(sweep_tx_receipt["complete"], True)
        tx_from_wallet = self.wallet.gettransaction(txid = sweep_tx_receipt["txid"], verbose = True)

        assert_equal(len(tx_from_wallet["decoded"]["vout"]), 2)
        self.assert_tx_has_output(tx_from_wallet, self.return_addr_with_amount, 5)
        self.assert_tx_has_output(tx_from_wallet, self.return_addr_remainder)

        self.assert_balance_swept_completely(tx_from_wallet, wallet_balance_before_sweep)

    def sweep_invalid_receiver_addresses(self):
        self.log.info("Testing sweep only with specified amount")
        self.generate_initial_utxos([12, 9])
        assert_greater_than(self.wallet.getbalances()["mine"]["trusted"], 0)

        assert_raises_rpc_error(-8, "Must provide at least one address without a specified amount" , self.wallet.sweep, [{self.return_addr_with_amount: 5}])

        self.clean_up()

    def sweep_invalid_amounts(self):
        self.log.info("Try sweeping more than balance")
        self.generate_initial_utxos([7, 14])
        wallet_balance_before_sweep = self.wallet.getbalances()["mine"]["trusted"]

        expected_tx = self.wallet.sweep(receivers=[{self.return_addr_with_amount: 5}, self.return_addr_remainder], options={"add_to_wallet": False})
        tx = self.wallet.decoderawtransaction(expected_tx['hex'])
        fee = 21 - sum([o["value"] for o in tx["vout"]])

        assert_raises_rpc_error(-8, "Assigned more value to outputs than available funds." , self.wallet.sweep, [{self.return_addr_with_amount: wallet_balance_before_sweep + 1}, self.return_addr_remainder])
        assert_raises_rpc_error(-6, "Insufficient funds for fees after creating specified outputs.", self.wallet.sweep, [{self.return_addr_with_amount: wallet_balance_before_sweep}, self.return_addr_remainder])
        assert_raises_rpc_error(-8, "Specified output amount to {} is below dust threshold".format(self.return_addr_with_amount), self.wallet.sweep, [{self.return_addr_with_amount: 0.00000001}, self.return_addr_remainder])
        assert_raises_rpc_error(-6, "Dynamically assigned remainder results in dust output.", self.wallet.sweep, [{self.return_addr_with_amount: wallet_balance_before_sweep - fee}, self.return_addr_remainder])
        assert_raises_rpc_error(-6, "Dynamically assigned remainder results in dust output.", self.wallet.sweep, [{self.return_addr_with_amount: wallet_balance_before_sweep - fee - Decimal(0.00000010)}, self.return_addr_remainder])

        self.clean_up()

    def sweep_negative_effective_value(self):
        self.log.info("Check that sweep fails if all UTXOs have negative effective value")
        self.nodes[0].createwallet("dustwallet")
        dust_wallet = self.nodes[0].get_wallet_rpc("dustwallet")

        self.def_wallet.sendtoaddress(dust_wallet.getnewaddress(), 0.00000400)
        self.def_wallet.sendtoaddress(dust_wallet.getnewaddress(), 0.00000300)
        self.generate(self.nodes[0], 1)
        assert_greater_than(dust_wallet.getbalances()["mine"]["trusted"], 0)

        assert_raises_rpc_error(-6, "Total value of UTXO pool too low to pay for sweep. Try using lower feerate or excluding uneconomic UTXOs with 'sendmax' option.", dust_wallet.sweep, receivers=[self.return_addr_remainder], fee_rate=300)

        dust_wallet.unloadwallet()

    def sweep_with_sendmax(self):
        self.log.info("Check that `sendmax` option causes negative value UTXOs to be left behind")
        self.def_wallet.sendtoaddress(self.wallet.getnewaddress(), 0.00000400)
        self.def_wallet.sendtoaddress(self.wallet.getnewaddress(), 0.00000300)
        self.def_wallet.sendtoaddress(self.wallet.getnewaddress(), 1)
        self.generate(self.nodes[0], 1)
        assert_greater_than(self.wallet.getbalances()["mine"]["trusted"], 0)

        # Sweep with sendmax
        sweep_tx_receipt = self.wallet.sweep(receivers=[self.return_addr_remainder], fee_rate=300, options={"sendmax": True})
        tx_from_wallet = self.wallet.gettransaction(txid = sweep_tx_receipt["txid"], verbose = True)

        assert_equal(len(tx_from_wallet["decoded"]["vin"]), 1)
        assert_equal(len(tx_from_wallet["decoded"]["vout"]), 1)
        self.assert_tx_has_output(tx_from_wallet, self.return_addr_remainder)
        assert_equal(self.wallet.getbalances()["mine"]["trusted"], Decimal("0.00000700"))

        self.def_wallet.sendtoaddress(self.wallet.getnewaddress(), 1)
        self.generate(self.nodes[0], 1)

        # Clean up: sweep without sendmax
        sweep_tx_receipt = self.wallet.sweep(receivers=[self.return_addr_remainder], fee_rate=300)
        tx_from_wallet = self.wallet.gettransaction(txid = sweep_tx_receipt["txid"], verbose = True)
        assert_equal(len(tx_from_wallet["decoded"]["vin"]), 3)
        assert_equal(len(tx_from_wallet["decoded"]["vout"]), 1)
        self.assert_tx_has_output(tx_from_wallet, self.return_addr_remainder)
        assert_equal(0, self.wallet.getbalances()["mine"]["trusted"]) # wallet is empty

    def run_test(self):
        self.nodes[0].createwallet("sweepwallet")
        self.wallet = self.nodes[0].get_wallet_rpc("sweepwallet")
        self.def_wallet  = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.generate(self.nodes[0], 101)
        self.return_addr_with_amount = self.def_wallet.getnewaddress() # address that receives a specific amount
        self.return_addr_remainder = self.def_wallet.getnewaddress() # address that receives the rest

        # Basic Sweep case without specific amounts
        self.sweep_two_utxos()

        # Basic Sweep case without specific amounts
        self.sweep_to_two_outputs()

        # Sweep fails with only specific amounts
        self.sweep_invalid_receiver_addresses()

        # Sweep fails when trying to spend more than the balance
        self.sweep_invalid_amounts()

        # Sweep fails when wallet has no economically spendable UTXOs
        self.sweep_negative_effective_value()

        # Sweep fails when wallet has no economically spendable UTXOs
        self.sweep_with_sendmax()

if __name__ == '__main__':
    WalletSweepTest().main()
