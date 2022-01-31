// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/fees.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

static void TestFillInputToWeight(int64_t additional_weight, std::vector<int64_t> expected_stack_sizes)
{
    static const int64_t EMPTY_INPUT_WEIGHT = GetTransactionInputWeight(CTxIn());

    CTxIn input;
    int64_t target_weight = EMPTY_INPUT_WEIGHT + additional_weight;
    BOOST_CHECK(FillInputToWeight(input, target_weight));
    BOOST_CHECK_EQUAL(GetTransactionInputWeight(input), target_weight);
    BOOST_CHECK_EQUAL(input.scriptWitness.stack.size(), expected_stack_sizes.size());
    for (unsigned int i = 0; i < expected_stack_sizes.size(); ++i) {
        BOOST_CHECK_EQUAL(input.scriptWitness.stack[i].size(), expected_stack_sizes[i]);
    }
}

BOOST_FIXTURE_TEST_CASE(FillInputToWeightTest, BasicTestingSetup)
{
    {
        // Less than or equal minimum of 165 should not add any witness data
        CTxIn input;
        BOOST_CHECK(!FillInputToWeight(input, -1));
        BOOST_CHECK_EQUAL(GetTransactionInputWeight(input), 165);
        BOOST_CHECK_EQUAL(input.scriptWitness.stack.size(), 0);
        BOOST_CHECK(!FillInputToWeight(input, 0));
        BOOST_CHECK_EQUAL(GetTransactionInputWeight(input), 165);
        BOOST_CHECK_EQUAL(input.scriptWitness.stack.size(), 0);
        BOOST_CHECK(!FillInputToWeight(input, 164));
        BOOST_CHECK_EQUAL(GetTransactionInputWeight(input), 165);
        BOOST_CHECK_EQUAL(input.scriptWitness.stack.size(), 0);
        BOOST_CHECK(FillInputToWeight(input, 165));
        BOOST_CHECK_EQUAL(GetTransactionInputWeight(input), 165);
        BOOST_CHECK_EQUAL(input.scriptWitness.stack.size(), 0);
    }

    // Make sure we can add at least one weight
    TestFillInputToWeight(1, {0});

    // 1 byte compact size uint boundary
    TestFillInputToWeight(252, {251});
    TestFillInputToWeight(253, {83, 168});
    TestFillInputToWeight(262, {86, 174});
    TestFillInputToWeight(263, {260});

    // 3 byte compact size uint boundary
    TestFillInputToWeight(65535, {65532});
    TestFillInputToWeight(65536, {21842, 43688});
    TestFillInputToWeight(65545, {21845, 43694});
    TestFillInputToWeight(65546, {65541});

    // Note: We don't test the next boundary because of memory allocation constraints.
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
