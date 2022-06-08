# Copyright 2022 The Tari Project
# SPDX-License-Identifier: BSD-3-Clause

@dan
Feature: Validator Node
    @broken
    Scenario: Test committee
        Given I have committee from 4 validator nodes connected
        Then I send instruction successfully with metadata {"issuer" : {"num_clicks" : 1}}
        Then At least 3 out of 4 validator nodes have filled asset data

    @current @broken
    Scenario: Start asset
        Given I have a seed node NODE1
        And I have wallet WALLET1 connected to all seed nodes
        When I mine 9 blocks using wallet WALLET1 on NODE1
        Then I wait for wallet WALLET1 to have at least 1000000 uT
        When I wait 30 seconds
        When I register an NFT asset with committee of 4
        And I mine 3 blocks
        And I create 40 NFTs
        And I mine 3 blocks

    Scenario: Publish contract acceptance
        Given I have a seed node NODE1
        And I have wallet WALLET1 connected to all seed nodes
        When I mine 9 blocks using wallet WALLET1 on NODE1
        Then I wait for wallet WALLET1 to have at least 1000000 uT
        And I have a validator node VN1 connected to base node NODE1 and wallet WALLET1
        Then I publish a contract acceptance transaction for the validator node VN1
        When I mine 4 blocks using wallet WALLET1 on NODE1
        Then wallet WALLET1 has at least 1 transactions that are all TRANSACTION_STATUS_MINED_CONFIRMED and not cancelled
