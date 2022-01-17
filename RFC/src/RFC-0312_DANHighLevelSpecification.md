# RFC-0312/DANSpecification

## High level Digital Asset Network Specification

![status: draft](theme/images/status-draft.svg)

**Maintainer(s)**: [Cayle Sharrock](https://github.com/CjS77)

# Licence

[The 3-Clause BSD Licence](https://opensource.org/licenses/BSD-3-Clause).

Copyright 2019 The Tari Development Community

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of this document must retain the above copyright notice, this list of conditions and the following
   disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
   disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS DOCUMENT IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS", AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Language

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
"NOT RECOMMENDED", "MAY" and "OPTIONAL" in this document are to be interpreted as described in
[BCP 14](https://tools.ietf.org/html/bcp14) (covering RFC2119 and RFC8174) when, and only when, they appear in all capitals, as
shown here.

## Disclaimer

This document and its content are intended for information purposes only and may be subject to change or update
without notice.

This document may include preliminary concepts that may or may not be in the process of being developed by the Tari
community. The release of this document is intended solely for review and discussion by the community of the
technological merits of the potential system outlined herein.

## Goals

This document describes the high level specification for how digital assets are created, managed, secured, and wound-
down on the Tari digital asset network (DAN).

The document covers, among other things:

* The relationship of side-chains to digital assets,
* Required characteristics of side-chains,
* Peg-in and peg-out mechanisms,
* Digital asset template minimum requirements,
* Validator node requirements,
* Checkpoint and refund mechanisms

This RFC covers a lot of ground. Therefore the intent is not to provide a detailed, code-ready specification for the
entire DAN infrastructure; those are left to other RFCs; but to establish a foundation onto which the rest of the DAN
specifications can be built.

This RFC supersedes and deprecates several older RFCs:
  - [RFC-0300: Digital Assets Network](RFCD-0300_DAN.md)
  - [RFC-0301: Namespace Registration](RFCD-0301_NamespaceRegistration.md)
  - [RFC-0302: Validator Nodes](RFCD-0302_ValidatorNodes.md)
  - [RFC-0304: Validator Node committee selection](RFCD-0304_VNCommittees.md)
  - [RFC-0345: Asset Life cycle](RFC-0345_AssetLifeCycle.md)

Several RFC documents are in the process of being revised in order to fit into this proposed framework:

* [RFC-0300: The Digital Assets Network](RFCD-0300_DAN.md)
* [RFC-0340: Validator Node Consensus](RFC-0340_VNConsensusOverview.md)

### Motivation
There are many ways to skin a cat.
The philosophy guiding the approach in the RFC is one that permits
scaling of the network to handle in the region of **1 billion messages per day** network-wide and
**1 million digital assets** with **near real-time user experience** on asset state retrieval, updating and transfer,
on a sufficiently decentralised and private basis.

The definition of _sufficient_ here is subjective, and part of the design philosophy of Tari is that we leave it up to the
user to determine what that means, keeping in mind that there is always a trade-off between decentralisation, performance,
and cost.

For some assets, decentralisation and censorship resistance will be paramount, and users will be willing to live with a
more laggy experience. Gamers in a Web 3.0-MMORPG on the other hand, want cheap, fast transactions with verifiable ownership, and
therefore will generally be happy to sacrifice decentralisation for that.

The goal of the DAN is for asset issuers to be able to configure the side-chain for their project to suit their particular
needs.

## Description

### The role of the Layer 1 base chain

The Tari Overview RFC describes [the role of the base layer](./RFC-0001_overview.md#the-role-of-the-base-layer).
In summary, the base layer maintains the integrity of the Tari cryptocurrency token, maintains a register of side-chains
and maintains a register of Validator nodes.

It does not know about or care about what happens in the side chains as long as the Tari consensus, side-chain and
validator node rules are kept.


### The (side-chain)-(contract)-(validator node) relationship

Every contract MUST be governed by one, and only one, Tari side-chain.

Every digital asset MUST be governed by a single smart contract. This contract can be very simple or highly complex.

Side-chains MUST be initiated by Asset Issuers at the time of contract creation.

The side-chain consensus MUST be maintained by one or more Validator Nodes.

### Asset accounts

Tari uses the UTXO model in its ledger accounting. On the other hand Tari side-chains SHOULD use an account-based system
to track balances and state.

The reasons for this are:
* An account-based approach leads to fewer outputs on peg-in transactions. There is roughly a 1:1 ratio of users
  to balances in an account-based system. On the other hand there are O(n) UTXOs in an output-based system where `n` are
  the number of transactions carried out on the side-chain. When a side-chain wants to shut down, they must record a new
  output on the base layer for every account or output (as the case may be) that they track in the peg-out transaction(s).
  It should be self-evident that account-based systems are far scalable in the vast majority of use-cases.
* Following on from this, Accounts scale better for micro-payment applications, where hundreds or thousands of tiny payments
  flow between the same two parties.
* Many DAN applications will want to track state (such as NFTs) as well as currency balances. Account-based ledgers make
  this type of application far simpler.

Tari side-chain accounts MUST be representable as, or convertible to, a valid base layer UTXO.

When a side-chain pegs out, either partially (when users withdraw funds) or completely (when the side-chain shuts down),
all balances MUST be returned to the base layer in a manner that satisfies the Tari base layer consensus rules.

#### Pedersen commitments and account-based ledgers

Standard Pedersen commitments are essentially useless in account-based ledgers.

The reason being that since the spending keys would be common to all transactions involving a given account, it is trivial
to use the accounting rules to cancel out the `k.G` terms from transactions and to use a pre-image attack to unblind all
the values.

The specific protocol of user accounts in the side-chain is decided by the asset issuer.

Options include:

* Fully trusted

In this configuration, the side-chain is controlled by a single validator node, perhaps a server running an RDMS.
The validator node has full visibility into the state of the side chain at all times. It may or may not share this
state with the public. If it does not, then the situation is analogous to current Web 2.0 server applications.

* Decentralised and federated

In this configuration, a distributed set of validator nodes maintain the side-chain state. The set of nodes are fixed.
If consensus between nodes is achieved using a mechanism such as HotStuff BFT, very high throughputs can be achieved.

* Decentralised and censorship resistant

In this configuration, the side-chain could itself be a proof-of-work blockchain. This offers maximum decentralisation,
and censorship resistance. However, throughput will be lower.

* Confidentiality

As mentioned above, Pedersen commitments are not suitable for account-based ledgers. However, the [Zether] protocol
was expressly designed to provide confidentiality in a smart-contract context. It can be combined with any of the above
 schemes. Zether can also be extended to provide privacy by including a ring-signature scheme for transfers.



[Zether]: https://eprint.iacr.org/2019/191.pdf "Zether: Towards Privacy in a Smart Contract World"





### Side-chain architecture

Side chains are registered on the base layer.

Side-chains MUST be created by publishing a peg-in transaction
Side-chain domain: The side-chain metadata is only concerned with information as it relates

Information captured on the base layer:
* the owner authority (PublicKey) - could be a multisig key
* ?a chain id (scalar) - deterministic hash of initial contract metadata. Immutable for the life of the SC
* contract name (UTF-8 string) 32 bytes
* ?stake commitment - for paying Validator nodes
* ?checkpoint number - 0 when creating SC
* ?checkpoint hash
* ?contract definition


### Validator Node registration requirements

Validator nodes:
* MUST register on the base-chain. Validator Nodes will not be able to be nominated as [authorised signers] on side-chains
  if they have not registered on the base-chain.
* MUST commit funds in their [Validator Node collateral].
* MAY have to stake Tari for each contract that it validates. Asset issuers will determine the nature and amount of stake
  required. The [Contract stake] amount needs to be variable on a contract-to-contract basis so that an efficient market
  between asset issuers and Validator nodes can develop.

It has been suggested in the past that Validator Nodes should post hardware benchmarks when registering. The problem
with this requirement is that it is fairly trivial to game. We cannot enforce that the machine that posted the benchmark
is the same as the one that is running validations.

A better approach is to leave this to the market. A [reputation contract] can be built, on Tari, of course, that
periodically and randomly asks Validator Nodes to perform cryptographically signed benchmarks in exchange for performance
certificates. Nodes can voluntarily sign up for such a service and acts as a form of credential. Nodes that do not sign
up may have trouble finding contracts to validate and might have to lower their price to get work.


### Contract creation flow

The [Asset Owner] creates and owns a contract. Each contract runs in its own side-chain, and is managed by one or more
[Validator nodes].

There are several steps that are required to launch a new contract. They are discussed in detail below and in the various
sub-RFCs, but the basic flow is

![Contract creation flow](contract_creation_flow.png)

#### The owner collects data

To complete the contract creation flow, two transactions will be published on the main chain. The first is the
[Asset Registration transaction], which also doubles as the first [checkpoint transaction].

The second is the [Peg-in transaction] which formally coincides with the genesis of the side-chain.

The registration transaction requires the following data:

* [Asset metadata],
* [Owner collateral],
* [Initial contract state], or more correctly, the hash of the initial contract state,
* [The checkpoint number], which is always zero for new assets.

The peg-in transaction requires
* a [funding commitment]. This represents a source of funds that will be paid over to validator nodes for managing the contract.
* a list of [peg-out signers]. These are a set of public keys that are authorised to sign the peg-out transaction.


#### Metadata specification
[Asset metadata]: #metadata-specification

The asset metadata contains all the information that base nodes need to build up and maintain the [Digital Asset Register].

This allows clients to search for, interrogate and interact with Digital Assets on Tari, even though they don't technically
exist on the base-chain. Think of the Digital Asset register as a DNS for smart contracts.

The asset metadata includes:
* The full [contract specification]. Validator nodes will use this in conjuction with the initial state to intialise and
  then run the contract. The contract specification is immutable for the lifetime of the contract.
* The owner's public key. This will typically be linked to a Yat so that that clients can easily ascertain who issued
  the contract and whether the contract is legitimate.
* The [contract name]. The name is purely informational, is OPTIONAL, does not have to be unique and is a UTF-8 string limited to 64 bytes.
* [Delegate authority]. The delegate authority is a [TariScript] script that delegates authority for [`UpdateSigner`]
  transactions.

#### Owner Collateral

The owner collateral is a small staked amount of at least `MINIMUM_OWNER_COLLATERAL`.
The amount is hard-coded into consensus rules and is a nominal amount to prevent spam, and encourages asset owners to
tidy up after themselves when a contract winds down.

Initially, `MINIMUM_OWNER_COLLATERAL` is set at 100 Tari, but MAY be changed across network upgrades.

The owner collateral MUST be present in the [Asset Registration transaction].

Assuming the collateral is represented by the UTXO commitment $C = kG + vH$, the minimum requirement is verified by
having the range-proof commit to $(k, v - v_\mathrm{min})$ rather than the usual  $(k, v)$.

The owner collateral UTXO MUST have the `OWNER_COLLATERAL` output feature flag set.

The owner collateral MUST be spent at every checkpoint into the new checkpoint transaction. [? - does it?]


#### Peg-out transaction

#### Peg-in transaction

#### Side-chain funding transaction

#### Refund transaction

#### Checkpoint transaction

#### Slashing authorised signers

#### Updating authorised signers

#### Contract-creation time-out

#### DAN contract template specification

#### Validator Node collateral
[Validator Node collateral]: #validator-node-collateral

Validator Nodes MUST stake collateral as part of their registration. The amount staked can be any amount, as long as it
is greater than `VALIDATOR_NODE_COLLATERAL`. This value is specified in the consensus code and is initially set
at least 10,000 Tari. This value can changed in a network upgrade.

The collateral stake is locked up for the entire period that the Validator Node is registered.
The stake MUST be recovered when the validator node de-registers.

This collateral cannot be slashed. There are individual contract stakes that can be slashed in response to byzantine
validator behaviour.

The primary purpose of the stake is to act as a Sybil attack deterrent.

The stake is locked up for a minimum period of `MINIMUM_VALIDATION_PERIOD`. This value is initially set at three months.

The requirements MUST be present in the [Validator Node registration] transaction and are enforced by consensus.


[RFC-0001]: RFC-0001_overview.md