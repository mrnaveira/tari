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

This RFC supercedes and deprecates several older RFCs:
  - [RFC-0301: Namespace Registration](RFCD-0301_NamespaceRegistration.md)
  - [RFC-0302: Validator Nodes](RFC-0302_ValidatorNodes.md)
  - [RFC-0304: Validator Node committee selection](RFC-0304_VNCommittees.md)
  - [RFC-0345: Asset Life cycle](RFC-0345_AssetLifeCycle.md)

Several RFC documents are in the process of being revised in order to fit into this proposed framework:

* [RFC-0300: The Digital Assets Network](RFC-0300_DAN.md)
* [RFC-0340: Validator Node Consensus](RFC-0340_VNConsensusOverview.md)

### Motivation
There are many ways to skin a cat.
The philosophy guiding the approach in the RFC is one that permits
scaling of the network to handle in the region of **1 billion messages per day** network-wide and
**1 billion digital assets**
with **near real-time user experience** on asset state retrieval, updating and transfer,
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

It's been mentioned in other RFCs ([RFC-0001])

### The (side-chain)-(contract)-(validator node) relationship

### Asset accounts

### Side-chain architecture

### Validator Node registration requirements

### Contract creation flow

#### The owner collects data

#### Metadata specification

#### Owner Collateral

#### Peg-out transaction

#### Peg-in transaction

#### Side-chain funding transaction

#### Refund transaction

#### Checkpoint transaction

#### Slashing authorised signers

#### Updating authorised signers

#### Contract-creation time-out

#### DAN contract template specification

[RFC-0001]: RFC-0001_overview.md