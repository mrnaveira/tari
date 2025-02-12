// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::{
    collections::HashMap,
    ops::{Add, RangeInclusive},
};

use chrono::{DateTime, Duration, Utc};
use tari_common::configuration::Network;
use tari_common_types::epoch::VnEpoch;
use tari_script::{script, OpcodeVersion};
use tari_utilities::epoch_time::EpochTime;

use crate::{
    borsh::SerializedSize,
    consensus::network::NetworkConsensus,
    proof_of_work::{Difficulty, PowAlgorithm},
    transactions::{
        tari_amount::{uT, MicroTari, T},
        transaction_components::{
            OutputFeatures,
            OutputFeaturesVersion,
            OutputType,
            RangeProofType,
            TransactionInputVersion,
            TransactionKernelVersion,
            TransactionOutputVersion,
        },
        weight::TransactionWeight,
    },
};

/// This is the inner struct used to control all consensus values.
#[derive(Debug, Clone)]
pub struct ConsensusConstants {
    /// The height at which these constants become effective
    effective_from_height: u64,
    /// The minimum maturity a coinbase utxo must have, in number of blocks
    coinbase_min_maturity: u64,
    /// Current version of the blockchain
    blockchain_version: u16,
    /// The blockchain version that are accepted. Values outside of this range will be rejected.
    valid_blockchain_version_range: RangeInclusive<u16>,
    /// The Future Time Limit (FTL) of the blockchain in seconds. This is the max allowable timestamp that is accepted.
    /// We suggest using T*N/20 where T = desired chain target time, and N = block_window
    future_time_limit: u64,
    /// When doing difficulty adjustments and FTL calculations this is the amount of blocks we look at
    /// <https://github.com/zawy12/difficulty-algorithms/issues/14>
    difficulty_block_window: u64,
    /// Maximum transaction weight used for the construction of new blocks.
    max_block_transaction_weight: u64,
    /// This is how many blocks we use to count towards the median timestamp to ensure the block chain timestamp moves
    /// forward
    median_timestamp_count: usize,
    /// This is the initial emission curve amount
    pub(in crate::consensus) emission_initial: MicroTari,
    /// This is the emission curve decay factor as a sum of fraction powers of two. e.g. [1,2] would be 1/2 + 1/4. [2]
    /// would be 1/4
    pub(in crate::consensus) emission_decay: &'static [u64],
    /// This is the emission curve tail amount
    pub(in crate::consensus) emission_tail: MicroTari,
    /// This is the maximum age a monero merge mined seed can be reused
    /// Monero forces a change every height mod 2048 blocks
    max_randomx_seed_height: u64,
    /// This keeps track of the block split targets and which algo is accepted
    /// Ideally this should count up to 100. If this does not you will reduce your target time.
    proof_of_work: HashMap<PowAlgorithm, PowAlgorithmConstants>,
    /// This is to keep track of the value inside of the genesis block
    faucet_value: MicroTari,
    /// Transaction Weight params
    transaction_weight: TransactionWeight,
    /// Maximum byte size of TariScript
    max_script_byte_size: usize,
    /// Range of valid transaction input versions
    input_version_range: RangeInclusive<TransactionInputVersion>,
    /// Range of valid transaction output (and features) versions
    output_version_range: OutputVersionRange,
    /// Range of valid transaction kernel versions
    kernel_version_range: RangeInclusive<TransactionKernelVersion>,
    /// An allowlist of output types
    permitted_output_types: &'static [OutputType],
    /// The allowlist of range proof types
    permitted_range_proof_types: &'static [RangeProofType],
    /// Coinbase outputs are allowed to have metadata, but it has the following length limit
    coinbase_output_features_extra_max_length: u32,
    /// Epoch duration in blocks
    vn_epoch_length: u64,
    /// The number of Epochs that a validator node registration is valid
    vn_validity_period_epochs: VnEpoch,
    vn_registration_min_deposit_amount: MicroTari,
    vn_registration_lock_height: u64,
    vn_registration_shuffle_interval: VnEpoch,
}

// todo: remove this once OutputFeaturesVersion is removed in favor of just TransactionOutputVersion
#[derive(Debug, Clone)]
pub struct OutputVersionRange {
    pub outputs: RangeInclusive<TransactionOutputVersion>,
    pub features: RangeInclusive<OutputFeaturesVersion>,
    pub opcode: RangeInclusive<OpcodeVersion>,
}

/// All V0 for Inputs, Outputs + Features, Kernels
fn version_zero() -> (
    RangeInclusive<TransactionInputVersion>,
    OutputVersionRange,
    RangeInclusive<TransactionKernelVersion>,
) {
    let input_version_range = TransactionInputVersion::V0..=TransactionInputVersion::V0;
    let kernel_version_range = TransactionKernelVersion::V0..=TransactionKernelVersion::V0;
    let output_version_range = OutputVersionRange {
        outputs: TransactionOutputVersion::V0..=TransactionOutputVersion::V0,
        features: OutputFeaturesVersion::V0..=OutputFeaturesVersion::V0,
        opcode: OpcodeVersion::V0..=OpcodeVersion::V0,
    };

    (input_version_range, output_version_range, kernel_version_range)
}

/// This is just a convenience struct to put all the info into a hashmap for each algorithm
#[derive(Clone, Debug)]
pub struct PowAlgorithmConstants {
    /// NB this is very important to set this as 6 * the target time
    pub max_target_time: u64,
    pub min_difficulty: Difficulty,
    pub max_difficulty: Difficulty,
    /// target time is calculated as desired chain target time / block %.
    /// example 120/0.5 = 240 for a 50% of the blocks, chain target time of 120.
    pub target_time: u64,
}

const ESMERALDA_FAUCET_VALUE: u64 = 5_025_126_665_742_480;

// The target time used by the difficulty adjustment algorithms, their target time is the target block interval * PoW
// algorithm count
impl ConsensusConstants {
    /// The height at which these constants become effective
    pub fn effective_from_height(&self) -> u64 {
        self.effective_from_height
    }

    /// This gets the emission curve values as (initial, decay, tail)
    pub fn emission_amounts(&self) -> (MicroTari, &'static [u64], MicroTari) {
        (self.emission_initial, self.emission_decay, self.emission_tail)
    }

    /// The min height maturity a coinbase utxo must have.
    pub fn coinbase_min_maturity(&self) -> u64 {
        self.coinbase_min_maturity
    }

    /// Current version of the blockchain.
    pub fn blockchain_version(&self) -> u16 {
        self.blockchain_version
    }

    /// Returns the valid blockchain version range
    pub fn valid_blockchain_version_range(&self) -> &RangeInclusive<u16> {
        &self.valid_blockchain_version_range
    }

    /// This returns the FTL (Future Time Limit) for blocks.
    /// Any block with a timestamp greater than this is rejected.
    pub fn ftl(&self) -> EpochTime {
        // Timestamp never negative
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_possible_wrap)]
        (Utc::now()
            .add(Duration::seconds(self.future_time_limit as i64))
            .timestamp() as u64)
            .into()
    }

    /// This returns the FTL(Future Time Limit) for blocks
    /// Any block with a timestamp greater than this is rejected.
    /// This function returns the FTL as a UTC datetime
    pub fn ftl_as_time(&self) -> DateTime<Utc> {
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_possible_wrap)]
        Utc::now().add(Duration::seconds(self.future_time_limit as i64))
    }

    /// When doing difficulty adjustments and FTL calculations this is the amount of blocks we look at.
    pub fn get_difficulty_block_window(&self) -> u64 {
        self.difficulty_block_window
    }

    /// Maximum transaction weight used for the construction of new blocks.
    pub fn get_max_block_transaction_weight(&self) -> u64 {
        self.max_block_transaction_weight
    }

    /// Maximum transaction weight used for the construction of new blocks. It leaves place for 1 kernel and 1 output
    pub fn get_max_block_weight_excluding_coinbase(&self) -> u64 {
        self.max_block_transaction_weight - self.coinbase_weight()
    }

    pub fn coinbase_weight(&self) -> u64 {
        // TODO: We do not know what script, features etc a coinbase has - this should be max coinbase size?
        let output_features = OutputFeatures { ..Default::default() };
        let features_and_scripts_size = self.transaction_weight.round_up_features_and_scripts_size(
            output_features.get_serialized_size() + script![Nop].get_serialized_size(),
        );
        self.transaction_weight.calculate(1, 0, 1, features_and_scripts_size)
    }

    pub fn coinbase_output_features_extra_max_length(&self) -> u32 {
        self.coinbase_output_features_extra_max_length
    }

    /// The amount of PoW algorithms used by the Tari chain.
    pub fn get_pow_algo_count(&self) -> u64 {
        self.proof_of_work.len() as u64
    }

    /// The target time used by the difficulty adjustment algorithms, their target time is the target block interval /
    /// algo block percentage
    pub fn get_diff_target_block_interval(&self, pow_algo: PowAlgorithm) -> u64 {
        match self.proof_of_work.get(&pow_algo) {
            Some(v) => v.target_time,
            _ => 0,
        }
    }

    /// The maximum time a block is considered to take. Used by the difficulty adjustment algorithms
    /// Multiplied by the PoW algorithm block percentage.
    pub fn get_difficulty_max_block_interval(&self, pow_algo: PowAlgorithm) -> u64 {
        match self.proof_of_work.get(&pow_algo) {
            Some(v) => v.max_target_time,
            _ => 0,
        }
    }

    /// This is how many blocks we use to count towards the median timestamp to ensure the block chain moves forward.
    pub fn get_median_timestamp_count(&self) -> usize {
        self.median_timestamp_count
    }

    /// The maximum serialized byte size of TariScript
    pub fn get_max_script_byte_size(&self) -> usize {
        self.max_script_byte_size
    }

    /// This is the min initial difficulty that can be requested for the pow
    pub fn min_pow_difficulty(&self, pow_algo: PowAlgorithm) -> Difficulty {
        match self.proof_of_work.get(&pow_algo) {
            Some(v) => v.min_difficulty,
            _ => 0.into(),
        }
    }

    /// This will return the value of the genesis block faucets
    pub fn faucet_value(&self) -> MicroTari {
        self.faucet_value
    }

    pub fn max_pow_difficulty(&self, pow_algo: PowAlgorithm) -> Difficulty {
        match self.proof_of_work.get(&pow_algo) {
            Some(v) => v.max_difficulty,
            _ => 0.into(),
        }
    }

    /// The maximum age a monero merge mined seed can be reused
    pub fn max_randomx_seed_height(&self) -> u64 {
        self.max_randomx_seed_height
    }

    pub fn transaction_weight(&self) -> &TransactionWeight {
        &self.transaction_weight
    }

    /// The range of acceptable transaction input versions
    pub fn input_version_range(&self) -> &RangeInclusive<TransactionInputVersion> {
        &self.input_version_range
    }

    /// The range of acceptable transaction output and features versions
    pub fn output_version_range(&self) -> &OutputVersionRange {
        &self.output_version_range
    }

    /// The range of acceptable transaction kernel versions
    pub fn kernel_version_range(&self) -> &RangeInclusive<TransactionKernelVersion> {
        &self.kernel_version_range
    }

    /// Returns the permitted OutputTypes
    pub fn permitted_output_types(&self) -> &[OutputType] {
        self.permitted_output_types
    }

    /// Returns the permitted range proof types
    pub fn permitted_range_proof_types(&self) -> &[RangeProofType] {
        self.permitted_range_proof_types
    }

    pub fn validator_node_validity_period_epochs(&self) -> VnEpoch {
        self.vn_validity_period_epochs
    }

    pub fn validator_node_registration_shuffle_interval(&self) -> VnEpoch {
        self.vn_registration_shuffle_interval
    }

    pub fn validator_node_registration_min_deposit_amount(&self) -> MicroTari {
        self.vn_registration_min_deposit_amount
    }

    pub fn validator_node_registration_min_lock_height(&self) -> u64 {
        self.vn_registration_lock_height
    }

    /// Returns the current epoch from the given height
    pub fn block_height_to_epoch(&self, height: u64) -> VnEpoch {
        VnEpoch(height / self.vn_epoch_length)
    }

    /// Returns the block height of the start of the given epoch
    pub fn epoch_to_block_height(&self, epoch: VnEpoch) -> u64 {
        epoch.as_u64() * self.vn_epoch_length
    }

    pub fn epoch_length(&self) -> u64 {
        self.vn_epoch_length
    }

    pub fn localnet() -> Vec<Self> {
        let difficulty_block_window = 90;
        let mut algos = HashMap::new();
        algos.insert(PowAlgorithm::Sha3, PowAlgorithmConstants {
            max_target_time: 1800,
            min_difficulty: 1.into(),
            max_difficulty: 1.into(),
            target_time: 300,
        });
        algos.insert(PowAlgorithm::Monero, PowAlgorithmConstants {
            max_target_time: 1200,
            min_difficulty: 1.into(),
            max_difficulty: 1.into(),
            target_time: 200,
        });
        let (input_version_range, output_version_range, kernel_version_range) = version_zero();
        vec![ConsensusConstants {
            effective_from_height: 0,
            coinbase_min_maturity: 2,
            blockchain_version: 0,
            valid_blockchain_version_range: 0..=0,
            future_time_limit: 540,
            difficulty_block_window,
            max_block_transaction_weight: 19500,
            median_timestamp_count: 11,
            emission_initial: 18_462_816_327 * uT,
            emission_decay: &ESMERALDA_DECAY_PARAMS,
            emission_tail: 800 * T,
            max_randomx_seed_height: u64::MAX,
            proof_of_work: algos,
            faucet_value: ESMERALDA_FAUCET_VALUE.into(), // The esmeralda genesis block is re-used for localnet
            transaction_weight: TransactionWeight::latest(),
            max_script_byte_size: 2048,
            input_version_range,
            output_version_range,
            kernel_version_range,
            permitted_output_types: OutputType::all(),
            permitted_range_proof_types: RangeProofType::all(),
            vn_epoch_length: 10,
            vn_validity_period_epochs: VnEpoch(100),
            vn_registration_min_deposit_amount: MicroTari(0),
            vn_registration_lock_height: 0,
            vn_registration_shuffle_interval: VnEpoch(100),
            coinbase_output_features_extra_max_length: 64,
        }]
    }

    pub fn igor() -> Vec<Self> {
        let mut algos = HashMap::new();
        // For SHA3/Monero to have a 40/60 split:
        // sha3_target_time = monero_target_time * (100 - 40) / 40
        // monero_target_time = sha3_target_time * (100 - 60) / 60
        // target_time = monero_target_time * sha3_target_time / (monero_target_time + sha3_target_time)
        const MONERO_SPLIT: u64 = 60; // Must be < 100
        const SHA3_SPLIT: u64 = 100 - MONERO_SPLIT;
        const MONERO_TARGET_TIME: u64 = 20; // usually 200 (for a 120 average block time)
        const SHA3_TARGET_TIME: u64 = MONERO_TARGET_TIME * (100 - SHA3_SPLIT) / SHA3_SPLIT;
        algos.insert(PowAlgorithm::Sha3, PowAlgorithmConstants {
            max_target_time: SHA3_TARGET_TIME * 6,               // target_time x 6
            min_difficulty: (SHA3_TARGET_TIME * 200_000).into(), // target_time x 200_000
            max_difficulty: u64::MAX.into(),
            target_time: SHA3_TARGET_TIME, // (monero_target_time x 1.5)
        });
        algos.insert(PowAlgorithm::Monero, PowAlgorithmConstants {
            max_target_time: MONERO_TARGET_TIME * 6,           // target_time x 6
            min_difficulty: (MONERO_TARGET_TIME * 300).into(), // target_time x 300
            max_difficulty: u64::MAX.into(),
            target_time: MONERO_TARGET_TIME,
        });
        let (input_version_range, output_version_range, kernel_version_range) = version_zero();
        vec![ConsensusConstants {
            effective_from_height: 0,
            coinbase_min_maturity: 6,
            blockchain_version: 0,
            valid_blockchain_version_range: 0..=0,
            future_time_limit: 540,
            difficulty_block_window: 90,
            // 65536 =  target_block_size / bytes_per_gram =  (1024*1024) / 16
            // adj. + 95% = 127,795 - this effectively targets ~2Mb blocks closely matching the previous 19500
            // weightings
            max_block_transaction_weight: 127_795,
            median_timestamp_count: 11,
            emission_initial: 5_538_846_115 * uT,
            emission_decay: &EMISSION_DECAY,
            emission_tail: 100.into(),
            max_randomx_seed_height: u64::MAX,
            proof_of_work: algos,
            faucet_value: 1_581_548_314_320_266.into(),
            transaction_weight: TransactionWeight::v1(),
            max_script_byte_size: 2048,
            input_version_range,
            output_version_range,
            kernel_version_range,
            // igor is the first network to support the new output types
            permitted_output_types: OutputType::all(),
            permitted_range_proof_types: RangeProofType::all(),
            vn_epoch_length: 10,
            vn_validity_period_epochs: VnEpoch(3),
            vn_registration_min_deposit_amount: MicroTari(0),
            vn_registration_lock_height: 0,
            vn_registration_shuffle_interval: VnEpoch(100),
            coinbase_output_features_extra_max_length: 64,
        }]
    }

    /// *
    /// Esmeralda testnet has the following characteristics:
    /// * 2 min blocks on average (5 min SHA-3, 3 min MM)
    /// * 21 billion tXTR with a 3-year half-life
    /// * 800 T tail emission (± 1% inflation after initial 21 billion has been mined)
    /// * Coinbase lock height - 12 hours = 360 blocks
    pub fn esmeralda() -> Vec<Self> {
        let mut algos = HashMap::new();
        // For SHA3/Monero to have a 40/60 split:
        // sha3_target_time = monero_target_time * (100 - 40) / 40
        // monero_target_time = sha3_target_time * (100 - 60) / 60
        // target_time = monero_target_time * sha3_target_time / (monero_target_time + sha3_target_time)
        algos.insert(PowAlgorithm::Sha3, PowAlgorithmConstants {
            max_target_time: 1800,
            min_difficulty: 60_000_000.into(),
            max_difficulty: u64::MAX.into(),
            target_time: 300,
        });
        algos.insert(PowAlgorithm::Monero, PowAlgorithmConstants {
            max_target_time: 1200,
            min_difficulty: 60_000.into(),
            max_difficulty: u64::MAX.into(),
            target_time: 200,
        });
        let (input_version_range, output_version_range, kernel_version_range) = version_zero();
        let consensus_constants_1 = ConsensusConstants {
            effective_from_height: 0,
            coinbase_min_maturity: 6,
            blockchain_version: 0,
            valid_blockchain_version_range: 0..=0,
            future_time_limit: 540,
            difficulty_block_window: 90,
            max_block_transaction_weight: 127_795,
            median_timestamp_count: 11,
            emission_initial: 18_462_816_327 * uT,
            emission_decay: &ESMERALDA_DECAY_PARAMS,
            emission_tail: 800 * T,
            max_randomx_seed_height: 3000,
            proof_of_work: algos,
            faucet_value: ESMERALDA_FAUCET_VALUE.into(),
            transaction_weight: TransactionWeight::v1(),
            max_script_byte_size: 2048,
            input_version_range,
            output_version_range,
            kernel_version_range,
            permitted_output_types: Self::current_permitted_output_types(),
            permitted_range_proof_types: Self::current_permitted_range_proof_types(),
            vn_epoch_length: 60,
            vn_validity_period_epochs: VnEpoch(100),
            vn_registration_min_deposit_amount: MicroTari(0),
            vn_registration_lock_height: 0,
            vn_registration_shuffle_interval: VnEpoch(100),
            coinbase_output_features_extra_max_length: 64,
        };

        vec![consensus_constants_1]
    }

    /// *
    /// Stagenet has the following characteristics:
    /// * 2 min blocks on average (5 min SHA-3, 3 min MM)
    /// * 21 billion tXTR with a 3-year half-life
    /// * 800 T tail emission (± 1% inflation after initial 21 billion has been mined)
    /// * Coinbase lock height - 12 hours = 360 blocks
    pub fn stagenet() -> Vec<Self> {
        // Note these values are all placeholders for final values
        // For SHA3/Monero to have a 40/60 split:
        // sha3_target_time = monero_target_time * (100 - 40) / 40
        // monero_target_time = sha3_target_time * (100 - 60) / 60
        // target_time = monero_target_time * sha3_target_time / (monero_target_time + sha3_target_time)
        let mut algos = HashMap::new();
        algos.insert(PowAlgorithm::Sha3, PowAlgorithmConstants {
            max_target_time: 1800,
            min_difficulty: 60_000_000.into(),
            max_difficulty: u64::MAX.into(),
            target_time: 300,
        });
        algos.insert(PowAlgorithm::Monero, PowAlgorithmConstants {
            max_target_time: 1200,
            min_difficulty: 60_000.into(),
            max_difficulty: u64::MAX.into(),
            target_time: 200,
        });
        let (input_version_range, output_version_range, kernel_version_range) = version_zero();
        vec![ConsensusConstants {
            effective_from_height: 0,
            coinbase_min_maturity: 360,
            blockchain_version: 0,
            valid_blockchain_version_range: 0..=0,
            future_time_limit: 540,
            difficulty_block_window: 90,
            max_block_transaction_weight: 127_795,
            median_timestamp_count: 11,
            emission_initial: 18_462_816_327 * uT,
            emission_decay: &EMISSION_DECAY,
            emission_tail: 800 * T,
            max_randomx_seed_height: 3000,
            proof_of_work: algos,
            faucet_value: 0.into(),
            transaction_weight: TransactionWeight::v1(),
            max_script_byte_size: 2048,
            input_version_range,
            output_version_range,
            kernel_version_range,
            permitted_output_types: Self::current_permitted_output_types(),
            permitted_range_proof_types: Self::current_permitted_range_proof_types(),
            vn_epoch_length: 60,
            vn_validity_period_epochs: VnEpoch(100),
            vn_registration_min_deposit_amount: MicroTari(0),
            vn_registration_lock_height: 0,
            vn_registration_shuffle_interval: VnEpoch(100),
            coinbase_output_features_extra_max_length: 64,
        }]
    }

    pub fn nextnet() -> Vec<Self> {
        // Note these values are all placeholders for final values
        // For SHA3/Monero to have a 40/60 split:
        // sha3_target_time = monero_target_time * (100 - 40) / 40
        // monero_target_time = sha3_target_time * (100 - 60) / 60
        // target_time = monero_target_time * sha3_target_time / (monero_target_time + sha3_target_time)
        let mut algos = HashMap::new();
        algos.insert(PowAlgorithm::Sha3, PowAlgorithmConstants {
            max_target_time: 1800,
            min_difficulty: 60_000_000.into(),
            max_difficulty: u64::MAX.into(),
            target_time: 300,
        });
        algos.insert(PowAlgorithm::Monero, PowAlgorithmConstants {
            max_target_time: 1200,
            min_difficulty: 60_000.into(),
            max_difficulty: u64::MAX.into(),
            target_time: 200,
        });
        let (input_version_range, output_version_range, kernel_version_range) = version_zero();
        vec![ConsensusConstants {
            effective_from_height: 0,
            coinbase_min_maturity: 360,
            blockchain_version: 0,
            valid_blockchain_version_range: 0..=0,
            future_time_limit: 540,
            difficulty_block_window: 90,
            max_block_transaction_weight: 127_795,
            median_timestamp_count: 11,
            emission_initial: 18_462_816_327 * uT,
            emission_decay: &EMISSION_DECAY,
            emission_tail: 800 * T,
            max_randomx_seed_height: 3000,
            proof_of_work: algos,
            faucet_value: 0.into(),
            transaction_weight: TransactionWeight::v1(),
            max_script_byte_size: 2048,
            input_version_range,
            output_version_range,
            kernel_version_range,
            permitted_output_types: Self::current_permitted_output_types(),
            permitted_range_proof_types: Self::current_permitted_range_proof_types(),
            vn_epoch_length: 60,
            vn_validity_period_epochs: VnEpoch(100),
            vn_registration_min_deposit_amount: MicroTari(0),
            vn_registration_lock_height: 0,
            vn_registration_shuffle_interval: VnEpoch(100),
            coinbase_output_features_extra_max_length: 64,
        }]
    }

    pub fn mainnet() -> Vec<Self> {
        // Note these values are all placeholders for final values
        // For SHA3/Monero to have a 40/60 split:
        // sha3_target_time = monero_target_time * (100 - 40) / 40
        // monero_target_time = sha3_target_time * (100 - 60) / 60
        // target_time = monero_target_time * sha3_target_time / (monero_target_time + sha3_target_time)
        let difficulty_block_window = 90;
        let mut algos = HashMap::new();
        algos.insert(PowAlgorithm::Sha3, PowAlgorithmConstants {
            max_target_time: 1800,
            min_difficulty: 40_000.into(),
            max_difficulty: u64::MAX.into(),
            target_time: 300,
        });
        algos.insert(PowAlgorithm::Monero, PowAlgorithmConstants {
            max_target_time: 800,
            min_difficulty: 70_000_000.into(),
            max_difficulty: u64::MAX.into(),
            target_time: 200,
        });
        let (input_version_range, output_version_range, kernel_version_range) = version_zero();
        vec![ConsensusConstants {
            effective_from_height: 0,
            coinbase_min_maturity: 1,
            blockchain_version: 1,
            valid_blockchain_version_range: 0..=0,
            future_time_limit: 540,
            difficulty_block_window,
            max_block_transaction_weight: 19500,
            median_timestamp_count: 11,
            emission_initial: 10_000_000.into(),
            emission_decay: &EMISSION_DECAY,
            emission_tail: 100.into(),
            max_randomx_seed_height: u64::MAX,
            proof_of_work: algos,
            faucet_value: MicroTari::from(0),
            transaction_weight: TransactionWeight::v1(),
            max_script_byte_size: 2048,
            input_version_range,
            output_version_range,
            kernel_version_range,
            permitted_output_types: Self::current_permitted_output_types(),
            permitted_range_proof_types: Self::current_permitted_range_proof_types(),
            vn_epoch_length: 60,
            vn_validity_period_epochs: VnEpoch(100),
            vn_registration_min_deposit_amount: MicroTari(0),
            vn_registration_lock_height: 0,
            vn_registration_shuffle_interval: VnEpoch(100),
            coinbase_output_features_extra_max_length: 64,
        }]
    }

    const fn current_permitted_output_types() -> &'static [OutputType] {
        &[OutputType::Coinbase, OutputType::Standard, OutputType::Burn]
    }

    const fn current_permitted_range_proof_types() -> &'static [RangeProofType] {
        &[RangeProofType::BulletProofPlus]
    }
}

static EMISSION_DECAY: [u64; 6] = [21u64, 22, 23, 25, 26, 37];
const ESMERALDA_DECAY_PARAMS: [u64; 6] = [21u64, 22, 23, 25, 26, 37]; // less significant values don't matter

/// Class to create custom consensus constants
pub struct ConsensusConstantsBuilder {
    consensus: ConsensusConstants,
}

impl ConsensusConstantsBuilder {
    pub fn new(network: Network) -> Self {
        Self {
            consensus: NetworkConsensus::from(network)
                .create_consensus_constants()
                .pop()
                .expect("Empty consensus constants"),
        }
    }

    pub fn clear_proof_of_work(mut self) -> Self {
        self.consensus.proof_of_work = HashMap::new();
        self
    }

    pub fn add_proof_of_work(mut self, proof_of_work: PowAlgorithm, constants: PowAlgorithmConstants) -> Self {
        self.consensus.proof_of_work.insert(proof_of_work, constants);
        self
    }

    pub fn with_coinbase_lockheight(mut self, height: u64) -> Self {
        self.consensus.coinbase_min_maturity = height;
        self
    }

    pub fn with_max_script_byte_size(mut self, byte_size: usize) -> Self {
        self.consensus.max_script_byte_size = byte_size;
        self
    }

    pub fn with_max_block_transaction_weight(mut self, weight: u64) -> Self {
        self.consensus.max_block_transaction_weight = weight;
        self
    }

    pub fn with_consensus_constants(mut self, consensus: ConsensusConstants) -> Self {
        self.consensus = consensus;
        self
    }

    pub fn with_max_randomx_seed_height(mut self, height: u64) -> Self {
        self.consensus.max_randomx_seed_height = height;
        self
    }

    pub fn with_faucet_value(mut self, value: MicroTari) -> Self {
        self.consensus.faucet_value = value;
        self
    }

    pub fn with_emission_amounts(
        mut self,
        intial_amount: MicroTari,
        decay: &'static [u64],
        tail_amount: MicroTari,
    ) -> Self {
        self.consensus.emission_initial = intial_amount;
        self.consensus.emission_decay = decay;
        self.consensus.emission_tail = tail_amount;
        self
    }

    pub fn with_permitted_output_types(mut self, permitted_output_types: &'static [OutputType]) -> Self {
        self.consensus.permitted_output_types = permitted_output_types;
        self
    }

    pub fn with_permitted_range_proof_types(mut self, permitted_range_proof_types: &'static [RangeProofType]) -> Self {
        self.consensus.permitted_range_proof_types = permitted_range_proof_types;
        self
    }

    pub fn with_blockchain_version(mut self, version: u16) -> Self {
        self.consensus.blockchain_version = version;
        self
    }

    pub fn build(self) -> ConsensusConstants {
        self.consensus
    }
}

#[cfg(test)]
mod test {
    use crate::{
        consensus::{
            emission::{Emission, EmissionSchedule},
            ConsensusConstants,
        },
        transactions::tari_amount::{uT, MicroTari},
    };

    #[test]
    fn esmeralda_schedule() {
        let esmeralda = ConsensusConstants::esmeralda();
        let schedule = EmissionSchedule::new(
            esmeralda[0].emission_initial,
            esmeralda[0].emission_decay,
            esmeralda[0].emission_tail,
        );
        // No genesis block coinbase
        assert_eq!(schedule.block_reward(0), MicroTari(0));
        // Coinbases starts at block 1
        let coinbase_offset = 1;
        let first_reward = schedule.block_reward(coinbase_offset);
        assert_eq!(first_reward, esmeralda[0].emission_initial * uT);
        assert_eq!(schedule.supply_at_block(coinbase_offset), first_reward);
        let three_years = 365 * 24 * 30 * 3;
        assert_eq!(
            schedule.supply_at_block(three_years + coinbase_offset),
            10_500_682_498_903_652 * uT
        ); // Around 10.5 billion
           // Tail emission starts after block 3,574,175
        let mut rewards = schedule.iter().skip(3_574_174 + coinbase_offset as usize);
        let (block_num, reward, supply) = rewards.next().unwrap();
        assert_eq!(block_num, 3_574_175 + coinbase_offset);
        assert_eq!(reward, 800_000_598 * uT);
        assert_eq!(supply, 20_100_525_123_936_707 * uT); // Still 900 mil tokens to go when tail emission kicks in
        let (_, reward, _) = rewards.next().unwrap();
        assert_eq!(reward, esmeralda[0].emission_tail);
    }

    #[test]
    fn igor_schedule() {
        let igor = ConsensusConstants::igor();
        let schedule = EmissionSchedule::new(igor[0].emission_initial, igor[0].emission_decay, igor[0].emission_tail);
        // No genesis block coinbase
        assert_eq!(schedule.block_reward(0), MicroTari(0));
        // Coinbases starts at block 1
        let coinbase_offset = 1;
        let first_reward = schedule.block_reward(coinbase_offset);
        assert_eq!(first_reward, igor[0].emission_initial * uT);
        assert_eq!(schedule.supply_at_block(coinbase_offset), first_reward);
        let three_years = 365 * 24 * 30 * 3;
        assert_eq!(
            schedule.supply_at_block(three_years + coinbase_offset),
            3_150_642_608_358_864 * uT
        );
        // Tail emission starts after block 11_084_819
        let rewards = schedule.iter().skip(11_084_819 - 25);
        let mut previous_reward = MicroTari(0);
        for (block_num, reward, supply) in rewards {
            if reward == previous_reward {
                assert_eq!(block_num, 11_084_819 + 1);
                assert_eq!(supply, MicroTari(6_326_198_792_915_738));
                // These set of constants does not result in a tail emission equal to the specified tail emission
                assert_ne!(reward, igor[0].emission_tail);
                assert_eq!(reward, MicroTari(2_097_151));
                break;
            }
            previous_reward = reward;
        }
    }
}
