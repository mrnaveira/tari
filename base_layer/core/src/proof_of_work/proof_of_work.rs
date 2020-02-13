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

use crate::{
    blocks::BlockHeader,
    proof_of_work::{blake_pow::blake_difficulty, monero_rx::monero_difficulty, Difficulty},
};
use bytes::{self, BufMut};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fmt::{Display, Error, Formatter},
};
use tari_crypto::tari_utilities::hex::Hex;

pub trait AchievedDifficulty {}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PowAlgorithm {
    Monero = 0,
    Blake = 1,
}

/// Used to compare proof of work difficulties without scaling factors
#[derive(Debug, Clone, PartialEq)]
pub enum Ordering {
    GreaterThan,
    LessThan,
    Equal,
    Indeterminate,
}

impl TryFrom<u64> for PowAlgorithm {
    type Error = String;

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(PowAlgorithm::Monero),
            1 => Ok(PowAlgorithm::Blake),
            _ => Err("Invalid PoWAlgorithm".into()),
        }
    }
}

/// The proof of work data structure that is included in the block header. There's some non-Rustlike redundancy here
/// to make serialization more straightforward
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofOfWork {
    /// The total accumulated difficulty for each proof of work algorithms for all blocks since Genesis,
    /// but not including this block, tracked separately.
    pub accumulated_monero_difficulty: Difficulty,
    pub accumulated_blake_difficulty: Difficulty,
    /// The algorithm used to mine this block
    pub pow_algo: PowAlgorithm,
    /// Supplemental proof of work data. For example for Blake, this would be empty (only the block header is
    /// required), but for Monero merge mining we need the Monero block header and RandomX seed hash.
    pub pow_data: Vec<u8>,
}

impl Default for ProofOfWork {
    fn default() -> Self {
        Self {
            accumulated_monero_difficulty: Difficulty::default(),
            accumulated_blake_difficulty: Difficulty::default(),
            pow_algo: PowAlgorithm::Blake,
            pow_data: vec![],
        }
    }
}

impl ProofOfWork {
    /// Create a new `ProofOfWork` instance. Except for the algorithm used, the fields are uninitialized.
    /// [achieved_difficulty] and [add_difficulty] can be used subsequently to properly populate the struct's fields.
    pub fn new(pow_algo: PowAlgorithm) -> Self {
        Self {
            pow_algo,
            accumulated_monero_difficulty: Difficulty::default(),
            accumulated_blake_difficulty: Difficulty::default(),
            pow_data: vec![],
        }
    }

    /// This function  will calculate the achieved difficulty for the proof of work
    /// given the block header.
    /// This function is used to validate proofs of work generated by miners.
    ///
    /// Generally speaking, the difficulty is roughly how many mining attempts a miner will make, _on average_ before
    /// finding a nonce that meets the difficulty target.
    ///
    /// In actuality, the difficulty is _defined_ as the maximum target value (u265) divided by the block header hash
    /// (as a u256)
    ///
    /// If there are any problems with calculating a difficulty (e.g. an invalid header), then the function returns a
    /// difficulty of one.
    pub fn achieved_difficulty(header: &BlockHeader) -> Difficulty {
        match header.pow.pow_algo {
            PowAlgorithm::Monero => monero_difficulty(header),
            PowAlgorithm::Blake => blake_difficulty(header),
        }
    }

    /// Calculates the total _ accumulated difficulty for the blockchain from the genesis block up until,
    /// but _not including_ this block.
    ///
    /// This uses a geometric mean to compare the two difficulties. See Issue #1075 (https://github.com/tari-project/tari/issues/1075) as to why this was done
    ///
    /// The total accumulated difficulty is most often used to decide on which of two forks is the longest chain.
    pub fn total_accumulated_difficulty(&self) -> Difficulty {
        let d = (self.accumulated_monero_difficulty.as_u64() as f64 *
            self.accumulated_blake_difficulty.as_u64() as f64)
            .sqrt();

        Difficulty::from(d.ceil() as u64)
    }

    /// Replaces the `next` proof of work's difficulty with the sum of this proof of work's total cumulative
    /// difficulty and the provided `added_difficulty`.
    pub fn add_difficulty(&mut self, prev: &ProofOfWork, added_difficulty: Difficulty) {
        let (m, b) = match prev.pow_algo {
            PowAlgorithm::Monero => (
                prev.accumulated_monero_difficulty + added_difficulty,
                prev.accumulated_blake_difficulty,
            ),
            PowAlgorithm::Blake => (
                prev.accumulated_monero_difficulty,
                prev.accumulated_blake_difficulty + added_difficulty,
            ),
        };
        self.accumulated_blake_difficulty = b;
        self.accumulated_monero_difficulty = m;
    }

    /// Compare the difficulties of this and another proof of work, without knowing anything about scaling factors.
    /// Even without scaling factors, it is often possible to definitively order difficulties.
    pub fn partial_cmp(&self, other: &ProofOfWork) -> Ordering {
        if self.accumulated_blake_difficulty == other.accumulated_blake_difficulty &&
            self.accumulated_monero_difficulty == other.accumulated_monero_difficulty
        {
            Ordering::Equal
        } else if self.accumulated_blake_difficulty <= other.accumulated_blake_difficulty &&
            self.accumulated_monero_difficulty <= other.accumulated_monero_difficulty
        {
            Ordering::LessThan
        } else if self.accumulated_blake_difficulty >= other.accumulated_blake_difficulty &&
            self.accumulated_monero_difficulty >= other.accumulated_monero_difficulty
        {
            Ordering::GreaterThan
        } else {
            Ordering::Indeterminate
        }
    }

    /// Serialises the ProofOfWork instance into a byte string. Useful for feeding the PoW into a hash function.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        buf.put_u8(*&self.pow_algo as u8);
        buf.put_u64_le(self.accumulated_monero_difficulty.as_u64());
        buf.put_u64_le(self.accumulated_blake_difficulty.as_u64());
        buf.put_slice(&self.pow_data);
        buf
    }
}

impl Display for PowAlgorithm {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), Error> {
        let algo = match self {
            PowAlgorithm::Monero => "Monero",
            PowAlgorithm::Blake => "Blake",
        };
        fmt.write_str(&format!("{}", algo))
    }
}

impl Display for ProofOfWork {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), Error> {
        fmt.write_str(&format!(
            "Mining algorithm: {}, \nTotal accumulated difficulty: \nMonero={}, Blake={}\nPow data: {}",
            self.pow_algo,
            self.accumulated_monero_difficulty,
            self.accumulated_blake_difficulty,
            self.pow_data.to_hex(),
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::proof_of_work::{
        proof_of_work::{Ordering, PowAlgorithm, ProofOfWork},
        Difficulty,
    };

    #[test]
    fn display() {
        let pow = ProofOfWork::default();
        assert_eq!(
            &format!("{}", pow),
            "Mining algorithm: Blake, \nTotal accumulated difficulty: \nMonero=1, Blake=1\nPow data: "
        );
    }

    #[test]
    fn to_bytes() {
        let mut pow = ProofOfWork::default();
        pow.accumulated_monero_difficulty = Difficulty::from(65);
        pow.accumulated_blake_difficulty = Difficulty::from(257);
        pow.pow_algo = PowAlgorithm::Blake;
        assert_eq!(pow.to_bytes(), vec![1, 65, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn total_difficulty() {
        let mut pow = ProofOfWork::default();
        // Simple cases
        pow.accumulated_monero_difficulty = 500.into();
        pow.accumulated_blake_difficulty = 100.into();
        assert_eq!(pow.total_accumulated_difficulty(), 224.into(), "Case 1");
        pow.accumulated_monero_difficulty = 50.into();
        pow.accumulated_blake_difficulty = 1000.into();
        assert_eq!(pow.total_accumulated_difficulty(), 224.into(), "Case 2");
        // Edge cases - Very large OOM difficulty differences
        pow.accumulated_monero_difficulty = 444.into();
        pow.accumulated_blake_difficulty = 1_555_222_888_555_555.into();
        assert_eq!(pow.total_accumulated_difficulty(), 830_974_707.into(), "Case 3");
        pow.accumulated_monero_difficulty = 1.into();
        pow.accumulated_blake_difficulty = 15_222_333_444_555_666_777.into();
        assert_eq!(pow.total_accumulated_difficulty(), 3_901_580_891.into(), "Case 4");
    }

    #[test]
    fn add_difficulty() {
        let mut pow = ProofOfWork::new(PowAlgorithm::Monero);
        pow.accumulated_blake_difficulty = Difficulty::from(42);
        pow.accumulated_monero_difficulty = Difficulty::from(420);
        let mut pow2 = ProofOfWork::default();
        pow2.add_difficulty(&pow, Difficulty::from(80));
        assert_eq!(pow2.accumulated_blake_difficulty, Difficulty::from(42));
        assert_eq!(pow2.accumulated_monero_difficulty, Difficulty::from(500));
    }

    #[test]
    fn partial_cmp() {
        let mut pow1 = ProofOfWork::default();
        let mut pow2 = ProofOfWork::default();
        // (0,0) vs (0,0)
        assert_eq!(pow1.partial_cmp(&pow2), Ordering::Equal);
        pow1.accumulated_monero_difficulty = 100.into();
        // (100,0) vs (0,0)
        assert_eq!(pow1.partial_cmp(&pow2), Ordering::GreaterThan);
        pow2.accumulated_blake_difficulty = 50.into();
        // (100,0) vs (0,50)
        assert_eq!(pow1.partial_cmp(&pow2), Ordering::Indeterminate);
        pow2.accumulated_monero_difficulty = 110.into();
        // (100,0) vs (110, 50)
        assert_eq!(pow1.partial_cmp(&pow2), Ordering::LessThan);
        pow1.accumulated_blake_difficulty = 50.into();
        // (100,50) vs (110, 50)
        assert_eq!(pow1.partial_cmp(&pow2), Ordering::LessThan);
        pow1.accumulated_monero_difficulty = 110.into();
        // (110,50) vs (110, 50)
        assert_eq!(pow1.partial_cmp(&pow2), Ordering::Equal);
        pow1.accumulated_monero_difficulty = 200.into();
        pow1.accumulated_blake_difficulty = 80.into();
        // (200,80) vs (110, 50)
        assert_eq!(pow1.partial_cmp(&pow2), Ordering::GreaterThan);
    }
}
