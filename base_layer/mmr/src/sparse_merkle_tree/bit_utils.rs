// Copyright 2023. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::sparse_merkle_tree::{NodeKey, SMTError};

/// Gets the bit at an offset from the most significant bit. Does NOT perform range checking
#[inline]
pub(crate) fn get_bit(data: &[u8], position: usize) -> usize {
    if (data[position / 8] as usize) & (1 << (8 - 1 - (position % 8))) > 0 {
        return 1;
    }
    0
}

/// Sets the n-th bit in a byte array to the given value. `position` 0 is the most significant bit.
///
/// # Panics
/// `set_bit` will panic if
/// * `position` is out of bounds
/// * `value` is not 0 or 1
#[inline]
pub(crate) fn set_bit(data: &mut [u8], position: usize, value: usize) {
    match value {
        0 => data[position / 8] &= !(1 << (7 - (position % 8))),
        1 => data[position / 8] |= 1 << (7 - (position % 8)),
        _ => panic!("Invalid bit value"),
    }
}

/// Given two node keys, this function returns the number of bits that are common to both keys, starting from the most
/// significant bit. This function is used to tell you the height at which two node keys would diverge in the sparse
/// merkle tree. For example, key 0110 and 0101 would diverge at height 2, because the first two bits are the same.
#[inline]
pub(crate) fn count_common_prefix(a: &NodeKey, b: &NodeKey) -> usize {
    let mut offset = 0;
    let n = a.len().min(b.len());
    let a = a.as_slice();
    let b = b.as_slice();
    while offset < n && a[offset] == b[offset] {
        offset += 1;
    }
    if offset == n {
        return offset * 8;
    }
    let mut i = 0;
    while get_bit(&a[offset..=offset], i) == get_bit(&b[offset..=offset], i) {
        i += 1;
    }
    offset * 8 + i
}

/// For branch nodes, the key is the first `height` bits of all descendant node keys. This function calculates the
/// branch key for a given key and height.
#[inline]
pub fn height_key(key: &NodeKey, height: usize) -> NodeKey {
    let mut result = NodeKey::default();
    // Keep the first `height` bits and ignore the rest
    let key = key.as_slice();
    let bytes = result.as_mut_slice();
    // First height/8 bytes are the same, so just copy
    bytes[0..height / 8].copy_from_slice(&key[0..height / 8]);
    // The height/8th byte is only partially copied, so mask the byte & 11100000, where the number of 1s is
    // height % 8
    bytes[height / 8] = key[height / 8] & !(0xff >> (height % 8));
    result
}

pub fn path_matches_key(key: &NodeKey, path: &[TraverseDirection]) -> bool {
    let height = path.len();

    let prefix = path
        .iter()
        .enumerate()
        .fold(NodeKey::default(), |mut prefix, (i, dir)| {
            let bit = match dir {
                TraverseDirection::Left => 0,
                TraverseDirection::Right => 1,
            };
            set_bit(prefix.as_mut_slice(), i, bit);
            prefix
        });
    count_common_prefix(key, &prefix) >= height
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraverseDirection {
    Left,
    Right,
}

/// Checks whether the `child_key` would be a left or right child of the `parent_key` at the given height
pub fn traverse_direction(
    parent_height: usize,
    parent_key: &NodeKey,
    child_key: &NodeKey,
) -> Result<TraverseDirection, SMTError> {
    let common_prefix = count_common_prefix(parent_key, child_key);
    if common_prefix < parent_height {
        return Err(SMTError::InvalidChildKey {
            height: parent_height,
            child_key: child_key.clone(),
            parent_key: parent_key.clone(),
        });
    }

    match get_bit(child_key.as_slice(), parent_height) {
        0 => Ok(TraverseDirection::Left),
        1 => Ok(TraverseDirection::Right),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use super::*;
    use crate::sparse_merkle_tree::{bit_utils::count_common_prefix, NodeKey};

    #[test]
    fn test_common_prefix() {
        let a = NodeKey::from(b"abcdefgh12345678abcdefgh12345678");
        let b = NodeKey::from(b"abcdefgh12345678abcdefgh12345678");
        assert_eq!(count_common_prefix(&a, &b), 256);

        let b = NodeKey::from(b"abcDEFgh12345678abcdefgh12345678");
        // 'd' in binary is 01100100
        // 'D' in binary is 01000100
        assert_eq!(count_common_prefix(&a, &b), 3 * 8 + 2);

        let b = NodeKey::from(b"\xffbcdefgh12345678abcdefgh12345678");
        assert_eq!(count_common_prefix(&a, &b), 0);
    }

    #[test]
    fn traverse_directions() {
        let parent_key = NodeKey::try_from(b"\xffbcdefgh12345678abcdefgh12345678").unwrap();
        // 10111111 in hex is 0xBF
        let child_key = NodeKey::try_from(b"\xBFbcdefgh12345678abcdefgh12345678").unwrap();
        assert_eq!(
            traverse_direction(0, &parent_key, &child_key).unwrap(),
            TraverseDirection::Right
        );
        assert_eq!(
            traverse_direction(1, &parent_key, &child_key).unwrap(),
            TraverseDirection::Left
        );
        // 111... doesn't match 101.. to 2 places, so is an error
        let err = traverse_direction(2, &parent_key, &child_key);
        let expected_err = Err(SMTError::InvalidChildKey {
            height: 2,
            child_key,
            parent_key: parent_key.clone(),
        });
        assert_eq!(err, expected_err);
        // 11011111 in hex is 0xDF
        let child_key = NodeKey::try_from(b"\xDFbcdefgh12345678abcdefgh12345678").unwrap();
        assert_eq!(
            traverse_direction(0, &parent_key, &child_key).unwrap(),
            TraverseDirection::Right
        );
        // matches to 1 place, next is a 1, so is a right child
        assert_eq!(
            traverse_direction(1, &parent_key, &child_key).unwrap(),
            TraverseDirection::Right
        );
        // matches to 2 places, next is a 0, so is a left child
        assert_eq!(
            traverse_direction(2, &parent_key, &child_key).unwrap(),
            TraverseDirection::Left
        );

        let parent_key = NodeKey::try_from(b"abcdefgh\x082345678abcdefgh12345678").unwrap();
        let child_key = NodeKey::try_from(b"abcdefgh\x0A2345678abcdefgh12345678").unwrap();
        // 0x8 in binary is 00001000
        // 0xA in binary is 00001010
        // matches to 8*8 + 5 places, next is a 0, so is a left child
        assert_eq!(
            traverse_direction(69, &parent_key, &child_key).unwrap(),
            TraverseDirection::Left
        );
        // 0xC in binary is 00001100
        // matches to 8*8 + 5 places, next is a 1, so is a right child
        let child_key = NodeKey::try_from(b"abcdefgh\x0C2345678abcdefgh12345678").unwrap();
        assert_eq!(
            traverse_direction(69, &parent_key, &child_key).unwrap(),
            TraverseDirection::Right
        );

        // doesn't match to 70 places, so is an error
        let err = traverse_direction(71, &parent_key, &child_key);
        let expected_err: Result<TraverseDirection, _> = Err(SMTError::InvalidChildKey {
            height: 71,
            child_key,
            parent_key,
        });
        assert_eq!(err, expected_err);
    }

    #[test]
    fn height_keys() {
        let key = NodeKey::try_from(b"abcdefgh12345678abcdefgh12345678").unwrap();
        let hkey = height_key(&key, 0);
        assert_eq!(hkey.as_slice(), &[0u8; 32]);
        let hkey = height_key(&key, 3);
        let expected = NodeKey::from([
            96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(hkey, expected);
        let hkey = height_key(&key, 16);
        // 'a' in decimal is 97
        let expected = NodeKey::from([
            97, 98, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(hkey, expected);
        let hkey = height_key(&key, 5 * 8 + 2);
        // 102 in binary is 01100110
        let expected = NodeKey::from([
            97, 98, 99, 100, 101, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(hkey, expected);
    }

    #[test]
    fn set_bits() {
        let mut val = [0b10101010, 0b01010101];
        set_bit(&mut val, 0, 1);
        assert_eq!(val, [0b10101010, 0b01010101]);
        set_bit(&mut val, 1, 1);
        assert_eq!(val, [0b11101010, 0b01010101]);
        set_bit(&mut val, 2, 1);
        assert_eq!(val, [0b11101010, 0b01010101]);
        set_bit(&mut val, 3, 1);
        assert_eq!(val, [0b11111010, 0b01010101]);
        set_bit(&mut val, 4, 1);
        assert_eq!(val, [0b11111010, 0b01010101]);
        set_bit(&mut val, 5, 1);
        assert_eq!(val, [0b11111110, 0b01010101]);
        set_bit(&mut val, 6, 1);
        assert_eq!(val, [0b11111110, 0b01010101]);
        set_bit(&mut val, 7, 1);
        assert_eq!(val, [0b11111111, 0b01010101]);
        set_bit(&mut val, 8, 0);
        assert_eq!(val, [0b11111111, 0b01010101]);
        set_bit(&mut val, 9, 0);
        assert_eq!(val, [0b11111111, 0b00010101]);
        set_bit(&mut val, 10, 0);
        assert_eq!(val, [0b11111111, 0b00010101]);
        set_bit(&mut val, 11, 0);
        assert_eq!(val, [0b11111111, 0b00000101]);
        set_bit(&mut val, 12, 0);
        assert_eq!(val, [0b11111111, 0b00000101]);
        set_bit(&mut val, 13, 0);
        assert_eq!(val, [0b11111111, 0b00000001]);
        set_bit(&mut val, 14, 0);
        assert_eq!(val, [0b11111111, 0b00000001]);
        set_bit(&mut val, 15, 0);
        assert_eq!(val, [0b11111111, 0b00000000]);
    }

    #[test]
    fn get_bits() {
        let val = [0b10101010, 0b10101010, 0b00000000, 0b11111111];
        for i in 0..16 {
            assert_eq!(get_bit(&val, i), (i + 1) % 2);
        }
        for i in 16..24 {
            assert_eq!(get_bit(&val, i), 0);
        }
        for i in 24..32 {
            assert_eq!(get_bit(&val, i), 1);
        }
    }
}
