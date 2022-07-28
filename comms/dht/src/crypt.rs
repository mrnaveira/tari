// Copyright 2020, The Tari Project
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

use std::mem::size_of;

use chacha20::{
    cipher::{NewCipher, StreamCipher},
    ChaCha20,
    Key,
    Nonce,
};
use chacha20poly1305::{
    self,
    aead::{Aead, NewAead},
    ChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use tari_comms::types::{CommsPublicKey, CommsSecretKey};
use tari_crypto::{
    keys::DiffieHellmanSharedSecret,
    tari_utilities::{epoch_time::EpochTime, ByteArray},
};
use zeroize::Zeroize;

use crate::{
    comms_dht_hash_domain_challenge,
    comms_dht_hash_domain_key_message,
    comms_dht_hash_domain_key_signature,
    envelope::{DhtMessageFlags, DhtMessageHeader, DhtMessageType, NodeDestination},
    outbound::DhtOutboundError,
    version::DhtProtocolVersion,
};

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct CipherKey(chacha20::Key);
pub struct AuthenticatedCipherKey(chacha20poly1305::Key);

/// Generates a Diffie-Hellman secret `kx.G` as a `chacha20::Key` given secret scalar `k` and public key `P = x.G`.
pub fn generate_ecdh_secret(secret_key: &CommsSecretKey, public_key: &CommsPublicKey) -> [u8; 32] {
    // TODO: PK will still leave the secret in released memory. Implementing Zerioze on RistrettoPublicKey is not
    //       currently possible because (Compressed)RistrettoPoint does not implement it.
    let k = CommsPublicKey::shared_secret(secret_key, public_key);
    let mut output = [0u8; 32];

    output.copy_from_slice(k.as_bytes());
    output
}

pub fn generate_key_message(data: &[u8]) -> CipherKey {
    // domain separated hash of data (e.g. ecdh shared secret) using hashing API
    let domain_separated_hash = comms_dht_hash_domain_key_message().chain(data).finalize();

    // Domain separation uses Challenge = Blake256, thus its output has 32-byte length
    CipherKey(*Key::from_slice(domain_separated_hash.as_ref()))
}

pub fn generate_key_signature_for_authenticated_encryption(data: &[u8]) -> AuthenticatedCipherKey {
    // domain separated of data (e.g. ecdh shared secret) using hashing API
    let domain_separated_hash = comms_dht_hash_domain_key_signature().chain(data).finalize();

    // Domain separation uses Challenge = Blake256, thus its output has 32-byte length
    AuthenticatedCipherKey(*chacha20poly1305::Key::from_slice(domain_separated_hash.as_ref()))
}

/// Decrypts cipher text using ChaCha20 stream cipher given the cipher key and cipher text with integral nonce.
pub fn decrypt(cipher_key: &CipherKey, cipher_text: &[u8]) -> Result<Vec<u8>, DhtOutboundError> {
    if cipher_text.len() < size_of::<Nonce>() {
        return Err(DhtOutboundError::CipherError(
            "Cipher text is not long enough to include nonce".to_string(),
        ));
    }

    let (nonce, cipher_text) = cipher_text.split_at(size_of::<Nonce>());
    let nonce = Nonce::from_slice(nonce);
    let mut cipher_text = cipher_text.to_vec();

    let mut cipher = ChaCha20::new(&cipher_key.0, nonce);
    cipher.apply_keystream(cipher_text.as_mut_slice());
    Ok(cipher_text)
}

pub fn decrypt_with_chacha20_poly1305(
    cipher_key: &AuthenticatedCipherKey,
    cipher_signature: &[u8],
) -> Result<Vec<u8>, DhtOutboundError> {
    let nonce = [0u8; size_of::<chacha20poly1305::Nonce>()];

    let nonce_ga = chacha20poly1305::Nonce::from_slice(&nonce);

    let cipher = ChaCha20Poly1305::new(&cipher_key.0);
    let decrypted_signature = cipher
        .decrypt(nonce_ga, cipher_signature)
        .map_err(|_| DhtOutboundError::CipherError(String::from("Authenticated decryption failed")))?;

    Ok(decrypted_signature)
}

/// Encrypt the plain text using the ChaCha20 stream cipher
pub fn encrypt(cipher_key: &CipherKey, plain_text: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; size_of::<Nonce>()];
    OsRng.fill_bytes(&mut nonce);

    let nonce_ga = Nonce::from_slice(&nonce);
    let mut cipher = ChaCha20::new(&cipher_key.0, nonce_ga);

    let mut buf = vec![0u8; plain_text.len() + nonce.len()];
    buf[..nonce.len()].copy_from_slice(&nonce[..]);
    buf[nonce.len()..].copy_from_slice(plain_text);
    cipher.apply_keystream(&mut buf[nonce.len()..]);
    buf
}

/// Produces authenticated encryption of the signature using the ChaCha20-Poly1305 stream cipher,
/// refer to https://docs.rs/chacha20poly1305/latest/chacha20poly1305/# for more details.
/// Attention: as pointed in https://github.com/tari-project/tari/issues/4138, it is possible
/// to use a fixed Nonce, with homogeneous zero data, as this does not incur any security
/// vulnerabilities. However, such function is not intented to be used outside of dht scope
pub fn encrypt_with_chacha20_poly1305(
    cipher_key: &AuthenticatedCipherKey,
    signature: &[u8],
) -> Result<Vec<u8>, DhtOutboundError> {
    let nonce = [0u8; size_of::<chacha20poly1305::Nonce>()];

    let nonce_ga = chacha20poly1305::Nonce::from_slice(&nonce);
    let cipher = ChaCha20Poly1305::new(&cipher_key.0);

    // length of encrypted equals signature.len() + 16 (the latter being the tag size for ChaCha20-poly1305)
    let encrypted = cipher
        .encrypt(nonce_ga, signature)
        .map_err(|_| DhtOutboundError::CipherError(String::from("Authenticated encryption failed")))?;

    Ok(encrypted)
}

/// Generates a 32-byte hashed challenge that commits to the message header and body
pub fn create_message_domain_separated_hash(header: &DhtMessageHeader, body: &[u8]) -> [u8; 32] {
    create_message_domain_separated_hash_parts(
        header.version,
        &header.destination,
        header.message_type,
        header.flags,
        header.expires,
        header.ephemeral_public_key.as_ref(),
        body,
    )
}

/// Generates a 32-byte hashed challenge that commits to all message parts
pub fn create_message_domain_separated_hash_parts(
    protocol_version: DhtProtocolVersion,
    destination: &NodeDestination,
    message_type: DhtMessageType,
    flags: DhtMessageFlags,
    expires: Option<EpochTime>,
    ephemeral_public_key: Option<&CommsPublicKey>,
    body: &[u8],
) -> [u8; 32] {
    // get byte representation of `expires` input
    let expires = expires.map(|t| t.as_u64().to_le_bytes()).unwrap_or_default();

    // get byte representation of `ephemeral_public_key`
    let e_pk = ephemeral_public_key
        .map(|e_pk| {
            let mut buf = [0u8; 32];
            // CommsPublicKey::as_bytes returns 32-bytes
            buf.copy_from_slice(e_pk.as_bytes());
            buf
        })
        .unwrap_or_default();

    // we digest the given data into a domain independent hash function to produce a signature
    // use of the hashing API for domain separation and deal with variable length input
    let domain_separated_hash = comms_dht_hash_domain_challenge()
        .chain(&protocol_version.as_bytes())
        .chain(destination.to_inner_bytes())
        .chain(&(message_type as i32).to_le_bytes())
        .chain(&flags.bits().to_le_bytes())
        .chain(&expires)
        .chain(&e_pk)
        .chain(&body)
        .finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(domain_separated_hash.as_ref());
    output
}

#[cfg(test)]
mod test {
    use tari_crypto::keys::PublicKey;
    use tari_utilities::hex::from_hex;

    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let pk = CommsPublicKey::default();
        let key = CipherKey(*chacha20::Key::from_slice(pk.as_bytes()));
        let plain_text = "Last enemy position 0830h AJ 9863".as_bytes().to_vec();
        let encrypted = encrypt(&key, &plain_text);
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plain_text);
    }

    #[test]
    fn decrypt_fn() {
        let pk = CommsPublicKey::default();
        let key = CipherKey(*chacha20::Key::from_slice(pk.as_bytes()));
        let cipher_text =
            from_hex("24bf9e698e14938e93c09e432274af7c143f8fb831f344f244ef02ca78a07ddc28b46fec536a0ca5c04737a604")
                .unwrap();
        let plain_text = decrypt(&key, &cipher_text).unwrap();
        let secret_msg = "Last enemy position 0830h AJ 9863".as_bytes().to_vec();
        assert_eq!(plain_text, secret_msg);
    }

    #[test]
    fn sanity_check() {
        let domain_separated_hash = comms_dht_hash_domain_key_signature()
            .chain(&[10, 12, 13, 82, 93, 101, 87, 28, 27, 17, 11, 35, 43])
            .finalize();

        let domain_separated_hash = domain_separated_hash.as_ref();

        // Domain separation uses Challenge = Blake256, thus its output has 32-byte length
        let key = AuthenticatedCipherKey(*chacha20poly1305::Key::from_slice(domain_separated_hash));

        let signature = b"Top secret message, handle with care".as_slice();
        let n = signature.len();
        let nonce = [0u8; size_of::<chacha20poly1305::Nonce>()];

        let nonce_ga = chacha20poly1305::Nonce::from_slice(&nonce);
        let cipher = ChaCha20Poly1305::new(&key.0);

        let encrypted = cipher
            .encrypt(nonce_ga, signature)
            .map_err(|_| DhtOutboundError::CipherError(String::from("Authenticated encryption failed")))
            .unwrap();

        assert_eq!(encrypted.len(), n + 16);
    }

    #[test]
    fn decryption_fails_in_case_tag_is_manipulated() {
        let (sk, pk) = CommsPublicKey::random_keypair(&mut OsRng);
        let key_data = generate_ecdh_secret(&sk, &pk);
        let key = generate_key_signature_for_authenticated_encryption(&key_data);

        let signature = b"Top secret message, handle with care".as_slice();

        let mut encrypted = encrypt_with_chacha20_poly1305(&key, signature).unwrap();

        // sanity check to validate that encrypted.len() = signature.len() + 16
        assert_eq!(encrypted.len(), signature.len() + 16);

        // manipulate tag and check that decryption fails
        let n = encrypted.len();
        encrypted[n - 1] += 1;

        // decryption should fail
        assert!(decrypt_with_chacha20_poly1305(&key, encrypted.as_slice())
            .unwrap_err()
            .to_string()
            .contains("Authenticated decryption failed"));
    }

    #[test]
    fn decryption_fails_in_case_body_message_is_manipulated() {
        let (sk, pk) = CommsPublicKey::random_keypair(&mut OsRng);
        let key_data = generate_ecdh_secret(&sk, &pk);
        let key = generate_key_signature_for_authenticated_encryption(&key_data);

        let signature = b"Top secret message, handle with care".as_slice();

        let mut encrypted = encrypt_with_chacha20_poly1305(&key, signature).unwrap();

        // manipulate encrypted message body and check that decryption fails
        encrypted[0] += 1;

        // decryption should fail
        assert!(decrypt_with_chacha20_poly1305(&key, encrypted.as_slice())
            .unwrap_err()
            .to_string()
            .contains("Authenticated decryption failed"));
    }

    #[test]
    fn decryption_fails_if_message_sned_to_incorrect_node() {
        let (sk, pk) = CommsPublicKey::random_keypair(&mut OsRng);
        let (other_sk, other_pk) = CommsPublicKey::random_keypair(&mut OsRng);

        let key_data = generate_ecdh_secret(&sk, &pk);
        let other_key_data = generate_ecdh_secret(&other_sk, &other_pk);

        let key = generate_key_signature_for_authenticated_encryption(&key_data);
        let other_key = generate_key_signature_for_authenticated_encryption(&other_key_data);

        let signature = b"Top secret message, handle with care".as_slice();

        let encrypted = encrypt_with_chacha20_poly1305(&key, signature).unwrap();

        // decryption should fail
        assert!(decrypt_with_chacha20_poly1305(&other_key, encrypted.as_slice())
            .unwrap_err()
            .to_string()
            .contains("Authenticated decryption failed"));
    }
}
