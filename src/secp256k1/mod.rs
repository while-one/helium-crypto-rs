use crate::*;
use k256::{
    ecdsa,
    elliptic_curve::{sec1::ToEncodedPoint},
};
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Clone)]
pub struct PublicKey(k256::PublicKey);

#[derive(Debug, PartialEq, Clone)]
pub struct Signature(ecdsa::Signature);

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    secret: k256::ecdsa::SigningKey,
}

// Network/type byte plus 32 bytes of secret scalar.
pub const KEYPAIR_LENGTH: usize = 33;
// Network/type byte plus even/odd byte plus 32 bytes of X coordinate.
pub const PUBLIC_KEY_LENGTH: usize = 34;

impl PartialEq for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network && self.public_key == other.public_key
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("tag", &self.key_tag())
            .field("public", &self.public_key)
            .finish()
    }
}

impl keypair::Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.to_vec())
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = Error;
    fn try_from(input: &[u8]) -> Result<Self> {
        let network = Network::try_from(input[0])?;
        let secret = k256::SecretKey::from_bytes(&input[1..])?;
        let public_key =
            public_key::PublicKey::for_network(network, PublicKey(secret.public_key()));
        Ok(Keypair {
            network,
            public_key,
            secret: k256::ecdsa::SigningKey::from(secret),
        })
    }
}

impl IntoBytes for Keypair {
    fn bytes_into(&self, output: &mut [u8]) {
        output[0] = u8::from(self.key_tag());
        output[1..].copy_from_slice(&self.secret.to_bytes());
    }
}

impl Keypair {
    pub fn generate<R>(network: Network, csprng: &mut R) -> Keypair
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let secret = k256::SecretKey::random(&mut *csprng);
        let public_key = secret.public_key();
        Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, PublicKey(public_key)),
            secret: k256::ecdsa::SigningKey::from(secret),
        }
    }

    pub fn generate_from_entropy(network: Network, entropy: &[u8]) -> Result<Keypair> {
        let secret = k256::SecretKey::from_bytes(entropy)?;
        let public_key = secret.public_key();
        Ok(Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, PublicKey(public_key)),
            secret: k256::ecdsa::SigningKey::from(secret),
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = vec![0u8; KEYPAIR_LENGTH];
        self.bytes_into(&mut result);
        result
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: KeyType::Secp256k1,
        }
    }

    pub fn secret_to_vec(&self) -> Result<Vec<u8>> {
        Ok(self.secret.to_bytes().as_slice().to_vec())
    }
}

impl signature::Signature for Signature {
    fn from_bytes(input: &[u8]) -> std::result::Result<Self, signature::Error> {
        Ok(Signature(signature::Signature::from_bytes(input)?))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        Ok(Signature(self.secret.sign(msg)))
    }
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Signature(signature::Signature::from_bytes(bytes)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_der().as_bytes().to_vec()
    }
}

impl PublicKeySize for PublicKey {
    fn public_key_size(&self) -> usize {
        PUBLIC_KEY_LENGTH
    }
}

impl public_key::Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result {
        use signature::Verifier;
        let signature = k256::ecdsa::Signature::from_der(signature).map_err(Error::from)?;
        Ok(k256::ecdsa::VerifyingKey::from(self.0).verify(msg, &signature)?)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        // Assume this is a compressed key we've encoded before. Strip off the
        // network/type tag, leaving what should be a even/odd tag byte
        // followed by an X coordinate.
        let encoded_point = k256::EncodedPoint::from_bytes(&input[1..])?;
        let public_key = k256::PublicKey::from_encoded_point(&encoded_point)
            .expect("uncompressed point");
        Ok(PublicKey(public_key))
    }
}

impl IntoBytes for PublicKey {
    fn bytes_into(&self, output: &mut [u8]) {
        let encoded = self
            .0
            .as_affine()
            .to_encoded_point(true);
        output.copy_from_slice(&encoded.as_bytes()[..])
    }
}

#[cfg(test)]
mod tests {
    use super::{Keypair, TryFrom};
    use crate::{Network, Sign, Verify};
    use hex_literal::hex;
    use rand::rngs::OsRng;

    #[test]
    fn sign_roundtrip() {
        let keypair = Keypair::generate(Network::MainNet, &mut OsRng);
        let signature = keypair.sign(b"hello world").expect("signature");
        assert!(keypair
            .public_key
            .verify(b"hello world", &signature)
            .is_ok())
    }

    #[test]
    fn bytes_roundtrip() {
        use rand::rngs::OsRng;
        let keypair = Keypair::generate(Network::MainNet, &mut OsRng);
        let bytes = keypair.to_vec();
        assert_eq!(
            keypair,
            super::Keypair::try_from(&bytes[..]).expect("keypair")
        );
    }

    #[test]
    fn verify() {
        // Test a msg signed and verified with a keypair generated with erlang crypto
        // and compressed by hand.
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "1SpLY6fic4fGthLGjeAUdLVNVYk1gJGrWTGhsukm2dnELaSEQmhL";
        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        const SIG: &[u8] =
            &hex!("3045022100b72de78c39ecdb7db78429362bcdea509cd414dc75c84303d8b7128d864600d002204b857cc29ab999b2b7df9c8c2ab25678787d5632c6aa98227b444aaa9b42df3b");
        assert!(public_key.verify(MSG, SIG).is_ok());
    }

    #[test]
    #[ignore]
    // Test to be skipped until BIP-0062 adjustments to k256 ECDSA are removed
    // from elliptic-curves library.
    fn verify_high_s() {
        // Test a msg signed and verified with a keypair generated with erlang crypto
        // and compressed by hand.
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "1SpLY6fic4fGthLGjeAUdLVNVYk1gJGrWTGhsukm2dnELaSEQmhL";
        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        const SIG: &[u8] =
            &hex!("304502205fa60e66389d90894fa65f47cd50eae6486bfcb8c80ae6209a90a380e46343250221008902ac3932100615ad4db3eecb89a86da8bd97eefb357c5226952b7b3c4aa385");
        assert!(public_key.verify(MSG, SIG).is_ok());
    }

    #[test]
    fn b58_roundtrip() {
        const B58: &str = "1SpLY6fic4fGthLGjeAUdLVNVYk1gJGrWTGhsukm2dnELaSEQmhL";
        let decoded: crate::PublicKey = B58.parse().expect("b58 public key");
        assert_eq!(B58, decoded.to_string());
    }
}
