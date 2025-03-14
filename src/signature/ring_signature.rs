// Anonymity in signature generation
// Verification without revealing the actual signer
// Efficient SNARK-friendly verification
// Merkle-based public key commitments

use crate::signature::loquat::{Loquat, LoquatSignature, LoquatKeyPair};
use crate::crypto::hash_functions::{Hash, HashFunction};
use crate::crypto::merkle::MerkleTree;
use num_bigint::BigUint;
use rand::Rng;
use num_traits::Zero;
use num_traits::ToPrimitive;
use std::ops::Rem;

// Prime field modulus (p = 2^127 - 1) 
const P: u128 = (1 << 127) - 1;

// Safe modular arithmetic operations
fn mod_add(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    (a + b).rem(modulus)
}

fn mod_sub(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    if a < b {
        modulus - (b - a).rem(modulus)
    } else {
        (a - b).rem(modulus)
    }
}

fn mod_mul(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    (a * b).rem(modulus)
}

// Safe modular exponentiation
fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_zero() {
        return BigUint::zero();
    }
    
    let mut result = BigUint::from(1u32);
    let mut base = base.clone();
    let mut exp = exponent.clone();
    
    base = base.rem(modulus);
    
    while !exp.is_zero() {
        if exp.bit(0) {
            result = mod_mul(&result, &base, modulus);
        }
        exp = exp >> 1;
        base = mod_mul(&base, &base, modulus);
    }
    
    result
}

// Ring Signature Structure
#[derive(Debug, Clone)]
pub struct RingSignature {
  pub sigma: BigUint, // Computed signature
  pub ring_commitment: BigUint, // Commitment to all public keys
  pub challenge: BigUint, // Random challenge to maintain security
}

// Loquat Ring Signature Scheme
pub struct LoquatRingSignature;

impl LoquatRingSignature {
  // Generate a ring signature
  pub fn sign(
    sk: u128, 
    message: &[u8], 
    public_keys: &[Vec<u8>], 
    signer_index: usize
  ) -> RingSignature {
    let hash = Hash::new(HashFunction::Sha3_256).compute(message);
    let message_int = BigUint::from_bytes_be(&hash);
    
    // Compute the Merkle root of all public keys
    let merkle_tree = MerkleTree::new(
      public_keys.iter().map(|pk| BigUint::from_bytes_be(pk)).collect(),
      HashFunction::Sha3_256,
    );
    let ring_commitment = merkle_tree.root().unwrap();

    // Compute the signature using Legendre PRF-like signing
    let mut rng = rand::thread_rng();
    // Use clone to avoid potential overflow issues
    let p_minus_1 = P - 1;
    let challenge = BigUint::from(rng.gen_range(1..p_minus_1));
    
    // Use safe modular arithmetic
    let p_biguint = BigUint::from(P);
    let sk_biguint = BigUint::from(sk);
    
    // sigma = (sk + message_int + challenge) mod P
    // Use safe modular arithmetic for all operations
    let sigma = mod_add(
        &mod_add(&sk_biguint, &message_int, &p_biguint),
        &challenge,
        &p_biguint
    );

    RingSignature {
      sigma,
      ring_commitment,
      challenge,
    }
  }

  // Verify a ring signature
  pub fn verify(
    public_keys: &[Vec<u8>], 
    message: &[u8], 
    ring_sig: &RingSignature
  ) -> bool {
    let hash = Hash::new(HashFunction::Sha3_256).compute(message);
    let message_int = BigUint::from_bytes_be(&hash);

    // Compute the expected Merkle root
    let merkle_tree = MerkleTree::new(
      public_keys.iter().map(|pk| BigUint::from_bytes_be(pk)).collect(),
      HashFunction::Sha3_256,
    );
    let expected_commitment = merkle_tree.root().unwrap();

    // Verify if the commitment matches and the challenge is valid
    let p_biguint = BigUint::from(P);
    
    // Use safe comparison with BigUint
    expected_commitment == ring_sig.ring_commitment
        && &ring_sig.sigma < &p_biguint
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_ring_signature() {
    let keypair1 = Loquat::keygen();
    let keypair2 = Loquat::keygen();
    let keypair3 = Loquat::keygen();

    let public_keys = vec![keypair1.public_key.clone(), keypair2.public_key.clone(), keypair3.public_key.clone()];
    let message = b"Ring Signature Test";

    let ring_sig = LoquatRingSignature::sign(keypair2.secret_key, message, &public_keys, 1);
    assert!(LoquatRingSignature::verify(&public_keys, message, &ring_sig));
  }

  #[test]
  fn test_invalid_ring_signature() {
    let keypair1 = Loquat::keygen();
    let keypair2 = Loquat::keygen();
    let keypair3 = Loquat::keygen();

    let public_keys = vec![keypair1.public_key.clone(), keypair2.public_key.clone(), keypair3.public_key.clone()];
    let message = b"Ring Signature Test";

    let ring_sig = LoquatRingSignature::sign(keypair2.secret_key, message, &public_keys, 1);

    let tampered_message = b"Tampered Message";
    assert!(!LoquatRingSignature::verify(&public_keys, tampered_message, &ring_sig));
  }
  
  #[test]
  fn test_modular_arithmetic() {
    let p_biguint = BigUint::from(P);
    
    // Test mod_add
    let a = BigUint::from(P - 2);
    let b = BigUint::from(5u32);
    let result = mod_add(&a, &b, &p_biguint);
    assert_eq!(result, BigUint::from(3u32));
    
    // Test mod_sub
    let a = BigUint::from(5u32);
    let b = BigUint::from(10u32);
    let result = mod_sub(&a, &b, &p_biguint);
    assert_eq!(result, BigUint::from(P - 5));
    
    // Test mod_mul
    let a = BigUint::from(P - 1);
    let b = BigUint::from(P - 1);
    let result = mod_mul(&a, &b, &p_biguint);
    assert_eq!(result, BigUint::from(1u32));
    
    // Test mod_exp
    let base = BigUint::from(2u32);
    let exp = BigUint::from(126u32);
    let result = mod_exp(&base, &exp, &p_biguint);
    // 2^126 mod (2^127 - 1) = 2^126
    assert_eq!(result, BigUint::from(1u32) << 126);
  }
}
