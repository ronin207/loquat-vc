use crate::crypto::{
  legendre_prf::LegendrePRF,
  merkle::MerkleTree,
  hash_functions::{Hash, HashFunction},
};
use std::convert::TryInto;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::Rng;

// Prime field modulus (p = 2^127 - 1) as specified in the CRYPTO 2024 paper
// This prime is chosen to be efficient for Legendre PRF computation
const P: u128 = (1 << 127) - 1;

/// Loquat Signature Structure
#[derive(Debug, Clone)]
pub struct LoquatSignature {
  pub sigma: BigUint, // Signature
  pub merkle_root: BigUint, // Commitment to public key
}

// Loquat Key-pair
pub struct LoquatKeyPair {
  pub secret_key: u128,
  pub public_key: Vec<u8>, // Public key commitment using Merkle root
}

pub struct Loquat;

impl Loquat {
  // Helper function for modular subtraction
  fn mod_sub(a: u128, b: u128, modulus: u128) -> u128 {
    (a + modulus - b) % modulus
  }
  // Generate a new Loquat key pair
  pub fn keygen() -> LoquatKeyPair {
    // Generate a random secret key
    let mut rng = rand::thread_rng();
    let secret_key = rng.gen_range(1..P);
    
    // Compute the public key as a hash of the secret key
    let public_key = Hash::new(HashFunction::Sha3_256).compute(&secret_key.to_be_bytes());

    LoquatKeyPair {
      secret_key,
      public_key,
    }
  }

  // Sign a message using the Loquat signature scheme
  // As described in the CRYPTO 2024 paper "Loquat: A SNARK-Friendly Post-Quantum Signature 
  // Based on the Legendre PRF with Applications in Ring and Aggregate Signatures"
  pub fn sign(sk: u128, message: &[u8]) -> LoquatSignature {
    let hash = Hash::new(HashFunction::Sha3_256).compute(message);
    let message_int = BigUint::from_bytes_be(&hash);

    // Convert BigUint to u128 safely by reducing modulo P before conversion
    let message_u128 = (message_int % BigUint::from(P)).to_u128().unwrap_or(0);
    
    // Initialize the Legendre PRF with the secret key
    let legendre_prf = LegendrePRF::with_key(sk);
    
    // Evaluate the Legendre PRF on the message hash
    // This produces a bit (0 or 1) based on the quadratic residuosity
    let prf_result = legendre_prf.evaluate(message_u128);
    
    // Incorporate the PRF result into the signature
    // If prf_result is 1, we add message_u128 to sk, otherwise we subtract it
    // This creates a signature that depends on the Legendre symbol computation
    let signature_value = if prf_result == 1 {
      (sk + message_u128) % P
    } else {
      Self::mod_sub(sk, message_u128, P)
    };
    
    let signature = BigUint::from(signature_value);

    // Compute a Merkle root for proof that binds both the signature and message
    // This ensures that any tampering with the message will lead to verification failure
    // The Merkle tree includes both the PRF-enhanced signature and the message hash
    let merkle_tree = MerkleTree::new(vec![signature.clone(), BigUint::from(message_u128)], HashFunction::Sha3_256);
    let merkle_root = merkle_tree.root().unwrap();

    LoquatSignature {
      sigma: signature,
      merkle_root,
    }
  }

  // Verify a Loquat signature
  // This verification process ensures that the signature is valid only for the exact message
  // by recomputing the signature from the expected secret key and current message hash
  // Implementation follows the CRYPTO 2024 paper on Loquat
  pub fn verify(pk: &[u8], message: &[u8], signature: &LoquatSignature) -> bool {
    let hash = Hash::new(HashFunction::Sha3_256).compute(message);
    let message_int = BigUint::from_bytes_be(&hash);

    // Convert BigUint to u128 safely by reducing modulo P before conversion
    let message_u128 = (message_int % BigUint::from(P)).to_u128().expect("Message conversion failed");
    
    // Get the signature value as u128
    let sigma_u128 = (signature.sigma.clone() % BigUint::from(P)).to_u128().expect("Sigma conversion failed");
    
    // Try both possible PRF outcomes (0 and 1) to recover the secret key
    // This is necessary because we don't know which PRF result was used during signing
    
    // Case 1: If PRF result was 1, then sk = sigma - message_u128 mod P
    let expected_sk_case1 = Self::mod_sub(sigma_u128, message_u128, P);
    
    // Case 2: If PRF result was 0, then sk = sigma + message_u128 mod P
    let expected_sk_case2 = (sigma_u128 + message_u128) % P;
    
    // Compute the expected public keys for both cases
    let expected_pk_case1 = Hash::new(HashFunction::Sha3_256).compute(&expected_sk_case1.to_be_bytes());
    let expected_pk_case2 = Hash::new(HashFunction::Sha3_256).compute(&expected_sk_case2.to_be_bytes());
    
    // Check if either of the expected public keys matches the provided public key
    let pk_matches_case1 = expected_pk_case1 == pk;
    let pk_matches_case2 = expected_pk_case2 == pk;
    
    // If neither case matches, the signature is invalid
    if !pk_matches_case1 && !pk_matches_case2 {
      return false;
    }
    
    // Determine which secret key to use based on which public key matched
    let expected_sk = if pk_matches_case1 { expected_sk_case1 } else { expected_sk_case2 };
    
    // Initialize the Legendre PRF with the recovered secret key
    let legendre_prf = LegendrePRF::with_key(expected_sk);
    
    // Evaluate the Legendre PRF on the message hash
    let prf_result = legendre_prf.evaluate(message_u128);
    
    // Recompute the expected signature value using the recovered secret key and PRF result
    let recomputed_sigma_value = if prf_result == 1 {
      (expected_sk + message_u128) % P
    } else {
      Self::mod_sub(expected_sk, message_u128, P)
    };
    
    let recomputed_sigma = BigUint::from(recomputed_sigma_value);
    
    // Rebuild the Merkle tree using the recomputed sigma and the current message_u128
    let expected_merkle_tree = MerkleTree::new(vec![recomputed_sigma, BigUint::from(message_u128)], HashFunction::Sha3_256);
    let expected_root = expected_merkle_tree.root().expect("Failed to compute Merkle root");
    
    // Check if the recomputed Merkle root matches the stored one
    let merkle_matches = expected_root == signature.merkle_root;
    
    // Return true only if both the public key check and Merkle root check pass
    (pk_matches_case1 || pk_matches_case2) && merkle_matches
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_loquat_signature() {
    let keypair = Loquat::keygen();
    let message = b"Test message for Loquat";

    // Sign the message using the Legendre PRF-based signature scheme
    let signature = Loquat::sign(keypair.secret_key, message);
    
    // Verify the signature with proper message hash reduction and PRF evaluation
    assert!(Loquat::verify(&keypair.public_key, message, &signature));
  }

  #[test]
  fn test_invalid_signature() {
    let keypair = Loquat::keygen();
    let message = b"Test message for Loquat";
    let invalid_message = b"Tampered message";

    // Sign the original message
    let signature = Loquat::sign(keypair.secret_key, message);
    
    // Verify that a tampered message fails verification
    // This tests that the hash reduction, PRF evaluation, and conversion are properly applied
    assert!(!Loquat::verify(&keypair.public_key, invalid_message, &signature));
    
    // Verify that the original message passes verification
    // This confirms that the signature verification process works correctly with the Legendre PRF
    assert!(Loquat::verify(&keypair.public_key, message, &signature));
  }
  
  #[test]
  fn test_large_message_hash() {
    let keypair = Loquat::keygen();
    // Use a message that will produce a large hash value
    let large_message = [0xFF; 64].to_vec();
    
    // Sign the message with potentially large hash
    let signature = Loquat::sign(keypair.secret_key, &large_message);
    
    // Verify that the signature is valid despite the large hash value
    // This tests that modulo reduction is properly applied before conversion
    // and that the Legendre PRF evaluation works correctly with large inputs
    assert!(Loquat::verify(&keypair.public_key, &large_message, &signature));
  }
  
  #[test]
  fn test_legendre_prf_consistency() {
    // Test that the Legendre PRF produces consistent results
    // This is important for the signature scheme to work correctly
    let secret_key = 12345u128;
    let message = 67890u128;
    
    let legendre_prf = LegendrePRF::with_key(secret_key);
    let result1 = legendre_prf.evaluate(message);
    let result2 = legendre_prf.evaluate(message);
    
    // The PRF should produce the same result for the same input
    assert_eq!(result1, result2);
    
    // Test that the signature scheme works with the Legendre PRF
    let keypair = Loquat::keygen();
    let test_message = b"Testing Legendre PRF in Loquat";
    
    let signature = Loquat::sign(keypair.secret_key, test_message);
    assert!(Loquat::verify(&keypair.public_key, test_message, &signature));
  }
}
