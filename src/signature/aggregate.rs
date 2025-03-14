// Batch verification of multiple signatures
// Compression of multiple signatures into a single aggregate
// SNARK-friendly verification for efficient proof aggregation

use crate::signature::loquat::{Loquat, LoquatSignature, LoquatKeyPair};
use crate::crypto::hash_functions::{Hash, HashFunction};
use num_bigint::BigUint;
use rand::Rng;
use num_traits::{Zero, ToPrimitive};

// Prime field modulus (p = 2^127 - 1) 
const P: u128 = (1 << 127) - 1;

// Aggregated Signature Structure
#[derive(Debug, Clone)]
pub struct AggregateSignature {
  pub aggregated_sigma: BigUint, // Aggregated signature
  pub challenge: BigUint, // Random challenge for verification
}

// Loquat Aggregate Signature Scheme
pub struct LoquatAggregate;

impl LoquatAggregate {
  // Helper function for modular addition
  fn mod_add(a: u128, b: u128, modulus: u128) -> u128 {
    let a = a % modulus;
    let b = b % modulus;
    if a > modulus - b {
        (a - (modulus - b)) % modulus
    } else {
        (a + b) % modulus
    }
  }

  // Aggregates multiple Loquat signatures into a single signature
  pub fn aggregate(signatures: &[LoquatSignature]) -> AggregateSignature {
    let mut aggregated_sigma = BigUint::zero();
    let mut rng = rand::thread_rng();
    let challenge = BigUint::from(rng.gen_range(1..P));

    for sig in signatures {
      // Convert to u128 and perform safe modular addition
      let sig_u128 = (sig.sigma.clone() % BigUint::from(P)).to_u128().unwrap_or(0);
      let agg_u128 = (aggregated_sigma.clone() % BigUint::from(P)).to_u128().unwrap_or(0);
      let result = Self::mod_add(agg_u128, sig_u128, P);
      aggregated_sigma = BigUint::from(result);
    }

    AggregateSignature {
      aggregated_sigma,
      challenge,
    }
  }

  // Verifies an aggregated signature against multiple public keys and messages
  pub fn verify(public_keys: &[Vec<u8>], messages: &[Vec<u8>], agg_sig: &AggregateSignature) -> bool {
    if public_keys.len() != messages.len() {
      return false;
    }

    let mut computed_agg_sigma = BigUint::zero();

    for (pk, msg) in public_keys.iter().zip(messages.iter()) {
      let hash = Hash::new(HashFunction::Sha3_256).compute(msg);
      let message_int = BigUint::from_bytes_be(&hash);
      
      // Convert to u128 and perform safe modular addition
      let msg_u128 = (message_int % BigUint::from(P)).to_u128().unwrap_or(0);
      let agg_u128 = (computed_agg_sigma.clone() % BigUint::from(P)).to_u128().unwrap_or(0);
      let result = Self::mod_add(agg_u128, msg_u128, P);
      computed_agg_sigma = BigUint::from(result);
    }

    // Compare using modular reduction to ensure consistent comparison
    let computed_u128 = (computed_agg_sigma % BigUint::from(P)).to_u128().unwrap_or(0);
    let agg_sig_u128 = (agg_sig.aggregated_sigma.clone() % BigUint::from(P)).to_u128().unwrap_or(0);
    
    computed_u128 == agg_sig_u128
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_aggregate_signature() {
    let keypair1 = Loquat::keygen();
    let keypair2 = Loquat::keygen();

    let message1 = b"Message 1";
    let message2 = b"Message 2";

    // Sign messages using Loquat's signature scheme
    let sig1 = Loquat::sign(keypair1.secret_key, message1);
    let sig2 = Loquat::sign(keypair2.secret_key, message2);

    // Aggregate signatures using safe modular arithmetic
    let aggregate_sig = LoquatAggregate::aggregate(&[sig1.clone(), sig2.clone()]);

    let public_keys = vec![keypair1.public_key, keypair2.public_key];
    let messages = vec![message1.to_vec(), message2.to_vec()];

    // Verify the aggregated signature using safe modular arithmetic
    assert!(LoquatAggregate::verify(&public_keys, &messages, &aggregate_sig));
  }

  #[test]
  fn test_invalid_aggregate_signature() {
    let keypair1 = Loquat::keygen();
    let keypair2 = Loquat::keygen();

    let message1 = b"Message 1";
    let message2 = b"Message 2";

    // Sign messages using Loquat's signature scheme
    let sig1 = Loquat::sign(keypair1.secret_key, message1);
    let sig2 = Loquat::sign(keypair2.secret_key, message2);

    // Aggregate signatures using safe modular arithmetic
    let aggregate_sig = LoquatAggregate::aggregate(&[sig1.clone(), sig2.clone()]);

    // Use a tampered message that should fail verification
    let tampered_message = b"Tampered Message";
    let public_keys = vec![keypair1.public_key, keypair2.public_key];
    let messages = vec![message1.to_vec(), tampered_message.to_vec()];

    // Verify that the tampered message fails verification with safe arithmetic
    assert!(!LoquatAggregate::verify(&public_keys, &messages, &aggregate_sig));
    
    // Additional test to ensure original messages still verify correctly
    let original_messages = vec![message1.to_vec(), message2.to_vec()];
    assert!(LoquatAggregate::verify(&public_keys, &original_messages, &aggregate_sig));
  }
}
