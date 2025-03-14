use sha3::{Digest, Sha3_256, Shake128};
use sha3::digest::Update;
use sha3::digest::ExtendableOutput;
use sha3::digest::XofReader;
use tiny_keccak::{Hasher, Keccak};
use num_bigint::BigUint;
use num_traits::Zero;
use num_traits::ToPrimitive;
use std::convert::TryInto;

// Prime field modulus (p = 2^127 - 1)
const P: u128 = (1 << 127) - 1;

// Supported Hash Functions
#[derive(Clone, Debug)]
pub enum HashFunction {
  Sha3_256,
  Shake128,
  Poseidon,
  Griffin,
}

// Hash function wrapper
pub struct Hash {
  algorithm: HashFunction,
}

impl Hash {
  // Create a new hash instance
  pub fn new(algorithm: HashFunction) -> Self {
    Self { algorithm }
  }

  // Compute the hash of input data
  pub fn compute(&self, input: &[u8]) -> Vec<u8> {
    match self.algorithm {
      HashFunction::Sha3_256 => Self::sha3_256(input),
      HashFunction::Shake128 => Self::shake128(input),
      HashFunction::Poseidon => Self::poseidon(input),
      HashFunction::Griffin => Self::griffin(input),
    }
  }

  // Compute the hash of input data using SHA3-256
  fn sha3_256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    Update::update(&mut hasher, input);
    hasher.finalize().to_vec()
  }

  // Compute the hash of input data using SHAKE-128
  fn shake128(input: &[u8]) -> Vec<u8> {
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, input);
    let mut output = [0u8; 32];
    hasher.finalize_xof().read(&mut output);
    output.to_vec()
  }

  // Compute the hash of input data using Poseidon
  // This is a simplified implementation of the Poseidon hash function
  // For production use, consider using a dedicated crate like 'dusk-poseidon' or 'poseidon-primitives'
  fn poseidon(input: &[u8]) -> Vec<u8> {
    // Constants for Poseidon hash (simplified version)
    const WIDTH: usize = 3; // State width (t)
    const FULL_ROUNDS: usize = 8; // Number of full rounds
    const PARTIAL_ROUNDS: usize = 57; // Number of partial rounds for width 3
    
    // Convert input to field elements (simplified)
    let mut state = [0u128; WIDTH];
    
    // Initialize state with input bytes
    for (i, chunk) in input.chunks(16).enumerate().take(WIDTH) {
      let mut value = 0u128;
      for (j, &byte) in chunk.iter().enumerate() {
        value |= (byte as u128) << (8 * j);
      }
      state[i] = value % P; // This is safe as value is built from bytes and won't overflow
    }
    
    // Simplified permutation (actual implementation would include S-box, MDS matrix, etc.)
    // This is just a placeholder to demonstrate the structure
    for _ in 0..FULL_ROUNDS / 2 {
      // Full round (all state elements)
      for i in 0..WIDTH {
        // S-box: x^5 (simplified)
        state[i] = Self::pow_mod(state[i], 5, P);
      }
      // Mix layer would go here
    }
    
    for _ in 0..PARTIAL_ROUNDS {
      // Partial round (only first element)
      state[0] = Self::pow_mod(state[0], 5, P);
      // Mix layer would go here
    }
    
    for _ in 0..FULL_ROUNDS / 2 {
      // Full round (all state elements)
      for i in 0..WIDTH {
        // S-box: x^5 (simplified)
        state[i] = Self::pow_mod(state[i], 5, P);
      }
      // Mix layer would go here
    }
    
    // Convert state to output bytes
    let mut output = Vec::with_capacity(32);
    for &value in &state[0..2] { // Use first two elements for output
      for j in 0..16 {
        output.push(((value >> (8 * j)) & 0xFF) as u8);
      }
    }
    
    // Ensure output is exactly 32 bytes
    output.resize(32, 0);
    output
  }

  // Compute the hash of input data using Griffin
  // This is a simplified implementation of the Griffin hash function
  // Griffin combines elements of Horst construction and Rescue-like SPN schemes
  fn griffin(input: &[u8]) -> Vec<u8> {
    // Constants for Griffin hash (simplified version)
    const WIDTH: usize = 3; // State width
    const ROUNDS: usize = 10; // Number of rounds (simplified)
    const SBOX_EXP: u32 = 5; // S-box exponent
    const INV_SBOX_EXP: u128 = (P + 1) / 5; // Inverse S-box exponent (x^(1/5) ≡ x^((p+1)/5) mod p)
    
    // Convert input to field elements (simplified)
    let mut state = [0u128; WIDTH];
    
    // Initialize state with input bytes
    for (i, chunk) in input.chunks(16).enumerate().take(WIDTH) {
      let mut value = 0u128;
      for (j, &byte) in chunk.iter().enumerate() {
        value |= (byte as u128) << (8 * j);
      }
      state[i] = Self::mod_reduce(value, P);
    }
    
    // Simplified permutation
    for round in 0..ROUNDS {
      // Apply S-box or inverse S-box based on round parity
      for i in 0..WIDTH {
        if round % 2 == 0 {
          // Forward S-box: x^5
          state[i] = Self::pow_mod(state[i], SBOX_EXP as u128, P);
        } else {
          // Inverse S-box: x^(1/5)
          state[i] = Self::pow_mod(state[i], INV_SBOX_EXP, P);
        }
      }
      
      // Simple mixing function (actual implementation would use a proper MDS matrix)
      if WIDTH > 1 {
        let temp = state.clone();
        for i in 0..WIDTH {
          state[i] = Self::mod_add(state[i], temp[(i + 1) % WIDTH], P);
        }
      }
    }
    
    // Convert state to output bytes
    let mut output = Vec::with_capacity(32);
    for &value in &state[0..2] { // Use first two elements for output
      for j in 0..16 {
        output.push(((value >> (8 * j)) & 0xFF) as u8);
      }
    }
    
    // Ensure output is exactly 32 bytes
    output.resize(32, 0);
    output
  }
  
  // Helper function for modular exponentiation
  fn pow_mod(base: u128, exponent: u128, modulus: u128) -> u128 {
    if modulus == 1 { return 0 }
    
    let mut result = 1;
    let mut base = Self::mod_reduce(base, modulus);
    let mut exp = exponent;
    
    while exp > 0 {
      if exp % 2 == 1 {
        result = Self::mod_mul(result, base, modulus);
      }
      exp >>= 1;
      base = Self::mod_mul(base, base, modulus);
    }
    
    result
  }
  
  // Helper function for modular addition
  fn mod_add(a: u128, b: u128, modulus: u128) -> u128 {
    // Convert to BigUint to avoid overflow
    let a_big = BigUint::from(a);
    let b_big = BigUint::from(b);
    let mod_big = BigUint::from(modulus);
    
    // Perform addition and modulo
    let result = (a_big + b_big) % mod_big;
    
    // Convert back to u128
    result.to_u128().expect("Result should fit in u128")
  }
  
  // Helper function for modular multiplication
  fn mod_mul(a: u128, b: u128, modulus: u128) -> u128 {
    // Convert to BigUint to avoid overflow
    let a_big = BigUint::from(a);
    let b_big = BigUint::from(b);
    let mod_big = BigUint::from(modulus);
    
    // Perform multiplication and modulo
    let result = (a_big * b_big) % mod_big;
    
    // Convert back to u128
    result.to_u128().expect("Result should fit in u128")
  }
  
  // Helper function for modular reduction
  fn mod_reduce(a: u128, modulus: u128) -> u128 {
    // Convert to BigUint to avoid overflow
    let a_big = BigUint::from(a);
    let mod_big = BigUint::from(modulus);
    
    // Perform modulo operation
    let result = a_big % mod_big;
    
    // Convert back to u128
    result.to_u128().expect("Result should fit in u128")
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_sha3_256() {
    let input = b"Loquat Test";
    let hash = Hash::new(HashFunction::Sha3_256).compute(input);
    assert_eq!(hash.len(), 32);
  }

  #[test]
  fn test_shake128() {
    let input = b"Loquat Test";
    let hash = Hash::new(HashFunction::Shake128).compute(input);
    assert_eq!(hash.len(), 32);
  }

  #[test]
  fn test_poseidon() {
    let input = b"Loquat Test";
    let hash = Hash::new(HashFunction::Poseidon).compute(input);
    assert_eq!(hash.len(), 32);
    
    // Test modular multiplication
    let a: u128 = 12345;
    let b: u128 = 67890;
    let result = Hash::mod_mul(a, b, P);
    
    // Verify using BigUint
    let a_big = BigUint::from(a);
    let b_big = BigUint::from(b);
    let mod_big = BigUint::from(P);
    let expected = (a_big * b_big) % mod_big;
    let expected_u128 = expected.to_u128().expect("Result should fit in u128");
    
    assert_eq!(result, expected_u128);
  }

  #[test]
  fn test_griffin() {
    let input = b"Loquat Test";
    let hash = Hash::new(HashFunction::Griffin).compute(input);
    assert_eq!(hash.len(), 32);
    
    // Test modular arithmetic with BigUint conversion
    let a: u128 = 98765;
    let b: u128 = 43210;
    let result = Hash::mod_mul(a, b, P);
    
    // Verify using BigUint
    let a_big = BigUint::from(a);
    let b_big = BigUint::from(b);
    let mod_big = BigUint::from(P);
    let expected = (a_big * b_big) % mod_big;
    let expected_u128 = expected.to_u128().expect("Result should fit in u128");
    
    assert_eq!(result, expected_u128);
  }
}
