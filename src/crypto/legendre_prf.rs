// Legendre PRF Definition: Computes the quadratic residuosity of an input in a prime field.
// Legendre Symbol Computation: Efficiently determines if a value is a quadratic residue.
// Key Generation: Generates a secret key from a finite field.
// Evaluation Function: Computes PRF outputs based on the secret key.

use rand::Rng;

const P: u128 = (1 << 127) - 1;

// Safe modular addition to avoid overflow
fn mod_add(a: u128, b: u128, modulus: u128) -> u128 {
  ((a % modulus) + (b % modulus)) % modulus
}

// Safe modular subtraction to avoid overflow
fn mod_sub(a: u128, b: u128, modulus: u128) -> u128 {
  let a_mod = a % modulus;
  let b_mod = b % modulus;
  if a_mod >= b_mod {
    (a_mod - b_mod) % modulus
  } else {
    (modulus + a_mod - b_mod) % modulus
  }
}

// Safe modular multiplication to avoid overflow
fn mod_mul(a: u128, b: u128, modulus: u128) -> u128 {
  let a_mod = a % modulus;
  let b_mod = b % modulus;
  
  // Use a method that avoids overflow
  let mut res = 0;
  let mut a_temp = a_mod;
  let mut b_temp = b_mod;
  
  while b_temp > 0 {
    if b_temp & 1 == 1 {
      res = mod_add(res, a_temp, modulus);
    }
    a_temp = mod_add(a_temp, a_temp, modulus);
    b_temp >>= 1;
  }
  
  res
}

// Safe modular exponentiation to avoid overflow
fn mod_pow(base: u128, exp: u128, modulus: u128) -> u128 {
  if modulus == 1 {
    return 0;
  }
  
  let mut result = 1;
  let mut base_mod = base % modulus;
  let mut exp_temp = exp;
  
  while exp_temp > 0 {
    if exp_temp & 1 == 1 {
      result = mod_mul(result, base_mod, modulus);
    }
    base_mod = mod_mul(base_mod, base_mod, modulus);
    exp_temp >>= 1;
  }
  
  result
}

pub struct LegendrePRF {
  secret_key: u128,
}

impl LegendrePRF {
  // Generate a new secret key
  pub fn new() -> Self {
    let mut rng = rand::thread_rng();
    let sk = rng.gen_range(1..P);
    Self { secret_key: sk }
  }
  
  // Initialize LegendrePRF with a provided secret key
  pub fn with_key(key: u128) -> Self {
    // Ensure the provided key is within the prime field
    Self { secret_key: key % P }
  }
  
  // Alias for new() to maintain compatibility with existing code
  pub fn keygen() -> Self {
    Self::new()
  }

  // Compute the Legendre symbol of a value in a prime field
  pub fn legendre_symbol(a: u128) -> i8 {
    if a == 0 {
      return 0;
    }

    let exp = mod_sub(P, 1, P) / 2;
    let result = mod_pow(a, exp, P);
    if result == 1 { 1 } else { -1 }
  }

  // Evaluate the PRF: L(K, x) = (K + x / P)
  pub fn evaluate(&self, x: u128) -> u8 {
    let k_x = mod_add(self.secret_key, x, P);
    match Self::legendre_symbol(k_x) {
      1 => 0,
      -1 => 1,
      _ => panic!("Invalid Legendre symbol"),
    }
  }
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_legendre_symbol() {
    // Test with safe modular arithmetic
    let a1 = 4;
    let a2 = 5;
    let exp = mod_sub(P, 1, P) / 2; // (P-1)/2
    
    // 4 is a quadratic residue mod P
    let result1 = mod_pow(a1, exp, P);
    assert_eq!(result1, 1);
    assert_eq!(LegendrePRF::legendre_symbol(a1), 1);
    
    // 5 is a quadratic non-residue mod P
    let result2 = mod_pow(a2, exp, P);
    assert_eq!(result2, P - 1); // Equivalent to -1 in the field
    assert_eq!(LegendrePRF::legendre_symbol(a2), -1);
  }

  #[test]
  fn test_legendre_prf() {
    let prf = LegendrePRF::keygen();
    let x = 42;
    
    // Safely compute k_x = (secret_key + x) % P
    let k_x = mod_add(prf.secret_key, x, P);
    
    // Evaluate the PRF
    let output = prf.evaluate(x);
    
    // Verify output is valid
    assert!(output == 0 || output == 1, "PRF output must be 0 or 1");
    
    // Additional verification using our safe mod_pow
    let exp = mod_sub(P, 1, P) / 2;
    let legendre = mod_pow(k_x, exp, P);
    let expected = if legendre == 1 { 0 } else { 1 };
    
    assert_eq!(output, expected, "PRF output should match expected value");
  }
}
