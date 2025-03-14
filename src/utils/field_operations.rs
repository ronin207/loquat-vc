// Modular addition, subtraction, multiplication, and inversion
// Exponentiation with modular arithmetic
// SNARK-friendly finite field operations
// Helper functions for modular arithmetic operations on u128 values

use num_bigint::BigUint;
use num_traits::{One, Zero, ToPrimitive};
use std::ops::{Add, Mul, Sub};

// Prime field modulus (p = 2^127 - 1) 
const P: u128 = (1 << 127) - 1;

// Struct representing an element in the finite field `Fp`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldElement {
  value: BigUint,
}

impl FieldElement {
  // Creates a new field element, ensuring it is reduced mod P
  pub fn new(value: u128) -> Self {
    Self {
      value: BigUint::from(value) % BigUint::from(P),
    }
  }

  // Modular addition
  pub fn add(&self, other: &Self) -> Self {
    Self {
      value: (self.value.clone() + other.value.clone()) % BigUint::from(P),
    }
  }

  // Modular subtraction
  pub fn sub(&self, other: &Self) -> Self {
    let mut result = (self.value.clone() + BigUint::from(P) - other.value.clone()) % BigUint::from(P);
    if result.is_zero() {
      result = BigUint::zero();
    }
    Self { value: result }
  }

  // Modular multiplication
  pub fn mul(&self, other: &Self) -> Self {
    Self {
      value: (self.value.clone() * other.value.clone()) % BigUint::from(P),
    }
  }

  // Modular exponentiation using square-and-multiply
  pub fn pow(&self, exp: u128) -> Self {
    let mut base = self.value.clone();
    let mut exponent = BigUint::from(exp);
    let mut result = BigUint::one();
    let modulus = BigUint::from(P);

    while !exponent.is_zero() {
      if &exponent % 2u8 == BigUint::one() {
        result = (result * &base) % &modulus;
      }
      base = (&base * &base) % &modulus;
      exponent /= 2u8;
    }

    Self { value: result }
  }

  // Modular inverse using the Extended Euclidean Algorithm
  pub fn inverse(&self) -> Option<Self> {
    let (gcd, x, _) = extended_gcd(self.value.clone(), BigUint::from(P));
    if gcd == BigUint::one() {
      Some(Self {
        value: (x + BigUint::from(P)) % BigUint::from(P),
      })
    } else {
      None
    }
  }
}

// Extended Euclidean Algorithm for modular inverse
fn extended_gcd(a: BigUint, b: BigUint) -> (BigUint, BigUint, BigUint) {
  let (mut old_r, mut r) = (a, b);
  let (mut old_s, mut s) = (BigUint::one(), BigUint::zero());
  let (mut old_t, mut t) = (BigUint::zero(), BigUint::one());

  while r != BigUint::zero() {
    let quotient = &old_r / &r;
    old_r = &old_r - &quotient * &r;
    old_s = &old_s - &quotient * &s;
    old_t = &old_t - &quotient * &t;

    std::mem::swap(&mut old_r, &mut r);
    std::mem::swap(&mut old_s, &mut s);
    std::mem::swap(&mut old_t, &mut t);
  }

  (old_r, old_s, old_t)
}

// Helper functions for modular arithmetic on u128 values

/// Modular addition: (a + b) mod m
pub fn mod_add(a: u128, b: u128, modulus: u128) -> u128 {
    // Reduce a and b
    let a = a % modulus;
    let b = b % modulus;
    if a > modulus - b {
        // If addition causes overflow, wrap around
        (a - (modulus - b)) % modulus
    } else {
        (a + b) % modulus
    }
}

/// Modular subtraction: (a - b) mod m
pub fn mod_sub(a: u128, b: u128, modulus: u128) -> u128 {
    // Use BigUint for intermediate calculation to avoid overflow
    let a_big = BigUint::from(a);
    let b_big = BigUint::from(b);
    let modulus_big = BigUint::from(modulus);
    
    let result = if a_big >= b_big {
        a_big - b_big
    } else {
        &modulus_big - ((&b_big - &a_big) % &modulus_big)
    };
    
    result.to_u128().unwrap()
}

/// Modular multiplication: (a * b) mod m
pub fn mod_mul(a: u128, b: u128, modulus: u128) -> u128 {
    // Use BigUint for intermediate calculation to avoid overflow
    let a_big = BigUint::from(a);
    let b_big = BigUint::from(b);
    let modulus_big = BigUint::from(modulus);
    
    let result = (a_big * b_big) % modulus_big;
    result.to_u128().unwrap()
}

/// Modular exponentiation: (a^exp) mod m
pub fn mod_pow(a: u128, exp: u128, modulus: u128) -> u128 {
    // Use BigUint for intermediate calculation to avoid overflow
    let mut base = BigUint::from(a % modulus);
    let mut result = BigUint::one();
    let mut exponent = exp;
    let modulus_big = BigUint::from(modulus);

    while exponent > 0 {
        if exponent & 1 == 1 {
            result = (&result * &base) % &modulus_big;
        }
        base = (&base * &base) % &modulus_big;
        exponent >>= 1;
    }

    result.to_u128().unwrap()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_field_operations() {
    let a = FieldElement::new(10);
    let b = FieldElement::new(7);

    assert_eq!(a.add(&b).value, BigUint::from(17u128));
    assert_eq!(a.sub(&b).value, BigUint::from(3u128));
    assert_eq!(a.mul(&b).value, BigUint::from((10 * 7) % P));

    let exp = a.pow(3);
    assert_eq!(exp.value, BigUint::from((10u128.pow(3)) % P));

    let inv_b = b.inverse().unwrap();
    assert_eq!(b.mul(&inv_b).value, BigUint::one());
  }

  #[test]
  fn test_modular_inverse() {
    let a = FieldElement::new(42);
    let inv_a = a.inverse().unwrap();
    
    // Test using FieldElement operations
    assert_eq!(a.mul(&inv_a).value, BigUint::one());
    
    // Test using mod_mul helper
    let a_val = 42u128;
    let inv_val = inv_a.value.to_u128().expect("conversion error");
    assert_eq!(mod_mul(a_val, inv_val, P), 1);
  }

  #[test]
  fn test_mod_add() {
    assert_eq!(mod_add(10, 20, 100), 30);
    assert_eq!(mod_add(90, 20, 100), 10);
    // Test overflow case
    assert_eq!(mod_add(u128::MAX - 5, 10, u128::MAX - 1), 4);
  }

  #[test]
  fn test_mod_sub() {
    assert_eq!(mod_sub(20, 10, 100), 10);
    assert_eq!(mod_sub(10, 20, 100), 90);
    // Test with modulus equal to P
    assert_eq!(mod_sub(10, 20, P), mod_sub(0, 10, P));
  }

  #[test]
  fn test_mod_mul() {
    assert_eq!(mod_mul(10, 20, 100), 0);
    assert_eq!(mod_mul(10, 20, 101), 99);
    // Test with smaller values to avoid overflow
    let a = 1u128 << 30;
    let b = 1u128 << 30;
    // Use BigUint for expected result calculation
    let expected = (BigUint::from(a) * BigUint::from(b) % BigUint::from(P)).to_u128().unwrap();
    assert_eq!(mod_mul(a, b, P), expected);
  }

  #[test]
  fn test_mod_pow() {
    assert_eq!(mod_pow(2, 10, 100), 24);  // 2^10 = 1024, 1024 % 100 = 24
    assert_eq!(mod_pow(3, 5, 100), 43);   // 3^5 = 243, 243 % 100 = 43
    
    // Test with smaller exponents to avoid overflow
    let base = 7u128;
    let exp = 10u128;
    let expected = (BigUint::from(base).pow(exp as u32) % BigUint::from(P))
        .to_u128()
        .expect("conversion error");
    assert_eq!(mod_pow(base, exp, P), expected);
    
    // Test with larger base but smaller exponent
    let base = 1u128 << 30;
    let exp = 3u128;
    let expected = (BigUint::from(base).pow(exp as u32) % BigUint::from(P))
        .to_u128()
        .expect("conversion error");
    assert_eq!(mod_pow(base, exp, P), expected);
  }
}
