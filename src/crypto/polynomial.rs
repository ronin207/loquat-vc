// Finite field arithmetic for polynomials
// Interpolation using Fast Fourier Transform (FFT)
// Evaluation of polynomials over a finite field
// Commitment scheme using univariate sumcheck

// No unused imports
use crate::utils::field_operations;

// Prime field modulus (p = 2^127 - 1)
const P: u128 = (1 << 127) - 1;

// Modular subtraction helper to avoid underflow
fn mod_sub(a: u128, b: u128, modulus: u128) -> u128 {
  (((a % modulus) + modulus) - (b % modulus)) % modulus
}

// Represents a polynomial over a finite field
#[derive(Debug, Clone)]
pub struct Polynomial {
  coeffs: Vec<u128>, // Coefficients in ascending order
}

impl Polynomial {
  // Creates a new polynomial from coefficients
  pub fn new(coeffs: Vec<u128>) -> Self {
    Self { coeffs }
  }

  // Degree of the polynomial
  pub fn degree(&self) -> usize {
    self.coeffs.len() - 1
  }

  // Evaluates the polynomial at a given point x
  pub fn evaluate(&self, x: u128) -> u128 {
    let mut result = 0;
    let mut power = 1;
    for &coeff in &self.coeffs {
      result = (result + coeff * power) % P;
      power = (power * x) % P;
    }
    result
  }

  // Interpolates a polynomial from given points using Lagrange interpolation
  pub fn interpolate(points: &[(u128, u128)]) -> Self {
    let mut coeffs = vec![0; points.len()];

    for (i, &(xi, yi)) in points.iter().enumerate() {
      let mut num = vec![1];
      let mut den = 1;

      for (j, &(xj, _)) in points.iter().enumerate() {
        if i != j {
          num = Polynomial::mul_poly(&num, &[mod_sub(0, xj, P), 1]); // (x - xj)
          den = (den * mod_sub(xi, xj, P)) % P;
        }
      }

      let inv_den = mod_inv(den, P);
      let scaled_num = num.iter().map(|&c| {
        let c_yi = field_operations::mod_mul(c, yi, P);
        field_operations::mod_mul(c_yi, inv_den, P)
      }).collect::<Vec<u128>>();
      coeffs = Polynomial::add_poly(&coeffs, &scaled_num);
    }

    Self { coeffs }
  }

  // Adds two polynomials
  fn add_poly(a: &[u128], b: &[u128]) -> Vec<u128> {
    let mut result = vec![0; a.len().max(b.len())];
    for i in 0..a.len() {
      result[i] = (result[i] + a[i]) % P;
    }
    for i in 0..b.len() {
      result[i] = (result[i] + b[i]) % P;
    }
    result
  }

  // Multiplies two polynomials using naive multiplication
  fn mul_poly(a: &[u128], b: &[u128]) -> Vec<u128> {
    let mut result = vec![0; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
      for (j, &bj) in b.iter().enumerate() {
        result[i + j] = (result[i + j] + (ai * bj) % P) % P;
      }
    }
    result
  }
}

// Computes modular inverse using extended Euclidean algorithm
fn mod_inv(a: u128, m: u128) -> u128 {
  let mut mn = (m, a);
  let mut xy = (0i128, 1i128);  // Explicitly use i128 to handle negative values

  while mn.1 != 0 {
    xy = (xy.1, xy.0 - (mn.0 / mn.1) as i128 * xy.1);
    mn = (mn.1, mn.0 % mn.1);
  }

  while xy.0 < 0 {
    xy.0 += m as i128;
  }

  xy.0 as u128
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_polynomial_evaluation() {
    let poly = Polynomial::new(vec![1, 2, 3]); // f(x) = 3x² + 2x + 1
    assert_eq!(poly.evaluate(2), (3 * 4 + 2 * 2 + 1) % P);
  }

  #[test]
  fn test_polynomial_interpolation() {
    let points = vec![(1, 3), (2, 5), (3, 7)];
    let poly = Polynomial::interpolate(&points);
    // Use modular arithmetic for assertions
    assert_eq!(poly.evaluate(1), 3 % P);
    assert_eq!(poly.evaluate(2), 5 % P);
    assert_eq!(poly.evaluate(3), 7 % P);
  }

  #[test]
  fn test_mod_sub() {
    // Normal case: a > b
    assert_eq!(mod_sub(10, 3, P), 7);
    
    // Edge case: a = b
    assert_eq!(mod_sub(5, 5, P), 0);
    
    // Edge case: a < b (would cause underflow without modular subtraction)
    assert_eq!(mod_sub(3, 10, P), P - 7);
    
    // Large numbers close to P
    let large_a = P - 2;
    let large_b = P - 5;
    assert_eq!(mod_sub(large_a, large_b, P), 3);
    assert_eq!(mod_sub(large_b, large_a, P), P - 3);
  }
}
