// Proving polynomial evaluations in zero-knowledge
// Verifying SNARK proofs with univariate sumcheck
// Support for batch verification of multiple statements

use crate::crypto::polynomial::Polynomial;
use crate::proof_system::univariate_sumcheck::{SumcheckProver, SumcheckVerifier};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use rand::Rng;

// Prime field modulus (p = 2^127 - 1) 
const P: u128 = (1 << 127) - 1;

// SNARK Prover
pub struct SNARKProver {
  polynomial: Polynomial,
}

impl SNARKProver {
  // Creates a new prover instance
  pub fn new(poly: Polynomial) -> Self {
    Self { polynomial: poly }
  }

  // Generates a SNARK proof for a polynomial evaluation
  pub fn generate_proof(&self, domain: &[u128]) -> (BigUint, Vec<BigUint>) {
    let sumcheck_prover = SumcheckProver::new(self.polynomial.clone());
    sumcheck_prover.generate_proof(domain)
  }
}

// SNARK Verifier
pub struct SNARKVerifier {
  claimed_sum: BigUint,
}

impl SNARKVerifier {
  // Creates a new verifier instance
  pub fn new(claimed_sum: BigUint) -> Self {
    Self { claimed_sum }
  }

  // Verifies a SNARK proof using sumcheck
  pub fn verify_proof(&self, proof: (BigUint, Vec<BigUint>), poly: &Polynomial, domain: &[u128]) -> bool {
    let sumcheck_verifier = SumcheckVerifier::new(proof.0.clone());
    sumcheck_verifier.verify_proof(proof, poly, domain)
  }

  // Batch verifies multiple SNARK proofs
  pub fn batch_verify(&self, proofs: Vec<(BigUint, Vec<BigUint>)>, polys: Vec<Polynomial>, domains: Vec<Vec<u128>>) -> bool {
    for ((proof, poly), domain) in proofs.iter().zip(polys.iter()).zip(domains.iter()) {
      if !self.verify_proof(proof.clone(), poly, domain) {
        return false;
      }
    }
    true
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use num_traits::ToPrimitive;
  
  // Safe modular arithmetic operations
  fn mod_add(a: u128, b: u128) -> u128 {
    ((a % P) + (b % P)) % P
  }
  
  fn mod_sub(a: u128, b: u128) -> u128 {
    ((a % P) + P - (b % P)) % P
  }
  
  fn mod_mul(a: u128, b: u128) -> u128 {
    ((a % P) * (b % P)) % P
  }
  
  fn mod_pow(base: u128, exp: u128) -> u128 {
    if exp == 0 {
      return 1;
    }
    
    // Use BigUint for intermediate calculations to prevent overflow
    let base_big = BigUint::from(base % P);
    let mut result = BigUint::from(1u128);
    let mut base_pow = base_big;
    let mut exp = exp;
    
    while exp > 0 {
      if exp & 1 == 1 {
        result = (result * &base_pow) % BigUint::from(P);
      }
      base_pow = (&base_pow * &base_pow) % BigUint::from(P);
      exp >>= 1;
    }
    
    biguint_to_u128(&result)
  }
  
  // Convert BigUint to u128 for modular operations
  fn biguint_to_u128(value: &BigUint) -> u128 {
    let reduced_value = value % BigUint::from(P);
    reduced_value.to_u128().unwrap_or(0)
  }
  
  // Convert u128 to BigUint after modular operations
  fn u128_to_biguint(value: u128) -> BigUint {
    BigUint::from(value % P)
  }

  #[test]
  fn test_snark_integration() {
    // Use safe modular arithmetic for polynomial coefficients
    let coeffs = vec![
      mod_add(0, 1),  // 1
      mod_add(0, 2),  // 2
      mod_add(0, 3)   // 3
    ];
    let poly = Polynomial::new(coeffs); // f(x) = 3x² + 2x + 1
    
    // Use safe modular arithmetic for domain values
    let domain = vec![
      mod_add(0, 1),  // 1
      mod_add(0, 2),  // 2
      mod_add(0, 3),  // 3
      mod_add(0, 4)   // 4
    ];

    let prover = SNARKProver::new(poly.clone());
    let proof = prover.generate_proof(&domain);

    let verifier = SNARKVerifier::new(proof.0.clone());
    assert!(verifier.verify_proof(proof, &poly, &domain));
  }

  #[test]
  fn test_batch_verification() {
    // Use safe modular arithmetic for polynomial coefficients
    let coeffs1 = vec![
      mod_add(0, 1),  // 1
      mod_add(0, 2),  // 2
      mod_add(0, 3)   // 3
    ];
    let coeffs2 = vec![
      mod_add(0, 4),  // 4
      mod_add(0, 5),  // 5
      mod_add(0, 6)   // 6
    ];
    
    let poly1 = Polynomial::new(coeffs1); // f(x) = 3x² + 2x + 1
    let poly2 = Polynomial::new(coeffs2); // g(x) = 6x² + 5x + 4
    
    // Use safe modular arithmetic for domain values
    let domain1 = vec![
      mod_add(0, 1),  // 1
      mod_add(0, 2),  // 2
      mod_add(0, 3),  // 3
      mod_add(0, 4)   // 4
    ];
    let domain2 = vec![
      mod_add(0, 2),  // 2
      mod_add(0, 3),  // 3
      mod_add(0, 4),  // 4
      mod_add(0, 5)   // 5
    ];

    let prover1 = SNARKProver::new(poly1.clone());
    let prover2 = SNARKProver::new(poly2.clone());

    let proof1 = prover1.generate_proof(&domain1);
    let proof2 = prover2.generate_proof(&domain2);

    let verifier1 = SNARKVerifier::new(proof1.0.clone());

    let proofs = vec![proof1, proof2];
    let polys = vec![poly1, poly2];
    let domains = vec![domain1, domain2];

    assert!(verifier1.batch_verify(proofs, polys, domains));
  }

  #[test]
  fn test_invalid_proof() {
    // Use safe modular arithmetic for polynomial coefficients
    let coeffs = vec![
      mod_add(0, 1),  // 1
      mod_add(0, 2),  // 2
      mod_add(0, 3)   // 3
    ];
    let poly = Polynomial::new(coeffs); // f(x) = 3x² + 2x + 1
    
    // Use safe modular arithmetic for domain values
    let domain = vec![
      mod_add(0, 1),  // 1
      mod_add(0, 2),  // 2
      mod_add(0, 3),  // 3
      mod_add(0, 4)   // 4
    ];

    let prover = SNARKProver::new(poly.clone());
    let proof = prover.generate_proof(&domain);

    // Use a different incorrect sum value that's within the field
    let incorrect_sum = mod_add(0, 999);
    let verifier = SNARKVerifier::new(u128_to_biguint(incorrect_sum));
    assert!(!verifier.verify_proof(proof, &poly, &domain));
  }
}
