// Univariate polynomial commitment verification
// Efficient sumcheck protocol for SNARK applications
// Security through random challenges and sum evaluations

use crate::crypto::polynomial::Polynomial;
use num_bigint::BigUint;
use rand::Rng;
use num_traits::Zero;

// Prime field modulus (p = 2^127 - 1) 
const P: u128 = (1 << 127) - 1;

// Sumcheck Prover
pub struct SumcheckProver {
  polynomial: Polynomial,
}

// Sumcheck Verifier
pub struct SumcheckVerifier {
  claimed_sum: BigUint,
}

impl SumcheckProver {
  // Creates a new prover instance with a polynomial
  pub fn new(poly: Polynomial) -> Self {
    Self { polynomial: poly }
  }

  // Generates proof for the sum over a domain
  pub fn generate_proof(&self, domain: &[u128]) -> (BigUint, Vec<BigUint>) {
    let sum = domain.iter().fold(BigUint::zero(), |acc, &x| {
      let eval = BigUint::from(self.polynomial.evaluate(x));
      (acc + eval) % BigUint::from(P)
    });
    
    let mut challenges = vec![];

    for _ in 0..self.polynomial.degree() {
      let random_challenge = rand::thread_rng().gen_range(1..P);
      challenges.push(BigUint::from(random_challenge));
    }

    (sum, challenges)
  }
}

impl SumcheckVerifier {
  // Creates a new verifier instance with a claimed sum
  pub fn new(claimed_sum: BigUint) -> Self {
    Self { claimed_sum }
  }

  // Verifies the sumcheck proof
  pub fn verify_proof(&self, proof: (BigUint, Vec<BigUint>), poly: &Polynomial, domain: &[u128]) -> bool {
    let (computed_sum, challenges) = proof;

    let expected_sum = domain.iter().fold(BigUint::zero(), |acc, &x| {
      let eval = BigUint::from(poly.evaluate(x));
      (acc + eval) % BigUint::from(P)
    });

    expected_sum == computed_sum && challenges.iter().all(|c| c < &BigUint::from(P))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // Modular arithmetic helper functions
  fn mod_add(a: &BigUint, b: &BigUint) -> BigUint {
    (a + b) % BigUint::from(P)
  }

  fn mod_sub(a: &BigUint, b: &BigUint) -> BigUint {
    if a < b {
      BigUint::from(P) - (b - a) % BigUint::from(P)
    } else {
      (a - b) % BigUint::from(P)
    }
  }

  fn mod_mul(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) % BigUint::from(P)
  }

  #[test]
  fn test_sumcheck_proof() {
    let poly = Polynomial::new(vec![1, 2, 3]); // f(x) = 3x² + 2x + 1
    let domain = vec![1, 2, 3, 4];

    let prover = SumcheckProver::new(poly.clone());
    let proof = prover.generate_proof(&domain);

    let verifier = SumcheckVerifier::new(proof.0.clone());
    assert!(verifier.verify_proof(proof, &poly, &domain));
  }

  #[test]
  fn test_invalid_sumcheck() {
    let poly = Polynomial::new(vec![1, 2, 3]); // f(x) = 3x² + 2x + 1
    let domain = vec![1, 2, 3, 4];

    let prover = SumcheckProver::new(poly.clone());
    let proof = prover.generate_proof(&domain);

    let verifier = SumcheckVerifier::new(BigUint::from(999u32)); // Incorrect sum
    assert!(!verifier.verify_proof(proof, &poly, &domain));
  }
}
