use crate::crypto::hash_functions::{Hash, HashFunction};
use num_bigint::BigUint;
use std::collections::VecDeque;

// A Merkle Tree struct that supports SNARK-friendly hashing
#[derive(Debug, Clone)]
pub struct MerkleTree {
  leaves: Vec<BigUint>,
  tree: Vec<Vec<BigUint>>, // Tree layers
  hash_function: HashFunction,
}

impl MerkleTree {
  // Constructs a new Merkle Tree from a list of leaves using the specified hash function
  pub fn new(leaves: Vec<BigUint>, hash_function: HashFunction) -> Self {
    let mut tree = vec![];
    let mut level = leaves.clone();

    while level.len() > 1 {
      let mut next_level = vec![];
      for chunk in level.chunks(2) {
        let parent_hash = match chunk.len() {
          2 => MerkleTree::hash_two(&chunk[0], &chunk[1], &hash_function),
          1 => chunk[0].clone(), // Carry over if odd number of leaves
          _ => unreachable!(),
        };
        next_level.push(parent_hash);
      }
      tree.push(level);
      level = next_level;
    }

    if !level.is_empty() {
      tree.push(level);
    }

    Self {
      leaves,
      tree,
      hash_function,
    }
  }

  // Computes the root of the Merkle tree
  pub fn root(&self) -> Option<BigUint> {
    self.tree.last().map(|level| level[0].clone())
  }

  // Generates a Merkle proof for a given leaf index
  pub fn generate_proof(&self, index: usize) -> Option<Vec<(BigUint, bool)>> {
    if index >= self.leaves.len() {
      return None;
    }

    let mut proof = vec![];
    let mut idx = index;
    for level in &self.tree[..self.tree.len() - 1] {
      let sibling_index = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

      if sibling_index < level.len() {
          proof.push((level[sibling_index].clone(), idx % 2 == 0));
      }
      idx /= 2;
    }

    Some(proof)
  }

  // Verifies a Merkle proof
  pub fn verify_proof(root: &BigUint, leaf: &BigUint, proof: &[(BigUint, bool)], hash_function: &HashFunction) -> bool {
    let mut hash = leaf.clone();
    for (sibling, is_left) in proof {
      hash = if *is_left {
        MerkleTree::hash_two(&hash, sibling, hash_function)
      } else {
        MerkleTree::hash_two(sibling, &hash, hash_function)
      };
    }
    hash == *root
  }

  // Hashes two values together using the specified hash function
  fn hash_two(a: &BigUint, b: &BigUint, hash_function: &HashFunction) -> BigUint {
    let mut data = vec![];
    data.extend_from_slice(&a.to_bytes_be());
    data.extend_from_slice(&b.to_bytes_be());

    // Use clone() on the reference to get an owned HashFunction
    let hash = Hash::new(hash_function.clone()).compute(&data);
    BigUint::from_bytes_be(&hash)
  }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let leaves = vec![
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(3u32),
            BigUint::from(4u32),
        ];
        let tree = MerkleTree::new(leaves.clone(), HashFunction::Sha3_256);

        let root = tree.root().unwrap();
        let proof = tree.generate_proof(2).unwrap();
        assert!(MerkleTree::verify_proof(&root, &leaves[2], &proof, &HashFunction::Sha3_256));
    }

    #[test]
    fn test_invalid_proof() {
        let leaves = vec![
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(3u32),
            BigUint::from(4u32),
        ];
        let tree = MerkleTree::new(leaves.clone(), HashFunction::Sha3_256);

        let root = tree.root().unwrap();
        let proof = tree.generate_proof(1).unwrap();
        assert!(!MerkleTree::verify_proof(&root, &leaves[3], &proof, &HashFunction::Sha3_256));
    }
}
