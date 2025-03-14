//! # Signature Module
//! 
//! This module contains implementations of various signature schemes, with a focus on the Loquat
//! signature scheme and its applications.
//!
//! ## Loquat Signature Scheme
//!
//! The Loquat signature scheme is a SNARK-friendly post-quantum signature scheme based on the
//! Legendre PRF, as described in the CRYPTO 2024 paper:
//! "Loquat: A SNARK-Friendly Post-Quantum Signature Based on the Legendre PRF with Applications
//! in Ring and Aggregate Signatures" by Xinyu Zhang, Ron Steinfeld, Muhammed F. Esgin, et al.
//!
//! Key features of the Loquat signature scheme:
//! - Post-quantum security based on the hardness of the Legendre PRF
//! - SNARK-friendly design for efficient verification in zero-knowledge proofs
//! - Significantly fewer computational operations for verification compared to other
//!   symmetric-key-based post-quantum signature schemes
//! - Applications in ring signatures and aggregate signatures
//!
//! The current implementation follows the design specified in the paper and is inspired by
//! the reference Python implementation (LoquatPy). Further optimizations and enhancements
//! to the Legendre PRF integration are planned for future updates.
//!
//! ## Module Structure
//! - `loquat`: Core implementation of the Loquat signature scheme
//! - `ring_signature`: Ring signature implementation based on Loquat
//! - `aggregate`: Aggregate signature implementation based on Loquat

pub mod ring_signature;
pub mod aggregate;
pub mod loquat;
