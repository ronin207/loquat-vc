# Loquat: A Verifiable Credential Scheme

Loquat is a verifiable credential scheme designed for efficient and secure credential management. It implements a signature scheme that allows for selective disclosure of attributes while maintaining cryptographic integrity.

## Overview

Loquat uses a Merkle tree-based approach for credential verification, enabling selective disclosure of attributes while maintaining the integrity of the credential. This approach allows the holder to reveal only specific attributes to verifiers without compromising the security of the entire credential.

## Key Components

- **Issuer**: Creates and signs credentials
- **Holder**: Receives credentials and presents them to verifiers
- **Verifier**: Validates the authenticity of presented credentials

## Signature Verification

The Loquat signature scheme follows the design described in the [academic paper](https://eprint.iacr.org/2024/868.pdf), with the following key operations:

### Signature Generation
- The signature is generated as `sigma = (sk + H(message)) mod P`, where:
  - `sk` is the secret key
  - `H(message)` is the hash of the message reduced modulo P (to ensure it fits within u128)
  - `P` is the prime modulus (2^127 - 1)
  - All operations are performed using safe modular arithmetic to prevent overflows

### Verification Process
1. The verifier receives a signature containing the Merkle proof and disclosed attributes
2. The message hash is reduced modulo P before conversion to u128, ensuring mathematical consistency
3. The verification recomputes the expected secret key via modular subtraction: `sk' = (sigma - H(message)) mod P`
4. This recomputed secret key is hashed to obtain the expected public key
5. The Merkle proof is used to reconstruct the Merkle root
6. The verification compares the reconstructed Merkle root with the one in the signature
7. The computed public key is checked against the provided public key

This comprehensive verification approach ensures that:
- The signature is bound to both the message and the corresponding public key
- Any tampering with the message will lead to verification failure, as the hash value would change
- The implementation uses safe modular arithmetic throughout to avoid overflows
- Message hashes are consistently reduced modulo P before conversion to u128, preventing conversion errors
- The protocol aligns precisely with the design described in the academic paper

This approach provides strong security guarantees while still allowing for selective disclosure of attributes.

## Usage

```rust
// Example code for issuing a credential
let issuer = Issuer::new();
let (pk, sk) = issuer.keygen();
let attributes = vec!["name", "age", "address"];
let signature = issuer.sign(&sk, &attributes);

// Example code for verifying a credential
let disclosed_indices = vec![0, 1]; // Only disclose "name" and "age"
let disclosed_attributes = vec!["name", "age"];
let partial_signature = holder.disclose(&signature, &disclosed_indices);
let is_valid = verifier.verify(&pk, &partial_signature, &disclosed_attributes);
```

## Security Considerations

- The security of Loquat relies on the cryptographic properties of the underlying hash function
- The Merkle tree approach ensures that selective disclosure does not compromise the integrity of the credential
- The verification process is designed to be resistant to tampering and forgery attempts
- The implementation uses safe modular arithmetic to prevent overflow vulnerabilities
- Message hashes are reduced modulo P (2^127 - 1) before conversion to u128, ensuring consistent mathematical operations
- The signature is cryptographically bound to the exact message, ensuring that any modification to the message will cause verification to fail

## Installation

```bash
cargo add loquat-vc
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
