//! Example demonstrating key generation for Loquat signatures
//!
//! This example shows how to generate a new key pair for the Loquat signature scheme.
//! Run with: cargo run --example keygen

use loquat_vc::signature::loquat::Loquat;

fn main() {
    println!("Generating a new Loquat key pair...");
    
    // Call the keygen function to generate a new key pair
    let keypair = Loquat::keygen();
    
    // Print the generated keys in a user-friendly format
    println!("\nGenerated Key Pair:");
    println!("------------------");
    println!("Secret Key: {:?}", keypair.secret_key);
    println!("Public Key: {:?}", keypair.public_key);
    
    println!("\nKey generation successful!");
}
