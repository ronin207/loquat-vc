//! Example demonstrating how to sign a message using Loquat

use loquat_vc::signature::loquat::Loquat;

fn main() {
    // Define a sample message to sign
    let message = b"Hello, world!";
    println!("Message to sign: {:?}", message);

    // Generate a new keypair
    let keypair = Loquat::keygen();
    println!("Secret key generated successfully");

    // Sign the message using the secret key
    let signature = Loquat::sign(keypair.secret_key, message);
    
    // Print the signature components
    println!("\nSignature created successfully:");
    println!("Sigma: {:?}", signature.sigma);
    println!("Merkle root: {:?}", signature.merkle_root);
}
