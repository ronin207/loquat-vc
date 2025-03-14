//! Example demonstrating signature verification with Loquat.
//! 
//! This example shows how to verify a digital signature using the Loquat signature scheme.
//! It generates a key pair, signs a message, and then verifies the signature.

use loquat_vc::signature::loquat::Loquat;

fn main() {
    // Set up a sample message to be signed
    let message = b"This is a test message for Loquat signature verification";
    println!("Message: {:?}", String::from_utf8_lossy(message));
    
    // Generate a key pair (public key and private key)
    println!("Generating key pair...");
    let keypair = Loquat::keygen();
    println!("Key pair generated successfully");
    
    // Sign the message using the private key
    println!("Signing message...");
    let signature = Loquat::sign(keypair.secret_key, message);
    println!("Signature created: {:?}", signature);
    
    // Verify the signature using the public key
    println!("Verifying signature...");
    let is_valid = Loquat::verify(&keypair.public_key, message, &signature);
    
    // Print the verification result
    println!("\nSignature verification result: {}", if is_valid {
        "VALID ✓"
    } else {
        "INVALID ✗"
    });
    
    // Demonstrate an invalid verification case by modifying the message
    let modified_message = b"This is a MODIFIED message that wasn't signed";
    println!("\nTrying to verify with a modified message:");
    println!("Modified message: {:?}", String::from_utf8_lossy(modified_message));
    
    let is_valid_modified = Loquat::verify(&keypair.public_key, modified_message, &signature);
    println!("Verification result with modified message: {}", if is_valid_modified {
        "VALID ✓ (This should not happen!)"
    } else {
        "INVALID ✗ (Expected result for modified message)"
    });
}
