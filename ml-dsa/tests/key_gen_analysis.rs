// CD: adding a key gen analysis test to isolate key gen for analysis
use ml_dsa::*;
use ml_dsa::signature::Verifier;
use hybrid_array::Array;
use std::time::Instant;

#[test]
fn analyze_key_gen_internal() {
    println!("\nAnalyzing ML-DSA-44 Key Generation:");
    println!("----------------------------------");
    
    // Create a fixed seed for reproducibilitys
    let seed = Array([42u8; 32]); // Fixed seed for reproducible results

    // Time the key generation
    let start = Instant::now();
    let kp = MlDsa44::key_gen_internal(&seed);
    let duration = start.elapsed();
    
    println!("Key generation took: {:?}", duration);
    
    // Access signing and verifying keys
    let sk = kp.signing_key();
    let vk = kp.verifying_key();
    
    // Get encoded forms to see sizes
    let sk_encoded = sk.encode();
    let vk_encoded = vk.encode();
    
    println!("\nEncoded Key Sizes:");
    println!("Encoded Signing Key Size: {} bytes", sk_encoded.len());
    println!("Encoded Verifying Key Size: {} bytes", vk_encoded.len());
    
    // // Run the same test with different security levels
    // println!("\nAnalyzing ML-DSA-65 Key Generation:");
    // println!("----------------------------------");
    // let start = Instant::now();
    // let kp = MlDsa65::key_gen_internal(&seed);
    // let duration = start.elapsed();
    // println!("Key generation took: {:?}", duration);
    // let sk_encoded = kp.signing_key().encode();
    // let vk_encoded = kp.verifying_key().encode();
    // println!("Encoded Signing Key Size: {} bytes", sk_encoded.len());
    // println!("Encoded Verifying Key Size: {} bytes", vk_encoded.len());
    
    // println!("\nAnalyzing ML-DSA-87 Key Generation:");
    // println!("----------------------------------");
    // let start = Instant::now();
    // let kp = MlDsa87::key_gen_internal(&seed);
    // let duration = start.elapsed();
    // println!("Key generation took: {:?}", duration);
    // let sk_encoded = kp.signing_key().encode();
    // let vk_encoded = kp.verifying_key().encode();
    // println!("Encoded Signing Key Size: {} bytes", sk_encoded.len());
    // println!("Encoded Verifying Key Size: {} bytes", vk_encoded.len());
    
    // Test a simple signature to ensure keys are working
    let msg = b"test message";
    let sig = kp.signing_key().sign_deterministic(msg, &[]).unwrap();
    assert!(kp.verifying_key().verify(msg, &sig).is_ok());
}