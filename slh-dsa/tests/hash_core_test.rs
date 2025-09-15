use hmac::{Hmac, KeyInit, Mac};
use sha2::Digest;
use std::time::Instant;

#[test]
fn compare_core_operations() {
    // Test parameters
    let iterations = 10_000;
    let key = [0u8; 32];
    let msg1 = [1u8; 32];
    let msg2 = [2u8; 32];
    let msg3 = [3u8; 32];

    // Test operation similar to prf_sk
    println!("\nTesting prf_sk-like operation (key + 3 small messages):");

    // BLAKE3 version 1 (current)
    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&msg1);
        hasher.update(&msg2);
        hasher.update(&msg3);
        let mut output = [0u8; 32];
        hasher.finalize_xof().fill(&mut output);
        let _ = &output[..16];
    }
    let blake3_v1_time = start.elapsed();
    println!("BLAKE3 (current) time: {:?}", blake3_v1_time);

    // BLAKE3 version 2 (optimized)
    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&msg1);
        hasher.update(&msg2);
        hasher.update(&msg3);
        let output = hasher.finalize();
        let _ = &output.as_bytes()[..16];
    }
    let blake3_v2_time = start.elapsed();
    println!("BLAKE3 (optimized) time: {:?}", blake3_v2_time);

    // SHA2-HMAC
    let start = Instant::now();
    for _ in 0..iterations {
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&msg1);
        mac.update(&msg2);
        mac.update(&msg3);
        let result = mac.finalize();
        let _ = &result.into_bytes()[..16];
    }
    let sha2_time = start.elapsed();
    println!("SHA2-HMAC time: {:?}", sha2_time);

    println!("\nRelative performance:");
    println!(
        "Current vs Optimized BLAKE3: {:.2}x",
        blake3_v1_time.as_secs_f64() / blake3_v2_time.as_secs_f64()
    );
    println!(
        "SHA2 vs Optimized BLAKE3: {:.2}x",
        sha2_time.as_secs_f64() / blake3_v2_time.as_secs_f64()
    );

    // Test operation similar to h_msg (hash multiple messages)
    println!("\nTesting h_msg-like operation (hash multiple messages):");

    // BLAKE3 version 1 (current)
    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&msg1);
        hasher.update(&msg2);
        hasher.update(&msg3);
        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);
        let _ = &output[..34];
    }
    let blake3_v1_time = start.elapsed();
    println!("BLAKE3 (current) time: {:?}", blake3_v1_time);

    // BLAKE3 version 2 (optimized)
    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&msg1);
        hasher.update(&msg2);
        hasher.update(&msg3);
        let output = hasher.finalize();
        let mut xof = [0u8; 34];
        xof[..32].copy_from_slice(output.as_bytes());
        if output.as_bytes()[0] & 1 == 1 {
            xof[32..].copy_from_slice(&[0xFF, 0xFF]);
        }
    }
    let blake3_v2_time = start.elapsed();
    println!("BLAKE3 (optimized) time: {:?}", blake3_v2_time);

    // SHA2
    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&msg1);
        hasher.update(&msg2);
        hasher.update(&msg3);
        let result = hasher.finalize();
        let mut output = [0u8; 34];
        output[..32].copy_from_slice(&result);
        if result[0] & 1 == 1 {
            output[32..].copy_from_slice(&[0xFF, 0xFF]);
        }
    }
    let sha2_time = start.elapsed();
    println!("SHA2 time: {:?}", sha2_time);

    println!("\nRelative performance:");
    println!(
        "Current vs Optimized BLAKE3: {:.2}x",
        blake3_v1_time.as_secs_f64() / blake3_v2_time.as_secs_f64()
    );
    println!(
        "SHA2 vs Optimized BLAKE3: {:.2}x",
        sha2_time.as_secs_f64() / blake3_v2_time.as_secs_f64()
    );
}
