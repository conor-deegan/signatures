use hmac::{Hmac, KeyInit, Mac};
use sha2::Digest;
use std::time::Instant;

#[test]
fn compare_raw_hash_performance() {
    // Test parameters
    let iterations = 10_000; // More iterations since raw hashing is faster
    let key = [0u8; 32];

    println!("\nTesting with different message sizes:");
    let sizes = [64, 1024, 8192, 65536]; // 64B, 1KB, 8KB, 64KB
    for size in sizes {
        let msg = vec![42u8; size];

        // BLAKE3
        let start = Instant::now();
        for _ in 0..iterations {
            let mut hasher = blake3::Hasher::new_keyed(&key);
            hasher.update(&msg);
            let mut output = [0u8; 32];
            hasher.finalize_xof().fill(&mut output);
        }
        let blake3_time = start.elapsed();

        // SHA2-HMAC
        let start = Instant::now();
        for _ in 0..iterations {
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(&msg);
            let _ = mac.finalize();
        }
        let sha2_time = start.elapsed();

        println!("\nMessage size: {} bytes", size);
        println!("BLAKE3 time: {:?}", blake3_time);
        println!("SHA2 time: {:?}", sha2_time);
        println!(
            "SHA2 vs BLAKE3: {:.2}x",
            sha2_time.as_secs_f64() / blake3_time.as_secs_f64()
        );
        println!("Throughput:");
        println!(
            "BLAKE3: {:.2} MB/s",
            (size * iterations) as f64 / blake3_time.as_secs_f64() / 1_000_000.0
        );
        println!(
            "SHA2: {:.2} MB/s",
            (size * iterations) as f64 / sha2_time.as_secs_f64() / 1_000_000.0
        );
    }
}
