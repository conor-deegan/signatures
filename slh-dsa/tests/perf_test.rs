use signature::{Keypair, Signer};
use slh_dsa::*;
use std::time::Instant;

#[test]
fn compare_hash_performance() {
    // Test parameters
    let iterations = 10;
    let msg = b"Hello, world!";

    // Test BLAKE3 (small)
    let mut rng = rand::rng();
    let sk_blake3_s = SigningKey::<Blake3_128s>::new(&mut rng);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk_blake3_s.try_sign(msg).unwrap();
    }
    let blake3_s_time = start.elapsed();
    println!(
        "BLAKE3 (small) time for {} iterations: {:?}",
        iterations, blake3_s_time
    );

    // Test BLAKE3 (fast)
    let sk_blake3_f = SigningKey::<Blake3_128f>::new(&mut rng);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk_blake3_f.try_sign(msg).unwrap();
    }
    let blake3_f_time = start.elapsed();
    println!(
        "BLAKE3 (fast) time for {} iterations: {:?}",
        iterations, blake3_f_time
    );

    // Test SHA2 (small)
    let sk_sha2_s = SigningKey::<Sha2_128s>::new(&mut rng);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk_sha2_s.try_sign(msg).unwrap();
    }
    let sha2_s_time = start.elapsed();
    println!(
        "SHA2 (small) time for {} iterations: {:?}",
        iterations, sha2_s_time
    );

    // Test SHA2 (fast)
    let sk_sha2_f = SigningKey::<Sha2_128f>::new(&mut rng);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk_sha2_f.try_sign(msg).unwrap();
    }
    let sha2_f_time = start.elapsed();
    println!(
        "SHA2 (fast) time for {} iterations: {:?}",
        iterations, sha2_f_time
    );

    // Test SHAKE (small)
    let sk_shake_s = SigningKey::<Shake128s>::new(&mut rng);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk_shake_s.try_sign(msg).unwrap();
    }
    let shake_s_time = start.elapsed();
    println!(
        "SHAKE (small) time for {} iterations: {:?}",
        iterations, shake_s_time
    );

    // Test SHAKE (fast)
    let sk_shake_f = SigningKey::<Shake128f>::new(&mut rng);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk_shake_f.try_sign(msg).unwrap();
    }
    let shake_f_time = start.elapsed();
    println!(
        "SHAKE (fast) time for {} iterations: {:?}",
        iterations, shake_f_time
    );

    println!("\nRelative performance (small variants):");
    println!(
        "BLAKE3 vs SHA2: {:.2}x",
        sha2_s_time.as_secs_f64() / blake3_s_time.as_secs_f64()
    );
    println!(
        "BLAKE3 vs SHAKE: {:.2}x",
        shake_s_time.as_secs_f64() / blake3_s_time.as_secs_f64()
    );

    println!("\nRelative performance (fast variants):");
    println!(
        "BLAKE3 vs SHA2: {:.2}x",
        sha2_f_time.as_secs_f64() / blake3_f_time.as_secs_f64()
    );
    println!(
        "BLAKE3 vs SHAKE: {:.2}x",
        shake_f_time.as_secs_f64() / blake3_f_time.as_secs_f64()
    );
}
