use criterion::{Criterion, criterion_group, criterion_main};
use ml_dsa::crypto::H as ShakeH;
use ml_dsa::crypto_blake3::G as Blake3G;
use ml_dsa::{B32, B64};

// Test different patterns of absorb/squeeze
fn bench_hash_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_state_patterns");
    let input = &[42u8; 32]; // 32 byte input

    // Pattern 1: Single absorb followed by single squeeze
    group.bench_function("SHAKE-single-absorb-squeeze", |b| {
        b.iter(|| {
            let h = ShakeH::default();
            let mut h = h.absorb(input);
            let _: B32 = h.squeeze_new();
        })
    });

    group.bench_function("BLAKE3-single-absorb-squeeze", |b| {
        b.iter(|| {
            let h = Blake3G::default();
            let mut h = h.absorb(input);
            let _: B32 = h.squeeze_new();
        })
    });

    // Pattern 2: Multiple absorbs (3) followed by single squeeze
    group.bench_function("SHAKE-multi-absorb-squeeze", |b| {
        b.iter(|| {
            let h = ShakeH::default();
            let h = h.absorb(input);
            let h = h.absorb(input);
            let mut h = h.absorb(input);
            let _: B32 = h.squeeze_new();
        })
    });

    group.bench_function("BLAKE3-multi-absorb-squeeze", |b| {
        b.iter(|| {
            let h = Blake3G::default();
            let h = h.absorb(input);
            let h = h.absorb(input);
            let mut h = h.absorb(input);
            let _: B32 = h.squeeze_new();
        })
    });

    // Pattern 3: Single absorb followed by multiple squeezes
    group.bench_function("SHAKE-absorb-multi-squeeze", |b| {
        b.iter(|| {
            let h = ShakeH::default();
            let mut h = h.absorb(input);
            let _: B32 = h.squeeze_new();
            let _: B32 = h.squeeze_new();
            let _: B32 = h.squeeze_new();
        })
    });

    group.bench_function("BLAKE3-absorb-multi-squeeze", |b| {
        b.iter(|| {
            let h = Blake3G::default();
            let mut h = h.absorb(input);
            let _: B32 = h.squeeze_new();
            let _: B32 = h.squeeze_new();
            let _: B32 = h.squeeze_new();
        })
    });

    // Pattern 4: ML-DSA key generation pattern
    group.bench_function("SHAKE-mldsa-pattern", |b| {
        b.iter(|| {
            // Key generation pattern
            let h = ShakeH::default();
            let h = h.absorb(&[42u8; 32]); // xi
            let h = h.absorb(&[4]); // K
            let h = h.absorb(&[4]); // L
            let mut h = h.absorb(&[0]); // Extra byte for good measure
            let _: B32 = h.squeeze_new(); // rho
            let _: B64 = h.squeeze_new(); // rhop
            let _: B32 = h.squeeze_new(); // K

            // Sampling pattern (sample_in_ball-like)
            let h = ShakeH::default();
            let mut h = h.absorb(&[42u8; 32]); // rho
            for _ in 0..100 {
                // Simulate multiple squeezes
                let mut out = [0u8; 8];
                h.squeeze(&mut out);
            }

            // rej_ntt_poly-like pattern
            let h = ShakeH::default();
            let h = h.absorb(&[42u8; 32]); // rho
            let h = h.absorb(&[1]); // s
            let mut h = h.absorb(&[2]); // r
            for _ in 0..100 {
                // Simulate coefficient generation
                let mut out = [0u8; 3];
                h.squeeze(&mut out);
            }
        })
    });

    group.bench_function("BLAKE3-mldsa-pattern", |b| {
        b.iter(|| {
            // Key generation pattern
            let h = Blake3G::default();
            let h = h.absorb(&[42u8; 32]); // xi
            let h = h.absorb(&[4]); // K
            let h = h.absorb(&[4]); // L
            let mut h = h.absorb(&[0]); // Extra byte for good measure
            let _: B32 = h.squeeze_new(); // rho
            let _: B64 = h.squeeze_new(); // rhop
            let _: B32 = h.squeeze_new(); // K

            // Sampling pattern (sample_in_ball-like)
            let h = Blake3G::default();
            let mut h = h.absorb(&[42u8; 32]); // rho
            for _ in 0..100 {
                // Simulate multiple squeezes
                let mut out = [0u8; 8];
                h.squeeze(&mut out);
            }

            // rej_ntt_poly-like pattern
            let h = Blake3G::default();
            let h = h.absorb(&[42u8; 32]); // rho
            let h = h.absorb(&[1]); // s
            let mut h = h.absorb(&[2]); // r
            for _ in 0..100 {
                // Simulate coefficient generation
                let mut out = [0u8; 3];
                h.squeeze(&mut out);
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_hash_patterns);
criterion_main!(benches);
