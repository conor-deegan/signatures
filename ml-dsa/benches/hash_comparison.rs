use blake3::Hasher as Blake3Hasher;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use sha3::{
    Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use ml_dsa::B32;
use ml_dsa::crypto::{G as ShakeG, H as ShakeH};
use ml_dsa::crypto_blake3::G as Blake3G;

// Test sizes based on ML-DSA usage patterns
const SMALL_INPUT: &[u8] = &[42; 4]; // 4 bytes - small parameters/counters
const MEDIUM_INPUT: &[u8] = &[42; 64]; // 64 bytes - keys/randomness
const LARGE_INPUT: &[u8] = &[42; 256]; // 256 bytes - messages/signatures

// Raw hash function benchmarks
fn bench_raw_hashes(c: &mut Criterion) {
    let mut group = c.benchmark_group("raw_hash_functions");

    // Test different input sizes
    for size in [SMALL_INPUT, MEDIUM_INPUT, LARGE_INPUT] {
        // SHAKE-128
        group.bench_with_input(
            BenchmarkId::new("SHAKE-128", size.len()),
            size,
            |b, input| {
                b.iter(|| {
                    let mut shake = Shake128::default();
                    shake.update(input);
                    let mut reader = shake.finalize_xof();
                    let mut output = [0u8; 32];
                    reader.read(&mut output);
                    black_box(output)
                })
            },
        );

        // SHAKE-256
        group.bench_with_input(
            BenchmarkId::new("SHAKE-256", size.len()),
            size,
            |b, input| {
                b.iter(|| {
                    let mut shake = Shake256::default();
                    shake.update(input);
                    let mut reader = shake.finalize_xof();
                    let mut output = [0u8; 32];
                    reader.read(&mut output);
                    black_box(output)
                })
            },
        );

        // BLAKE3 (rayon, xof)
        group.bench_with_input(
            BenchmarkId::new("BLAKE3 (rayon, xof)", size.len()),
            size,
            |b, input| {
                b.iter(|| {
                    let mut hasher = Blake3Hasher::new();
                    hasher.update_rayon(input); // Using rayon for parallel processing
                    let mut output = [0u8; 32];
                    let mut reader = hasher.finalize_xof();
                    reader.fill(&mut output);
                    black_box(output)
                })
            },
        );

        // BLAKE3 (single, xof)
        group.bench_with_input(
            BenchmarkId::new("BLAKE3 (single, xof)", size.len()),
            size,
            |b, input| {
                b.iter(|| {
                    let mut hasher = Blake3Hasher::new();
                    hasher.update(input);
                    let mut output = [0u8; 32];
                    let mut reader = hasher.finalize_xof();
                    reader.fill(&mut output);
                    black_box(output)
                })
            },
        );

        // BLAKE3 (rayon, fixed)
        group.bench_with_input(
            BenchmarkId::new("BLAKE3 (rayon, fixed)", size.len()),
            size,
            |b, input| {
                b.iter(|| {
                    let mut hasher = Blake3Hasher::new();
                    hasher.update_rayon(input);
                    black_box(hasher.finalize())
                })
            },
        );

        // BLAKE3 (single, fixed)
        group.bench_with_input(
            BenchmarkId::new("BLAKE3 (single, fixed)", size.len()),
            size,
            |b, input| {
                b.iter(|| {
                    let mut hasher = Blake3Hasher::new();
                    hasher.update(input);
                    black_box(hasher.finalize())
                })
            },
        );
    }
    group.finish();
}

// ML-DSA wrapper benchmarks
fn bench_wrapped_hashes(c: &mut Criterion) {
    let mut group = c.benchmark_group("wrapped_hash_functions");

    for size in [SMALL_INPUT, MEDIUM_INPUT, LARGE_INPUT] {
        // SHAKE-128
        group.bench_with_input(
            BenchmarkId::new("SHAKE-128", size.len()),
            size,
            |b, input| {
                b.iter(|| {
                    let g = ShakeG::default();
                    let mut g = g.absorb(input);
                    let a: B32 = g.squeeze_new();
                    black_box(a);
                })
            },
        );

        // SHAKE-256
        group.bench_with_input(
            BenchmarkId::new("SHAKE-256", size.len()),
            size,
            |b, input| {
                b.iter(|| {
                    let g = ShakeH::default();
                    let mut g = g.absorb(input);
                    let a: B32 = g.squeeze_new();
                    black_box(a);
                })
            },
        );

        // BLAKE3
        group.bench_with_input(BenchmarkId::new("BLAKE3", size.len()), size, |b, input| {
            b.iter(|| {
                let h = Blake3G::default();
                let mut h = h.absorb(input);
                let a: B32 = h.squeeze_new();
                black_box(a);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_raw_hashes, bench_wrapped_hashes);
criterion_main!(benches);
