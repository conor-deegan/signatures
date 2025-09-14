use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ml_dsa::{KeyGen, MlDsa44};
use hybrid_array::Array;

fn criterion_benchmark(c: &mut Criterion) {
    // Print which hash function is being used
    let seed = Array([42u8; 32]);
    let _ = MlDsa44::key_gen_internal(&seed);

    c.bench_function("ML-DSA-44 key generation", |b| {
        b.iter(|| {
            black_box(MlDsa44::key_gen_internal(&seed))
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);