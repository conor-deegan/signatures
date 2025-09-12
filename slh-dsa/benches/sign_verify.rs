use criterion::{Criterion, black_box, criterion_group, criterion_main};
use signature::{Keypair, Signer, Verifier};
use slh_dsa::*;
use std::time::Duration;

pub fn sign_benchmark<P: ParameterSet>(c: &mut Criterion) {
    let mut rng = rand::rng();
    let sk = SigningKey::<P>::new(&mut rng);
    c.bench_function(&format!("sign: {}", P::NAME), |b| {
        b.iter(|| {
            let msg = b"Hello, world!";
            let sig = sk.try_sign(msg).unwrap();
            black_box(sig)
        })
    });
}

pub fn verify_benchmark<P: ParameterSet>(c: &mut Criterion) {
    let mut rng = rand::rng();
    let sk = SigningKey::<P>::new(&mut rng);
    let msg = b"Hello, world!";
    let sig = sk.try_sign(msg).unwrap();
    let vk = sk.verifying_key();
    c.bench_function(&format!("verify: {}", P::NAME), |b| {
        b.iter(|| {
            let ok = vk.verify(msg, &sig);
            black_box(ok)
        })
    });
}

// SHAKE benchmarks
criterion_group!(name = shake_sign_benches;
    config = Criterion::default().sample_size(10);
    targets = sign_benchmark<Shake128s>, sign_benchmark<Shake192s>, sign_benchmark<Shake256s>,
              sign_benchmark<Shake128f>, sign_benchmark<Shake192f>, sign_benchmark<Shake256f>,
);

criterion_group!(name = shake_verify_benches;
    config = Criterion::default().sample_size(10);
    targets = verify_benchmark<Shake128s>, verify_benchmark<Shake192s>, verify_benchmark<Shake256s>,
              verify_benchmark<Shake128f>, verify_benchmark<Shake192f>, verify_benchmark<Shake256f>,
);

// SHA2 benchmarks
criterion_group!(name = sha2_sign_benches;
    config = Criterion::default().sample_size(10);
    targets = sign_benchmark<Sha2_128s>, sign_benchmark<Sha2_192s>, sign_benchmark<Sha2_256s>,
              sign_benchmark<Sha2_128f>, sign_benchmark<Sha2_192f>, sign_benchmark<Sha2_256f>,
);

criterion_group!(name = sha2_verify_benches;
    config = Criterion::default().sample_size(10);
    targets = verify_benchmark<Sha2_128s>, verify_benchmark<Sha2_192s>, verify_benchmark<Sha2_256s>,
              verify_benchmark<Sha2_128f>, verify_benchmark<Sha2_192f>, verify_benchmark<Sha2_256f>,
);

// Quick test benchmark
criterion_group!(name = quick_bench;
    config = Criterion::default().sample_size(3).measurement_time(std::time::Duration::from_secs(1));
    targets = sign_benchmark<Blake3_128s>,
);

criterion_main!(quick_bench);
