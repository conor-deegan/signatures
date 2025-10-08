# Tracking updates for testing different hash functions

## Overview

I am using a feature flag to compare different hash functions.

## Added `crypto_blake3_niave.rs`, `crypto_blake3_optimized.rs`, and `crypto_aes.rs` modules

These modules are a wrapper around the the various hash functions which exposes a similar interface to the SHAKE hash function.

To test the modules:

```bash
cargo test --lib crypto
cargo test --lib crypto_blake3_niave
cargo test --lib crypto_blake3_optimized
cargo test --lib crypto_aes
```

## Round Trip Analysis

```bash
cargo test --test round_trip_analysis --features shake -- --nocapture
cargo test --test round_trip_analysis --features aes -- --nocapture
cargo test --test round_trip_analysis --features blake3-niave -- --nocapture
cargo test --test round_trip_analysis --features blake3-optimized -- --nocapture
```

## Benchmarking

```bash
cargo bench --bench ml_dsa --no-default-features --features shake
cargo bench --bench ml_dsa --no-default-features --features aes
cargo bench --bench ml_dsa --no-default-features --features blake3-niave
cargo bench --bench ml_dsa --no-default-features --features blake3-optimized
```

```bash
cargo bench --bench ml_dsa_warm_v_cold --no-default-features --features shake
cargo bench --bench ml_dsa_warm_v_cold --no-default-features --features aes
cargo bench --bench ml_dsa_warm_v_cold --no-default-features --features blake3-niave
cargo bench --bench ml_dsa_warm_v_cold --no-default-features --features blake3-optimized
```

Takeaways

Wins:
• Mid-size (256–1024 B): B3 is 2–5× faster.
• Bigger (≥1 MiB): B3 is 2–9× faster.
• Round trip (keygen+sign+verify): 1.6× faster overall.
• Ties: verify (pure check), 256 KiB messages.

Losses:
• Very small (32 B) → B3 is ~1.5–2× slower.
• 4 KiB messages → B3 is ~20–30% slower.
• Keygen → small overhead in B3 path.
