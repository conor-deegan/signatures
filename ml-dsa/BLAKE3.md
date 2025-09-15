# Tracking updates for adding BLAKE3 support

Note, any changes I have made I have added a comment to the code prefixing with CD. Example:

```
CD: Description of the change
```

## Overview

I am using a feature flag to compare different hash functions.

## Added `crypto_blake3.rs` module

This module is a wrapper around the BLAKE3 hash function which exposes a similar interface to the SHAKE hash function.

To test the module:

```bash
cargo test --lib crypto_blake3
```

## Key Gen

To generate a single keypair and see the timing with SHAKE:

```bash
cargo test --test key_gen_analysis --features shake -- --nocapture
```

To generate a single keypair and see the timing with BLAKE3:

```bash
cargo test --test key_gen_analysis --features blake3 -- --nocapture
```

## Benchmarking

To benchmark all operations with SHAKE:

```bash
cargo bench --bench ml_dsa
```

To benchmark all operations with BLAKE3:

```bash
cargo bench --bench ml_dsa --features blake3 
```

### Hash specific benchmarks

Found in the `benches/hash_comparison.rs` file.

```bash
cargo bench --bench hash_comparison
```

From this it's clear that BLAKE3 is faster than SHAKE for all input sizes.

### State specific benchmarks

Found in the `benches/state_comparison.rs` file.

The point of these benchmarks is to compare the performance of the hash function when used in a similar way to the ML-DSA implementation.

```bash
cargo bench --bench state_comparison
```

Now we finally get a sense of what is going on. When there are multiple absorbs and/or squeezes, the difference is less pronounced and when we get up to the scale of the ML-DSA key generation, BLAKE3 ends up being slower than SHAKE. BLAKE3 pays a bigger penalty when used in the current ML-DSA pattern.