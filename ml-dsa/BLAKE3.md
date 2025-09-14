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