# Tracking updates for adding BLAKE3 support

Note, any changes I have made I have added a comment to the code prefixing with CD. Example:

```
CD: Description of the change
```

## Overview

I am using a feature flag to compare different hash functions.

## Key Gen

### Single Keypair

To generate a single keypair and see the timing with SHAKE:

```
cargo test --test key_gen_analysis --features shake -- --nocapture
```

To generate a single keypair and see the timing with BLAKE3:

```
cargo test --test key_gen_analysis --features blake3 -- --nocapture
```

### Benchmarking

To benchmark the key generation with SHAKE:

```
cargo bench --bench hash_comparison
```

To benchmark the key generation with BLAKE3:

```
cargo bench --bench hash_comparison --features blake3 
```