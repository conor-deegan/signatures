use aes::{
    Aes128,
    cipher::{KeyIvInit, StreamCipher},
};
use blake3::Hasher;
use ctr::Ctr64BE;
use hybrid_array::Array;
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::module_lattice::encode::ArraySize;

type AesCtr = Ctr64BE<Aes128>;

static PRINT_ONCE: Once = Once::new();

/// Tunable parameters for the AES-based XOF.
#[derive(Clone, Copy, Debug)]
pub struct AesParams {
    /// Size of the keystream cache (bytes).
    pub cache_bytes: usize,
    /// Initial number of bytes to precompute after switching to squeezing.
    pub initial_fill: usize,
    /// Minimum refill size once the cache is depleted.
    pub min_refill: usize,
}

impl AesParams {
    /// Default settings chosen to balance throughput and memory.
    pub const DEFAULT: Self = Self {
        cache_bytes: 16_384,
        initial_fill: 512,
        min_refill: 512,
    };

    fn sanitized(self) -> Self {
        let cache_bytes = align16(self.cache_bytes.max(16));
        let mut initial_fill = align16(self.initial_fill.max(16));
        let mut min_refill = align16(self.min_refill.max(16));

        if initial_fill > cache_bytes {
            initial_fill = cache_bytes;
        }
        if min_refill > cache_bytes {
            min_refill = cache_bytes;
        }

        Self {
            cache_bytes,
            initial_fill,
            min_refill,
        }
    }
}

impl Default for AesParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

static CACHE_BYTES: AtomicUsize = AtomicUsize::new(AesParams::DEFAULT.cache_bytes);
static INITIAL_FILL: AtomicUsize = AtomicUsize::new(AesParams::DEFAULT.initial_fill);
static MIN_REFILL: AtomicUsize = AtomicUsize::new(AesParams::DEFAULT.min_refill);

fn current_params() -> AesParams {
    AesParams {
        cache_bytes: CACHE_BYTES.load(Ordering::Relaxed),
        initial_fill: INITIAL_FILL.load(Ordering::Relaxed),
        min_refill: MIN_REFILL.load(Ordering::Relaxed),
    }
}

/// Fetch the active AES parameters.
pub fn get_aes_params() -> AesParams {
    current_params()
}

/// Override the global AES parameters, returning the previous set.
pub fn set_aes_params(params: AesParams) -> AesParams {
    let sanitized = params.sanitized();
    let old = current_params();

    CACHE_BYTES.store(sanitized.cache_bytes, Ordering::Relaxed);
    INITIAL_FILL.store(sanitized.initial_fill, Ordering::Relaxed);
    MIN_REFILL.store(sanitized.min_refill, Ordering::Relaxed);

    old
}

/// Execute `f` with the provided AES parameters, restoring old values afterwards.
pub fn with_aes_params<F, R>(params: AesParams, f: F) -> R
where
    F: FnOnce() -> R,
{
    struct Guard(AesParams);

    impl Guard {
        fn new(params: AesParams) -> Self {
            Guard(set_aes_params(params))
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            set_aes_params(self.0);
        }
    }

    let guard = Guard::new(params);
    let result = f();
    drop(guard);
    result
}

#[inline]
fn align16(n: usize) -> usize {
    (n + 15) & !15
}

/// AES-CTR backed extendable-output state
pub enum AesState {
    /// Accumulates input using a streaming BLAKE3 hasher until squeezing begins.
    Absorbing {
        /// BLAKE3 hasher providing fast, incremental key derivation.
        hasher: Hasher,
        /// Active tuning parameters.
        params: AesParams,
    },
    /// Streams keystream bytes from AES-CTR with cached output.
    Squeezing {
        /// AES-CTR cipher instance.
        cipher: AesCtr,
        /// Cached keystream bytes.
        cache: Vec<u8>,
        /// Next unread offset in the cache.
        off: usize,
        /// Bytes currently valid in the cache.
        len: usize,
        /// Active tuning parameters.
        params: AesParams,
    },
}

impl Default for AesState {
    fn default() -> Self {
        PRINT_ONCE.call_once(|| {
            println!("\n ⍆ Using AES hash function\n");
        });
        let params = current_params();
        AesState::Absorbing {
            hasher: Hasher::new(),
            params,
        }
    }
}

impl AesState {
    #[allow(dead_code)]
    /// Absorb input into the hash state.
    pub fn absorb(mut self, input: &[u8]) -> Self {
        match &mut self {
            AesState::Absorbing { hasher, .. } => {
                hasher.update(input);
            }
            AesState::Squeezing { .. } => unreachable!(),
        }
        self
    }

    fn ensure_cipher(&mut self) {
        if let AesState::Absorbing { hasher, params } = self {
            use core::mem;

            let hasher = mem::replace(hasher, Hasher::new());
            let (key, nonce) = derive_key_nonce(hasher);

            let mut cipher = AesCtr::new(&key.into(), &nonce.into());
            let mut cache = vec![0u8; params.cache_bytes];
            let first = align16(params.initial_fill.min(cache.len()));
            if first > 0 {
                cipher.apply_keystream(&mut cache[..first]);
            }

            *self = AesState::Squeezing {
                cipher,
                cache,
                off: 0,
                len: first,
                params: *params,
            };
        }
    }

    #[allow(dead_code)]
    /// Squeeze output from the hash state.
    pub fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        self.ensure_cipher();

        if let AesState::Squeezing {
            cipher,
            cache,
            off,
            len,
            params,
        } = self
        {
            let mut written = 0;
            while written < output.len() {
                if *off == *len {
                    let need = output.len() - written;
                    let cache_capacity = cache.len();
                    if cache_capacity == 0 {
                        cipher.apply_keystream(&mut output[written..]);
                        return self;
                    }

                    let want = align16(core::cmp::max(need, params.min_refill));
                    let filln = core::cmp::min(want, cache_capacity);
                    cipher.apply_keystream(&mut cache[..filln]);
                    *off = 0;
                    *len = filln;
                }

                let avail = *len - *off;
                let need = output.len() - written;
                let take = core::cmp::min(avail, need);
                output[written..written + take].copy_from_slice(&cache[*off..*off + take]);
                *off += take;
                written += take;
            }
        } else {
            unreachable!();
        }

        self
    }

    #[allow(dead_code)]
    /// Squeeze output from the hash state into a new array.
    pub fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        let mut v = Array::default();
        self.squeeze(&mut v);
        v
    }
}

fn derive_key_nonce(hasher: Hasher) -> ([u8; 16], [u8; 16]) {
    let mut reader = hasher.finalize_xof();
    let mut key = [0u8; 16];
    let mut nonce = [0u8; 16];
    reader.fill(&mut key);
    reader.fill(&mut nonce);
    (key, nonce)
}

#[allow(dead_code)]
/// AES hash state for G function
pub type G = AesState;
#[allow(dead_code)]
/// AES hash state for H function
pub type H = AesState;

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::B32;
    use hex_literal::hex;

    #[test]
    fn g() {
        let input = b"hello world";
        let expected1 = hex!("e03f0d1922245256d0ee5d8ff0a9da66c893fbd69e8ff59c4189967505a72c09");
        let expected2 = hex!("efdc57f8f746cfe03c300ad03ea6d2289104b1f76d5ce31469a3d7d655175460");

        let mut g = G::default().absorb(input);

        let mut actual = [0u8; 32];
        g.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = g.squeeze_new();
        assert_eq!(actual, expected2);
    }

    #[test]
    fn h() {
        let input = b"hello world";
        let expected1 = hex!("e03f0d1922245256d0ee5d8ff0a9da66c893fbd69e8ff59c4189967505a72c09");
        let expected2 = hex!("efdc57f8f746cfe03c300ad03ea6d2289104b1f76d5ce31469a3d7d655175460");

        let mut h = H::default().absorb(input);

        let mut actual = [0u8; 32];
        h.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = h.squeeze_new();
        assert_eq!(actual, expected2);
    }
}
