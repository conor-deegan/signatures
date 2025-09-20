// CD: Added crypto_blake3 module
use crate::module_lattice::encode::ArraySize;
use blake3::{Hasher, OutputReader};
use hybrid_array::Array;
use std::sync::Once;

#[allow(dead_code)]
static PRINT_ONCE: Once = Once::new();

// Cache for holding hash output
const CACHE_BYTES: usize = 16_384; // multiple of 32;
const PARALLEL_THRESHOLD: usize = 32 * 1024; // 32 KiB;
const INITIAL_FILL: usize = 512; // first pull after finalize_xof(), must be multiple of 32
const MIN_REFILL: usize = 512; // minimum on later refills, must be multiple of 32
#[inline]
fn align32(n: usize) -> usize {
    (n + 31) & !31
}

#[derive(Debug)]
/// BLAKE3 hash state
pub enum Blake3State {
    // Buffer inputs; do not touch the hasher until the first squeeze.
    /// Absorbing state
    Absorbing {
        /// Hasher
        hasher: Hasher,
        /// Hash Buffer
        buf: Vec<u8>,
    },
    // After first squeeze, keep a single OutputReader and a local cache.
    /// Squeezing state
    Squeezing {
        /// `OutputReader`
        reader: OutputReader,
        /// Cache
        cache: Box<[u8; CACHE_BYTES]>,
        /// Next unread index in cache
        off: usize,
        /// Bytes currently valid in cache
        len: usize,
    },
}

impl Default for Blake3State {
    fn default() -> Self {
        PRINT_ONCE.call_once(|| {
            println!("\n ⍆ Using BLAKE3 optimized hash function\n");
        });
        Blake3State::Absorbing {
            hasher: Hasher::new(),
            buf: Vec::with_capacity(128),
        }
    }
}

impl Blake3State {
    #[allow(dead_code)] // removing compiler warnings given feature flags
    /// Absorb input into the hash state
    #[must_use] pub fn absorb(mut self, input: &[u8]) -> Self {
        match &mut self {
            Blake3State::Absorbing { hasher, buf } => {
                if input.len() >= PARALLEL_THRESHOLD {
                    println!("Using parallel absorb");
                    if !buf.is_empty() {
                        hasher.update(buf);
                        buf.clear();
                    }
                    // Large message → parallel absorb (requires blake3 with rayon enabled)
                    hasher.update_rayon(input);
                } else {
                    // println!("Using sequential absorb");
                    // Small message → just buffer; we hash once at first squeeze()
                    buf.extend_from_slice(input);
                }
            }
            Blake3State::Squeezing { .. } => unreachable!(), // absorb-after-squeeze not allowed
        }
        self
    }

    #[inline]
    fn ensure_reader(&mut self) {
        if let Blake3State::Absorbing { hasher, buf } = self {
            // println!("Updating hasher");
            // Hash all buffered input once, then finalize into an XOF reader.
            hasher.update(buf);
            buf.clear();
            let mut reader = hasher.finalize_xof();

            // Prime the cache with a large fill to avoid tiny reads.
            // println!("Priming cache");
            let mut cache = Box::new([0u8; CACHE_BYTES]);
            let first = INITIAL_FILL.min(CACHE_BYTES);
            reader.fill(&mut cache[..first]);

            // println!("Switching to squeezing state");
            *self = Blake3State::Squeezing {
                reader,
                cache,
                off: 0,
                len: first,
            };
        }
    }

    /// Squeeze output from the hash state
    pub fn squeeze(&mut self, out: &mut [u8]) -> &mut Self {
        // println!("Squeezing");
        // On first squeeze, finalize and switch to streaming mode.
        self.ensure_reader();

        // Now we’re guaranteed to be in Squeezing.
        if let Blake3State::Squeezing {
            reader,
            cache,
            off,
            len,
        } = self
        {
            let mut written = 0;
            while written < out.len() {
                // Refill cache if empty.
                if *off == *len {
                    // println!("Refilling cache");
                    let need = out.len() - written; // bytes caller still needs
                    let want = align32(core::cmp::max(need, MIN_REFILL)); // >=512 and multiple of 32
                    let filln = core::cmp::min(want, CACHE_BYTES); // cap to cache size
                    reader.fill(&mut cache[..filln]);
                    *off = 0;
                    *len = filln;
                } else {
                    // println!("Serving from cache");
                }
                let avail = *len - *off;
                let need = out.len() - written;
                let take = if avail < need { avail } else { need };

                // Serve from cache.
                out[written..written + take].copy_from_slice(&cache[*off..*off + take]);
                *off += take;
                written += take;
            }
        } else {
            unreachable!();
        }
        self
    }

    #[allow(dead_code)] // removing compiler warnings given feature flags
    /// Squeeze output from the hash state
    pub fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        let mut v = Array::default();
        self.squeeze(&mut v);
        v
    }
}

#[allow(dead_code)] // removing compiler warnings given feature flags
/// BLAKE3 hash state for G function
pub type G = Blake3State;
#[allow(dead_code)] // removing compiler warnings given feature flags
/// BLAKE3 hash state for H function
pub type H = Blake3State;

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::B32;
    use hex_literal::hex;

    #[test]
    fn g() {
        let input = b"hello world";
        let expected1 = hex!("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
        let expected2 = hex!("a020ed55aed9a6ab2eaf3fd70d2c98c949e142d8f42a10250190b699e02cf9eb");

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
        let expected1 = hex!("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
        let expected2 = hex!("a020ed55aed9a6ab2eaf3fd70d2c98c949e142d8f42a10250190b699e02cf9eb");

        let mut h = H::default().absorb(input);

        let mut actual = [0u8; 32];
        h.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = h.squeeze_new();
        assert_eq!(actual, expected2);
    }
}
