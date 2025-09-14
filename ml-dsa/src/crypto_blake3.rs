// CD: Added crypto_blake3 module
use hybrid_array::Array;
use crate::module_lattice::encode::ArraySize;
use blake3::{Hasher, OutputReader};
use std::sync::Once;

#[allow(dead_code)]
static PRINT_ONCE: Once = Once::new();

#[derive(Debug)]
pub enum Blake3State {
    Absorbing(Hasher),
    Squeezing(OutputReader),
}

impl Default for Blake3State {
    fn default() -> Self {
        PRINT_ONCE.call_once(|| {
            println!("\n ⍆ Using BLAKE3 hash function\n");
        });
        Self::Absorbing(Hasher::new())
    }
}

impl Blake3State {
    #[allow(dead_code)] // removing compiler warnings given feature flags
    pub fn absorb(mut self, input: &[u8]) -> Self {
        match &mut self {
            Self::Absorbing(hasher) => {
                hasher.update(input);
            }
            Self::Squeezing(_) => unreachable!(),
        }
        self
    }

    pub fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        match self {
            Self::Absorbing(hasher) => {
                let mut reader = hasher.clone().finalize_xof();
                reader.fill(output);
                *self = Self::Squeezing(reader);
            }
            Self::Squeezing(reader) => {
                reader.fill(output);
            }
        }
        self
    }

    #[allow(dead_code)] // removing compiler warnings given feature flags
    pub fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        let mut v = Array::default();
        self.squeeze(&mut v);
        v
    }
}

#[allow(dead_code)] // removing compiler warnings given feature flags
pub type G = Blake3State;
#[allow(dead_code)] // removing compiler warnings given feature flags
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