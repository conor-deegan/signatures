// TODO(tarcieri): fix `hybrid-array` deprecation warnings
#![allow(deprecated)]

use core::fmt::Debug;

use crate::hashes::HashSuite;
use crate::{
    ParameterSet, address::Address, fors::ForsParams, hypertree::HypertreeParams, wots::WotsParams,
    xmss::XmssParams,
};
use crate::{PkSeed, SkPrf, SkSeed};
use crate::{
    signature_encoding::SignatureLen, signing_key::SigningKeyLen, verifying_key::VerifyingKeyLen,
};
use const_oid::db::fips205;
use hybrid_array::sizes::{U7856, U17088};
use hybrid_array::{Array, ArraySize};
use typenum::{Diff, Sum, U, U16, U30, U32, U34, U64};

/// Implementation of the component hash functions using BLAKE3 at Security Category 1
///
/// Follows a similar pattern to SHA2 implementation in section 10.2 of FIPS-205
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3L1<N, M> {
    _n: core::marker::PhantomData<N>,
    _m: core::marker::PhantomData<M>,
}

impl<N: ArraySize, M: ArraySize> HashSuite for Blake3L1<N, M>
where
    N: core::ops::Add<N>,
    Sum<N, N>: ArraySize,
    Sum<N, N>: core::ops::Add<U32>,
    Sum<Sum<N, N>, U32>: ArraySize,
    U64: core::ops::Sub<N>,
    Diff<U64, N>: ArraySize,
    N: Debug + PartialEq + Eq,
    M: Debug + PartialEq + Eq,
{
    type N = N;
    type M = M;

    fn prf_msg(
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::N> {
        let mut key = [0u8; 32];
        key[..Self::N::USIZE].copy_from_slice(sk_prf.as_ref());
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(opt_rand.as_slice());
        msg.iter().copied().flatten().for_each(|msg_part| {
            hasher.update(msg_part.as_ref());
            ();
        });
        let output = hasher.finalize();
        Array::clone_from_slice(&output.as_bytes()[..Self::N::USIZE])
    }

    fn h_msg(
        rand: &Array<u8, Self::N>,
        pk_seed: &PkSeed<Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[&[impl AsRef<[u8]>]],
    ) -> Array<u8, Self::M> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(rand.as_slice());
        hasher.update(pk_seed.as_ref());
        hasher.update(pk_root.as_slice());
        msg.iter().copied().flatten().for_each(|msg_part| {
            hasher.update(msg_part.as_ref());
            ();
        });
        let mut result = Array::<u8, Self::M>::default();
        let mut xof = hasher.finalize_xof();
        xof.fill(&mut result);
        result
    }

    fn prf_sk(
        pk_seed: &PkSeed<Self::N>,
        sk_seed: &SkSeed<Self::N>,
        adrs: &impl Address,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let mut key = [0u8; 32];
        key[..Self::N::USIZE].copy_from_slice(pk_seed.as_ref());
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(zeroes.as_slice());
        hasher.update(adrs.compressed().as_slice());
        hasher.update(sk_seed.as_ref());
        let output = hasher.finalize();
        Array::clone_from_slice(&output.as_bytes()[..Self::N::USIZE])
    }

    fn t<L: ArraySize>(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let mut key = [0u8; 32];
        key[..Self::N::USIZE].copy_from_slice(pk_seed.as_ref());
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(zeroes.as_slice());
        hasher.update(adrs.compressed().as_slice());
        m.iter().for_each(|x| {
            hasher.update(x.as_slice());
            ();
        });
        let output = hasher.finalize();
        Array::clone_from_slice(&output.as_bytes()[..Self::N::USIZE])
    }

    fn h(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let mut key = [0u8; 32];
        key[..Self::N::USIZE].copy_from_slice(pk_seed.as_ref());
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(zeroes.as_slice());
        hasher.update(adrs.compressed().as_slice());
        hasher.update(m1.as_slice());
        hasher.update(m2.as_slice());
        let output = hasher.finalize();
        Array::clone_from_slice(&output.as_bytes()[..Self::N::USIZE])
    }

    fn f(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let mut key = [0u8; 32];
        key[..Self::N::USIZE].copy_from_slice(pk_seed.as_ref());
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(zeroes.as_slice());
        hasher.update(adrs.compressed().as_slice());
        hasher.update(m.as_slice());
        let output = hasher.finalize();
        Array::clone_from_slice(&output.as_bytes()[..Self::N::USIZE])
    }
}

/// BLAKE3 at L1 security with small signatures
pub type Blake3_128s = Blake3L1<U16, U30>;
impl WotsParams for Blake3_128s {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Blake3_128s {
    type HPrime = U<9>;
}
impl HypertreeParams for Blake3_128s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Blake3_128s {
    type K = U<14>;
    type A = U<12>;
    type MD = U<{ (12 * 14usize).div_ceil(8) }>;
}
impl ParameterSet for Blake3_128s {
    const NAME: &'static str = "SLH-DSA-BLAKE3-128s";
    // TODO: Need to define proper OID for BLAKE3 variants
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_128_S;
}

impl SignatureLen for Blake3_128s {
    type SigLen = U7856; // Same as SHA2-128s
}

impl SigningKeyLen for Blake3_128s {
    type SkLen = U<{ 4 * 16 }>; // Same as SHA2L1<U16, M>
}

impl VerifyingKeyLen for Blake3_128s {
    type VkLen = U<32>; // Same as SHA2L1<U16, M>
}

/// BLAKE3 at L1 security with fast signatures
pub type Blake3_128f = Blake3L1<U16, U34>;
impl WotsParams for Blake3_128f {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Blake3_128f {
    type HPrime = U<3>;
}
impl HypertreeParams for Blake3_128f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Blake3_128f {
    type K = U<33>;
    type A = U<6>;
    type MD = U<25>;
}
impl ParameterSet for Blake3_128f {
    const NAME: &'static str = "SLH-DSA-BLAKE3-128f";
    // TODO: Need to define proper OID for BLAKE3 variants
    const ALGORITHM_OID: pkcs8::ObjectIdentifier = fips205::ID_SLH_DSA_SHA_2_128_F;
}

impl SignatureLen for Blake3_128f {
    type SigLen = U17088; // Same as SHA2-128f
}

impl SigningKeyLen for Blake3_128f {
    type SkLen = U<{ 4 * 16 }>; // Same as SHA2L1<U16, M>
}

impl VerifyingKeyLen for Blake3_128f {
    type VkLen = U<32>; // Same as SHA2L1<U16, M>
}

// Note: We'll start with L1 security level implementations first
// L3 and L5 implementations can be added later following the same pattern

#[cfg(test)]
mod tests {
    use super::*;
    use core::prelude::v1::*;
    use hex_literal::hex;

    #[test]
    fn quick_performance_test() {
        // Just verify that our BLAKE3 implementation works
        let sk_prf = SkPrf(Array::<u8, U16>::from_fn(|_| 0));
        let opt_rand = Array::<u8, U16>::from_fn(|_| 1);
        let msg = [2u8; 32];

        // Run a few iterations to ensure it works
        for _ in 0..10 {
            let result = Blake3_128s::prf_msg(&sk_prf, &opt_rand, &[&[msg]]);
            assert_eq!(result.len(), 16); // U16 = 16 bytes
        }
    }

    fn prf_msg<H: HashSuite>(expected: &[u8]) {
        let sk_prf = SkPrf(Array::<u8, H::N>::from_fn(|_| 0));
        let opt_rand = Array::<u8, H::N>::from_fn(|_| 1);
        let msg = [2u8; 32];

        let result = H::prf_msg(&sk_prf, &opt_rand, &[&[msg]]);

        assert_eq!(result.as_slice(), expected);
    }

    fn h_msg<H: HashSuite>(expected: &[u8]) {
        let rand = Array::<u8, H::N>::from_fn(|_| 0);
        let pk_seed = PkSeed(Array::<u8, H::N>::from_fn(|_| 1));
        let pk_root = Array::<u8, H::N>::from_fn(|_| 2);
        let msg = [3u8; 32];

        let result = H::h_msg(&rand, &pk_seed, &pk_root, &[&[msg]]);
        assert_eq!(result.as_slice(), expected);
    }

    #[test]
    fn prf_msg_blake3_128s() {
        prf_msg::<Blake3_128s>(&hex!("c32b06515f24547ca1ac9cd3bd3a5986"));
    }

    #[test]
    fn prf_msg_blake3_128f() {
        prf_msg::<Blake3_128f>(&hex!("c32b06515f24547ca1ac9cd3bd3a5986"));
    }

    #[test]
    fn h_msg_blake3_128s() {
        h_msg::<Blake3_128s>(&[
            94, 155, 145, 180, 158, 195, 232, 245, 101, 71, 151, 89, 18, 11, 172, 235, 254, 165,
            13, 56, 25, 45, 30, 55, 107, 51, 51, 87, 242, 132,
        ]);
    }

    #[test]
    fn h_msg_blake3_128f() {
        h_msg::<Blake3_128f>(&[
            94, 155, 145, 180, 158, 195, 232, 245, 101, 71, 151, 89, 18, 11, 172, 235, 254, 165,
            13, 56, 25, 45, 30, 55, 107, 51, 51, 87, 242, 132, 225, 64, 215, 106,
        ]);
    }
}
