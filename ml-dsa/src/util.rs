use hybrid_array::{
    Array,
    typenum::{U32, U64, U256},
};

/// A 32-byte array, defined here for brevity because it is used several times
pub type B32 = Array<u8, U32>;

/// A 64-byte array, defined here for brevity because it is used several times
pub type B64 = Array<u8, U64>;

/// A 256-byte array, defined here for brevity because it is used several times
pub type B256 = Array<u8, U256>;