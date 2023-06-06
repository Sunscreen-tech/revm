use crate::{Error, PrecompileAddress};
use crate::{Precompile, PrecompileResult};
use crate::u64_to_b160;

use alloc::vec::Vec;

use fhe_precompiles::testnet::one::FHE;
use fhe_precompiles::FheError;

pub const COST_FHE_ADD: u64 = 200;
pub const COST_FHE_ADD_PLAIN: u64 = 200;
pub const COST_FHE_SUBTRACT: u64 = 200;
pub const COST_FHE_SUBTRACT_PLAIN: u64 = 200;
pub const COST_FHE_MULTIPLY: u64 = 1000;
pub const COST_FHE_ENCRYPT_ZERO: u64 = 100;

fn to_error(value: FheError) -> Error {
    match value {
        FheError::UnexpectedEOF => Error::Other("Not enough input".into()),
        FheError::PlatformArchitecture => {
            Error::Other("Validator needs at least 32B architecture".into())
        }
        FheError::InvalidEncoding => Error::Other("Invalid bincode encoding".into()),
        FheError::Overflow => Error::Other("i64 overflow".into()),
        FheError::SunscreenError(e) => {
            Error::Other(format!("Sunscreen error: {:?}", e).into())
        }
    }
}

fn to_precompile<F>(f: F, input: &[u8], op_cost: u64, gas_limit: u64) -> PrecompileResult
where
    F: Fn(&[u8]) -> Result<Vec<u8>, FheError>,
{
    if op_cost > gas_limit {
        return Err(Error::OutOfGas);
    }

    f(input)
        .map(|x| (op_cost, x))
        .map_err(|e| to_error(e))
}

pub const FHE_ADD: PrecompileAddress = PrecompileAddress(
    u64_to_b160(0xF00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.add(x), input, COST_FHE_ADD, gas_limit)
    }),
);

pub const FHE_ADD_PLAIN: PrecompileAddress = PrecompileAddress(
    u64_to_b160(0xF01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.add_plain(x), input, COST_FHE_ADD_PLAIN, gas_limit)
    }),
);

pub const FHE_SUBTRACT: PrecompileAddress = PrecompileAddress(
    u64_to_b160(0xF02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.subtract(x), input, COST_FHE_SUBTRACT, gas_limit)
    }),
);

pub const FHE_SUBTRACT_PLAIN: PrecompileAddress = PrecompileAddress(
    u64_to_b160(0xF03),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.subtract_plain(x),
            input,
            COST_FHE_SUBTRACT_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MULTIPLY: PrecompileAddress = PrecompileAddress(
    u64_to_b160(0xF04),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.multiply(x), input, COST_FHE_MULTIPLY, gas_limit)
    }),
);

pub const FHE_ENCRYPT_ZERO: PrecompileAddress = PrecompileAddress(
    u64_to_b160(0xF10),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.encrypt_zero(x),
            input,
            COST_FHE_ENCRYPT_ZERO,
            gas_limit,
        )
    }),
);
