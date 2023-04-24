use super::{Precompile, PrecompileResult, Return};
use crate::{Address, PrecompileOutput};

use fhe_precompiles::testnet::one::FHE;
use fhe_precompiles::FheError;

pub const COST_FHE_ADD: u64 = 200;
pub const COST_FHE_ADD_PLAIN: u64 = 200;
pub const COST_FHE_SUBTRACT: u64 = 200;
pub const COST_FHE_SUBTRACT_PLAIN: u64 = 200;
pub const COST_FHE_MULTIPLY: u64 = 1000;
pub const COST_FHE_ENCRYPT_ZERO: u64 = 100;

impl From<FheError> for Return {
    fn from(value: FheError) -> Self {
        match value {
            FheError::UnexpectedEOF => Return::Other("Not enough input".into()),
            FheError::PlatformArchitecture => {
                Return::Other("Validator needs at least 32B architecture".into())
            }
            FheError::InvalidEncoding => Return::Other("Invalid bincode encoding".into()),
            FheError::Overflow => Return::Other("i64 overflow".into()),
            FheError::SunscreenError(e) => {
                Return::Other(format!("Sunscreen error: {:?}", e).into())
            }
        }
    }
}

fn to_precompile<F>(f: F, input: &[u8], op_cost: u64, gas_limit: u64) -> PrecompileResult
where
    F: Fn(&[u8]) -> Result<Vec<u8>, FheError>,
{
    if op_cost > gas_limit {
        return Err(Return::OutOfGas);
    }

    f(input)
        .map(|x| PrecompileOutput::without_logs(op_cost, x))
        .map_err(|e| e.into())
}

pub const FHE_ADD: (Address, Precompile) = (
    crate::make_address(0, 205),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.add(x), input, COST_FHE_ADD, gas_limit)
    }),
);

pub const FHE_ADD_PLAIN: (Address, Precompile) = (
    crate::make_address(0, 206),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.add_plain(x), input, COST_FHE_ADD_PLAIN, gas_limit)
    }),
);

pub const FHE_SUBTRACT: (Address, Precompile) = (
    crate::make_address(0, 207),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.subtract(x), input, COST_FHE_SUBTRACT, gas_limit)
    }),
);

pub const FHE_SUBTRACT_PLAIN: (Address, Precompile) = (
    crate::make_address(0, 208),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.subtract_plain(x),
            input,
            COST_FHE_SUBTRACT_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MULTIPLY: (Address, Precompile) = (
    crate::make_address(0, 209),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.multiply(x), input, COST_FHE_MULTIPLY, gas_limit)
    }),
);

pub const FHE_ENCRYPT_ZERO: (Address, Precompile) = (
    crate::make_address(0, 210),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.encrypt_zero(x),
            input,
            COST_FHE_ENCRYPT_ZERO,
            gas_limit,
        )
    }),
);
