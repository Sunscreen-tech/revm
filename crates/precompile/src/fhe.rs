use crate::u64_to_b160;
use crate::{Error, PrecompileAddress};
use crate::{Precompile, PrecompileResult};

use alloc::vec::Vec;

use fhe_precompiles::testnet::one::FHE;
use fhe_precompiles::FheError;

pub const FHE_BASE_ADDRESS: u64 = 0xF0_00_00_00;
pub const FHE_U256_ADDRESS: u64 = 0x00_00_00_00;
pub const FHE_U64_ADDRESS: u64 = 0x00_00_01_00;
pub const FHE_I64_ADDRESS: u64 = 0x00_00_02_00;
pub const FHE_FRAC64_ADDRESS: u64 = 0x00_00_03_00;

pub const FHE_ADD_ADDRESS: u64 = 0x00;
pub const FHE_SUB_ADDRESS: u64 = 0x10;
pub const FHE_MUL_ADDRESS: u64 = 0x20;

pub const FHE_NETWORK_API_ADDRESS: u64 = 0x01_00_00_00;
pub const FHE_NETWORK_KEY_ADDRESS: u64 = 0x00_00_00_00;
pub const FHE_ENCRYPT_ADDRESS: u64 = 0x00_00_00_10;
pub const FHE_REENCRYPT_ADDRESS: u64 = 0x00_00_00_20;
pub const FHE_DECRYPT_ADDRESS: u64 = 0x00_00_00_30;

pub const COST_FHE_ADD: u64 = 200;
pub const COST_FHE_ADD_PLAIN: u64 = 200;
pub const COST_FHE_SUB: u64 = 200;
pub const COST_FHE_SUB_PLAIN: u64 = 200;
pub const COST_FHE_MUL: u64 = 1000;
pub const COST_FHE_MUL_PLAIN: u64 = 200;

pub const COST_FHE_NETWORK_KEY: u64 = 0;
pub const COST_FHE_ENCRYPT: u64 = 1000;
pub const COST_FHE_REENCRYPT: u64 = 2000;
pub const COST_FHE_DECRYPT: u64 = 1000;

fn to_error(value: FheError) -> Error {
    match value {
        FheError::UnexpectedEOF => Error::Other("Not enough input".into()),
        FheError::PlatformArchitecture => {
            Error::Other("Validator needs at least 32B architecture".into())
        }
        FheError::InvalidEncoding => Error::Other("Invalid bincode encoding".into()),
        FheError::Overflow => Error::Other("i64 overflow".into()),
        FheError::FailedDecryption => Error::Other("Failed decryption".into()),
        FheError::FailedEncryption => Error::Other("Failed Encryption".into()),
        FheError::SunscreenError(e) => Error::Other(format!("Sunscreen error: {:?}", e).into()),
    }
}

fn to_precompile<F>(f: F, input: &[u8], op_cost: u64, gas_limit: u64) -> PrecompileResult
where
    F: Fn(&[u8]) -> Result<Vec<u8>, FheError>,
{
    if op_cost > gas_limit {
        return Err(Error::OutOfGas);
    }

    f(input).map(|x| (op_cost, x)).map_err(to_error)
}

/**************************************************************************
 * U256
 *************************************************************************/

pub const FHE_ADD_CIPHERU256_CIPHERU256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U256_ADDRESS + FHE_ADD_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_cipheru256_cipheru256(x),
            input,
            COST_FHE_ADD,
            gas_limit,
        )
    }),
);

pub const FHE_ADD_CIPHERU256_U256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U256_ADDRESS + FHE_ADD_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_cipheru256_u256(x),
            input,
            COST_FHE_ADD_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_ADD_U256_CIPHERU256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U256_ADDRESS + FHE_ADD_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_u256_cipheru256(x),
            input,
            COST_FHE_ADD_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_CIPHERU256_CIPHERU256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U256_ADDRESS + FHE_SUB_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_cipheru256_cipheru256(x),
            input,
            COST_FHE_SUB,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_CIPHERU256_U256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U256_ADDRESS + FHE_SUB_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_cipheru256_u256(x),
            input,
            COST_FHE_SUB_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_U256_CIPHERU256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U256_ADDRESS + FHE_SUB_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_u256_cipheru256(x),
            input,
            COST_FHE_SUB_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_CIPHERU256_CIPHERU256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U256_ADDRESS + FHE_MUL_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_cipheru256_cipheru256(x),
            input,
            COST_FHE_MUL,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_CIPHERU256_U256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U256_ADDRESS + FHE_MUL_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_cipheru256_u256(x),
            input,
            COST_FHE_MUL_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_U256_CIPHERU256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U256_ADDRESS + FHE_MUL_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_u256_cipheru256(x),
            input,
            COST_FHE_MUL_PLAIN,
            gas_limit,
        )
    }),
);

/**************************************************************************
 * U64
 *************************************************************************/

pub const FHE_ADD_CIPHERU64_CIPHERU64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U64_ADDRESS + FHE_ADD_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_cipheru64_cipheru64(x),
            input,
            COST_FHE_ADD,
            gas_limit,
        )
    }),
);

pub const FHE_ADD_CIPHERU64_U64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U64_ADDRESS + FHE_ADD_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_cipheru64_u64(x),
            input,
            COST_FHE_ADD_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_ADD_U64_CIPHERU64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U64_ADDRESS + FHE_ADD_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_u64_cipheru64(x),
            input,
            COST_FHE_ADD_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_CIPHERU64_CIPHERU64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U64_ADDRESS + FHE_SUB_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_cipheru64_cipheru64(x),
            input,
            COST_FHE_SUB,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_CIPHERU64_U64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U64_ADDRESS + FHE_SUB_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_cipheru64_u64(x),
            input,
            COST_FHE_SUB_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_U64_CIPHERU64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U64_ADDRESS + FHE_SUB_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_u64_cipheru64(x),
            input,
            COST_FHE_SUB_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_CIPHERU64_CIPHERU64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U64_ADDRESS + FHE_MUL_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_cipheru64_cipheru64(x),
            input,
            COST_FHE_MUL,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_CIPHERU64_U64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U64_ADDRESS + FHE_MUL_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_cipheru64_u64(x),
            input,
            COST_FHE_MUL_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_U64_CIPHERU64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_U64_ADDRESS + FHE_MUL_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_u64_cipheru64(x),
            input,
            COST_FHE_MUL_PLAIN,
            gas_limit,
        )
    }),
);

/**************************************************************************
 * I64
 *************************************************************************/

pub const FHE_ADD_CIPHERI64_CIPHERI64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_I64_ADDRESS + FHE_ADD_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_cipheri64_cipheri64(x),
            input,
            COST_FHE_ADD,
            gas_limit,
        )
    }),
);

pub const FHE_ADD_CIPHERI64_I64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_I64_ADDRESS + FHE_ADD_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_cipheri64_i64(x),
            input,
            COST_FHE_ADD_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_ADD_I64_CIPHERI64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_I64_ADDRESS + FHE_ADD_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_i64_cipheri64(x),
            input,
            COST_FHE_ADD_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_CIPHERI64_CIPHERI64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_I64_ADDRESS + FHE_SUB_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_cipheri64_cipheri64(x),
            input,
            COST_FHE_SUB,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_CIPHERI64_I64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_I64_ADDRESS + FHE_SUB_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_cipheri64_i64(x),
            input,
            COST_FHE_SUB_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_I64_CIPHERI64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_I64_ADDRESS + FHE_SUB_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_i64_cipheri64(x),
            input,
            COST_FHE_SUB_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_CIPHERI64_CIPHERI64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_I64_ADDRESS + FHE_MUL_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_cipheri64_cipheri64(x),
            input,
            COST_FHE_MUL,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_CIPHERI64_I64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_I64_ADDRESS + FHE_MUL_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_cipheri64_i64(x),
            input,
            COST_FHE_MUL_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_I64_CIPHERI64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_I64_ADDRESS + FHE_MUL_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_i64_cipheri64(x),
            input,
            COST_FHE_MUL_PLAIN,
            gas_limit,
        )
    }),
);

/**************************************************************************
 * FRAC64
 *************************************************************************/

pub const FHE_ADD_CIPHERFRAC64_CIPHERFRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_FRAC64_ADDRESS + FHE_ADD_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_cipherfrac64_cipherfrac64(x),
            input,
            COST_FHE_ADD,
            gas_limit,
        )
    }),
);

pub const FHE_ADD_CIPHERFRAC64_FRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_FRAC64_ADDRESS + FHE_ADD_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_cipherfrac64_frac64(x),
            input,
            COST_FHE_ADD_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_ADD_FRAC64_CIPHERFRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_FRAC64_ADDRESS + FHE_ADD_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.add_frac64_cipherfrac64(x),
            input,
            COST_FHE_ADD_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_CIPHERFRAC64_CIPHERFRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_FRAC64_ADDRESS + FHE_SUB_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_cipherfrac64_cipherfrac64(x),
            input,
            COST_FHE_SUB,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_CIPHERFRAC64_FRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_FRAC64_ADDRESS + FHE_SUB_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_cipherfrac64_frac64(x),
            input,
            COST_FHE_SUB_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_SUB_FRAC64_CIPHERFRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_FRAC64_ADDRESS + FHE_SUB_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.sub_frac64_cipherfrac64(x),
            input,
            COST_FHE_SUB_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_CIPHERFRAC64_CIPHERFRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_FRAC64_ADDRESS + FHE_MUL_ADDRESS + 0x00),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_cipherfrac64_cipherfrac64(x),
            input,
            COST_FHE_MUL,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_CIPHERFRAC64_FRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_FRAC64_ADDRESS + FHE_MUL_ADDRESS + 0x01),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_cipherfrac64_frac64(x),
            input,
            COST_FHE_MUL_PLAIN,
            gas_limit,
        )
    }),
);

pub const FHE_MUL_FRAC64_CIPHERFRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_FRAC64_ADDRESS + FHE_MUL_ADDRESS + 0x02),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.mul_frac64_cipherfrac64(x),
            input,
            COST_FHE_MUL_PLAIN,
            gas_limit,
        )
    }),
);

/**************************************************************************
 * Network API
 *************************************************************************/

pub const FHE_NETWORK_PUBLIC_KEY: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_NETWORK_KEY_ADDRESS),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.public_key_bytes(x),
            input,
            COST_FHE_NETWORK_KEY,
            gas_limit,
        )
    }),
);

// Encrypt ////////////////////////////////////////////////////////////////

pub const FHE_ENCRYPT_U256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(
        FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_U256_ADDRESS + FHE_ENCRYPT_ADDRESS,
    ),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.encrypt_u256(x), input, COST_FHE_ENCRYPT, gas_limit)
    }),
);

pub const FHE_ENCRYPT_U64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_U64_ADDRESS + FHE_ENCRYPT_ADDRESS),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.encrypt_u64(x), input, COST_FHE_ENCRYPT, gas_limit)
    }),
);

pub const FHE_ENCRYPT_I64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_I64_ADDRESS + FHE_ENCRYPT_ADDRESS),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.encrypt_i64(x), input, COST_FHE_ENCRYPT, gas_limit)
    }),
);

pub const FHE_ENCRYPT_FRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(
        FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_FRAC64_ADDRESS + FHE_ENCRYPT_ADDRESS,
    ),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.encrypt_frac64(x),
            input,
            COST_FHE_ENCRYPT,
            gas_limit,
        )
    }),
);

// Reencrypt //////////////////////////////////////////////////////////////

pub const FHE_REENCRYPT_U256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(
        FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_U256_ADDRESS + FHE_REENCRYPT_ADDRESS,
    ),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.reencrypt_u256(x),
            input,
            COST_FHE_REENCRYPT,
            gas_limit,
        )
    }),
);

pub const FHE_REENCRYPT_U64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(
        FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_U64_ADDRESS + FHE_REENCRYPT_ADDRESS,
    ),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.reencrypt_u64(x),
            input,
            COST_FHE_REENCRYPT,
            gas_limit,
        )
    }),
);

pub const FHE_REENCRYPT_I64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(
        FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_I64_ADDRESS + FHE_REENCRYPT_ADDRESS,
    ),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.reencrypt_i64(x),
            input,
            COST_FHE_REENCRYPT,
            gas_limit,
        )
    }),
);

pub const FHE_REENCRYPT_FRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(
        FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_FRAC64_ADDRESS + FHE_REENCRYPT_ADDRESS,
    ),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.reencrypt_frac64(x),
            input,
            COST_FHE_REENCRYPT,
            gas_limit,
        )
    }),
);

// Decrypt ////////////////////////////////////////////////////////////////

pub const FHE_DECRYPT_U256: PrecompileAddress = PrecompileAddress(
    u64_to_b160(
        FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_U256_ADDRESS + FHE_DECRYPT_ADDRESS,
    ),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.decrypt_u256(x), input, COST_FHE_DECRYPT, gas_limit)
    }),
);

pub const FHE_DECRYPT_U64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_U64_ADDRESS + FHE_DECRYPT_ADDRESS),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.decrypt_u64(x), input, COST_FHE_DECRYPT, gas_limit)
    }),
);

pub const FHE_DECRYPT_I64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_I64_ADDRESS + FHE_DECRYPT_ADDRESS),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(|x| FHE.decrypt_i64(x), input, COST_FHE_DECRYPT, gas_limit)
    }),
);

pub const FHE_DECRYPT_FRAC64: PrecompileAddress = PrecompileAddress(
    u64_to_b160(
        FHE_BASE_ADDRESS + FHE_NETWORK_API_ADDRESS + FHE_FRAC64_ADDRESS + FHE_DECRYPT_ADDRESS,
    ),
    Precompile::Custom(|input, gas_limit| {
        to_precompile(
            |x| FHE.decrypt_frac64(x),
            input,
            COST_FHE_DECRYPT,
            gas_limit,
        )
    }),
);
