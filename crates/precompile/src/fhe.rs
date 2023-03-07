use crate::{CustomPrecompileFn, Error, Precompile, PrecompileResult, B160};
use lazy_static::lazy_static;
use sunscreen::{
    fhe_program,
    types::{bfv::Signed, Cipher},
    Application, Ciphertext, Compiler, PublicKey, Runtime, RuntimeError,
};

pub const COST_FHE_ADD: u64 = 200;
pub const COST_FHE_MULTIPLY: u64 = 1000;

// TODO This should maybe go in a separate crate that the wallet imports as
// well, to ensure the same params are used.
lazy_static! {
    static ref FHE_APP: Application = {
        Compiler::new()
            .fhe_program(add)
            .fhe_program(multiply)
            .compile()
            .unwrap()
    };
}

// Copied from revm_precompile
/// Make an address by concatenating the bytes from two given numbers.
/// Note that 32 + 128 = 160 = 20 bytes (the length of an address). This function is used
/// as a convenience for specifying the addresses of the various precompiles.
const fn u64_to_b160(x: u64) -> B160 {
    let x_bytes = x.to_be_bytes();
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x_bytes[0], x_bytes[1], x_bytes[2], x_bytes[3],
        x_bytes[4], x_bytes[5], x_bytes[6], x_bytes[7],
    ]
}

//pub const FHE_ARBITRARY: (B160, Precompile) = (
//u64_to_b160(204), // 0xcc
//Precompile::Custom(fhe_arbitrary as CustomPrecompileFn),
//);

pub const FHE_ADD: (B160, Precompile) = (
    u64_to_b160(205), // 0xcd
    Precompile::Custom(fhe_add as CustomPrecompileFn),
);

pub const FHE_MULTIPLY: (B160, Precompile) = (
    u64_to_b160(206), // 0xce
    Precompile::Custom(fhe_multiply as CustomPrecompileFn),
);

/// Expects
///
/// ```text
/// <--- 2 * 4B ---><~----------------------------~>
/// [Addend offsets][Public key][Addend 1][Addend 2]
/// ```
///
/// 1. u32 -> offset fo
// TODO proper error handling
fn fhe_add(input: &[u8], gas_limit: u64) -> PrecompileResult {
    fhe_binary_op(COST_FHE_ADD, run_add, input, gas_limit)
}

fn fhe_multiply(input: &[u8], gas_limit: u64) -> PrecompileResult {
    fhe_binary_op(COST_FHE_MULTIPLY, run_multiply, input, gas_limit)
}

/// Expects
///
/// ```text
/// <- 2 * 4B -> <~----------------------->
/// [Arg offsets][Public key][Arg 1][Arg 2]
/// ```
fn fhe_binary_op<F>(op_cost: u64, op: F, input: &[u8], gas_limit: u64) -> PrecompileResult
where
    F: FnOnce(PublicKey, Ciphertext, Ciphertext) -> Result<Ciphertext, RuntimeError>,
{
    if op_cost > gas_limit {
        return Err(Error::OutOfGas);
    }
    if input.len() < 8 {
        return Err(FheErr::UnexpectedEOF.into());
    }
    let ix_1 = &input[..4];
    let ix_2 = &input[4..8];
    let ix_1: usize = u32::from_be_bytes(ix_1.try_into().map_err(|_| FheErr::UnexpectedEOF)?)
        .try_into()
        .map_err(|_| FheErr::PlatformArchitecture)?;
    let ix_2: usize = u32::from_be_bytes(ix_2.try_into().unwrap())
        .try_into()
        .map_err(|_| FheErr::PlatformArchitecture)?;

    let pubk = rmp_serde::from_slice(&input[8..ix_1]).map_err(|_| FheErr::InvalidEncoding)?;
    let arg1 = rmp_serde::from_slice(&input[ix_1..ix_2]).map_err(|_| FheErr::InvalidEncoding)?;
    let arg2 = rmp_serde::from_slice(&input[ix_2..]).map_err(|_| FheErr::InvalidEncoding)?;

    let result = op(pubk, arg1, arg2).unwrap();

    Ok((op_cost, rmp_serde::to_vec(&result).unwrap()))
}

enum FheErr {
    UnexpectedEOF,
    PlatformArchitecture,
    InvalidEncoding,
}

impl From<FheErr> for Error {
    fn from(value: FheErr) -> Self {
        match value {
            FheErr::UnexpectedEOF => Error::Other("Not enough input".into()),
            FheErr::PlatformArchitecture => {
                Error::Other("Validator needs at least 32B architecture".into())
            }
            FheErr::InvalidEncoding => Error::Other("Invalid MessagePack encoding".into()),
        }
    }
}

fn run_add(
    public_key: PublicKey,
    a: Ciphertext,
    b: Ciphertext,
) -> Result<Ciphertext, RuntimeError> {
    // TODO does it make sense to keep a singleton/oncecell runtime as well?
    let runtime = Runtime::new(FHE_APP.params()).unwrap();
    runtime
        .run(FHE_APP.get_program(add).unwrap(), vec![a, b], &public_key)
        .map(|mut out| out.pop().unwrap())
}

fn run_multiply(
    public_key: PublicKey,
    a: Ciphertext,
    b: Ciphertext,
) -> Result<Ciphertext, RuntimeError> {
    // TODO does it make sense to keep a singleton/oncecell runtime as well?
    let runtime = Runtime::new(FHE_APP.params()).unwrap();
    runtime
        .run(
            FHE_APP.get_program(multiply).unwrap(),
            vec![a, b],
            &public_key,
        )
        .map(|mut out| out.pop().unwrap())
}

/// Addition
#[fhe_program(scheme = "bfv")]
fn add(a: Cipher<Signed>, b: Cipher<Signed>) -> Cipher<Signed> {
    a + b
}

/// Multiplication
#[fhe_program(scheme = "bfv")]
fn multiply(a: Cipher<Signed>, b: Cipher<Signed>) -> Cipher<Signed> {
    a * b
}

#[cfg(test)]
mod tests {
    use super::*;
    use sunscreen::{types::bfv::Signed, Runtime, RuntimeError};

    #[test]
    fn fhe_add_works() -> Result<(), RuntimeError> {
        let runtime = Runtime::new(FHE_APP.params())?;
        let (public_key, private_key) = runtime.generate_keys()?;

        let a = runtime.encrypt(Signed::from(16), &public_key)?;
        let b = runtime.encrypt(Signed::from(4), &public_key)?;

        let result = run_add(public_key, a, b)?;
        let c: Signed = runtime.decrypt(&result, &private_key)?;
        assert_eq!(<Signed as Into<i64>>::into(c), 20_i64);
        Ok(())
    }

    #[test]
    fn fhe_multiply_works() -> Result<(), RuntimeError> {
        let runtime = Runtime::new(FHE_APP.params())?;
        let (public_key, private_key) = runtime.generate_keys()?;

        let a = runtime.encrypt(Signed::from(16), &public_key)?;
        let b = runtime.encrypt(Signed::from(4), &public_key)?;

        let result = run_multiply(public_key, a, b)?;
        let c: Signed = runtime.decrypt(&result, &private_key)?;
        assert_eq!(<Signed as Into<i64>>::into(c), 64_i64);
        Ok(())
    }

    #[test]
    fn be_bytes_work_as_expected() {
        let v = u32::from_be_bytes([0x00, 0x00, 0x00, 0x01]);
        assert_eq!(v, 1);
        let v = u32::from_be_bytes([0x00, 0x00, 0x00, 0x10]);
        assert_eq!(v, 16);
    }

    #[test]
    fn precompile_fhe_add_works() -> Result<(), RuntimeError> {
        precompile_fhe_op_works(fhe_add, COST_FHE_ADD, 4, 5, 9)
    }

    #[test]
    fn precompile_fhe_multiply_works() -> Result<(), RuntimeError> {
        precompile_fhe_op_works(fhe_multiply, COST_FHE_MULTIPLY, 4, 5, 20)
    }

    fn precompile_fhe_op_works<F>(
        fhe_op: F,
        op_cost: u64,
        a: i64,
        b: i64,
        expected: i64,
    ) -> Result<(), RuntimeError>
    where
        F: Fn(&[u8], u64) -> PrecompileResult,
    {
        let runtime = Runtime::new(FHE_APP.params())?;
        let (public_key, private_key) = runtime.generate_keys()?;

        // Encrypt values
        let a_encrypted = runtime.encrypt(Signed::from(a), &public_key)?;
        let b_encrypted = runtime.encrypt(Signed::from(b), &public_key)?;

        // Encode values
        let pubk_enc = rmp_serde::to_vec(&public_key).unwrap();
        let a_enc = rmp_serde::to_vec(&a_encrypted).unwrap();
        let b_enc = rmp_serde::to_vec(&b_encrypted).unwrap();

        // Build input bytes
        let mut input: Vec<u8> = Vec::new();
        let offset_1 = 8 + pubk_enc.len();
        let offset_2 = offset_1 + a_enc.len();
        input.extend((offset_1 as u32).to_be_bytes());
        input.extend((offset_2 as u32).to_be_bytes());
        input.extend(pubk_enc);
        input.extend(a_enc);
        input.extend(b_enc);

        // run precompile w/o gas
        let res = fhe_op(&input, op_cost - 1);
        assert!(matches!(res, Err(Error::OutOfGas)));

        // run precompile w/ gas
        let (cost, output) = fhe_op(&input, op_cost).unwrap();
        // decode it
        let c_encrypted = rmp_serde::from_slice(&output).unwrap();
        // decrypt it
        let c: Signed = runtime.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(cost, op_cost);
        assert_eq!(expected, <Signed as Into<i64>>::into(c));
        Ok(())
    }
}
