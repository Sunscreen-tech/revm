use std;

use crate::{Address, PrecompileOutput};

use super::{CustomPrecompileFn, Precompile, PrecompileResult, Return as Error};
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

//pub const FHE_ARBITRARY: (B160, Precompile) = (
//u64_to_b160(204), // 0xcc
//Precompile::Custom(fhe_arbitrary as CustomPrecompileFn),
//);

pub const FHE_ADD: (Address, Precompile) = (
    crate::make_address(0, 205), // 0xcd
    Precompile::Custom(fhe_add as CustomPrecompileFn),
);

pub const FHE_MULTIPLY: (Address, Precompile) = (
    crate::make_address(0, 206), // 0xce
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
    println!("LOG fhe_add running with gas_limit: {gas_limit}");
    let res = fhe_binary_op(COST_FHE_ADD, run_add, input, gas_limit);
    println!("LOG fhe_add finished with Ok == {}!", res.is_ok());
    res
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

    Ok(PrecompileOutput::without_logs(
        op_cost,
        rmp_serde::to_vec(&result).unwrap(),
    ))
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

/// Expected format for `input`:
/// 1B: # of args -> N
/// 2(4B ~ u32) - N(4B ~ u32): for each arg, an offset into bytes array
/// <args>
/// <possibly padding?>
/// <serialized program>
// TODO finish this function
//fn fhe_arbitrary(input: &[u8], gas_limit: u64) -> PrecompileResult {
//// TODO probably some variability to cost based on input size?
//let cost = 200;
//if cost > gas_limit {
//return Err(Error::OutOfGas);
//}

//let num_args = input[0] as usize;
//let mut offsets = Vec::with_capacity(num_args);
//let mut args = Vec::with_capacity(num_args);
//for ix in 1..=num_args + 1 {
//}
//for w in offsets.windows(2) {
//}

//let program = args.pop();

//let output = todo!(); // call fhe(args, program)
//Ok((cost, output))
//}

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
        let PrecompileOutput { cost, output, .. } = fhe_op(&input, op_cost).unwrap();
        // decode it
        let c_encrypted = rmp_serde::from_slice(&output).unwrap();
        // decrypt it
        let c: Signed = runtime.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(cost, op_cost);
        assert_eq!(expected, <Signed as Into<i64>>::into(c));
        Ok(())
    }
}
