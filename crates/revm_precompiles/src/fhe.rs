use std;

use crate::{Address, PrecompileOutput};

use super::{CustomPrecompileFn, Precompile, PrecompileResult, Return as Error};
use lazy_static::lazy_static;
use sunscreen::{
    fhe_program,
    types::{bfv::Signed, Cipher},
    Application, Ciphertext, Compiler, Params, PublicKey, Runtime, RuntimeError, SchemeType,
};

pub const COST_FHE_ADD: u64 = 200;
pub const COST_FHE_SUBTRACT: u64 = 200;
pub const COST_FHE_MULTIPLY: u64 = 1000;
pub const COST_FHE_ENC_ZERO: u64 = 100;

// TODO This should maybe go in a separate crate that the wallet imports as
// well, to ensure the same params are used.
// TODO make a static Runtime as well
lazy_static! {
    static ref FHE_APP: Application = {
        Compiler::new()
            .fhe_program(add)
            .fhe_program(subtract)
            .fhe_program(multiply)
            .with_params(&Params {
                lattice_dimension: 4096,
                coeff_modulus: vec![0xffffee001, 0xffffc4001, 0x1ffffe0001],
                plain_modulus: 4_096,
                scheme_type: SchemeType::Bfv,
                security_level: sunscreen::SecurityLevel::TC128,
            })
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

pub const FHE_SUBTRACT: (Address, Precompile) = (
    crate::make_address(0, 206), // 0xce
    Precompile::Custom(fhe_subtract as CustomPrecompileFn),
);

pub const FHE_ENC_ZERO: (Address, Precompile) = (
    crate::make_address(0, 207), // 0xcf
    Precompile::Custom(fhe_enc_zero as CustomPrecompileFn),
);

pub const FHE_MULTIPLY: (Address, Precompile) = (
    crate::make_address(0, 208), // 0xd0
    Precompile::Custom(fhe_multiply as CustomPrecompileFn),
);

/// Expects
///
/// ```text
/// <--- 2 * 4B ---><~----------------------------~>
/// [Addend offsets][Public key][Addend 1][Addend 2]
/// ```
fn fhe_add(input: &[u8], gas_limit: u64) -> PrecompileResult {
    fhe_binary_op(COST_FHE_ADD, run_add, input, gas_limit)
}

/// Expects
///
/// ```text
/// <--- 2 * 4B ---><~-----------------------------~>
/// [ Arg offsets  ][Public key][Minuend][Subtrahend]
/// ```
fn fhe_subtract(input: &[u8], gas_limit: u64) -> PrecompileResult {
    fhe_binary_op(COST_FHE_SUBTRACT, run_subtract, input, gas_limit)
}

/// Expects
///
/// ```text
/// <--- 2 * 4B ---><~----------------------------~>
/// [Factor offsets][Public key][Factor 1][Factor 2]
/// ```
fn fhe_multiply(input: &[u8], gas_limit: u64) -> PrecompileResult {
    fhe_binary_op(COST_FHE_MULTIPLY, run_multiply, input, gas_limit)
}

/// Expects
///
/// ```text
/// <~--------~>
/// [Public key]
/// ```
fn fhe_enc_zero(input: &[u8], gas_limit: u64) -> PrecompileResult {
    if COST_FHE_ENC_ZERO > gas_limit {
        return Err(Error::OutOfGas);
    }
    let pubk = bincode::deserialize(input).map_err(|_| FheErr::InvalidEncoding)?;
    let runtime = Runtime::new(FHE_APP.params()).map_err(FheErr::SunscreenError)?;
    let zero = runtime
        .encrypt(Signed::from(0), &pubk)
        .map_err(FheErr::SunscreenError)?;

    Ok(PrecompileOutput::without_logs(
        COST_FHE_ENC_ZERO,
        bincode::serialize(&zero).unwrap(),
    ))
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

    let pubk = bincode::deserialize(&input[8..ix_1]).map_err(|_| FheErr::InvalidEncoding)?;
    let arg1 = bincode::deserialize(&input[ix_1..ix_2]).map_err(|_| FheErr::InvalidEncoding)?;
    let arg2 = bincode::deserialize(&input[ix_2..]).map_err(|_| FheErr::InvalidEncoding)?;

    let result = op(pubk, arg1, arg2).unwrap();

    Ok(PrecompileOutput::without_logs(
        op_cost,
        bincode::serialize(&result).unwrap(),
    ))
}

enum FheErr {
    UnexpectedEOF,
    PlatformArchitecture,
    InvalidEncoding,
    SunscreenError(RuntimeError),
}

impl From<FheErr> for Error {
    fn from(value: FheErr) -> Self {
        match value {
            FheErr::UnexpectedEOF => Error::Other("Not enough input".into()),
            FheErr::PlatformArchitecture => {
                Error::Other("Validator needs at least 32B architecture".into())
            }
            FheErr::InvalidEncoding => Error::Other("Invalid bincode encoding".into()),
            FheErr::SunscreenError(e) => Error::Other(format!("Sunscreen error: {:?}", e).into()),
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
    let runtime = Runtime::new(FHE_APP.params()).unwrap();
    runtime
        .run(FHE_APP.get_program(add).unwrap(), vec![a, b], &public_key)
        .map(|mut out| out.pop().unwrap())
}

fn run_subtract(
    public_key: PublicKey,
    a: Ciphertext,
    b: Ciphertext,
) -> Result<Ciphertext, RuntimeError> {
    let runtime = Runtime::new(FHE_APP.params()).unwrap();
    runtime
        .run(
            FHE_APP.get_program(subtract).unwrap(),
            vec![a, b],
            &public_key,
        )
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

/// Subtraction
#[fhe_program(scheme = "bfv")]
fn subtract(a: Cipher<Signed>, b: Cipher<Signed>) -> Cipher<Signed> {
    a - b
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

    #[test]
    fn precompile_fhe_subtract_works() -> Result<(), RuntimeError> {
        precompile_fhe_op_works(fhe_subtract, COST_FHE_SUBTRACT, 10, 8, 2)
    }

    #[test]
    fn precompile_fhe_enc_zero_works() -> Result<(), RuntimeError> {
        let runtime = Runtime::new(FHE_APP.params())?;
        let (public_key, private_key) = runtime.generate_keys()?;

        // Encode pubk
        let pubk_enc = bincode::serialize(&public_key).unwrap();

        // run precompile w/o gas
        let PrecompileOutput { output, .. } = fhe_enc_zero(&pubk_enc, COST_FHE_ENC_ZERO).unwrap();
        // decode it
        let c_encrypted = bincode::deserialize(&output).unwrap();
        // decrypt it
        let c: Signed = runtime.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(0, <Signed as Into<i64>>::into(c));
        Ok(())
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
        let pubk_enc = bincode::serialize(&public_key).unwrap();
        let a_enc = bincode::serialize(&a_encrypted).unwrap();
        let b_enc = bincode::serialize(&b_encrypted).unwrap();

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
        let c_encrypted = bincode::deserialize(&output).unwrap();
        // decrypt it
        let c: Signed = runtime.decrypt(&c_encrypted, &private_key)?;

        assert_eq!(cost, op_cost);
        assert_eq!(expected, <Signed as Into<i64>>::into(c));
        Ok(())
    }
}
