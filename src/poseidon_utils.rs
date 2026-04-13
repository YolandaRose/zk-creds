//! 定义了一些基于 Poseidon 哈希函数的承诺和哈希的结构体和函数

use crate::zk_utils::UnitVar;

use core::fmt;

use ark_bls12_381::Fr as BlsFr;
use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    Error as ArkError,
};
use ark_ff::{to_bytes, PrimeField, ToConstraintField, UniformRand};
use ark_r1cs_std::{
    bits::{uint8::UInt8, ToBytesGadget},
    fields::fp::FpVar,
    R1CSVar, ToConstraintFieldGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use arkworks_native_gadgets::poseidon::{
    sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters,
};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};
use arkworks_utils::{bytes_matrix_to_f, bytes_vec_to_f, Curve};
use lazy_static::lazy_static;
use rand::Rng;

// 承诺随机数是一个256位的值
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ComNonce(pub [u8; 32]);

impl fmt::Debug for ComNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("[omitted]")
    }
}

impl UniformRand for ComNonce {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        ComNonce(UniformRand::rand(rng))
    }
}

impl ComNonce {
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

// 设置Poseidon参数
pub fn setup_poseidon_params<F: PrimeField>(
    curve: Curve,
    exp: i8,
    width: u8,
) -> PoseidonParameters<F> {
    let pos_data =
        arkworks_utils::poseidon_params::setup_poseidon_params(curve, exp, width).unwrap();

    let mds_f = bytes_matrix_to_f(&pos_data.mds);
    let rounds_f = bytes_vec_to_f(&pos_data.rounds);

    PoseidonParameters {
        mds_matrix: mds_f,
        round_keys: rounds_f,
        full_rounds: pos_data.full_rounds,
        partial_rounds: pos_data.partial_rounds,
        sbox: PoseidonSbox(pos_data.exp),
        width: pos_data.width,
    }
}

// 选择BLS12-381上的Poseidon的全局参数
const POSEIDON_WIDTH: u8 = 5;
//domain_sep:为了区分不同用途的哈希输入
const COM_DOMAIN_SEP: &[u8] = b"pcom";//用于承诺
const CRH_DOMAIN_SEP: &[u8] = b"pcrh";//用于Merkle tree、proof of membership
lazy_static! {
    static ref BLS12_POSEIDON_PARAMS: PoseidonParameters<BlsFr> =
        setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
}

// 使用BLS12-381上的Poseidon哈希函数的承诺方案
pub struct Bls12PoseidonCommitter;
// 迭代地计算Poseidon哈希
fn poseidon_iterated_hash(input: &[BlsFr]) -> BlsFr {
    let hasher = Poseidon::new(BLS12_POSEIDON_PARAMS.clone());
    let first_block_len = core::cmp::min(input.len(), (POSEIDON_WIDTH - 1) as usize);

    let first_block = &input[..first_block_len];
    let mut running_hash = hasher.hash(first_block).unwrap();
    for block in input[first_block_len..].chunks((POSEIDON_WIDTH - 2) as usize) {
        let next_input = &[&[running_hash], block].concat();
        running_hash = hasher.hash(next_input).unwrap();
    }
    running_hash
}

// 迭代地计算Poseidon哈希的ZK电路gadget版本
fn poseidon_iterated_hash_gadget(
    cs: &mut ConstraintSystemRef<BlsFr>,
    input: &[FpVar<BlsFr>],
) -> Result<FpVar<BlsFr>, SynthesisError> {
    let hasher = Poseidon::new(BLS12_POSEIDON_PARAMS.clone());
    let hasher_var = PoseidonGadget::from_native(cs, hasher)?;
    let first_block_len = core::cmp::min(input.len(), (POSEIDON_WIDTH - 1) as usize);

    let first_block = &input[..first_block_len];
    let mut running_hash = hasher_var.hash(first_block)?;
    for block in input[first_block_len..].chunks((POSEIDON_WIDTH - 2) as usize) {
        let next_input = &[&[running_hash], block].concat();
        running_hash = hasher_var.hash(next_input)?;
    }

    Ok(running_hash)
}

// 实现BLS12-381上的Poseidon承诺方案
impl CommitmentScheme for Bls12PoseidonCommitter {
    type Output = BlsFr;
    type Parameters = ();
    type Randomness = BlsFr;

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, ArkError> {
        Ok(())
    }

    // 计算H(domain_sep || randomness || input)
    fn commit(
        _parameters: &Self::Parameters,
        input: &[u8],
        r: &Self::Randomness,
    ) -> Result<Self::Output, ArkError> {
        // 连接所有输入并打包成域元素
        let hash_input: Vec<u8> = [COM_DOMAIN_SEP, &to_bytes!(r).unwrap(), input].concat();
        let packed_input: Vec<BlsFr> = hash_input
            .to_field_elements()
            .expect("could not pack inputs");

        // 计算哈希
        Ok(poseidon_iterated_hash(&packed_input))
    }
}

// 实现BLS12-381上的Poseidon承诺方案的ZK电路gadget版本
impl CommitmentGadget<Bls12PoseidonCommitter, BlsFr> for Bls12PoseidonCommitter {
    type OutputVar = FpVar<BlsFr>;
    type ParametersVar = UnitVar<BlsFr>;
    type RandomnessVar = FpVar<BlsFr>;

    // 计算H(domain_sep || randomness || input)
    fn commit(
        _parameters: &Self::ParametersVar,
        input: &[UInt8<BlsFr>],
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut cs = input.cs();

        // 连接所有输入并打包成域元素
        let hash_input: Vec<UInt8<BlsFr>> = [
            &UInt8::constant_vec(COM_DOMAIN_SEP),
            &r.to_bytes().unwrap(),
            input,
        ]
        .concat();
        let packed_input: Vec<FpVar<BlsFr>> = hash_input
            .to_constraint_field()
            .expect("could not pack inputs");

        // 计算哈希
        poseidon_iterated_hash_gadget(&mut cs, &packed_input)
    }
}

// 表示BLS12-381上的Poseidon的抗碰撞哈希功能
pub struct Bls12PoseidonCrh;

// TODO: 一旦arkworks-native-gadgets更新到新的Arkworks版本，更新这个使用新的Arkworks特征TwoToOneCRHScheme
// https://github.com/webb-tools/arkworks-gadgets/blob/master/arkworks-native-gadgets/src/mimc.rs#L2=
use ark_crypto_primitives::crh::{TwoToOneCRH, TwoToOneCRHGadget};

// 实现BLS12-381上的Poseidon的抗碰撞哈希功能
impl TwoToOneCRH for Bls12PoseidonCrh {
    // 这无关紧要，只用于默克尔树
    const LEFT_INPUT_SIZE_BITS: usize = 0;
    const RIGHT_INPUT_SIZE_BITS: usize = 0;

    type Parameters = ();
    type Output = BlsFr;

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, ArkError> {
        Ok(())
    }

    // 计算H(left || right)
    fn evaluate(_: &(), left_input: &[u8], right_input: &[u8]) -> Result<BlsFr, ArkError> {
        // 只用于BLS12-381上的默克尔树哈希，所以只需将输入长度固定为32
        assert_eq!(left_input.len(), 32);
        assert_eq!(right_input.len(), 32);

        // 连接所有输入并打包成域元素
        let hash_input: Vec<u8> = [CRH_DOMAIN_SEP, left_input, right_input].concat();
        let packed_input: Vec<BlsFr> = hash_input
            .to_field_elements()
            .expect("could not pack inputs");

        // 计算哈希
        Ok(poseidon_iterated_hash(&packed_input))
    }
}

// 实现BLS12-381上的Poseidon的抗碰撞哈希功能的ZK电路gadget版本
impl TwoToOneCRHGadget<Bls12PoseidonCrh, BlsFr> for Bls12PoseidonCrh {
    type ParametersVar = UnitVar<BlsFr>;
    type OutputVar = FpVar<BlsFr>;

    // 计算H(left || right)
    fn evaluate(
        _: &UnitVar<BlsFr>,
        left_input: &[UInt8<BlsFr>],
        right_input: &[UInt8<BlsFr>],
    ) -> Result<FpVar<BlsFr>, SynthesisError> {
        // 我们只用于BLS12-381上的默克尔树哈希，所以只需将输入长度固定为32
        assert_eq!(left_input.len(), 32);
        assert_eq!(right_input.len(), 32);

        let mut cs = left_input.cs().or(right_input.cs());

        // 连接所有输入并打包成域元素
        let hash_input: Vec<UInt8<_>> = [
            &UInt8::constant_vec(CRH_DOMAIN_SEP),
            left_input,
            right_input,
        ]
        .concat();
        let packed_input: Vec<FpVar<BlsFr>> = hash_input
            .to_constraint_field()
            .expect("could not pack inputs");

        // 计算哈希
        poseidon_iterated_hash_gadget(&mut cs, &packed_input)
    }
}
