//! 定义一些结构体用于测试

use core::borrow::Borrow;

use crate::{
    attrs::{AccountableAttrs, AccountableAttrsVar, Attrs, AttrsVar},
    poseidon_utils::{Bls12PoseidonCommitter, ComNonce},
    pred::PredicateChecker,
    zk_utils::UnitVar,
    Bytestring, Com, ComNonceVar, ComParam, ComParamVar,
};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    commitment::{self, constraints::CommitmentGadget, CommitmentScheme},
    crh::{bowe_hopwood, pedersen, TwoToOneCRH, CRH},
};
use ark_ec::PairingEngine;
use ark_ed_on_bls12_381::{
    constraints::{EdwardsVar as JubjubVar, FqVar},
    EdwardsParameters, EdwardsProjective as Jubjub,
};
use ark_ff::UniformRand;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBytesGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    io::Write,
    rand::{rngs::StdRng, Rng, SeedableRng},
};
use lazy_static::lazy_static;

// 为Pedersen承诺定义不同的窗口大小

#[derive(Clone)]
pub struct Window8x63;
impl pedersen::Window for Window8x63 {
    const WINDOW_SIZE: usize = 63;
    // This can be made smaller than 8, but the program panics if it's not divisible by 8. Tracking
    // issue here: https://github.com/arkworks-rs/crypto-primitives/issues/76
    const NUM_WINDOWS: usize = 8;
}

#[derive(Clone)]
pub struct Window8x128;
impl pedersen::Window for Window8x128 {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 10;
}

#[derive(Clone)]
pub struct Window3x63;
impl pedersen::Window for Window3x63 {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 3;
}

#[derive(Clone)]
pub struct Window9x63;
impl pedersen::Window for Window9x63 {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 9;
}

#[derive(Clone)]
pub struct Window17x63;
impl pedersen::Window for Window17x63 {
    const WINDOW_SIZE: usize = 63;
    const NUM_WINDOWS: usize = 17;
}

// Convenience types for commitment and two-to-one CRH
pub(crate) type PedersenCom<W> = commitment::pedersen::Commitment<Jubjub, W>;
pub(crate) type PedersenComG<W> =
    commitment::pedersen::constraints::CommGadget<Jubjub, JubjubVar, W>;

pub(crate) type CompressedPedersenCom<W> =
    crate::compressed_pedersen::Commitment<EdwardsParameters, W>;
pub(crate) type CompressedPedersenComG<W> =
    crate::compressed_pedersen::constraints::CommGadget<EdwardsParameters, FqVar, W>;

// Example types //

// Pick a pairing engine and a curve defined over E::Fr
pub(crate) type E = Bls12_381;
pub(crate) type Fr = <E as PairingEngine>::Fr;

// Pick a two-to-one CRH
pub type TestTreeH = bowe_hopwood::CRH<EdwardsParameters, Window9x63>;
pub type TestTreeHG = bowe_hopwood::constraints::CRHGadget<EdwardsParameters, FqVar>;

// Pick a commitment scheme
pub type TestComSchemePedersen = CompressedPedersenCom<Window8x128>;
pub type TestComSchemePedersenG = CompressedPedersenComG<Window8x128>;
//pub(crate) type TestComScheme = PedersenCom<Window8x128>;
//pub(crate) type TestComSchemeG = PedersenComG<Window8x128>;

lazy_static! {
    static ref BIG_COM_PARAM: <TestComSchemePedersen as CommitmentScheme>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-commitment-param").unwrap();
            StdRng::from_seed(seed)
        };
        TestComSchemePedersen::setup(&mut rng).unwrap()
    };
    pub static ref MERKLE_CRH_PARAM: <TestTreeH as TwoToOneCRH>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-merkle-param").unwrap();
            StdRng::from_seed(seed)
        };
        <TestTreeH as TwoToOneCRH>::setup(&mut rng).unwrap()
    };
}

const NAME_MAXLEN: usize = 16;

// 定义一个结构体，表示一个人的姓名和出生年份
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameAndBirthYear {
    nonce: ComNonce,
    seed: Fr,
    first_name: [u8; NAME_MAXLEN],
    birth_year: Fr,
    status: bool,
}

impl NameAndBirthYear {
    pub fn first_name(&self) -> &[u8] {
        &self.first_name
    }
}

// 定义一个结构体，表示一个人的姓名和出生年份的变量
#[derive(Clone)]
pub struct NameAndBirthYearVar {
    nonce: ComNonce,
    seed: FpVar<Fr>,
    first_name: Vec<UInt8<Fr>>,
    pub(crate) birth_year: FpVar<Fr>,
    status: UInt8<Fr>,
}

// 实现NameAndBirthYear结构体
impl NameAndBirthYear {
    // 构造一个新的`NameAndBirthYear`，采样一个随机nonce用于承诺
    pub fn new<R: Rng>(rng: &mut R, first_name: &[u8], birth_year: u16) -> NameAndBirthYear {
        assert!(first_name.len() <= NAME_MAXLEN);
        let mut name_buf = [0u8; 16];
        name_buf[..first_name.len()].copy_from_slice(first_name);

        let nonce = ComNonce::rand(rng);
        let seed = Fr::rand(rng);

        NameAndBirthYear {
            nonce,
            seed,
            first_name: name_buf,
            birth_year: Fr::from(birth_year),
            status: true,
        }
    }

    pub fn new_with_seed<R: Rng>(rng: &mut R, first_name: &[u8], birth_year: u16, seed: Fr) -> NameAndBirthYear {
        let mut attrs = Self::new(rng, first_name, birth_year);
        attrs.seed = seed;
        attrs
    }

    // 返回当前凭证状态的可读性字符串
    pub fn status_text(&self) -> &'static str {
        if self.status {
            "凭证未撤销"
        } else {
            "凭证已撤销"
        }
    }

    // 标记当前凭证为已撤销
    pub fn revoke(&mut self) {
        self.status = false;
    }

    // 返回当前凭证是否已撤销
    pub fn is_revoked(&self) -> bool {
        !self.status
    }
}

// 实现Attrs<Fr, TestComSchemePedersen> for NameAndBirthYear
impl Attrs<Fr, TestComSchemePedersen> for NameAndBirthYear {
    // 序列化属性为字节
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.first_name.to_vec();
        self.birth_year.serialize(&mut buf).unwrap();
        buf.push(self.status as u8);
        buf
    }

    // 获取承诺参数
    fn get_com_param(&self) -> &ComParam<TestComSchemePedersen> {
        &*BIG_COM_PARAM
    }

    // 获取承诺随机数
    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

// 实现Attrs<Fr, Bls12PoseidonCommitter> for NameAndBirthYear
impl Attrs<Fr, Bls12PoseidonCommitter> for NameAndBirthYear {
    /// Serializes the attrs into bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.first_name.to_vec();
        self.birth_year.serialize(&mut buf).unwrap();
        buf.push(self.status as u8);
        buf
    }

    // 获取承诺参数
    fn get_com_param(&self) -> &() {
        &()
    }

    // 获取承诺随机数
    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

// 实现AccountableAttrs<Fr, TestComSchemePedersen> for NameAndBirthYear
impl AccountableAttrs<Fr, TestComSchemePedersen> for NameAndBirthYear {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        self.first_name.to_vec()
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl ToBytesGadget<Fr> for NameAndBirthYearVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([
            self.first_name.to_bytes()?,
            self.birth_year.to_bytes()?,
            vec![self.status.clone()],
        ]
        .concat())
    }
}

impl AttrsVar<Fr, NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG>
    for NameAndBirthYearVar
{
    // 返回用于此变量的约束系统
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.seed
            .cs()
            .or(self.first_name.cs())
            .or(self.birth_year.cs())
            .or(self.status.cs())
    }

    // 分配一个UInt8向量。如果`f()`是`Err`，则会发生panic，因为我们不知道要分配多少字节
    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        native_attr: &NameAndBirthYear,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();

        // 正常获取nonce。这不是一个变量
        let nonce: ComNonce = native_attr.nonce.clone();

        // 见证种子、姓名、出生年份和状态
        let seed = FpVar::new_witness(ns!(cs, "seed"), || Ok(native_attr.seed))?;
        let first_name = UInt8::new_witness_vec(ns!(cs, "first name"), &native_attr.first_name)?;
        let birth_year =
            FpVar::<Fr>::new_witness(ns!(cs, "birth year"), || Ok(native_attr.birth_year))?;
        let status = UInt8::new_witness(ns!(cs, "status"), || Ok(native_attr.status as u8))?;

        // 返回见证的值
        Ok(NameAndBirthYearVar {
            nonce,
            seed,
            first_name,
            birth_year,
            status,
        })
    }

    fn get_com_param(
        &self,
    ) -> Result<ComParamVar<TestComSchemePedersen, TestComSchemePedersenG, Fr>, SynthesisError>
    {
        let cs = self.first_name[0].cs().or(self.birth_year.cs());
        ComParamVar::<_, TestComSchemePedersenG, _>::new_constant(cs, &*BIG_COM_PARAM)
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsVar<Fr, NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG>
    for NameAndBirthYearVar
{
    type Id = Bytestring<Fr>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Bytestring<Fr>, SynthesisError> {
        Ok(Bytestring(self.first_name.clone()))
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}

impl AttrsVar<Fr, NameAndBirthYear, Bls12PoseidonCommitter, Bls12PoseidonCommitter>
    for NameAndBirthYearVar
{
    // 返回用于此变量的约束系统
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.seed
            .cs()
            .or(self.first_name.cs())
            .or(self.birth_year.cs())
            .or(self.status.cs())
    }

    // 分配一个UInt8向量。如果`f()`是`Err`，则会发生panic，因为我们不知道要分配多少字节
    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        native_attr: &NameAndBirthYear,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();

        // 正常获取nonce。这不是一个变量
        let nonce: ComNonce = native_attr.nonce.clone();

        // 见证种子、姓名、出生年份和状态
        let seed = FpVar::new_witness(ns!(cs, "seed"), || Ok(native_attr.seed))?;
        let first_name = UInt8::new_witness_vec(ns!(cs, "first name"), &native_attr.first_name)?;
        let birth_year =
            FpVar::<Fr>::new_witness(ns!(cs, "birth year"), || Ok(native_attr.birth_year))?;
        let status = UInt8::new_witness(ns!(cs, "status"), || Ok(native_attr.status as u8))?;

        // 返回见证的值
        Ok(NameAndBirthYearVar {
            nonce,
            seed,
            first_name,
            birth_year,
            status,
        })
    }

    fn get_com_param(&self) -> Result<UnitVar<Fr>, SynthesisError> {
        Ok(UnitVar::default())
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrs<Fr, Bls12PoseidonCommitter> for NameAndBirthYear {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        self.first_name.to_vec()
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl AccountableAttrsVar<Fr, NameAndBirthYear, Bls12PoseidonCommitter, Bls12PoseidonCommitter>
    for NameAndBirthYearVar
{
    type Id = Bytestring<Fr>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Bytestring<Fr>, SynthesisError> {
        Ok(Bytestring(self.first_name.clone()))
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}

// 定义一个谓词，用于判断给定的`NameAndBirthYear`是否至少为X岁。谓词是：attrs.birth_year ≤ self.threshold_birth_year
#[derive(Clone)]
pub struct AgeChecker {
    pub threshold_birth_year: Fr,
}

impl
    PredicateChecker<
        Fr,
        NameAndBirthYear,
        NameAndBirthYearVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for AgeChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &NameAndBirthYearVar,
    ) -> Result<(), SynthesisError> {
        // 见证阈值年份作为公共输入
        let threshold_birth_year =
            FpVar::<Fr>::new_input(ns!(cs, "threshold year"), || Ok(self.threshold_birth_year))?;
        // 断言attrs.birth_year ≤ threshold_birth_year
        attrs
            .birth_year
            .enforce_cmp(&threshold_birth_year, core::cmp::Ordering::Less, true)?;
        // 断言凭证未被撤销
        attrs.status.enforce_equal(&UInt8::constant(1))
    }

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_birth_year]
    }
}

impl
    PredicateChecker<
        Fr,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
    > for AgeChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &NameAndBirthYearVar,
    ) -> Result<(), SynthesisError> {
        // 见证阈值年份作为公共输入
        let threshold_birth_year =
            FpVar::<Fr>::new_input(ns!(cs, "threshold year"), || Ok(self.threshold_birth_year))?;
        // 断言attrs.birth_year ≤ threshold_birth_year
        attrs
            .birth_year
            .enforce_cmp(&threshold_birth_year, core::cmp::Ordering::Less, true)?;
        // 断言凭证未被撤销
        attrs.status.enforce_equal(&UInt8::constant(1))
    }

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_birth_year]
    }
}

// 测试模块
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pred::{gen_pred_crs, prove_pred};
    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_std::test_rng;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    // 测试已撤销凭证被谓词拒绝
    #[test]
    fn test_revoked_credential_rejected_by_predicate() {
        let mut rng = test_rng();
        let mut person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
        person.revoke();
        assert!(person.is_revoked());
        assert_eq!(person.status_text(), "凭证已撤销");

        // 生成凭证承诺
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);
        let tree_height = 32;
        let mut tree = crate::com_tree::ComTree::empty(MERKLE_CRH_PARAM.clone(), tree_height);
        let auth_path = tree.insert(17, &person_com);

        // 生成谓词
        let age_checker = AgeChecker {
            threshold_birth_year: Fr::from(2001u16),
        };
        // 生成谓词电路的CRS
        let pk = gen_pred_crs::<
            _,
            _,
            E,
            _,
            _,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, age_checker.clone())
        .unwrap();

        // 证明谓词
        let result = catch_unwind(AssertUnwindSafe(|| {
            prove_pred(&mut rng, &pk, age_checker, person, &auth_path).unwrap();
        }));
        // 断言已撤销凭证应失败谓词证明
        assert!(result.is_err(), "revoked credential should fail predicate proof");
    }
}
