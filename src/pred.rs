//! 定义用于创建和证明属性谓词的特征

use crate::{
    attrs::{Attrs, AttrsVar},
    com_tree::ComTreePath,
    proof_data_structures::{PredProof, PredProvingKey, PredPublicInput, PredVerifyingKey},
    zk_utils::count_constraints,
};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
};
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;
use linkg16::groth16;

// 描述任何人在 `Attrs` 对象上想要证明的谓词
pub trait PredicateChecker<ConstraintF, A, AV, AC, ACG>
where
    ConstraintF: PrimeField,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 对给定的属性施加约束
    fn pred(self, cs: ConstraintSystemRef<ConstraintF>, attrs: &AV) -> Result<(), SynthesisError>;

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    fn public_inputs(&self) -> Vec<ConstraintF>;
}

// 生成谓词的CRS
pub fn gen_pred_crs<R, P, E, A, AV, AC, ACG, H, HG>(
    rng: &mut R,
    checker: P,
) -> Result<PredProvingKey<E, A, AV, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let prover: PredicateProver<_, _, _, _, _, _, _, HG> = PredicateProver {
        checker,
        attrs: A::default(),
        merkle_root: H::Output::default(),
        _marker: PhantomData,
    };
    let pk = groth16::generate_random_parameters(prover, rng)?;
    Ok(PredProvingKey {
        pk,
        _marker: PhantomData,
    })
}

// 证明给定谓词对属性的证明
pub fn prove_pred<R, P, E, A, AV, AC, ACG, H, HG>(
    rng: &mut R,
    pk: &PredProvingKey<E, A, AV, AC, ACG, H, HG>,
    checker: P,
    attrs: A,
    auth_path: &ComTreePath<E::Fr, H, AC>,
) -> Result<PredProof<E, A, AV, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let merkle_root = auth_path.path.root.clone();
    let prover: PredicateProver<_, _, _, _, _, _, _, HG> = PredicateProver {
        checker,
        attrs,
        merkle_root,
        _marker: PhantomData,
    };
    let proof = groth16::create_random_proof(prover, &pk.pk, rng)?;
    Ok(PredProof {
        proof,
        _marker: PhantomData,
    })
}

// 证明给定出生谓词对给定属性的证明
pub fn prove_birth<R, P, E, A, AV, AC, ACG, H, HG>(
    rng: &mut R,
    pk: &PredProvingKey<E, A, AV, AC, ACG, H, HG>,
    checker: P,
    attrs: A,
) -> Result<PredProof<E, A, AV, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    // 制作一个默认的com树路径，不需要指定长度，因为只使用占位符根值
    let auth_path = ComTreePath::default();
    prove_pred(rng, pk, checker, attrs, &auth_path)
}

pub fn count_pred_constraints<P, E, A, AV, AC, ACG, H, HG>(
    pk: &PredProvingKey<E, A, AV, AC, ACG, H, HG>,
    checker: P,
    attrs: A,
    auth_path: &ComTreePath<E::Fr, H, AC>,
) -> Result<(usize, usize, usize), SynthesisError>
where
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let merkle_root = auth_path.path.root.clone();
    let prover: PredicateProver<_, _, _, _, _, _, _, HG> = PredicateProver {
        checker,
        attrs,
        merkle_root,
        _marker: PhantomData,
    };

    count_constraints(prover)
}

pub fn count_birth_constraints<P, E, A, AV, AC, ACG, H, HG>(
    pk: &PredProvingKey<E, A, AV, AC, ACG, H, HG>,
    checker: P,
    attrs: A,
) -> Result<(usize, usize, usize), SynthesisError>
where
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let auth_path = ComTreePath::default();
    count_pred_constraints(pk, checker, attrs, &auth_path)
}

// 验证谓词证明
#[doc(hidden)]
pub fn verify_pred<P, E, A, AV, AC, ACG, H, HG>(
    vk: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
    proof: &PredProof<E, A, AV, AC, ACG, H, HG>,
    checker: &P,
    attrs_com: &AC::Output,
    merkle_root: &H::Output,
) -> Result<bool, SynthesisError>
where
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let attr_com_input = attrs_com.to_field_elements().unwrap();
    let root_input = merkle_root.to_field_elements().unwrap();

    let all_inputs = [attr_com_input, root_input, checker.public_inputs()].concat();
    groth16::verify_proof(&vk.vk, &proof.proof, &all_inputs)
}

// 验证出生谓词证明
pub fn verify_birth<P, E, A, AV, AC, ACG, H, HG>(
    vk: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
    proof: &PredProof<E, A, AV, AC, ACG, H, HG>,
    checker: &P,
    attrs_com: &AC::Output,
) -> Result<bool, SynthesisError>
where
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let merkle_root = H::Output::default();
    verify_pred(vk, proof, checker, attrs_com, &merkle_root)
}

// 准备谓词输入
pub fn prepare_pred_inputs<R, P, E, A, AV, AC, ACG, H, HG>(
    vk: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
    checker: &P,
) -> Result<PredPublicInput<E, A, AV, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let pinput = groth16::prepare_inputs(&vk.vk, &checker.public_inputs())?;
    Ok(PredPublicInput {
        pinput,
        _marker: PhantomData,
    })
}

// 用于证明谓词的内部对象
// 这需要实现 `ConstraintSynthesizer` 以便传递给Groth16证明函数。`AC` 是属性承诺方案，`MC` 是Merkle根承诺方案。
pub(crate) struct PredicateProver<ConstraintF, P, A, AV, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    P: PredicateChecker<ConstraintF, A, AV, AC, ACG>,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    checker: P,
    attrs: A,
    merkle_root: H::Output,
    _marker: PhantomData<(ConstraintF, AV, AC, ACG, HG)>,
}

impl<ConstraintF, P, A, AV, AC, ACG, H, HG> ConstraintSynthesizer<ConstraintF>
    for PredicateProver<ConstraintF, P, A, AV, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    P: PredicateChecker<ConstraintF, A, AV, AC, ACG>,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // 见证公共变量：在所有的zkcreds证明中，它是属性集的承诺和默克尔根
        let attrs_com_var =
            ACG::OutputVar::new_input(ns!(cs, "attrs com var"), || Ok(self.attrs.commit()))?;
        let _root_var = HG::OutputVar::new_input(ns!(cs, "root var"), || Ok(self.merkle_root))?;

        // 检查属性承诺的一致性
        let attrs_var = AV::witness_attrs(ns!(cs, "attrs var"), &self.attrs)?;
        attrs_com_var.enforce_equal(&attrs_var.commit()?)?;

        // 最后断言谓词为真
        self.checker.pred(cs, &attrs_var)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::test_util::{
        AgeChecker, NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH,
        TestTreeHG,
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};

    // 测试一个谓词，当且仅当给定的 `NameAndBirthYear` 至少为21时返回真
    #[test]
    fn test_age() {
        let mut rng = ark_std::test_rng();

        // 选择任何人出生在2001年或更早都满足的谓词
        let checker = AgeChecker {
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
        >(&mut rng, checker.clone())
        .unwrap();

        // 第一个名字是UTF-8编码的，末尾填充空字节
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
        // 制作一个占位符授权路径，这个值只在开始链接证明时相关
        let auth_path = ComTreePath::default();
        let merkle_root = auth_path.path.root;

        // 证明谓词
        let proof = prove_pred(&mut rng, &pk, checker.clone(), person.clone(), &auth_path).unwrap();

        // 通常我们无法验证谓词证明，因为它需要知道属性承诺。但这是测试模式，我们知道这个值，所以让我们确保谓词证明可以验证。
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);
        let vk = pk.prepare_verifying_key();
        assert!(verify_pred(&vk, &proof, &checker, &person_com, &merkle_root).unwrap());
    }
}
