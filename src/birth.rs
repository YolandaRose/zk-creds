//! 定义用于证明和验证出生谓词的函数，即必须证明的谓词，以便说服颁发者签发相关凭据

use crate::{
    attrs::{Attrs, AttrsVar},
    pred::PredicateChecker,
    proof_data_structures::{BirthProof, BirthProvingKey, BirthPublicInput, BirthVerifyingKey},
    Com,
};

use core::marker::PhantomData;

use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;
use linkg16::groth16;

// 生成出生谓词的CRS
pub fn gen_birth_crs<R, C, E, A, AV, AC, ACG>(
    rng: &mut R,
    birth_checker: C,
) -> Result<BirthProvingKey<E, A, AV, AC, ACG>, SynthesisError>
where
    R: Rng,
    C: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
{
    let prover = BirthProver {
        birth_checker,
        attrs: A::default(),
        _marker: PhantomData,
    };
    let pk = groth16::generate_random_parameters(prover, rng)?;
    Ok(BirthProvingKey {
        pk,
        _marker: PhantomData,
    })
}

// 证明出生谓词
pub fn prove_birth<R, C, E, A, AV, AC, ACG>(
    rng: &mut R,
    pk: &BirthProvingKey<E, A, AV, AC, ACG>,
    birth_checker: C,
    attrs: A,
) -> Result<BirthProof<E, A, AV, AC, ACG>, SynthesisError>
where
    R: Rng,
    C: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
{
    let prover = BirthProver {
        birth_checker,
        attrs,
        _marker: PhantomData,
    };
    let proof = groth16::create_random_proof(prover, &pk.pk, rng)?;
    Ok(BirthProof {
        proof,
        _marker: PhantomData,
    })
}

// 验证出生谓词
pub fn verify_birth<C, E, A, AV, AC, ACG>(
    vk: &BirthVerifyingKey<E, A, AV, AC, ACG>,
    proof: &BirthProof<E, A, AV, AC, ACG>,
    birth_checker: &C,
    attrs_com: &Com<AC>,
) -> Result<bool, SynthesisError>
where
    C: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
{
    let attr_com_input = attrs_com.to_field_elements().unwrap();

    let all_inputs = [attr_com_input, birth_checker.public_inputs()].concat();
    groth16::verify_proof(&vk.vk, &proof.proof, &all_inputs)
}

// 准备谓词输入
pub fn prepare_pred_inputs<R, C, E, A, AV, AC, ACG>(
    vk: &BirthVerifyingKey<E, A, AV, AC, ACG>,
    birth_checker: &C,
) -> Result<BirthPublicInput<E, A, AV, AC, ACG>, SynthesisError>
where
    R: Rng,
    C: PredicateChecker<E::Fr, A, AV, AC, ACG>,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AV: AttrsVar<E::Fr, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
{
    let pinput = groth16::prepare_inputs(&vk.vk, &birth_checker.public_inputs())?;
    Ok(BirthPublicInput {
        pinput,
        _marker: PhantomData,
    })
}

/// 用于证明出生谓词的内部对象。这需要实现 `ConstraintSynthesizer`
/// 以便传递给Groth16证明函数。`AC` 是属性承诺方案，`MC` 是Merkle根承诺方案。
pub(crate) struct BirthProver<ConstraintF, C, A, AV, AC, ACG>
where
    ConstraintF: PrimeField,
    C: PredicateChecker<ConstraintF, A, AV, AC, ACG>,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    birth_checker: C,
    attrs: A,
    _marker: PhantomData<(ConstraintF, AV, AC, ACG)>,
}

impl<ConstraintF, C, A, AV, AC, ACG> ConstraintSynthesizer<ConstraintF>
    for BirthProver<ConstraintF, C, A, AV, AC, ACG>
where
    ConstraintF: PrimeField,
    C: PredicateChecker<ConstraintF, A, AV, AC, ACG>,
    A: Attrs<ConstraintF, AC>,
    AV: AttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // 见证承诺
        let attrs_com_var =
            ACG::OutputVar::new_input(ns!(cs, "attrs com var"), || Ok(self.attrs.commit()))?;

        // 检查属性承诺的一致性
        let attrs_var = AV::witness_attrs(ns!(cs, "attrs var"), &self.attrs)?;
        attrs_com_var.enforce_equal(&attrs_var.commit()?)?;

        // 最后断言出生谓词为真
        self.birth_checker.pred(cs, &attrs_var)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_util::{
        AgeChecker, NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG,
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};

    #[test]
    fn test_birth() {
        let mut rng = ark_std::test_rng();

        // 我们选择任何人出生在2001年或更早都满足我们的谓词
        let birth_checker = AgeChecker {
            threshold_birth_year: Fr::from(2001u16),
        };

        // 生成出生谓词的CRS
        let pk = gen_birth_crs::<_, _, E, _, _, TestComSchemePedersen, TestComSchemePedersenG>(
            &mut rng,
            birth_checker.clone(),
        )
        .unwrap();

        // 第一个名字是UTF-8编码的，末尾填充空字节
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);

        // 证明谓词
        let proof = prove_birth(&mut rng, &pk, birth_checker.clone(), person.clone()).unwrap();

        // 通常我们无法验证谓词证明，因为它需要知道属性承诺。但这是测试模式，我们知道这个值，所以让我们确保谓词证明可以验证。
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);
        let vk = pk.prepare_verifying_key();
        assert!(verify_birth(&vk, &proof, &birth_checker, &person_com).unwrap());
    }
}
