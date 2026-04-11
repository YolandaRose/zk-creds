// 定义用于保存默克尔森林的结构，即一组默克尔树。这在凭证发行中使用。

use crate::{
    attrs::Attrs,
    com_tree::ComTree,
    proof_data_structures::{ForestProof, ForestProvingKey, ForestVerifyingKey},
};

use core::marker::PhantomData;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{constraints::TwoToOneCRHGadget, TwoToOneCRH},
};
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, bits::boolean::Boolean, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;
use linkg16::groth16;

#[derive(Clone, Copy)]
pub struct PreparedRoots<E: PairingEngine>(pub(crate) E::G1Projective);

// `ComForest`的根
pub struct ComForestRoots<ConstraintF, H>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
{
    pub roots: Vec<H::Output>,
    _marker: PhantomData<ConstraintF>,
}

impl<ConstraintF, H> Clone for ComForestRoots<ConstraintF, H>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
{
    fn clone(&self) -> Self {
        Self {
            roots: self.roots.clone(),
            _marker: PhantomData,
        }
    }
}

impl<ConstraintF, H> ComForestRoots<ConstraintF, H>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
{
    pub fn new(num_trees: usize) -> ComForestRoots<ConstraintF, H> {
        ComForestRoots {
            roots: vec![H::Output::default(); num_trees],
            _marker: PhantomData,
        }
    }

    pub fn prepare<E, A, AC, ACG, HG>(
        &self,
        vk: &ForestVerifyingKey<E, A, AC, ACG, H, HG>,
    ) -> Result<PreparedRoots<E>, SynthesisError>
    where
        E: PairingEngine<Fr = ConstraintF>,
        A: Attrs<E::Fr, AC>,
        AC: CommitmentScheme,
        ACG: CommitmentGadget<AC, E::Fr>,
        AC::Output: ToConstraintField<E::Fr>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        groth16::prepare_inputs(&vk.vk, &self.public_inputs()).map(PreparedRoots)
    }

    #[cfg(test)]
    pub(crate) fn verify_memb<E, A, AC, ACG, HG>(
        &self,
        vk: &ForestVerifyingKey<E, A, AC, ACG, H, HG>,
        proof: &ForestProof<E, A, AC, ACG, H, HG>,
        attrs_com: &AC::Output,
        member_root: &H::Output,
    ) -> Result<bool, SynthesisError>
    where
        E: PairingEngine<Fr = ConstraintF>,
        A: Attrs<E::Fr, AC>,
        AC: CommitmentScheme,
        ACG: CommitmentGadget<AC, E::Fr>,
        AC::Output: ToConstraintField<ConstraintF>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        let attr_com_input = attrs_com.to_field_elements().unwrap();
        let member_root_input = member_root.to_field_elements().unwrap();
        let roots_input = self.public_inputs();

        let all_inputs = [attr_com_input, member_root_input, roots_input].concat();
        groth16::verify_proof(&vk.vk, &proof.proof, &all_inputs)
    }

    pub fn public_inputs(&self) -> Vec<ConstraintF> {
        self.roots
            .iter()
            .flat_map(|t| t.to_field_elements().unwrap())
            .collect()
    }

    // 证明给定的属性承诺处于指定的树索引位置
    pub fn prove_membership<R, E, A, AC, ACG, HG>(
        &self,
        rng: &mut R,
        pk: &ForestProvingKey<E, A, AC, ACG, H, HG>,
        member_root: H::Output,
        attrs_com: AC::Output,
    ) -> Result<ForestProof<E, A, AC, ACG, H, HG>, SynthesisError>
    where
        R: Rng,
        E: PairingEngine<Fr = ConstraintF>,
        A: Attrs<E::Fr, AC>,
        AC: CommitmentScheme,
        ACG: CommitmentGadget<AC, E::Fr>,
        AC::Output: ToConstraintField<ConstraintF>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        let prover = ForestMembershipProver::<E::Fr, AC, ACG, H, HG> {
            roots: self.roots.clone(),
            attrs_com,
            member_root,
            _marker: PhantomData,
        };

        let proof = groth16::create_random_proof(prover, &pk.pk, rng)?;
        Ok(ForestProof {
            proof,
            _marker: PhantomData,
        })
    }
}

// 一组承诺树的森林
pub struct ComForest<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    pub trees: Vec<ComTree<ConstraintF, H, AC>>,
}

impl<ConstraintF, H, AC> ComForest<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    pub fn roots(&self) -> ComForestRoots<ConstraintF, H> {
        let roots = self.trees.iter().map(ComTree::root).collect();
        ComForestRoots {
            roots,
            _marker: PhantomData,
        }
    }
}

// 证明给定的属性承诺处于指定的树索引位置
pub fn gen_forest_memb_crs<R, E, A, AC, ACG, H, HG>(
    rng: &mut R,
    num_trees: usize,
) -> Result<ForestProvingKey<E, A, AC, ACG, H, HG>, SynthesisError>
where
    R: Rng,
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<E::Fr>,
    ACG: CommitmentGadget<AC, E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let roots = vec![H::Output::default(); num_trees];
    let attrs_com = AC::Output::default();
    let member_root = H::Output::default();
    let prover = ForestMembershipProver::<E::Fr, AC, ACG, H, HG> {
        roots,
        attrs_com,
        member_root,
        _marker: PhantomData,
    };

    let pk = groth16::generate_random_parameters(prover, rng)?;
    Ok(ForestProvingKey {
        pk,
        _marker: PhantomData,
    })
}

pub struct ForestMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    // 公共输入
    pub roots: Vec<H::Output>,

    // 私有输入 //
    // 这对于所有证明都是必要的
    pub attrs_com: AC::Output,
    // 森林中的成员根
    pub member_root: H::Output,

    // 标记 //
    pub _marker: PhantomData<(ConstraintF, AC, ACG, H, HG, HG)>,
}

impl<ConstraintF, AC, ACG, H, HG> ForestMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    pub fn circuit(
        &self,
        member_root: &HG::OutputVar,
        all_roots: &[HG::OutputVar],
    ) -> Result<(), SynthesisError> {
        // 断言member_root等于其中一个根
        let mut is_member = Boolean::FALSE;
        for root in all_roots {
            is_member = is_member.or(&member_root.is_eq(root)?)?;
        }

        is_member.enforce_equal(&Boolean::TRUE)
    }
}

impl<ConstraintF, AC, ACG, H, HG> ConstraintSynthesizer<ConstraintF>
    for ForestMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // 见证公共变量。在所有的zkcreds证明中，它是属性集的承诺和默克尔根
        let _attrs_com =
            ACG::OutputVar::new_input(ns!(cs, "attrs com"), || Ok(self.attrs_com.clone()))?;
        let member_root =
            HG::OutputVar::new_input(ns!(cs, "root"), || Ok(self.member_root.clone()))?;

        // 见证根
        let all_roots =
            Vec::<HG::OutputVar>::new_input(ns!(cs, "roots"), || Ok(self.roots.clone()))?;

        self.circuit(&member_root, &all_roots)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::test_util::{
        NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG,
        MERKLE_CRH_PARAM,
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_ff::UniformRand;

    pub(crate) fn random_tree<R: Rng>(
        rng: &mut R,
    ) -> ComTree<Fr, TestTreeH, TestComSchemePedersen> {
        let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), 32);
        let idx: u16 = rng.gen();
        let leaf = <<TestComSchemePedersen as CommitmentScheme>::Output as UniformRand>::rand(rng);
        tree.insert(idx as u64, &leaf);
        tree
    }

    // 测试一个谓词，如果给定的`NameAndBirthYear`至少为21，则返回true
    #[test]
    fn test_com_forest_proof() {
        let mut rng = ark_std::test_rng();
        let num_trees = 10;

        // 制作一个随机承诺。这个值不重要
        let attrs_com =
            <<TestComSchemePedersen as CommitmentScheme>::Output as UniformRand>::rand(&mut rng);

        // 生成谓词电路的CRS
        let pk = gen_forest_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, num_trees)
        .unwrap();

        // 制作一堆带有随机元素插入的树
        let trees: Vec<_> = core::iter::repeat_with(|| random_tree(&mut rng))
            .take(num_trees)
            .collect();
        let forest = ComForest { trees };

        // 开始成员资格证明。选择一个任意根
        let member_root = {
            let idx = rng.gen_range(0..num_trees);
            forest.trees[idx].root()
        };
        // 收集根。我们不需要整个森林来计算证明
        let roots = forest.roots();

        // 证明选定的根出现在森林中
        let proof = roots
            .prove_membership(&mut rng, &pk, member_root, attrs_com)
            .unwrap();

        // 验证

        let vk = pk.prepare_verifying_key();
        assert!(roots
            .verify_memb(&vk, &proof, &attrs_com, &member_root)
            .unwrap());
    }
}
