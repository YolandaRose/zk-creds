// 定义了一个默克尔树，用于保存凭证（正式名称为“属性集的承诺”）

use crate::{
    attrs::Attrs,
    proof_data_structures::{TreeProof, TreeProvingKey},
    sparse_merkle::{
        constraints::SparseMerkleTreePathVar, SparseMerkleTree, SparseMerkleTreePath,
        SparseMerkleTreeWireFormat,
    },
    zk_utils::{count_constraints, IdentityCRH, IdentityCRHGadget, UnitVar},
};

use core::marker::PhantomData;
use std::collections::BTreeMap;

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{constraints::TwoToOneCRHGadget, TwoToOneCRH, CRH},
    merkle_tree::{Config as TreeConfig, LeafParam, TwoToOneParam},
};
use ark_ec::PairingEngine;
use ark_ff::to_bytes;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::rand::Rng;
use linkg16::groth16;

#[cfg(test)]
use crate::proof_data_structures::TreeVerifyingKey;

// 一个稀疏默克尔树配置，使用身份函数作为叶子哈希（我们不需要对承诺进行哈希）
pub struct ComTreeConfig<H: TwoToOneCRH>(H);

impl<H: TwoToOneCRH> TreeConfig for ComTreeConfig<H> {
    type LeafHash = IdentityCRH;
    type TwoToOneHash = H;
}

// `ComTree`中的授权路径
pub struct ComTreePath<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 路径
    pub path: SparseMerkleTreePath<ComTreeConfig<H>>,

    _marker: PhantomData<(ConstraintF, AC)>,
}

impl<ConstraintF, H, AC> Clone for ComTreePath<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    fn clone(&self) -> ComTreePath<ConstraintF, H, AC> {
        ComTreePath {
            path: self.path.clone(),
            _marker: PhantomData,
        }
    }
}

impl<ConstraintF, H, AC> ComTreePath<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 此授权路径所属的树的根
    pub fn root(&self) -> H::Output {
        self.path.root.clone()
    }
}

impl<ConstraintF, H, AC> Default for ComTreePath<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    fn default() -> Self {
        let path = SparseMerkleTreePath::<ComTreeConfig<H>>::default();
        ComTreePath {
            path,
            _marker: PhantomData,
        }
    }
}

// 一个属性承诺的默克尔树
pub struct ComTree<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 树的内容
    tree: SparseMerkleTree<ComTreeConfig<H>>,

    _marker: PhantomData<(ConstraintF, AC)>,
}

// 一个可以序列化和反序列化的ComTree版本
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ComTreeWireFormat<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 树的内容
    tree: SparseMerkleTreeWireFormat<ComTreeConfig<H>>,

    _marker: PhantomData<(ConstraintF, AC)>,
}

impl<ConstraintF, H, AC> ComTreeWireFormat<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    pub fn into_com_tree(
        self,
        two_to_one_param: TwoToOneParam<ComTreeConfig<H>>,
    ) -> ComTree<ConstraintF, H, AC> {
        // 记住Com树不哈希其叶子
        let leaf_param = <IdentityCRH as CRH>::Parameters::default();
        ComTree {
            tree: self
                .tree
                .into_sparse_merkle_tree(leaf_param, two_to_one_param),
            _marker: self._marker,
        }
    }
}

impl<ConstraintF, H, AC> ComTree<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 返回此树的根
    pub fn root(&self) -> H::Output {
        self.tree.root()
    }

    // 制作一个容量为`2^tree_height`的空列表。高度必须至少为2。
    pub fn empty(crh_params: H::Parameters, tree_height: u32) -> ComTree<ConstraintF, H, AC> {
        ComTree {
            tree: SparseMerkleTree::empty::<AC::Output>((), crh_params, tree_height),
            _marker: PhantomData,
        }
    }

    // 制作一个容量为`2^tree_height`的列表，其中填充了所有给定的承诺
    // 在给定的索引处。高度必须至少为2。
    ///
    // 抛出
    // =====
    // 如果`coms`中的任何键大于或等于`2^tree_height`，则抛出
    pub fn new(
        crh_params: H::Parameters,
        tree_height: u32,
        coms: &BTreeMap<u64, AC::Output>,
    ) -> ComTree<ConstraintF, H, AC> {
        let tree = SparseMerkleTree::new::<AC::Output>((), crh_params, tree_height, coms)
            .expect("could not instantiate ComTree");

        ComTree {
            tree,
            _marker: PhantomData,
        }
    }

    // 在索引`idx`处插入一个承诺。如果存在，则覆盖现有条目。
    ///
    // 抛出
    // =====
    // 当`idx >= 2^log_capacity`时抛出
    pub fn insert(&mut self, idx: u64, com: &AC::Output) -> ComTreePath<ConstraintF, H, AC> {
        // 执行插入
        self.tree.insert(idx, com).expect("could not insert item");
        // 返回授权路径
        let path = self.tree.generate_proof(idx, com).unwrap();
        ComTreePath {
            path,
            _marker: PhantomData,
        }
    }

    // 删除索引`idx`处的条目，如果存在
    ///
    // 抛出
    // =====
    // 当`idx >= 2^tree_height`时抛出
    pub fn remove(&mut self, idx: u64) {
        self.tree.remove(idx).expect("could not remove item");
    }

    // 将此`ComTree`转换为可以序列化和反序列化的格式
    pub fn into_wire_format(&self) -> ComTreeWireFormat<ConstraintF, H, AC> {
        ComTreeWireFormat {
            tree: self.tree.into_wire_format(),
            _marker: PhantomData,
        }
    }
}

impl<ConstraintF, H, AC> ComTreePath<ConstraintF, H, AC>
where
    ConstraintF: PrimeField,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 证明给定的属性承诺在指定的树索引处
    pub fn prove_membership<R, E, A, ACG, HG>(
        &self,
        rng: &mut R,
        pk: &TreeProvingKey<E, A, AC, ACG, H, HG>,
        two_to_one_params: &H::Parameters,
        attrs_com: AC::Output,
    ) -> Result<TreeProof<E, A, AC, ACG, H, HG>, SynthesisError>
    where
        R: Rng,
        E: PairingEngine<Fr = ConstraintF>,
        A: Attrs<E::Fr, AC>,
        ACG: CommitmentGadget<AC, E::Fr>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        let root = self.path.root.clone();

        // 构造证明者，并证明
        let prover: TreeMembershipProver<E::Fr, AC, ACG, H, HG> = TreeMembershipProver {
            height: self.path.height(),
            crh_param: two_to_one_params.clone(),
            attrs_com,
            root,
            auth_path: Some(self.path.clone()),
            _marker: PhantomData,
        };

        let proof = groth16::create_random_proof(prover, &pk.pk, rng)?;
        Ok(TreeProof {
            proof,
            _marker: PhantomData,
        })
    }

    pub fn count_membership_constraints<E, A, ACG, HG>(
        &self,
        two_to_one_params: &H::Parameters,
        attrs_com: AC::Output,
    ) -> Result<(usize, usize, usize), SynthesisError>
    where
        E: PairingEngine<Fr = ConstraintF>,
        A: Attrs<E::Fr, AC>,
        ACG: CommitmentGadget<AC, E::Fr>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        let root = self.path.root.clone();
        let prover: TreeMembershipProver<E::Fr, AC, ACG, H, HG> = TreeMembershipProver {
            height: self.path.height(),
            crh_param: two_to_one_params.clone(),
            attrs_com,
            root,
            auth_path: Some(self.path.clone()),
            _marker: PhantomData,
        };

        count_constraints(prover)
    }
}

// 生成此树的成员资格证明密钥
pub fn gen_tree_memb_crs<R, E, A, AC, ACG, H, HG>(
    rng: &mut R,
    crh_param: H::Parameters,
    height: u32,
) -> Result<TreeProvingKey<E, A, AC, ACG, H, HG>, SynthesisError>
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
    let prover: TreeMembershipProver<E::Fr, AC, ACG, H, HG> = TreeMembershipProver {
        height,
        crh_param,
        attrs_com: Default::default(),
        root: Default::default(),
        //root: self.tree.root(),
        //root_com_nonce: self.nonce,
        auth_path: None,
        _marker: PhantomData,
    };
    let pk = groth16::generate_random_parameters(prover, rng)?;
    Ok(TreeProvingKey {
        pk,
        _marker: PhantomData,
    })
}

#[cfg(test)]
pub(crate) fn verify_tree_memb<E, A, AC, ACG, H, HG>(
    vk: &TreeVerifyingKey<E, A, AC, ACG, H, HG>,
    proof: &TreeProof<E, A, AC, ACG, H, HG>,
    attrs_com: &AC::Output,
    merkle_root: &H::Output,
) -> Result<bool, SynthesisError>
where
    E: PairingEngine,
    A: Attrs<E::Fr, AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, E::Fr>,
    AC::Output: ToConstraintField<E::Fr>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<E::Fr>,
    HG: TwoToOneCRHGadget<H, E::Fr>,
{
    let attr_com_input = attrs_com.to_field_elements().unwrap();
    let root_input = merkle_root.to_field_elements().unwrap();

    let all_inputs = [attr_com_input, root_input].concat();
    groth16::verify_proof(&vk.vk, &proof.proof, &all_inputs)
}

// 一个电路，证明一个承诺到`attrs`出现在高度为`height`的默克尔树中，由根哈希`root`定义。
pub struct TreeMembershipProver<ConstraintF, AC, ACG, H, HG>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    // 常量 //
    pub height: u32,
    pub crh_param: TwoToOneParam<ComTreeConfig<H>>,

    // 私有输入 //
    // 叶子值
    pub attrs_com: AC::Output,
    // 树根的值
    pub root: H::Output,
    // 叶子`attrs_com`的默克尔授权路径
    pub auth_path: Option<SparseMerkleTreePath<ComTreeConfig<H>>>,

    // 标记 //
    pub _marker: PhantomData<(ConstraintF, AC, ACG, H, HG, HG)>,
}

// 默认授权路径
pub fn default_auth_path<AC, H>(height: u32) -> SparseMerkleTreePath<ComTreeConfig<H>>
where
    AC: CommitmentScheme,
    H: TwoToOneCRH,
{
    // 默认承诺字节
    let default_com_bytes = to_bytes!(AC::Output::default()).unwrap();
    SparseMerkleTreePath::<ComTreeConfig<H>> {
        leaf_hashes: (default_com_bytes.clone(), default_com_bytes),
        // 内部哈希
        inner_hashes: vec![
            (H::Output::default(), H::Output::default());
            height.checked_sub(2).expect("tree height cannot be < 2") as usize
        ],
        // 根
        root: H::Output::default(),
    }
}

impl<ConstraintF, AC, ACG, H, HG> TreeMembershipProver<ConstraintF, AC, ACG, H, HG>
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
        attrs_com_var: &ACG::OutputVar,
        root_var: &HG::OutputVar,
        path_var: &SparseMerkleTreePathVar<ComTreeConfig<H>, IdentityCRHGadget, HG, ConstraintF>,
        crh_param_var: &HG::ParametersVar,
        leaf_param_var: &UnitVar<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let cs = attrs_com_var.cs().or(root_var.cs());

        path_var.check_membership(
            ns!(cs, "check_membership").cs(),
            leaf_param_var,
            crh_param_var,
            root_var,
            &attrs_com_var,
        )
    }
}

impl<ConstraintF, AC, ACG, H, HG> ConstraintSynthesizer<ConstraintF>
    for TreeMembershipProver<ConstraintF, AC, ACG, H, HG>
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
        let attrs_com_var =
            ACG::OutputVar::new_input(ns!(cs, "attrs com var"), || Ok(self.attrs_com.clone()))?;
        let root_var = HG::OutputVar::new_input(ns!(cs, "root var"), || Ok(self.root.clone()))?;

        // 现在我们进行树成员资格证明。输入两到一参数
        let crh_param_var =
            HG::ParametersVar::new_constant(ns!(cs, "two_to_one param"), &self.crh_param)?;
        // 这是一个占位符值。我们实际上不使用叶子哈希
        let leaf_param_var = UnitVar::default();

        // 如果没有授权路径，制作一个适当长度的路径
        let auth_path = self
            .auth_path
            .clone()
            .unwrap_or_else(|| default_auth_path::<AC, H>(self.height));

        // 见证授权路径
        let path_var = SparseMerkleTreePathVar::<_, IdentityCRHGadget, HG, _>::new_witness(
            ns!(cs, "auth path"),
            || Ok(auth_path),
            self.height,
        )?;

        self.circuit(
            &attrs_com_var,
            &root_var,
            &path_var,
            &crh_param_var,
            &leaf_param_var,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        poseidon_utils::{Bls12PoseidonCommitter, Bls12PoseidonCrh},
        test_util::{
            NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG,
            MERKLE_CRH_PARAM,
        },
    };

    use ark_bls12_381::Bls12_381 as E;

    // 测试树成员资格证明的正确性，使用Pedersen哈希进行树和承诺
    #[test]
    fn test_com_tree_proof_pedersen() {
        let mut rng = ark_std::test_rng();
        let tree_height = 32;

        // 制作一个属性放入树中
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);

        // 生成谓词电路的CRS
        let pk = gen_tree_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, MERKLE_CRH_PARAM.clone(), tree_height)
        .unwrap();

        // 制作一个树并“发行”，即在树的索引17处放入人的承诺
        let leaf_idx = 17;
        let mut tree = ComTree::<_, TestTreeH, TestComSchemePedersen>::empty(
            MERKLE_CRH_PARAM.clone(),
            tree_height,
        );
        let auth_path = tree.insert(leaf_idx, &person_com);

        // 现在人可以证明其在树中的成员资格
        let proof = auth_path
            .prove_membership(&mut rng, &pk, &*MERKLE_CRH_PARAM, person_com)
            .unwrap();

        let vk = pk.prepare_verifying_key();
        assert!(verify_tree_memb(&vk, &proof, &person_com, &tree.root()).unwrap());
    }

    // 测试树成员资格证明的正确性，使用Poseidon哈希进行树和承诺
    #[test]
    fn test_com_tree_proof_poseidon() {
        let mut rng = ark_std::test_rng();
        let tree_height = 32;

        // 制作一个属性放入树中
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
        let person_com = Attrs::<_, Bls12PoseidonCommitter>::commit(&person);

        // 生成谓词电路的CRS
        let pk = gen_tree_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            Bls12PoseidonCommitter,
            Bls12PoseidonCommitter,
            Bls12PoseidonCrh,
            Bls12PoseidonCrh,
        >(&mut rng, (), tree_height)
        .unwrap();

        // 制作一个树并“发行”，即在树的索引17处放入人的承诺
        let leaf_idx = 17;
        let mut tree =
            ComTree::<_, Bls12PoseidonCrh, Bls12PoseidonCommitter>::empty((), tree_height);
        let auth_path = tree.insert(leaf_idx, &person_com);

        // 现在人可以证明其在树中的成员资格
        let proof = auth_path
            .prove_membership(&mut rng, &pk, &(), person_com)
            .unwrap();

        let vk = pk.prepare_verifying_key();
        assert!(verify_tree_memb(&vk, &proof, &person_com, &tree.root()).unwrap());
    }
}
