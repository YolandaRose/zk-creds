//! 定义用于将谓词证明链接为单个“链接证明”的函数和结构

use crate::{
    attrs::{Attrs, AttrsVar},
    com_forest::PreparedRoots,
    pred::PredicateChecker,
    proof_data_structures::{
        ForestProof, ForestVerifyingKey, PredProof, PredVerifyingKey, TreeProof, TreeVerifyingKey,
    },
    Com,
};

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    crh::{constraints::TwoToOneCRHGadget, TwoToOneCRH},
};
use ark_ec::PairingEngine;
use ark_ff::{ToConstraintField, Zero};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::{CryptoRng, Rng};
use linkg16::{groth16, LinkedProof};

#[derive(Clone)]
pub struct PredPublicInputs<E: PairingEngine>(Vec<E::G1Projective>);

// 默认实现 PredPublicInputs 的默认值
impl<E: PairingEngine> Default for PredPublicInputs<E> {
    fn default() -> PredPublicInputs<E> {
        PredPublicInputs(Vec::default())
    }
}

// 准备谓词检查器并将其添加到公共输入中
impl<E: PairingEngine> PredPublicInputs<E> {
    pub fn prepare_pred_checker<P, A, AV, AC, ACG, H, HG>(
        &mut self,
        pred_verif_key: &PredVerifyingKey<E, A, AV, AC, ACG, H, HG>,
        checker: &P,
    ) where
        P: PredicateChecker<E::Fr, A, AV, AC, ACG>,
        A: Attrs<E::Fr, AC>,
        AV: AttrsVar<E::Fr, A, AC, ACG>,
        AC: CommitmentScheme,
        AC::Output: ToConstraintField<E::Fr>,
        ACG: CommitmentGadget<AC, E::Fr>,
        H: TwoToOneCRH,
        H::Output: ToConstraintField<E::Fr>,
        HG: TwoToOneCRHGadget<H, E::Fr>,
    {
        // 首先将公共输入设置为零。这是由 GS 链接证明填充的
        let attr_com_len = Com::<AC>::default().to_field_elements().unwrap().len();
        let root_len = H::Output::default().to_field_elements().unwrap().len();
        let common_inputs = vec![E::Fr::zero(); attr_com_len + root_len];

        // 现在添加此谓词的公共输入
        let mut pred_public_input = common_inputs;
        pred_public_input.extend(checker.public_inputs());

        // 准备输入并将其添加到谓词输入列表中
        let prepared = groth16::prepare_inputs(&pred_verif_key.vk, &pred_public_input).unwrap();
        self.0.push(prepared);
    }
}

// 链接验证密钥
pub struct LinkVerifyingKey<E, A, AV, AC, ACG, H, HG>
where
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
    pub pred_inputs: PredPublicInputs<E>,
    pub prepared_roots: PreparedRoots<E>,
    pub forest_verif_key: ForestVerifyingKey<E, A, AC, ACG, H, HG>,
    pub tree_verif_key: TreeVerifyingKey<E, A, AC, ACG, H, HG>,
    pub pred_verif_keys: Vec<PredVerifyingKey<E, A, AV, AC, ACG, H, HG>>,
}

// 实现 Clone 特征
impl<E, A, AV, AC, ACG, H, HG> Clone for LinkVerifyingKey<E, A, AV, AC, ACG, H, HG>
where
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
    fn clone(&self) -> Self {
        Self {
            pred_inputs: self.pred_inputs.clone(),
            prepared_roots: self.prepared_roots,
            forest_verif_key: self.forest_verif_key.clone(),
            tree_verif_key: self.tree_verif_key.clone(),
            pred_verif_keys: self.pred_verif_keys.clone(),
        }
    }
}

// 链接证明上下文
pub struct LinkProofCtx<E, A, AV, AC, ACG, H, HG>
where
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
    pub attrs_com: Com<AC>,
    pub merkle_root: H::Output,
    pub forest_proof: ForestProof<E, A, AC, ACG, H, HG>,
    pub tree_proof: TreeProof<E, A, AC, ACG, H, HG>,
    pub pred_proofs: Vec<PredProof<E, A, AV, AC, ACG, H, HG>>,
    pub vk: LinkVerifyingKey<E, A, AV, AC, ACG, H, HG>,
}

// 链接证明
pub fn link_proofs<R, E, A, AV, AC, ACG, H, HG>(
    rng: &mut R,
    ctx: &LinkProofCtx<E, A, AV, AC, ACG, H, HG>,
) -> LinkedProof<E>
where
    R: Rng + CryptoRng,
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
    // 获取两个证明共有多少个字段元素。这仅仅是 |attrs_com| + |root|
    let common_inputs = {
        let attr_com_input = ctx.attrs_com.to_field_elements().unwrap();
        let root_input = ctx.merkle_root.to_field_elements().unwrap();
        &[attr_com_input, root_input].concat()
    };

    // 收集所有谓词的 (vk, proof)
    let pred_pairs: Vec<(&groth16::VerifyingKey<E>, &groth16::Proof<E>)> = ctx
        .vk
        .pred_verif_keys
        .iter()
        .zip(ctx.pred_proofs.iter())
        .map(|(vk, proof)| (&vk.vk, &proof.proof))
        .collect();

    // 收集树和森林的 (proof, vk)
    let mut all_pairs = pred_pairs;
    all_pairs.push((&ctx.vk.tree_verif_key.vk, &ctx.tree_proof.proof));
    all_pairs.push((&ctx.vk.forest_verif_key.vk, &ctx.forest_proof.proof));

    linkg16::link(rng, &all_pairs, common_inputs)
}

// 验证链接证明
pub fn verif_link_proof<E, A, AV, AC, ACG, H, HG>(
    proof: &LinkedProof<E>,
    vk: &LinkVerifyingKey<E, A, AV, AC, ACG, H, HG>,
) -> Result<bool, SynthesisError>
where
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
    // 树证明的公共输入只是 attrs com 和 root，即所有输入都是隐藏的
    let tree_prepared_inputs = groth16::prepare_inputs(&vk.tree_verif_key.vk, &[]).unwrap();

    // 收集所有谓词的 (vk, prepared_inputs)
    let pred_tuples = vk
        .pred_verif_keys
        .iter()
        .zip(vk.pred_inputs.0.iter())
        .map(|(vk, input)| (&vk.vk, input))
        .collect();

    // 收集树和森林的 (vk, prepared_inputs)
    let mut all_tuples: Vec<(&groth16::VerifyingKey<E>, &E::G1Projective)> = pred_tuples;
    all_tuples.push((&vk.tree_verif_key.vk, &tree_prepared_inputs));
    all_tuples.push((&vk.forest_verif_key.vk, &vk.prepared_roots.0));

    linkg16::verify_link(proof, &all_tuples)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        attrs::Attrs,
        com_forest::{gen_forest_memb_crs, test::random_tree, ComForest},
        com_tree::{gen_tree_memb_crs, verify_tree_memb, ComTree},
        pred::{gen_pred_crs, prove_pred, verify_pred},
        test_util::{
            AgeChecker, NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH,
            TestTreeHG, MERKLE_CRH_PARAM,
        },
    };

    use ark_bls12_381::{Bls12_381 as E, Fr};

    // 测试一个谓词，如果给定的 `NameAndBirthYear` 至少为 21，则返回 true
    #[test]
    fn test_link() {
        let mut rng = ark_std::test_rng();
        let tree_height = 32;

        // 生成谓词电路的 CRS
        let tree_proving_key = gen_tree_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, MERKLE_CRH_PARAM.clone(), tree_height)
        .unwrap();

        // 创建一个属性并将其放入树中
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
        println!("{}", person.status_text());
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);

        // 创建一个树并“发行”，即在树中放置人员承诺，索引为 17
        let leaf_idx = 17;
        let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), tree_height);
        let auth_path = tree.insert(leaf_idx, &person_com);

        // 现在这个人可以证明其在树中的成员资格。计算根并证明关于该根。
        // root.
        let merkle_root = tree.root();
        let tree_proof = auth_path
            .prove_membership(&mut rng, &tree_proving_key, &*MERKLE_CRH_PARAM, person_com)
            .unwrap();

        let tree_verif_key = tree_proving_key.prepare_verifying_key();
        assert!(verify_tree_memb(&tree_verif_key, &tree_proof, &person_com, &merkle_root).unwrap());

        // 证明一个谓词

        // 我们选择任何人在 2001 年或之前出生都满足我们的谓词
        let age_checker = AgeChecker {
            threshold_birth_year: Fr::from(2001u16),
        };

        // 生成谓词电路的 CRS
        let pred_pk = gen_pred_crs::<_, _, E, _, _, _, _, TestTreeH, TestTreeHG>(
            &mut rng,
            age_checker.clone(),
        )
        .unwrap();

        // 证明谓词
        let pred_proof =
            prove_pred(&mut rng, &pred_pk, age_checker.clone(), person, &auth_path).unwrap();

        // 通常我们无法验证谓词证明，因为它需要知道属性承诺。但这是测试模式，我们知道这个值，所以让我们确保谓词证明可以验证。
        // of the attribute commitment. But this is testing mode and we know this value, so let's
        // make sure the predicate proof verifies.
        let pred_verif_key = pred_pk.prepare_verifying_key();
        assert!(verify_pred(
            &pred_verif_key,
            &pred_proof,
            &age_checker,
            &person_com,
            &merkle_root
        )
        .unwrap());

        // 证明树在森林中

        // 创建一个包含 10 棵树的森林，我们的树出现在森林中的随机索引处
        let num_trees = 10;
        let mut forest = ComForest {
            trees: core::iter::repeat_with(|| random_tree(&mut rng))
                .take(num_trees - 1)
                .collect(),
        };
        let rand_idx = rng.gen_range(0..num_trees);
        let root = tree.root();
        forest.trees.insert(rand_idx, tree);
        let roots = forest.roots();

        // 收集谓词公共输入
        let mut pred_inputs = PredPublicInputs::default();
        pred_inputs.prepare_pred_checker(&pred_verif_key, &age_checker);

        // 生成森林电路的 CRS
        let forest_pk = gen_forest_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, num_trees)
        .unwrap();
        let forest_proof = roots
            .prove_membership(&mut rng, &forest_pk, merkle_root, person_com)
            .unwrap();
        let forest_verif_key = forest_pk.prepare_verifying_key();
        assert!(roots
            .verify_memb(&forest_verif_key, &forest_proof, &person_com, &merkle_root)
            .unwrap());

        // 将所有链接在一起
        let link_vk = LinkVerifyingKey {
            pred_inputs: pred_inputs.clone(),
            prepared_roots: forest.roots().prepare(&forest_verif_key).unwrap(),
            forest_verif_key,
            tree_verif_key,
            pred_verif_keys: vec![pred_verif_key],
        };
        let link_ctx = LinkProofCtx {
            attrs_com: person_com,
            merkle_root: root,
            forest_proof,
            tree_proof,
            pred_proofs: vec![pred_proof],
            vk: link_vk.clone(),
        };
        let link_proof = link_proofs(&mut rng, &link_ctx);

        // 验证 link proof
        assert!(verif_link_proof(&link_proof, &link_vk).unwrap());
    }
}
