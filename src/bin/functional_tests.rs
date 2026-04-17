use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::UniformRand;
use ark_std::rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use std::panic::{catch_unwind, AssertUnwindSafe};

use arkworks_utils::Curve;
use zkcreds::attrs::Attrs;
use zkcreds::com_forest::{gen_forest_memb_crs, ComForest};
use zkcreds::com_tree::{gen_tree_memb_crs, ComTree};
use zkcreds::link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs};
use zkcreds::multishow::MultishowableAttrs;
use zkcreds::poseidon_utils::setup_poseidon_params;
use zkcreds::pred::{gen_pred_crs, prove_pred, verify_pred};
use zkcreds::test_util::{AgeChecker, NameAndBirthYear, NameAndBirthYearVar, MERKLE_CRH_PARAM, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG};
use zkcreds::Com;

type TestA = NameAndBirthYear;
type TestAV = NameAndBirthYearVar;

const TREE_HEIGHT: u32 = 32;
const NUM_TREES: usize = 4;
const POSEIDON_WIDTH: u8 = 5;

fn main() {
    let mut rng = StdRng::seed_from_u64(0xdead_beef);

    println!("=== functional tests start ===");

    if let Err(e) = test_issuance_correctness(&mut rng) {
        println!("[FAIL] 凭证发行正确性测试失败: {e}");
    }
    if let Err(e) = test_proof_generation_verification_correctness(&mut rng) {
        println!("[FAIL] 证明生成与验证正确性测试失败: {e}");
    }
    if let Err(e) = test_multicred_identity_binding(&mut rng) {
        println!("[FAIL] 多凭证身份绑定测试失败: {e}");
    }
    if let Err(e) = test_attribute_tampering(&mut rng) {
        println!("[FAIL] 属性篡改测试失败: {e}");
    }
    if let Err(e) = test_revoked_credential(&mut rng) {
        println!("[FAIL] 撤销凭证测试失败: {e}");
    }
    if let Err(e) = test_fake_cross_user_link(&mut rng) {
        println!("[FAIL] 假链接测试失败: {e}");
    }

    println!("=== functional tests complete ===");
}

fn test_attribute_tampering<R>(rng: &mut R) -> Result<(), String>
where
    R: Rng + CryptoRng,
{
    println!("\n[4] 属性篡改检测测试");

    let _tree_pk = gen_tree_memb_crs::<_, E, TestA, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        MERKLE_CRH_PARAM.clone(),
        TREE_HEIGHT,
    )
    .map_err(format_err)?;

    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(2001u16),
    };
    let pred_pk = gen_pred_crs::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        age_checker.clone(),
    )
    .map_err(format_err)?;
    let pred_vk = pred_pk.prepare_verifying_key();

    let person = NameAndBirthYear::new(rng, b"Alice", 1990);
    let person_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&person);
    println!("生成凭证: name=Alice, birth_year=1990, status={}", person.status_text());

    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let auth_path = tree.insert(17, &person_com);
    let merkle_root = tree.root();
    let pred_proof = prove_pred::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        &pred_pk,
        age_checker.clone(),
        person,
        &auth_path,
    )
    .map_err(format_err)?;
    let verified = verify_pred(&pred_vk, &pred_proof, &age_checker, &person_com, &merkle_root)
        .map_err(format_err)?;
    println!("原始证明验证结果: {}", verified);

    let tampered_person = NameAndBirthYear::new(rng, b"Alice", 2005);
    let tampered_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&tampered_person);
    let tampered_verified = verify_pred(&pred_vk, &pred_proof, &age_checker, &tampered_com, &merkle_root)
        .unwrap_or(false);
    println!(
        "篡改后凭证(出生年2005)使用原证明验证结果: {}",
        tampered_verified
    );

    if !verified {
        return Err("原始证明应验证成功，但未通过".into());
    }
    if tampered_verified {
        return Err("篡改后的凭证不应通过验证".into());
    }

    Ok(())
}

fn test_issuance_correctness<R>(rng: &mut R) -> Result<(), String>
where
    R: Rng + CryptoRng,
{
    println!("\n[1] 凭证发行正确性测试");

    let person = NameAndBirthYear::new(rng, b"Carol", 1992);
    let person_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&person);
    println!("生成凭证: name=Carol, birth_year=1992, status={}", person.status_text());

    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let root_before = tree.root();
    let auth_path = tree.insert(5, &person_com);
    let root_after = tree.root();
    println!("插入叶节点前后 Merkle 根是否变化: {}", root_before != root_after);

    if root_before == root_after {
        return Err("插入凭证后 Merkle 根未更新".into());
    }

    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(2001u16),
    };
    let pred_pk = gen_pred_crs::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        age_checker.clone(),
    )
    .map_err(format_err)?;
    let pred_proof = prove_pred::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        &pred_pk,
        age_checker.clone(),
        person,
        &auth_path,
    )
    .map_err(format_err)?;
    let pred_vk = pred_pk.prepare_verifying_key();
    let verified = verify_pred(&pred_vk, &pred_proof, &age_checker, &person_com, &root_after)
        .map_err(format_err)?;
    println!("凭证发行后证明验证结果: {}", verified);

    if !verified {
        return Err("发行后的凭证无法通过证明验证".into());
    }

    Ok(())
}

fn test_proof_generation_verification_correctness<R>(rng: &mut R) -> Result<(), String>
where
    R: Rng + CryptoRng,
{
    println!("\n[2] 证明生成与验证正确性测试");

    let person = NameAndBirthYear::new(rng, b"Dan", 1992);
    let person_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&person);
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let auth_path = tree.insert(11, &person_com);
    let merkle_root = tree.root();

    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(2001u16),
    };
    let pred_pk = gen_pred_crs::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        age_checker.clone(),
    )
    .map_err(format_err)?;
    let pred_vk = pred_pk.prepare_verifying_key();

    let pred_proof = prove_pred::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        &pred_pk,
        age_checker.clone(),
        person.clone(),
        &auth_path,
    )
    .map_err(format_err)?;

    let verified = verify_pred(&pred_vk, &pred_proof, &age_checker, &person_com, &merkle_root)
        .map_err(format_err)?;
    println!("合法输入证明验证结果: {}", verified);
    if !verified {
        return Err("合法输入的证明应验证成功".into());
    }

    let tampered_person = NameAndBirthYear::new(rng, b"Dan", 2005);
    let tampered_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&tampered_person);
    let tampered_verified = verify_pred(&pred_vk, &pred_proof, &age_checker, &tampered_com, &merkle_root)
        .unwrap_or(false);
    println!("修改属性后的验证结果: {}", tampered_verified);
    if tampered_verified {
        return Err("修改属性后的证明不应通过验证".into());
    }

    let wrong_root = ComTree::<Fr, TestTreeH, TestComSchemePedersen>::empty(
        MERKLE_CRH_PARAM.clone(),
        TREE_HEIGHT,
    )
    .root();
    let wrong_root_verified = verify_pred(&pred_vk, &pred_proof, &age_checker, &person_com, &wrong_root)
        .unwrap_or(false);
    println!("伪造路径（错误根）验证结果: {}", wrong_root_verified);
    if wrong_root_verified {
        return Err("伪造路径的证明不应通过验证".into());
    }

    Ok(())
}

fn test_multicred_identity_binding<R>(rng: &mut R) -> Result<(), String>
where
    R: Rng + CryptoRng,
{
    println!("\n[3] 多凭证与身份绑定正确性测试");

    let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
    let epoch = 5;
    let ctr: u16 = 1;

    let user_seed = Fr::rand(rng);
    let cred1 = NameAndBirthYear::new_with_seed(rng, b"Eve", 1990, user_seed);
    let cred2 = NameAndBirthYear::new_with_seed(rng, b"Eve", 1990, user_seed);
    let other_cred = NameAndBirthYear::new(rng, b"Frank", 1990);

    let token1 = MultishowableAttrs::<_, TestComSchemePedersen>::compute_presentation_token(
        &cred1,
        params.clone(),
        epoch,
        ctr,
    )
    .map_err(format_err)?;
    let token2 = MultishowableAttrs::<_, TestComSchemePedersen>::compute_presentation_token(
        &cred2,
        params.clone(),
        epoch,
        ctr,
    )
    .map_err(format_err)?;
    let token3 = MultishowableAttrs::<_, TestComSchemePedersen>::compute_presentation_token(
        &other_cred,
        params.clone(),
        epoch,
        ctr,
    )
    .map_err(format_err)?;

    println!(
        "同一用户两凭证的 hidden_ctr 是否相同: {}",
        token1.hidden_ctr() == token2.hidden_ctr()
    );
    println!(
        "不同用户凭证的 hidden_ctr 是否不同: {}",
        token1.hidden_ctr() != token3.hidden_ctr()
    );

    if token1.hidden_ctr() != token2.hidden_ctr() {
        return Err("同一用户凭证应具有可关联的 multishow token".into());
    }
    if token1.hidden_ctr() == token3.hidden_ctr() {
        return Err("不同用户凭证不应具有相同的 multishow token".into());
    }

    let same_token_again = MultishowableAttrs::<_, TestComSchemePedersen>::compute_presentation_token(
        &cred1,
        params.clone(),
        epoch,
        ctr,
    )
    .map_err(format_err)?;

    println!(
        "重复使用同一凭证的 hidden_ctr 是否相同: {}",
        token1.hidden_ctr() == same_token_again.hidden_ctr()
    );
    if token1.hidden_ctr() != same_token_again.hidden_ctr() {
        return Err("重复使用同一凭证应产生相同的 multishow token".into());
    }

    Ok(())
}

fn test_revoked_credential<R>(rng: &mut R) -> Result<(), String>
where
    R: Rng + CryptoRng,
{
    println!("\n[5] 已撤销凭证检测测试");

    let _tree_pk = gen_tree_memb_crs::<_, E, TestA, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        MERKLE_CRH_PARAM.clone(),
        TREE_HEIGHT,
    )
    .map_err(format_err)?;

    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(2001u16),
    };
    let pred_pk = gen_pred_crs::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        age_checker.clone(),
    )
    .map_err(format_err)?;

    let mut person = NameAndBirthYear::new(rng, b"Bob", 1990);
    person.revoke();
    println!("生成已撤销凭证: status={}", person.status_text());

    let person_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&person);
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let auth_path = tree.insert(42, &person_com);

    let result = catch_unwind_silently(AssertUnwindSafe(|| {
        prove_pred::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            &pred_pk,
            age_checker.clone(),
            person,
            &auth_path,
        )
    }));

    match result {
        Ok(Ok(_proof)) => Err("撤销凭证不应生成有效证明".into()),
        Ok(Err(err)) => {
            println!("撤销凭证证明生成失败，系统检测到撤销: {err}");
            Ok(())
        }
        Err(_) => {
            println!("撤销凭证证明生成过程中遇到 panic，系统检测到撤销");
            Ok(())
        }
    }
}

fn test_fake_cross_user_link<R>(rng: &mut R) -> Result<(), String>
where
    R: Rng + CryptoRng,
{
    println!("\n[6] 假链接跨用户检测测试");

    let tree_pk = gen_tree_memb_crs::<_, E, NameAndBirthYear, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        MERKLE_CRH_PARAM.clone(),
        TREE_HEIGHT,
    )
    .map_err(format_err)?;
    let forest_pk = gen_forest_memb_crs::<_, E, TestA, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        NUM_TREES,
    )
    .map_err(format_err)?;

    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(2001u16),
    };
    let pred_pk = gen_pred_crs::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        age_checker.clone(),
    )
    .map_err(format_err)?;
    let pred_vk = pred_pk.prepare_verifying_key();

    let alice = NameAndBirthYear::new(rng, b"Alice", 1988);
    let alice_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&alice);
    let mut alice_tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let alice_auth_path = alice_tree.insert(7, &alice_com);
    let alice_merkle_root = alice_tree.root();
    let alice_tree_proof = alice_auth_path
        .prove_membership(rng, &tree_pk, &MERKLE_CRH_PARAM, alice_com)
        .map_err(format_err)?;
    let alice_tree_vk = tree_pk.prepare_verifying_key();

    let num_trees = NUM_TREES;
    let rand_idx = rng.gen_range(0..num_trees);
    let mut alice_forest = ComForest {
        trees: core::iter::repeat_with(|| random_empty_tree(rng)).take(num_trees).collect(),
    };
    alice_forest.trees[rand_idx] = alice_tree;
    let alice_roots = alice_forest.roots();
    let alice_forest_proof = alice_roots
        .prove_membership(rng, &forest_pk, alice_merkle_root, alice_com)
        .map_err(format_err)?;
    let alice_forest_vk = forest_pk.prepare_verifying_key();

    let bob = NameAndBirthYear::new(rng, b"Bob", 1990);
    let bob_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&bob);
    let mut bob_tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let bob_auth_path = bob_tree.insert(13, &bob_com);
    let _bob_merkle_root = bob_tree.root();
    let bob_pred_proof = prove_pred::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        &pred_pk,
        age_checker.clone(),
        bob,
        &bob_auth_path,
    )
    .map_err(format_err)?;

    println!(
        "Alice凭证和Bob凭证分别生成。正在尝试将Bob的证明与Alice的链接上下文组合。"
    );

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&pred_vk, &age_checker);

    let link_vk = LinkVerifyingKey {
        pred_inputs: pred_inputs.clone(),
        prepared_roots: alice_roots.prepare(&alice_forest_vk).map_err(format_err)?,
        forest_verif_key: alice_forest_vk.clone(),
        tree_verif_key: alice_tree_vk.clone(),
        pred_verif_keys: vec![pred_vk.clone()],
    };
    let link_ctx = LinkProofCtx {
        attrs_com: alice_com,
        merkle_root: alice_merkle_root,
        forest_proof: alice_forest_proof,
        tree_proof: alice_tree_proof,
        pred_proofs: vec![bob_pred_proof],
        vk: link_vk.clone(),
    };

    let result = catch_unwind_silently(AssertUnwindSafe(|| {
        let link_proof = link_proofs(rng, &link_ctx);
        verif_link_proof(&link_proof, &link_vk).unwrap_or(false)
    }));

    match result {
        Ok(linked_valid) => {
            println!("跨用户假链接验证结果: {}", linked_valid);
            if linked_valid {
                return Err("跨用户假链接不应通过验证".into());
            }
        }
        Err(_) => {
            println!("跨用户假链接过程中发生 panic，系统检测到伪链接或不一致");
        }
    }

    Ok(())
}

fn random_empty_tree<R>(rng: &mut R) -> ComTree<Fr, TestTreeH, TestComSchemePedersen>
where
    R: ark_std::rand::RngCore,
{
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let leaf = Com::<TestComSchemePedersen>::rand(rng);
    tree.insert(0, &leaf);
    tree
}

fn format_err<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn catch_unwind_silently<F, R>(f: F) -> std::thread::Result<R>
where
    F: FnOnce() -> R + std::panic::UnwindSafe,
{
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(f);
    std::panic::set_hook(prev_hook);
    result
}
