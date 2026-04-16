//! 跨两凭证联合基准：单一 Poseidon 承诺 + Merkle 成员 + 多谓词链接（Groth16-Sahai）。
//!
//! - **学生–员工**：校企合作  
//! - **护照–学生**：国际优惠  
//! - **护照–员工**：跨境商务  
//!
//! 发行仅校验 `SHA256(blob_a || blob_b)`（无 RSA）。

mod circuit_util;
mod hash_checker;
mod params;
mod passport_employee;
mod passport_student;
mod preds;
mod student_employee;

use self::hash_checker::{PeJointHashChecker, PsJointHashChecker, SeJointHashChecker};
use self::params::{
    ComForest, ComForestRoots, ComTree, ComTreePath, Fr, JointComScheme, JointComSchemeG,
    CARD_TODAY, H, HG, MERKLE_CRH_PARAM, NUM_TREES, PASSPORT_TODAY, TREE_HEIGHT,
};
use self::passport_employee::{
    PassportEmployeeJointInfo, PassportEmployeeJointInfoVar, PeForestPk, PeForestProof, PeForestVk,
    PePredPk, PePredProof, PePredVk, PeTreePk, PeTreeProof, PeTreeVk,
};
use self::passport_student::{
    PassportStudentJointInfo, PassportStudentJointInfoVar, PsForestPk, PsForestProof, PsForestVk,
    PsPredPk, PsPredProof, PsPredVk, PsTreePk, PsTreeProof, PsTreeVk,
};
use self::preds::{
    JointHolderTagChecker, PeBusinessChecker, PeEmployeeExpiryChecker, PePassportExpiryChecker,
    PsPassportExpiryChecker, PsStudentExpiryChecker, PsTicketChecker, SeEmployeeExpiryChecker,
    SeNameSchoolCompanyChecker, SeStudentExpiryChecker,
};
use self::student_employee::{
    SeForestPk, SeForestProof, SeForestVk, SePredPk, SePredProof, SePredVk, SeTreePk, SeTreeProof,
    SeTreeVk, StudentEmployeeJointInfo, StudentEmployeeJointInfoVar,
};

use crate::credentials::employee_id::employee_dump::EmployeeDump;
use crate::credentials::passport::passport_dump::PassportDump;
use crate::credentials::student_id::student_dump::StudentDump;

use zkcreds::{
    attrs::Attrs,
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    poseidon_utils::setup_poseidon_params,
    pred::{prove_birth, prove_pred, verify_birth, PredicateChecker},
    pseudonymous_show::PseudonymousAttrs,
    Com,
};

use std::path::Path;

use ark_bls12_381::Bls12_381;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::{rand::{CryptoRng, Rng}, Zero};
use arkworks_utils::Curve;
use criterion::Criterion;

struct IssuerState {
    com_forest: ComForest,
    next_free_tree: usize,
    next_free_leaf: u64,
}

fn rand_tree<R: Rng>(rng: &mut R) -> ComTree {
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let idx: u16 = rng.gen();
    let leaf = Com::<JointComScheme>::rand(rng);
    tree.insert(idx as u64, &leaf);
    tree
}

fn rand_forest<R: Rng>(rng: &mut R) -> ComForest {
    let trees = (0..NUM_TREES).map(|_| rand_tree(rng)).collect();
    ComForest { trees }
}

fn init_issuer<R: Rng>(rng: &mut R) -> IssuerState {
    let com_forest = rand_forest(rng);
    let next_free_tree = rng.gen_range(0..NUM_TREES);
    let next_free_leaf = rng.gen_range(0..2u64.pow(TREE_HEIGHT - 1));
    IssuerState {
        com_forest,
        next_free_tree,
        next_free_leaf,
    }
}

fn load_student_json() -> StudentDump {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches/credentials/student_id/student_card.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read student_card.json: {e}"));
    let json = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        &bytes[..]
    };
    serde_json::from_slice(json).unwrap_or_else(|e| panic!("parse student_card.json: {e}"))
}

fn load_employee_json() -> EmployeeDump {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches/credentials/employee_id/employee_card.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read employee_card.json: {e}"));
    let json = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        &bytes[..]
    };
    serde_json::from_slice(json).unwrap_or_else(|e| panic!("parse employee_card.json: {e}"))
}

fn load_passport_json() -> PassportDump {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches/credentials/passport/passport_dump.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read passport_dump.json: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse passport_dump.json: {e}"))
}

fn cred_token(cred: &Com<JointComScheme>) -> String {
    cred.into_repr()
        .to_bytes_le()
        .iter()
        .take(12)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn compute_holder_tag<A>(attrs: &A) -> Fr
where
    A: PseudonymousAttrs<Fr, JointComScheme>,
{
    let params = setup_poseidon_params(Curve::Bls381, 3, 5);
    attrs.compute_presentation_token(params).unwrap().pseudonym
}

// --- 学生–员工（校企合作）---
pub fn bench_joint_student_employee(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    println!("\n======== 联合基准：学生–员工（校企合作）========\n");

    let iss_pk = zkcreds::pred::gen_pred_crs::<
        _,
        SeJointHashChecker,
        Bls12_381,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(&mut rng, SeJointHashChecker::default())
    .unwrap();
    let iss_vk = iss_pk.prepare_verifying_key();

    let p_stu = zkcreds::pred::gen_pred_crs::<
        _,
        SeStudentExpiryChecker,
        Bls12_381,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        SeStudentExpiryChecker {
            threshold_expiry: Fr::from(CARD_TODAY),
        },
    )
    .unwrap();
    let v_stu = p_stu.prepare_verifying_key();
    let p_emp = zkcreds::pred::gen_pred_crs::<
        _,
        SeEmployeeExpiryChecker,
        Bls12_381,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        SeEmployeeExpiryChecker {
            threshold_expiry: Fr::from(CARD_TODAY),
        },
    )
    .unwrap();
    let v_emp = p_emp.prepare_verifying_key();

    // 校企：姓名一致 + 学校/公司（bench 中会用 credential 自身的值做 expected_*）
    let p_scene = zkcreds::pred::gen_pred_crs::<
        _,
        SeNameSchoolCompanyChecker,
        Bls12_381,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        SeNameSchoolCompanyChecker {
            expected_school: [0u8; 32],
            expected_company: [0u8; 32],
        },
    )
    .unwrap();
    let v_scene = p_scene.prepare_verifying_key();

    let p_holder = zkcreds::pred::gen_pred_crs::<
        _,
        JointHolderTagChecker,
        Bls12_381,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        JointHolderTagChecker {
            holder_tag: Fr::zero(),
        },
    )
    .unwrap();
    let v_holder = p_holder.prepare_verifying_key();

    let tree_pk = zkcreds::com_tree::gen_tree_memb_crs::<
        _,
        Bls12_381,
        StudentEmployeeJointInfo,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(&mut rng, MERKLE_CRH_PARAM.clone(), TREE_HEIGHT)
    .unwrap();
    let tree_vk = tree_pk.prepare_verifying_key();
    let forest_pk = zkcreds::com_forest::gen_forest_memb_crs::<
        _,
        Bls12_381,
        StudentEmployeeJointInfo,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(&mut rng, NUM_TREES)
    .unwrap();
    let forest_vk = forest_pk.prepare_verifying_key();

    let mut issuer = init_issuer(&mut rng);
    let sd = load_student_json();
    let ed = load_employee_json();
    let (_, sb) = sd.to_student_info(&mut rng);
    let (_, eb) = ed.to_employee_info(&mut rng);
    let info = StudentEmployeeJointInfo::from_blobs(&mut rng, &sb, &eb, Fr::from(123456u64));
    let attrs_com = info.commit();
    let holder_tag = compute_holder_tag(&info);
    let hc = SeJointHashChecker::from_info(&info);
    let digest = hc.record_digest;
    c.bench_function("Joint SE: proving joint record hash", |b| {
        b.iter(|| {
            prove_birth(&mut rng, &iss_pk, hc.clone(), info.clone()).unwrap();
        })
    });
    let birth_proof = prove_birth(&mut rng, &iss_pk, hc, info.clone()).unwrap();
    let mut verify_checker = SeJointHashChecker::default();
    verify_checker.record_digest = digest;
    c.bench_function("Joint SE: verifying joint record hash", |b| {
        b.iter(|| {
            assert!(verify_birth(&iss_vk, &birth_proof, &verify_checker, &attrs_com).unwrap());
        })
    });
    assert!(verify_birth(&iss_vk, &birth_proof, &verify_checker, &attrs_com).unwrap());
    let tree_idx = issuer.next_free_tree;
    let leaf_idx = issuer.next_free_leaf;
    println!(
        "[发行方] 联合记录 SHA256 验证通过；承诺前缀 {}…",
        cred_token(&attrs_com)
    );
    let auth_path = issuer.com_forest.trees[tree_idx].insert(leaf_idx, &attrs_com);
    println!("[发行方] 联合承诺已入林：树 {} 叶 {}", tree_idx, leaf_idx);

    let pr_stu = prove_se_pred(
        &mut rng,
        c,
        "Joint SE: proving student card expiry",
        &p_stu,
        &SeStudentExpiryChecker {
            threshold_expiry: Fr::from(CARD_TODAY),
        },
        &info,
        &auth_path,
    );
    let pr_emp = prove_se_pred(
        &mut rng,
        c,
        "Joint SE: proving employee card expiry",
        &p_emp,
        &SeEmployeeExpiryChecker {
            threshold_expiry: Fr::from(CARD_TODAY),
        },
        &info,
        &auth_path,
    );
    let mut expected_school = [0u8; 32];
    expected_school.copy_from_slice(&sb[32..64]);
    let mut expected_company = [0u8; 32];
    expected_company.copy_from_slice(&eb[32..64]);
    let pr_scene = prove_se_pred(
        &mut rng,
        c,
        "Joint SE: proving name+school+company",
        &p_scene,
        &SeNameSchoolCompanyChecker {
            expected_school,
            expected_company,
        },
        &info,
        &auth_path,
    );
    let pr_holder = prove_se_pred(
        &mut rng,
        c,
        "Joint SE: proving holder tag",
        &p_holder,
        &JointHolderTagChecker { holder_tag },
        &info,
        &auth_path,
    );

    let cred = attrs_com;
    let roots = issuer.com_forest.roots();
    let tree_proof = prove_se_tree(
        &mut rng,
        c,
        "Joint SE: proving tree",
        &auth_path,
        &tree_pk,
        cred,
    );
    let forest_proof = prove_se_forest(
        &mut rng,
        c,
        "Joint SE: proving forest",
        &roots,
        &auth_path,
        &forest_pk,
        cred,
    );

    let mut pred_in = PredPublicInputs::default();
    pred_in.prepare_pred_checker(
        &v_stu,
        &SeStudentExpiryChecker {
            threshold_expiry: Fr::from(CARD_TODAY),
        },
    );
    pred_in.prepare_pred_checker(
        &v_emp,
        &SeEmployeeExpiryChecker {
            threshold_expiry: Fr::from(CARD_TODAY),
        },
    );
    pred_in.prepare_pred_checker(
        &v_scene,
        &SeNameSchoolCompanyChecker {
            expected_school,
            expected_company,
        },
    );
    pred_in.prepare_pred_checker(&v_holder, &JointHolderTagChecker { holder_tag });
    let link_vk = LinkVerifyingKey {
        pred_inputs: pred_in,
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk.clone(),
        tree_verif_key: tree_vk.clone(),
        pred_verif_keys: vec![v_stu, v_emp, v_scene, v_holder],
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: auth_path.root(),
        forest_proof: forest_proof.clone(),
        tree_proof: tree_proof.clone(),
        pred_proofs: vec![pr_stu, pr_emp, pr_scene, pr_holder],
        vk: link_vk.clone(),
    };
    c.bench_function("Joint SE: proving linkage", |b| {
        b.iter(|| link_proofs(&mut rng, &link_ctx))
    });
    let lp = link_proofs(&mut rng, &link_ctx);
    crate::util::record_size("Joint SE: proving linkage", &lp);
    c.bench_function("Joint SE: verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof(&lp, &link_vk).unwrap()))
    });
    assert!(verif_link_proof(&lp, &link_vk).unwrap());
    println!("[验证方] 学生–员工联合链接证明通过。\n");
}

fn prove_se_pred<R, P>(
    rng: &mut R,
    c: &mut Criterion,
    name: &str,
    pk: &SePredPk,
    checker: &P,
    info: &StudentEmployeeJointInfo,
    path: &ComTreePath,
) -> SePredProof
where
    R: Rng,
    P: Clone
        + PredicateChecker<
            Fr,
            StudentEmployeeJointInfo,
            StudentEmployeeJointInfoVar,
            JointComScheme,
            JointComSchemeG,
        >,
{
    c.bench_function(name, |b| {
        b.iter(|| prove_pred(rng, pk, checker.clone(), info.clone(), path).unwrap());
    });
    let proof = prove_pred(rng, pk, checker.clone(), info.clone(), path).unwrap();
    assert!(zkcreds::pred::verify_pred(
        &pk.prepare_verifying_key(),
        &proof,
        checker,
        &info.commit(),
        &path.root(),
    )
    .unwrap());
    proof
}

fn prove_se_tree<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    name: &str,
    path: &ComTreePath,
    pk: &SeTreePk,
    cred: Com<JointComScheme>,
) -> SeTreeProof {
    c.bench_function(name, |b| {
        b.iter(|| {
            path.prove_membership(rng, pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap()
        });
    });
    path.prove_membership(rng, pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap()
}

fn prove_se_forest<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    name: &str,
    roots: &ComForestRoots,
    path: &ComTreePath,
    pk: &SeForestPk,
    cred: Com<JointComScheme>,
) -> SeForestProof {
    c.bench_function(name, |b| {
        b.iter(|| roots.prove_membership(rng, pk, path.root(), cred).unwrap());
    });
    roots.prove_membership(rng, pk, path.root(), cred).unwrap()
}

// --- 护照–学生（国际优惠）---
pub fn bench_joint_passport_student(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    println!("\n======== 联合基准：护照–学生（国际优惠）========\n");

    let iss_pk = zkcreds::pred::gen_pred_crs::<
        _,
        PsJointHashChecker,
        Bls12_381,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(&mut rng, PsJointHashChecker::default())
    .unwrap();
    let iss_vk = iss_pk.prepare_verifying_key();

    let p_pp = zkcreds::pred::gen_pred_crs::<
        _,
        PsPassportExpiryChecker,
        Bls12_381,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        PsPassportExpiryChecker {
            threshold_expiry: Fr::from(PASSPORT_TODAY),
        },
    )
    .unwrap();
    let v_pp = p_pp.prepare_verifying_key();
    let p_stu = zkcreds::pred::gen_pred_crs::<
        _,
        PsStudentExpiryChecker,
        Bls12_381,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        PsStudentExpiryChecker {
            threshold_expiry: Fr::from(CARD_TODAY),
        },
    )
    .unwrap();
    let v_stu = p_stu.prepare_verifying_key();

    let p_ticket = zkcreds::pred::gen_pred_crs::<
        _,
        PsTicketChecker,
        Bls12_381,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        PsTicketChecker {
            threshold_dob: Fr::from(20040101u32),
            expected_nationality: *b"CHN",
        },
    )
    .unwrap();
    let v_ticket = p_ticket.prepare_verifying_key();

    let p_holder = zkcreds::pred::gen_pred_crs::<
        _,
        JointHolderTagChecker,
        Bls12_381,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        JointHolderTagChecker {
            holder_tag: Fr::zero(),
        },
    )
    .unwrap();
    let v_holder = p_holder.prepare_verifying_key();

    let tree_pk = zkcreds::com_tree::gen_tree_memb_crs::<
        _,
        Bls12_381,
        PassportStudentJointInfo,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(&mut rng, MERKLE_CRH_PARAM.clone(), TREE_HEIGHT)
    .unwrap();
    let tree_vk = tree_pk.prepare_verifying_key();
    let forest_pk = zkcreds::com_forest::gen_forest_memb_crs::<
        _,
        Bls12_381,
        PassportStudentJointInfo,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(&mut rng, NUM_TREES)
    .unwrap();
    let forest_vk = forest_pk.prepare_verifying_key();

    let mut issuer = init_issuer(&mut rng);
    let pd = load_passport_json();
    let sd = load_student_json();
    let (_, pb) = pd.to_personal_info(&mut rng);
    let (_, sb) = sd.to_student_info(&mut rng);
    let info = PassportStudentJointInfo::from_blobs(&mut rng, &pb, &sb, Fr::from(123456u64));
    let attrs_com = info.commit();
    let holder_tag = compute_holder_tag(&info);
    let hc = PsJointHashChecker::from_info(&info);
    let digest = hc.record_digest;
    c.bench_function("Joint PS: proving joint record hash", |b| {
        b.iter(|| prove_birth(&mut rng, &iss_pk, hc.clone(), info.clone()).unwrap());
    });
    let birth_proof = prove_birth(&mut rng, &iss_pk, hc, info.clone()).unwrap();
    let mut verify_checker = PsJointHashChecker::default();
    verify_checker.record_digest = digest;
    assert!(verify_birth(&iss_vk, &birth_proof, &verify_checker, &attrs_com).unwrap());
    let tree_idx = issuer.next_free_tree;
    let leaf_idx = issuer.next_free_leaf;
    println!(
        "[发行方] 联合记录 SHA256 验证通过；承诺前缀 {}…",
        cred_token(&attrs_com)
    );
    let auth_path = issuer.com_forest.trees[tree_idx].insert(leaf_idx, &attrs_com);
    println!("[发行方] 联合承诺已入林：树 {} 叶 {}", tree_idx, leaf_idx);

    let pr_pp = prove_ps_pred(
        &mut rng,
        c,
        "Joint PS: proving passport expiry",
        &p_pp,
        &PsPassportExpiryChecker {
            threshold_expiry: Fr::from(PASSPORT_TODAY),
        },
        &info,
        &auth_path,
    );
    let pr_stu = prove_ps_pred(
        &mut rng,
        c,
        "Joint PS: proving student card expiry",
        &p_stu,
        &PsStudentExpiryChecker {
            threshold_expiry: Fr::from(CARD_TODAY),
        },
        &info,
        &auth_path,
    );
    let mut nat = [0u8; 3];
    nat.copy_from_slice(&pb[0..3]);
    let pr_ticket = prove_ps_pred(
        &mut rng,
        c,
        "Joint PS: proving ticket(name+age+nat)",
        &p_ticket,
        &PsTicketChecker {
            threshold_dob: Fr::from(20040101u32),
            expected_nationality: nat,
        },
        &info,
        &auth_path,
    );
    let pr_holder = prove_ps_pred(
        &mut rng,
        c,
        "Joint PS: proving holder tag",
        &p_holder,
        &JointHolderTagChecker { holder_tag },
        &info,
        &auth_path,
    );

    let cred = attrs_com;
    let roots = issuer.com_forest.roots();
    let tree_proof = prove_ps_tree(
        &mut rng,
        c,
        "Joint PS: proving tree",
        &auth_path,
        &tree_pk,
        cred,
    );
    let forest_proof = prove_ps_forest(
        &mut rng,
        c,
        "Joint PS: proving forest",
        &roots,
        &auth_path,
        &forest_pk,
        cred,
    );

    let mut pred_in = PredPublicInputs::default();
    pred_in.prepare_pred_checker(
        &v_pp,
        &PsPassportExpiryChecker {
            threshold_expiry: Fr::from(PASSPORT_TODAY),
        },
    );
    pred_in.prepare_pred_checker(
        &v_stu,
        &PsStudentExpiryChecker {
            threshold_expiry: Fr::from(CARD_TODAY),
        },
    );
    pred_in.prepare_pred_checker(
        &v_ticket,
        &PsTicketChecker {
            threshold_dob: Fr::from(20040101u32),
            expected_nationality: nat,
        },
    );
    pred_in.prepare_pred_checker(&v_holder, &JointHolderTagChecker { holder_tag });
    let link_vk = LinkVerifyingKey {
        pred_inputs: pred_in,
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk.clone(),
        tree_verif_key: tree_vk.clone(),
        pred_verif_keys: vec![v_pp, v_stu, v_ticket, v_holder],
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: auth_path.root(),
        forest_proof: forest_proof.clone(),
        tree_proof: tree_proof.clone(),
        pred_proofs: vec![pr_pp, pr_stu, pr_ticket, pr_holder],
        vk: link_vk.clone(),
    };
    c.bench_function("Joint PS: proving linkage", |b| {
        b.iter(|| link_proofs(&mut rng, &link_ctx))
    });
    let lp = link_proofs(&mut rng, &link_ctx);
    crate::util::record_size("Joint PS: proving linkage", &lp);
    c.bench_function("Joint PS: verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof(&lp, &link_vk).unwrap()))
    });
    assert!(verif_link_proof(&lp, &link_vk).unwrap());
    println!("[验证方] 护照–学生联合链接证明通过。\n");
}

fn prove_ps_pred<R, P>(
    rng: &mut R,
    c: &mut Criterion,
    name: &str,
    pk: &PsPredPk,
    checker: &P,
    info: &PassportStudentJointInfo,
    path: &ComTreePath,
) -> PsPredProof
where
    R: Rng,
    P: Clone
        + PredicateChecker<
            Fr,
            PassportStudentJointInfo,
            PassportStudentJointInfoVar,
            JointComScheme,
            JointComSchemeG,
        >,
{
    c.bench_function(name, |b| {
        b.iter(|| prove_pred(rng, pk, checker.clone(), info.clone(), path).unwrap());
    });
    let proof = prove_pred(rng, pk, checker.clone(), info.clone(), path).unwrap();
    assert!(zkcreds::pred::verify_pred(
        &pk.prepare_verifying_key(),
        &proof,
        checker,
        &info.commit(),
        &path.root(),
    )
    .unwrap());
    proof
}

fn prove_ps_tree<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    name: &str,
    path: &ComTreePath,
    pk: &PsTreePk,
    cred: Com<JointComScheme>,
) -> PsTreeProof {
    c.bench_function(name, |b| {
        b.iter(|| {
            path.prove_membership(rng, pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap()
        });
    });
    path.prove_membership(rng, pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap()
}

fn prove_ps_forest<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    name: &str,
    roots: &ComForestRoots,
    path: &ComTreePath,
    pk: &PsForestPk,
    cred: Com<JointComScheme>,
) -> PsForestProof {
    c.bench_function(name, |b| {
        b.iter(|| roots.prove_membership(rng, pk, path.root(), cred).unwrap());
    });
    roots.prove_membership(rng, pk, path.root(), cred).unwrap()
}

// --- 护照–员工（跨境商务）---
pub fn bench_joint_passport_employee(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    println!("\n======== 联合基准：护照–员工（跨境商务）========\n");

    let iss_pk = zkcreds::pred::gen_pred_crs::<
        _,
        PeJointHashChecker,
        Bls12_381,
        PassportEmployeeJointInfo,
        PassportEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(&mut rng, PeJointHashChecker::default())
    .unwrap();
    let iss_vk = iss_pk.prepare_verifying_key();

    let p_pp = zkcreds::pred::gen_pred_crs::<
        _,
        PePassportExpiryChecker,
        Bls12_381,
        PassportEmployeeJointInfo,
        PassportEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        PePassportExpiryChecker {
            threshold_expiry: Fr::from(PASSPORT_TODAY),
        },
    )
    .unwrap();
    let v_pp = p_pp.prepare_verifying_key();

    // 商务：公司名 + 工作证有效期 + 姓名一致
    let p_biz = zkcreds::pred::gen_pred_crs::<
        _,
        PeBusinessChecker,
        Bls12_381,
        PassportEmployeeJointInfo,
        PassportEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        PeBusinessChecker {
            expected_company: [0u8; 32],
            threshold_employee_expiry: Fr::from(CARD_TODAY),
        },
    )
    .unwrap();
    let v_biz = p_biz.prepare_verifying_key();

    let p_holder = zkcreds::pred::gen_pred_crs::<
        _,
        JointHolderTagChecker,
        Bls12_381,
        PassportEmployeeJointInfo,
        PassportEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(
        &mut rng,
        JointHolderTagChecker {
            holder_tag: Fr::zero(),
        },
    )
    .unwrap();
    let v_holder = p_holder.prepare_verifying_key();

    let tree_pk = zkcreds::com_tree::gen_tree_memb_crs::<
        _,
        Bls12_381,
        PassportEmployeeJointInfo,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(&mut rng, MERKLE_CRH_PARAM.clone(), TREE_HEIGHT)
    .unwrap();
    let tree_vk = tree_pk.prepare_verifying_key();
    let forest_pk = zkcreds::com_forest::gen_forest_memb_crs::<
        _,
        Bls12_381,
        PassportEmployeeJointInfo,
        JointComScheme,
        JointComSchemeG,
        H,
        HG,
    >(&mut rng, NUM_TREES)
    .unwrap();
    let forest_vk = forest_pk.prepare_verifying_key();

    let mut issuer = init_issuer(&mut rng);
    let pd = load_passport_json();
    let ed = load_employee_json();
    let (_, pb) = pd.to_personal_info(&mut rng);
    let (_, eb) = ed.to_employee_info(&mut rng);
    let info = PassportEmployeeJointInfo::from_blobs(&mut rng, &pb, &eb, Fr::from(123456u64));
    let attrs_com = info.commit();
    let holder_tag = compute_holder_tag(&info);
    let hc = PeJointHashChecker::from_info(&info);
    let digest = hc.record_digest;
    c.bench_function("Joint PE: proving joint record hash", |b| {
        b.iter(|| prove_birth(&mut rng, &iss_pk, hc.clone(), info.clone()).unwrap());
    });
    let birth_proof = prove_birth(&mut rng, &iss_pk, hc, info.clone()).unwrap();
    let mut verify_checker = PeJointHashChecker::default();
    verify_checker.record_digest = digest;
    assert!(verify_birth(&iss_vk, &birth_proof, &verify_checker, &attrs_com).unwrap());
    let tree_idx = issuer.next_free_tree;
    let leaf_idx = issuer.next_free_leaf;
    println!(
        "[发行方] 联合记录 SHA256 验证通过；承诺前缀 {}…",
        cred_token(&attrs_com)
    );
    let auth_path = issuer.com_forest.trees[tree_idx].insert(leaf_idx, &attrs_com);
    println!("[发行方] 联合承诺已入林：树 {} 叶 {}", tree_idx, leaf_idx);

    let pr_pp = prove_pe_pred(
        &mut rng,
        c,
        "Joint PE: proving passport expiry",
        &p_pp,
        &PePassportExpiryChecker {
            threshold_expiry: Fr::from(PASSPORT_TODAY),
        },
        &info,
        &auth_path,
    );
    let mut expected_company = [0u8; 32];
    expected_company.copy_from_slice(&eb[32..64]);
    let pr_biz = prove_pe_pred(
        &mut rng,
        c,
        "Joint PE: proving business(name+company+expiry)",
        &p_biz,
        &PeBusinessChecker {
            expected_company,
            threshold_employee_expiry: Fr::from(CARD_TODAY),
        },
        &info,
        &auth_path,
    );
    let pr_holder = prove_pe_pred(
        &mut rng,
        c,
        "Joint PE: proving holder tag",
        &p_holder,
        &JointHolderTagChecker { holder_tag },
        &info,
        &auth_path,
    );

    let cred = attrs_com;
    let roots = issuer.com_forest.roots();
    let tree_proof = prove_pe_tree(
        &mut rng,
        c,
        "Joint PE: proving tree",
        &auth_path,
        &tree_pk,
        cred,
    );
    let forest_proof = prove_pe_forest(
        &mut rng,
        c,
        "Joint PE: proving forest",
        &roots,
        &auth_path,
        &forest_pk,
        cred,
    );

    let mut pred_in = PredPublicInputs::default();
    pred_in.prepare_pred_checker(
        &v_pp,
        &PePassportExpiryChecker {
            threshold_expiry: Fr::from(PASSPORT_TODAY),
        },
    );
    pred_in.prepare_pred_checker(
        &v_biz,
        &PeBusinessChecker {
            expected_company,
            threshold_employee_expiry: Fr::from(CARD_TODAY),
        },
    );
    pred_in.prepare_pred_checker(&v_holder, &JointHolderTagChecker { holder_tag });
    let link_vk = LinkVerifyingKey {
        pred_inputs: pred_in,
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk.clone(),
        tree_verif_key: tree_vk.clone(),
        pred_verif_keys: vec![v_pp, v_biz, v_holder],
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: auth_path.root(),
        forest_proof: forest_proof.clone(),
        tree_proof: tree_proof.clone(),
        pred_proofs: vec![pr_pp, pr_biz, pr_holder],
        vk: link_vk.clone(),
    };
    c.bench_function("Joint PE: proving linkage", |b| {
        b.iter(|| link_proofs(&mut rng, &link_ctx))
    });
    let lp = link_proofs(&mut rng, &link_ctx);
    crate::util::record_size("Joint PE: proving linkage", &lp);
    c.bench_function("Joint PE: verifying linkage", |b| {
        b.iter(|| assert!(verif_link_proof(&lp, &link_vk).unwrap()))
    });
    assert!(verif_link_proof(&lp, &link_vk).unwrap());
    println!("[验证方] 护照–员工联合链接证明通过。\n");
}

fn prove_pe_pred<R, P>(
    rng: &mut R,
    c: &mut Criterion,
    name: &str,
    pk: &PePredPk,
    checker: &P,
    info: &PassportEmployeeJointInfo,
    path: &ComTreePath,
) -> PePredProof
where
    R: Rng,
    P: Clone
        + PredicateChecker<
            Fr,
            PassportEmployeeJointInfo,
            PassportEmployeeJointInfoVar,
            JointComScheme,
            JointComSchemeG,
        >,
{
    c.bench_function(name, |b| {
        b.iter(|| prove_pred(rng, pk, checker.clone(), info.clone(), path).unwrap());
    });
    let proof = prove_pred(rng, pk, checker.clone(), info.clone(), path).unwrap();
    assert!(zkcreds::pred::verify_pred(
        &pk.prepare_verifying_key(),
        &proof,
        checker,
        &info.commit(),
        &path.root(),
    )
    .unwrap());
    proof
}

fn prove_pe_tree<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    name: &str,
    path: &ComTreePath,
    pk: &PeTreePk,
    cred: Com<JointComScheme>,
) -> PeTreeProof {
    c.bench_function(name, |b| {
        b.iter(|| {
            path.prove_membership(rng, pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap()
        });
    });
    path.prove_membership(rng, pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap()
}

fn prove_pe_forest<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    name: &str,
    roots: &ComForestRoots,
    path: &ComTreePath,
    pk: &PeForestPk,
    cred: Com<JointComScheme>,
) -> PeForestProof {
    c.bench_function(name, |b| {
        b.iter(|| roots.prove_membership(rng, pk, path.root(), cred).unwrap());
    });
    roots.prove_membership(rng, pk, path.root(), cred).unwrap()
}
