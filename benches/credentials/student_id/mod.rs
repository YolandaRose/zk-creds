mod issuance_checker;
mod params;
mod preds;
mod student_dump;
mod student_info;

use crate::credentials::common::sig_verif::load_issuer_pubkey;
use crate::credentials::student_id::issuance_checker::{
    StudentIssuanceReq, StudentRecordHashChecker,
};
use crate::credentials::student_id::params::{
    ComForest, ComForestRoots, ComTree, ComTreePath, ForestProof, ForestProvingKey,
    ForestVerifyingKey, PredProof, PredProvingKey, PredVerifyingKey, StudentComScheme,
    StudentComSchemeG, TreeProof, TreeProvingKey, TreeVerifyingKey, H, HG, MERKLE_CRH_PARAM,
};
use crate::credentials::student_id::preds::{HolderTagChecker, StudentCardExpiryChecker};
use crate::credentials::student_id::student_dump::StudentDump;
use crate::credentials::student_id::student_info::{StudentInfo, StudentInfoVar};

use zkcreds::{
    attrs::Attrs,
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    pred::{prove_birth, prove_pred, verify_birth, PredicateChecker},
    Com,
};

use std::fs::File;
use std::path::Path;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_std::rand::{CryptoRng, Rng};
use criterion::Criterion;

const LOG2_NUM_LEAVES: u32 = 31;
const LOG2_NUM_TREES: u32 = 8;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);

const STUDENT_CARD_TODAY: u32 = 20220101;
const HOLDER_TAG_RAW: u64 = 424242;

// 加载学生卡数据（相对 `CARGO_MANIFEST_DIR`，避免从其它工作目录跑 bench 时路径错或读到空文件）
fn load_dump() -> StudentDump {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/credentials/student_id/student_card.json");
    let file = File::open(&path)
        .unwrap_or_else(|e| panic!("open student_card.json ({}): {e}", path.display()));
    serde_json::from_reader(file).unwrap_or_else(|e| {
        panic!(
            "parse student_card.json ({}): {e}. 若文件为空或损坏，请对照仓库内示例并运行 sign_student_record.ps1",
            path.display()
        )
    })
}

// 随机生成树和森林
fn rand_tree<R: Rng>(rng: &mut R) -> ComTree {
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let idx: u16 = rng.gen();
    let leaf = Com::<StudentComScheme>::rand(rng);
    tree.insert(idx as u64, &leaf);
    tree
}

fn rand_forest<R: Rng>(rng: &mut R) -> ComForest {
    let trees = (0..NUM_TREES).map(|_| rand_tree(rng)).collect();
    ComForest { trees }
}

// 发行方状态
struct IssuerState {
    com_forest: ComForest,
    next_free_tree: usize,
    next_free_leaf: u64,
}

// 生成颁发凭证的CRS
fn gen_issuance_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // 生成哈希检查器电路的CRS
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        StudentInfo,
        StudentInfoVar,
        StudentComScheme,
        StudentComSchemeG,
        H,
        HG,
    >(rng, StudentRecordHashChecker::default())
    .unwrap();
    (pk.clone(), pk.prepare_verifying_key())
}

// 生成有效期检查器的CRS
fn gen_expiry_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        StudentInfo,
        StudentInfoVar,
        StudentComScheme,
        StudentComSchemeG,
        H,
        HG,
    >(
        rng,
        StudentCardExpiryChecker {
            threshold_expiry: Fr::from(STUDENT_CARD_TODAY),
        },
    )
    .unwrap();
    (pk.clone(), pk.prepare_verifying_key())
}

// 生成持有者标签检查器的CRS
fn gen_holdertag_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        StudentInfo,
        StudentInfoVar,
        StudentComScheme,
        StudentComSchemeG,
        H,
        HG,
    >(
        rng,
        HolderTagChecker {
            holder_tag: Fr::from(HOLDER_TAG_RAW),
        },
    )
    .unwrap();
    (pk.clone(), pk.prepare_verifying_key())
}

// 生成树的CRS
fn gen_tree_crs<R: Rng>(rng: &mut R) -> (TreeProvingKey, TreeVerifyingKey) {
    let pk = zkcreds::com_tree::gen_tree_memb_crs::<
        _,
        Bls12_381,
        StudentInfo,
        StudentComScheme,
        StudentComSchemeG,
        H,
        HG,
    >(rng, MERKLE_CRH_PARAM.clone(), TREE_HEIGHT)
    .unwrap();
    (pk.clone(), pk.prepare_verifying_key())
}

// 生成森林的CRS
fn gen_forest_crs<R: Rng>(rng: &mut R) -> (ForestProvingKey, ForestVerifyingKey) {
    let pk = zkcreds::com_forest::gen_forest_memb_crs::<
        _,
        Bls12_381,
        StudentInfo,
        StudentComScheme,
        StudentComSchemeG,
        H,
        HG,
    >(rng, NUM_TREES)
    .unwrap();
    (pk.clone(), pk.prepare_verifying_key())
}

// 初始化发行方状态
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

// 用户请求颁发凭证
fn user_req_issuance<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    issuance_pk: &PredProvingKey,
) -> (StudentInfo, StudentIssuanceReq) {
    let dump = load_dump();
    let (mut my_info, _) = dump.to_student_info(rng);
    my_info.seed = Fr::from(HOLDER_TAG_RAW);
    let attrs_com = my_info.commit();
    let hash_checker = StudentRecordHashChecker::from_holder(&my_info);

    c.bench_function("Student ID: proving birth", |b| {
        b.iter(|| {
            prove_birth(rng, issuance_pk, hash_checker.clone(), my_info.clone()).unwrap();
        })
    });
    let hash_proof =
        prove_birth(rng, issuance_pk, hash_checker, my_info.clone()).unwrap();

    let req = StudentIssuanceReq {
        attrs_com,
        record_digest: dump.record_digest(),
        sig: dump.sig.clone(),
        hash_proof,
    };

    (my_info, req)
}

// 发行方接收凭证请求并验证
fn issue(
    c: &mut Criterion,
    state: &mut IssuerState,
    birth_vk: &PredVerifyingKey,
    req: &StudentIssuanceReq,
) -> ComTreePath {
    let hash_checker = StudentRecordHashChecker::from_issuance_req(req);
    let sig_pubkey = load_issuer_pubkey();
    c.bench_function("Student ID: verifying birth+sig", |b| {
        b.iter(|| {
            assert!(verify_birth(birth_vk, &req.hash_proof, &hash_checker, &req.attrs_com).unwrap());
            assert!(sig_pubkey.verify(&req.sig, &req.record_digest));
        })
    });
    state.com_forest.trees[state.next_free_tree].insert(state.next_free_leaf, &req.attrs_com)
}

// 获取有效期检查器
fn get_expiry_checker() -> StudentCardExpiryChecker {
    StudentCardExpiryChecker {
        threshold_expiry: Fr::from(STUDENT_CARD_TODAY),
    }
}

// 获取持有者标签检查器
fn get_holdertag_checker() -> HolderTagChecker {
    HolderTagChecker {
        holder_tag: Fr::from(HOLDER_TAG_RAW),
    }
}

// 用户证明树成员资格
fn user_prove_tree_memb<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    auth_path: &ComTreePath,
    tree_pk: &TreeProvingKey,
    cred: Com<StudentComScheme>,
) -> TreeProof {
    c.bench_function("Student ID: proving tree", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap();
        })
    });
    auth_path
        .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap()
}

// 用户证明森林成员资格
fn user_prove_forest_memb<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    roots: &ComForestRoots,
    auth_path: &ComTreePath,
    forest_pk: &ForestProvingKey,
    cred: Com<StudentComScheme>,
) -> ForestProof {
    c.bench_function("Student ID: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(rng, forest_pk, auth_path.root(), cred)
                .unwrap();
        })
    });
    roots
        .prove_membership(rng, forest_pk, auth_path.root(), cred)
        .unwrap()
}

// 用户证明谓词
fn user_prove_pred<R, P>(
    rng: &mut R,
    c: &mut Criterion,
    bench_name: &str,
    pk: &PredProvingKey,
    checker: &P,
    info: &StudentInfo,
    auth_path: &ComTreePath,
) -> PredProof
where
    R: Rng,
    P: Clone
        + PredicateChecker<Fr, StudentInfo, StudentInfoVar, StudentComScheme, StudentComSchemeG>,
{
    c.bench_function(bench_name, |b| {
        b.iter(|| {
            prove_pred(rng, pk, checker.clone(), info.clone(), auth_path).unwrap();
        })
    });
    let proof = prove_pred(rng, pk, checker.clone(), info.clone(), auth_path).unwrap();
    assert!(zkcreds::pred::verify_pred(
        &pk.prepare_verifying_key(),
        &proof,
        checker,
        &info.commit(),
        &auth_path.root(),
    )
    .unwrap());
    proof
}

// 用户链接凭证
fn user_link<R: Rng + CryptoRng>(
    rng: &mut R,
    c: &mut Criterion,
    proof_bench_name: &str,
    verif_bench_name: &str,
    tree_vk: &TreeVerifyingKey,
    forest_vk: &ForestVerifyingKey,
    roots: &ComForestRoots,
    pred_inputs: PredPublicInputs<Bls12_381>,
    pred_vks: Vec<PredVerifyingKey>,
    cred: Com<StudentComScheme>,
    auth_path: &ComTreePath,
    tree_proof: &TreeProof,
    forest_proof: &ForestProof,
    pred_proofs: Vec<PredProof>,
) {
    let link_vk = LinkVerifyingKey {
        pred_inputs,
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk.clone(),
        tree_verif_key: tree_vk.clone(),
        pred_verif_keys: pred_vks,
    };
    let link_ctx = LinkProofCtx {
        attrs_com: cred,
        merkle_root: auth_path.root(),
        forest_proof: forest_proof.clone(),
        tree_proof: tree_proof.clone(),
        pred_proofs,
        vk: link_vk.clone(),
    };

    c.bench_function(proof_bench_name, |b| b.iter(|| link_proofs(rng, &link_ctx)));
    let link_proof = link_proofs(rng, &link_ctx);
    crate::util::record_size(proof_bench_name, &link_proof);

    c.bench_function(verif_bench_name, |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
    });
}

// 学生证验证基准测试
pub fn bench_student_id(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    let (issuance_pk, issuance_vk) = gen_issuance_crs(&mut rng);
    let (expiry_pk, expiry_vk) = gen_expiry_crs(&mut rng);
    let (holdertag_pk, holdertag_vk) = gen_holdertag_crs(&mut rng);
    let (tree_pk, tree_vk) = gen_tree_crs(&mut rng);
    let (forest_pk, forest_vk) = gen_forest_crs(&mut rng);

    let mut issuer_state = init_issuer(&mut rng);

    let (student_info, issuance_req) = user_req_issuance(&mut rng, c, &issuance_pk);
    let cred = student_info.commit();

    let auth_path = issue(c, &mut issuer_state, &issuance_vk, &issuance_req);

    let expiry_proof = user_prove_pred(
        &mut rng,
        c,
        "Student ID: proving card expiry",
        &expiry_pk,
        &get_expiry_checker(),
        &student_info,
        &auth_path,
    );
    let holdertag_proof = user_prove_pred(
        &mut rng,
        c,
        "Student ID: proving holder tag",
        &holdertag_pk,
        &get_holdertag_checker(),
        &student_info,
        &auth_path,
    );

    let roots = issuer_state.com_forest.roots();
    let tree_proof = user_prove_tree_memb(&mut rng, c, &auth_path, &tree_pk, cred);
    let forest_proof = user_prove_forest_memb(&mut rng, c, &roots, &auth_path, &forest_pk, cred);

    let pred_inputs = PredPublicInputs::default();
    user_link(
        &mut rng,
        c,
        "Student ID: proving empty linkage",
        "Student ID: verifying empty linkage",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![],
    );

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&expiry_vk, &get_expiry_checker());
    pred_inputs.prepare_pred_checker(&holdertag_vk, &get_holdertag_checker());
    user_link(
        &mut rng,
        c,
        "Student ID: proving expiry linkage",
        "Student ID: verifying expiry linkage",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![expiry_vk, holdertag_vk],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![expiry_proof, holdertag_proof],
    );
}
