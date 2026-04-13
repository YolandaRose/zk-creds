mod issuance_checker;
pub(crate) mod params;
mod preds;
pub(crate) mod student_dump;
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
use std::time::Instant;

use crate::credentials::student_id::preds::{HolderTagChecker, StudentCardExpiryChecker};
use crate::credentials::student_id::student_dump::StudentDump;
use crate::credentials::student_id::student_info::{StudentInfo, StudentInfoVar};

use zkcreds::{
    attrs::Attrs,
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    poseidon_utils::setup_poseidon_params,
    pseudonymous_show::PseudonymousAttrs,
    pred::{prove_birth, prove_pred, verify_birth, PredicateChecker},
    Com,
};

use std::path::Path;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::{rand::{CryptoRng, Rng}, Zero};
use arkworks_utils::Curve;
use criterion::Criterion;

const LOG2_NUM_LEAVES: u32 = 31;
const LOG2_NUM_TREES: u32 = 8;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);

const POSEIDON_WIDTH: u8 = 5;

/// 基准日（YYYYMMDD，须为 8 位整数）。`card_expiry` 必须 **严格大于** 本值（同一整数比较），
/// 否则 7 位等错误写法会在数值上小于 8 位日期（例如 `2026631` < `20220101`），谓词无法通过。
const STUDENT_CARD_TODAY: u32 = 20220101;

/// 用于演示日志的凭证承诺短标识（域元素字节前缀）
fn cred_short_token(cred: &Com<StudentComScheme>) -> String {
    cred.into_repr()
        .to_bytes_le()
        .iter()
        .take(12)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

// 加载学生卡数据（相对 `CARGO_MANIFEST_DIR`，避免从其它工作目录跑 bench 时路径错或读到空文件）
fn load_dump() -> StudentDump {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/credentials/student_id/student_card.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read student_card.json ({}): {e}", path.display()));
    // PowerShell `Set-Content -Encoding UTF8` 常写入 UTF-8 BOM；serde_json 在首字节会解析失败
    let json = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        &bytes[..]
    };
    serde_json::from_slice(json).unwrap_or_else(|e| {
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
        HolderTagChecker { holder_tag: Fr::zero() },
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
) -> (StudentInfo, StudentIssuanceReq, Fr) {
    let dump = load_dump();
    let (mut my_info, _) = dump.to_student_info(rng);
    let holder_tag = compute_holder_tag(&my_info);
    let attrs_com = my_info.commit();
    let hash_checker = StudentRecordHashChecker::from_holder(&my_info);

    c.bench_function("Student ID: proving birth", |b| {
        b.iter(|| {
            prove_birth(rng, issuance_pk, hash_checker.clone(), my_info.clone()).unwrap();
        })
    });
    let start = Instant::now();
    let hash_proof =
        prove_birth(rng, issuance_pk, hash_checker, my_info.clone()).unwrap();
    let elapsed = start.elapsed();

    println!(
        "[用户] 已生成「记录 blob ↔ 属性承诺」一致性证明（Groth16 birth proof），准备提交学生证签发请求。耗时 {} ms",
        elapsed.as_millis()
    );

    let req = StudentIssuanceReq {
        attrs_com,
        record_digest: dump.record_digest(),
        sig: dump.sig.clone(),
        hash_proof,
    };

    (my_info, req, holder_tag)
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

    let start = Instant::now();
    assert!(
        verify_birth(birth_vk, &req.hash_proof, &hash_checker, &req.attrs_com).unwrap(),
        "发行方：出生证明验证失败"
    );
    assert!(
        sig_pubkey.verify(&req.sig, &req.record_digest),
        "发行方：RSA 签名与 record_digest 不一致"
    );
    let elapsed = start.elapsed();
    println!(
        "[发行方] 验证签发请求完成。耗时 {} ms",
        elapsed.as_millis()
    );

    let tree_idx = state.next_free_tree;
    let leaf_idx = state.next_free_leaf;
    let token = cred_short_token(&req.attrs_com);

    println!(
        "[发行方] 身份与材料验证通过：JSON 学生卡记录 SHA256 与链下 RSA 签名一致；链上出生证明（Groth16）验证通过。"
    );
    println!(
        "[发行方] 已颁发凭证。承诺摘要前缀: {}… ｜ 请妥善保管凭证秘密与随机数（nonce/seed）。",
        token
    );

    let path = state.com_forest.trees[tree_idx].insert(leaf_idx, &req.attrs_com);
    println!(
        "[发行方] 承诺已登记至 Merkle 森林：树索引 = {}，叶索引 = {}。",
        tree_idx, leaf_idx
    );

    path
}

// 获取有效期检查器
fn get_expiry_checker() -> StudentCardExpiryChecker {
    StudentCardExpiryChecker {
        threshold_expiry: Fr::from(STUDENT_CARD_TODAY),
    }
}

fn compute_holder_tag<A>(attrs: &A) -> Fr
where
    A: PseudonymousAttrs<Fr, StudentComScheme>,
{
    let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
    attrs.compute_presentation_token(params).unwrap().pseudonym
}

// 获取持有者标签检查器
fn get_holdertag_checker(holder_tag: Fr) -> HolderTagChecker {
    HolderTagChecker { holder_tag }
}

// 用户证明树成员资格
fn user_prove_tree_memb<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    auth_path: &ComTreePath,
    tree_pk: &TreeProvingKey,
    cred: Com<StudentComScheme>,
    user_log: &str,
) -> TreeProof {
    c.bench_function("Student ID: proving tree", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap();
        })
    });
    let start = Instant::now();
    let proof = auth_path
        .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap();
    let elapsed = start.elapsed();
    println!("[用户] {} 耗时 {} ms", user_log, elapsed.as_millis());
    proof
}

// 用户证明森林成员资格
fn user_prove_forest_memb<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    roots: &ComForestRoots,
    auth_path: &ComTreePath,
    forest_pk: &ForestProvingKey,
    cred: Com<StudentComScheme>,
    user_log: &str,
) -> ForestProof {
    c.bench_function("Student ID: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(rng, forest_pk, auth_path.root(), cred)
                .unwrap();
        })
    });
    let start = Instant::now();
    let proof = roots
        .prove_membership(rng, forest_pk, auth_path.root(), cred)
        .unwrap();
    let elapsed = start.elapsed();
    println!("[用户] {} 耗时 {} ms", user_log, elapsed.as_millis());
    proof
}

// 用户证明谓词
fn user_prove_pred<R, P>(
    rng: &mut R,
    c: &mut Criterion,
    bench_name: &str,
    user_log: &str,
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
    let start = Instant::now();
    let proof = prove_pred(rng, pk, checker.clone(), info.clone(), auth_path).unwrap();
    assert!(zkcreds::pred::verify_pred(
        &pk.prepare_verifying_key(),
        &proof,
        checker,
        &info.commit(),
        &auth_path.root(),
    )
    .unwrap());
    let elapsed = start.elapsed();

    println!("[用户] {} 耗时 {} ms", user_log, elapsed.as_millis());

    proof
}

// 用户链接凭证
fn user_link<R: Rng + CryptoRng>(
    rng: &mut R,
    c: &mut Criterion,
    proof_bench_name: &str,
    verif_bench_name: &str,
    stage_title: &str,
    stage_detail: &str,
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
    let num_predicates = pred_vks.len();
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
    let start = Instant::now();
    let link_proof = link_proofs(rng, &link_ctx);
    let elapsed = start.elapsed();
    crate::util::record_size(proof_bench_name, &link_proof);
    println!("[用户] {} 单次生成耗时 {} ms", proof_bench_name, elapsed.as_millis());

    c.bench_function(verif_bench_name, |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
    });

    let start = Instant::now();
    assert!(
        verif_link_proof(&link_proof, &link_vk).unwrap(),
        "验证方：链接证明验证失败"
    );
    let elapsed = start.elapsed();
    println!("[验证方] {} 单次验证耗时 {} ms", verif_bench_name, elapsed.as_millis());
    println!("\n──────── {} ────────", stage_title);
    println!(
        "[验证方] Merkle 树成员、森林成员、凭证承诺与公开输入一致性：通过（链接证明 Groth16-Sahai 验证通过）。"
    );
    if num_predicates == 0 {
        println!("[验证方] 本阶段未挂载数值谓词，仅完成成员资格链接。");
    } else {
        println!(
            "[验证方] 本阶段已链接谓词证明 {} 份，凭证有效性（谓词与承诺绑定）：通过。",
            num_predicates
        );
    }
    println!("[验证方] {}", stage_detail);
}

// 学生证验证基准测试
pub fn bench_student_id(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    println!("\n======== 学生证凭证全流程基准（含控制台演示日志）========\n");

    let (issuance_pk, issuance_vk) = gen_issuance_crs(&mut rng);
    let (expiry_pk, expiry_vk) = gen_expiry_crs(&mut rng);
    let (holdertag_pk, holdertag_vk) = gen_holdertag_crs(&mut rng);
    let (tree_pk, tree_vk) = gen_tree_crs(&mut rng);
    let (forest_pk, forest_vk) = gen_forest_crs(&mut rng);

    let mut issuer_state = init_issuer(&mut rng);

    let (student_info, issuance_req, holder_tag) = user_req_issuance(&mut rng, c, &issuance_pk);
    let cred = student_info.commit();

    let auth_path = issue(c, &mut issuer_state, &issuance_vk, &issuance_req);

    let expiry_proof = user_prove_pred(
        &mut rng,
        c,
        "Student ID: proving card expiry",
        "学生证有效期（未过期）通过；承诺与 Merkle 根一致（谓词 Groth16 本地自检通过）。",
        &expiry_pk,
        &get_expiry_checker(),
        &student_info,
        &auth_path,
    );
    let holdertag_proof = user_prove_pred(
        &mut rng,
        c,
        "Student ID: proving holder tag",
        "持有者标签与公开值一致；承诺与 Merkle 根一致（谓词 Groth16 本地自检通过）。",
        &holdertag_pk,
        &get_holdertag_checker(holder_tag),
        &student_info,
        &auth_path,
    );

    let roots = issuer_state.com_forest.roots();
    let tree_proof = user_prove_tree_memb(
        &mut rng,
        c,
        &auth_path,
        &tree_pk,
        cred,
        "已生成 Merkle 树成员证明（Groth16），凭证承诺与路径一致。",
    );
    let forest_proof = user_prove_forest_memb(
        &mut rng,
        c,
        &roots,
        &auth_path,
        &forest_pk,
        cred,
        "已生成森林成员证明（Groth16），成员树根属于公告森林根列表。",
    );

    let pred_inputs = PredPublicInputs::default();
    user_link(
        &mut rng,
        c,
        "Student ID: proving empty linkage",
        "Student ID: verifying empty linkage",
        "阶段：仅成员资格链接",
        "本阶段无附加谓词；验证方校验树/森林成员与链接一致性。",
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
    pred_inputs.prepare_pred_checker(&holdertag_vk, &get_holdertag_checker(holder_tag));
    user_link(
        &mut rng,
        c,
        "Student ID: proving expiry linkage",
        "Student ID: verifying expiry linkage",
        "阶段：有效期+持有者标签链接",
        "谓词含学生证未过期与持有者标签；与树/森林成员证明一并链接。",
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
