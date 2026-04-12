pub mod ark_sha256;
mod issuance_checker;
mod params;
mod passport_dump;
mod passport_info;
mod preds;

use crate::credentials::common::sig_verif::load_issuer_pubkey;
use crate::credentials::passport::{
    issuance_checker::{IssuanceReq, PassportRecordHashChecker},
    params::{
        ComForest, ComForestRoots, ComTree, ComTreePath, ForestProof, ForestProvingKey,
        ForestVerifyingKey, PassportComScheme, PassportComSchemeG, PredProof, PredProvingKey,
        PredVerifyingKey, TreeProof, TreeProvingKey, TreeVerifyingKey, H, HG, MERKLE_CRH_PARAM,
    },
    passport_dump::PassportDump,
    passport_info::{PersonalInfo, PersonalInfoVar},
    preds::{
        AgeAndExpiryChecker, AgeChecker, AgeFaceExpiryChecker, AgeMultishowExpiryChecker,
        ExpiryChecker, FaceChecker,
        HolderTagChecker,
    },
};

use zkcreds::{
    attrs::Attrs,
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    poseidon_utils::setup_poseidon_params,
    pred::{prove_birth, prove_pred, verify_birth, PredicateChecker},
    revealing_multishow::{MultishowableAttrs, RevealingMultishowChecker},
    Com,
};

use std::fs::File;
use std::path::Path;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::rand::{CryptoRng, Rng};
use arkworks_utils::Curve;
use criterion::Criterion;

const LOG2_NUM_LEAVES: u32 = 31;
const LOG2_NUM_TREES: u32 = 8;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);

const POSEIDON_WIDTH: u8 = 5;

// 护照验证的示例参数（展示谓词）：到期日、年龄等
const TODAY: u32 = 20220101u32;
const TWENTY_ONE_YEARS_AGO: u32 = TODAY - 210000;
const HOLDER_TAG_RAW: u64 = 424242;

/// 用于演示日志的凭证承诺短标识（域元素字节前缀）
fn cred_short_token(cred: &Com<PassportComScheme>) -> String {
    cred.into_repr()
        .to_bytes_le()
        .iter()
        .take(12)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn load_dump() -> PassportDump {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/credentials/passport/passport_dump.json");
    let file = File::open(&path)
        .unwrap_or_else(|e| panic!("open passport_dump.json ({}): {e}", path.display()));
    serde_json::from_reader(file).unwrap_or_else(|e| {
        panic!(
            "parse passport_dump.json ({}): {e}. 若文件为空或损坏，请运行 sign_passport_record.ps1",
            path.display()
        )
    })
}

//初始化树参数
fn rand_tree<R: Rng>(rng: &mut R) -> ComTree {
    let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
    let idx: u16 = rng.gen();
    let leaf = Com::<PassportComScheme>::rand(rng);
    tree.insert(idx as u64, &leaf);
    tree
}

//初始化森林
fn rand_forest<R: Rng>(rng: &mut R) -> ComForest {
    let trees = (0..NUM_TREES).map(|_| rand_tree(rng)).collect();
    ComForest { trees }
}

//发行方状态
struct IssuerState {
    // 承诺的森林
    com_forest: ComForest,
    // 下一个空闲树来插入承诺
    next_free_tree: usize,
    // 下一个空闲叶子来插入承诺
    next_free_leaf: u64,
}

//生成颁发凭证的CRS
fn gen_issuance_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // 生成哈希检查器电路的CRS
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, PassportRecordHashChecker::default())
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

//生成年龄、面部和到期日的CRS
fn gen_agefaceexpiry_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // 生成哈希检查器电路的CRS
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, AgeFaceExpiryChecker::default())
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

//生成到期日的CRS
fn gen_expiry_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // 生成哈希检查器电路的CRS
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, ExpiryChecker::default())
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

//生成年龄和到期日的CRS
fn gen_ageexpiry_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // 生成哈希检查器电路的CRS
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, AgeAndExpiryChecker::default())
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

//生成多重展示的CRS
fn gen_multishow_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    let checker = get_multishow_checker(&PersonalInfo::default());

    // 生成哈希检查器电路的CRS
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, checker)
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

//生成年龄、多重展示和到期日的CRS
fn gen_agemultishowexpiry_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    // 生成哈希检查器电路的CRS
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(
        rng,
        get_agemultishowexpiry_checker(&PersonalInfo::default()),
    )
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

//生成持有者标签检查器的CRS
fn gen_holdertag_crs<R: Rng>(rng: &mut R) -> (PredProvingKey, PredVerifyingKey) {
    let pk = zkcreds::pred::gen_pred_crs::<
        _,
        _,
        Bls12_381,
        PersonalInfo,
        PersonalInfoVar,
        PassportComScheme,
        PassportComSchemeG,
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

//生成树的CRS
fn gen_tree_crs<R: Rng>(rng: &mut R) -> (TreeProvingKey, TreeVerifyingKey) {
    // 生成谓词电路的CRS
    let pk = zkcreds::com_tree::gen_tree_memb_crs::<
        _,
        Bls12_381,
        PersonalInfo,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, MERKLE_CRH_PARAM.clone(), TREE_HEIGHT)
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

//生成森林的CRS
fn gen_forest_crs<R: Rng>(rng: &mut R) -> (ForestProvingKey, ForestVerifyingKey) {
    // 生成谓词电路的CRS
    let pk = zkcreds::com_forest::gen_forest_memb_crs::<
        _,
        Bls12_381,
        PersonalInfo,
        PassportComScheme,
        PassportComSchemeG,
        H,
        HG,
    >(rng, NUM_TREES)
    .unwrap();

    (pk.clone(), pk.prepare_verifying_key())
}

// 生成一个新的发行方状态
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

// 用户使用他们的护照构造一个`PersonalInfo`结构并请求颁发凭证
fn user_req_issuance<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    issuance_pk: &PredProvingKey,
) -> (PersonalInfo, IssuanceReq) {
    let dump = load_dump();
    let (mut my_info, _) = dump.to_personal_info(rng);
    my_info.seed = Fr::from(HOLDER_TAG_RAW);
    let attrs_com = my_info.commit();

    let hash_checker = PassportRecordHashChecker::from_holder(&my_info);

    // 证明记录 blob 与属性承诺一致
    c.bench_function("Passport: proving birth", |b| {
        b.iter(|| prove_birth(rng, issuance_pk, hash_checker.clone(), my_info.clone()).unwrap())
    });
    let hash_proof = prove_birth(rng, issuance_pk, hash_checker, my_info.clone()).unwrap();

    println!(
        "[用户] 已生成「记录 blob ↔ 属性承诺」一致性证明（Groth16 birth proof），准备提交签发请求。"
    );

    // 构建颁发请求
    let req = IssuanceReq {
        attrs_com,
        record_digest: dump.record_digest(),
        sig: dump.sig.clone(),
        hash_proof,
    };

    (my_info, req)
}

// 发行方接收颁发请求并验证
fn issue(
    c: &mut Criterion,
    state: &mut IssuerState,
    birth_vk: &PredVerifyingKey,
    req: &IssuanceReq,
) -> ComTreePath {
    // 检查哈希是否正确计算且哈希的签名正确
    let hash_checker = PassportRecordHashChecker::from_issuance_req(req);
    let sig_pubkey = load_issuer_pubkey();
    c.bench_function("Passport: verifying birth+sig", |b| {
        b.iter(|| {
            assert!(
                verify_birth(birth_vk, &req.hash_proof, &hash_checker, &req.attrs_com).unwrap()
            );
            assert!(sig_pubkey.verify(&req.sig, &req.record_digest));
        })
    });

    assert!(
        verify_birth(birth_vk, &req.hash_proof, &hash_checker, &req.attrs_com).unwrap(),
        "发行方：出生证明验证失败"
    );
    assert!(
        sig_pubkey.verify(&req.sig, &req.record_digest),
        "发行方：RSA 签名与 record_digest 不一致"
    );

    let tree_idx = state.next_free_tree;
    let leaf_idx = state.next_free_leaf;
    let token = cred_short_token(&req.attrs_com);

    println!("[发行方] 身份与材料验证通过：JSON 记录 SHA256 与链下 RSA 签名一致；链上出生证明（Groth16）验证通过。");
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

//获取年龄检查器
fn get_age_checker() -> AgeChecker {
    AgeChecker {
        threshold_dob: Fr::from(TWENTY_ONE_YEARS_AGO),
    }
}

//获取到期日检查器
fn get_expiry_checker() -> ExpiryChecker {
    ExpiryChecker {
        threshold_expiry: Fr::from(TODAY),
    }
}

//获取面部检查器
fn get_face_checker(info: &PersonalInfo) -> FaceChecker {
    FaceChecker {
        face_hash: info.biometrics_hash(),
    }
}

//获取多重展示检查器
fn get_multishow_checker(info: &PersonalInfo) -> RevealingMultishowChecker<Fr> {
    let poseidon_params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
    let max_num_presentations: u16 = 128;
    let nonce = Fr::from(1337u32);
    let epoch = 5;
    let ctr: u16 = 1;
    let token = info
        .compute_presentation_token(poseidon_params.clone(), epoch, ctr, nonce)
        .unwrap();

    RevealingMultishowChecker {
        token,
        epoch,
        nonce,
        max_num_presentations,
        ctr,
        params: poseidon_params,
    }
}

//获取年龄、面部和到期日的检查器
fn get_agefaceexpiry_checker(info: &PersonalInfo) -> AgeFaceExpiryChecker {
    AgeFaceExpiryChecker {
        age_checker: get_age_checker(),
        face_checker: get_face_checker(info),
        expiry_checker: get_expiry_checker(),
    }
}

//获取年龄和到期日的检查器
fn get_ageexpiry_checker() -> AgeAndExpiryChecker {
    AgeAndExpiryChecker {
        age_checker: get_age_checker(),
        expiry_checker: get_expiry_checker(),
    }
}

//获取年龄、多重展示和到期日的检查器
fn get_agemultishowexpiry_checker(info: &PersonalInfo) -> AgeMultishowExpiryChecker {
    AgeMultishowExpiryChecker {
        age_checker: get_age_checker(),
        multishow_checker: get_multishow_checker(info),
        expiry_checker: get_expiry_checker(),
    }
}

//获取持有者标签检查器
fn get_holdertag_checker() -> HolderTagChecker {
    HolderTagChecker {
        holder_tag: Fr::from(HOLDER_TAG_RAW),
    }
}

//用户证明树成员
fn user_prove_tree_memb<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    auth_path: &ComTreePath,
    tree_pk: &TreeProvingKey,
    cred: Com<PassportComScheme>,
    user_log: &str,
) -> TreeProof {
    c.bench_function("Passport: proving tree", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap()
        })
    });
    let proof = auth_path
        .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap();
    println!("[用户] {}", user_log);
    proof
}

//用户证明森林成员
fn user_prove_forest_memb<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    roots: &ComForestRoots,
    auth_path: &ComTreePath,
    forest_pk: &ForestProvingKey,
    cred: Com<PassportComScheme>,
    user_log: &str,
) -> ForestProof {
    c.bench_function("Passport: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(rng, forest_pk, auth_path.root(), cred)
                .unwrap()
        })
    });
    let proof = roots
        .prove_membership(rng, forest_pk, auth_path.root(), cred)
        .unwrap();
    println!("[用户] {}", user_log);
    proof
}

// 用户构造年龄和面部的谓词证明
fn user_prove_pred<R, P>(
    rng: &mut R,
    c: &mut Criterion,
    bench_name: &str,
    user_log: &str,
    pk: &PredProvingKey,
    checker: &P,
    info: &PersonalInfo,
    auth_path: &ComTreePath,
) -> PredProof
where
    R: Rng,
    P: Clone
        + PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>,
{
    // 计算公参数的证明
    c.bench_function(bench_name, |b| {
        b.iter(|| {
            prove_pred(rng, pk, checker.clone(), info.clone(), auth_path).unwrap();
        })
    });
    let proof = prove_pred(rng, pk, checker.clone(), info.clone(), auth_path).unwrap();

    // 断言证明验证
    assert!(zkcreds::pred::verify_pred(
        &pk.prepare_verifying_key(),
        &proof,
        checker,
        &info.commit(),
        &auth_path.root(),
    )
    .unwrap());

    println!("[用户] {}", user_log);

    proof
}

//用户链接凭证
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
    cred: Com<PassportComScheme>,
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
    let link_proof = link_proofs(rng, &link_ctx);
    crate::util::record_size(proof_bench_name, &link_proof);

    c.bench_function(verif_bench_name, |b| {
        b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
    });

    assert!(
        verif_link_proof(&link_proof, &link_vk).unwrap(),
        "验证方：链接证明验证失败"
    );
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

//护照验证基准测试
pub fn bench_passport(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    println!("\n======== 护照凭证全流程基准（含控制台演示日志）========\n");

    // 生成所有Groth16和Groth-Sahai的证明和验证密钥
    let (issuance_pk, issuance_vk) = gen_issuance_crs(&mut rng);
    let (agefaceexpiry_pk, agefaceexpiry_vk) = gen_agefaceexpiry_crs(&mut rng);
    let (agemultishowexpiry_pk, agemultishowexpiry_vk) = gen_agemultishowexpiry_crs(&mut rng);
    let (ageexpiry_pk, ageexpiry_vk) = gen_ageexpiry_crs(&mut rng);
    let (multishow_pk, multishow_vk) = gen_multishow_crs(&mut rng);
    let (expiry_pk, expiry_vk) = gen_expiry_crs(&mut rng);
    let (holdertag_pk, holdertag_vk) = gen_holdertag_crs(&mut rng);
    let (tree_pk, tree_vk) = gen_tree_crs(&mut rng);
    let (forest_pk, forest_vk) = gen_forest_crs(&mut rng);

    // 生成发行方初始状态
    let mut issuer_state = init_issuer(&mut rng);

    // 用户dump护照并发出凭证请求
    let (personal_info, issuance_req) = user_req_issuance(&mut rng, c, &issuance_pk);
    let cred = personal_info.commit();

    // 发行方验证护照并颁发凭证
    let auth_path = issue(c, &mut issuer_state, &issuance_vk, &issuance_req);

    let agefaceexpiry_proof = user_prove_pred(//用户证明年龄、面部和到期日
        &mut rng,
        c,
        "Passport: proving age+face+expiry",
        "年龄阈值属性通过；人脸/生物特征绑定通过；护照有效期（未过期）通过；承诺与 Merkle 根一致（谓词 Groth16 本地自检通过）。",
        &agefaceexpiry_pk,
        &get_agefaceexpiry_checker(&personal_info),
        &personal_info,
        &auth_path,
    );
    let agemultishowexpiry_proof = user_prove_pred(//用户证明年龄、多重展示和到期日
        &mut rng,
        c,
        "Passport: proving age+multishow+expiry",
        "年龄阈值属性通过；受控多次展示令牌通过；护照有效期（未过期）通过；承诺与 Merkle 根一致（谓词 Groth16 本地自检通过）。",
        &agemultishowexpiry_pk,
        &get_agemultishowexpiry_checker(&personal_info),
        &personal_info,
        &auth_path,
    );
    let ageexpiry_proof = user_prove_pred(//用户证明年龄和到期日
        &mut rng,
        c,
        "Passport: proving age+expiry",
        "年龄阈值属性通过；护照有效期（未过期）通过；承诺与 Merkle 根一致（谓词 Groth16 本地自检通过）。",
        &ageexpiry_pk,
        &get_ageexpiry_checker(),
        &personal_info,
        &auth_path,
    );
    let expiry_proof = user_prove_pred(//用户证明到期日
        &mut rng,
        c,
        "Passport: proving expiry",
        "护照有效期（未过期）通过；承诺与 Merkle 根一致（谓词 Groth16 本地自检通过）。",
        &expiry_pk,
        &get_expiry_checker(),
        &personal_info,
        &auth_path,
    );
    let multishow_proof = user_prove_pred(//用户证明多重展示
        &mut rng,
        c,
        "Passport: proving multishow",
        "受控多次展示令牌通过；承诺与 Merkle 根一致（谓词 Groth16 本地自检通过）。",
        &multishow_pk,
        &get_multishow_checker(&personal_info),
        &personal_info,
        &auth_path,
    );
    let holdertag_proof = user_prove_pred(
        &mut rng,
        c,
        "Passport: proving holder tag",
        "持有者标签与公开值一致；承诺与 Merkle 根一致（谓词 Groth16 本地自检通过）。",
        &holdertag_pk,
        &get_holdertag_checker(),
        &personal_info,
        &auth_path,
    );

    // 用户从发行方获取所有根
    let roots = issuer_state.com_forest.roots();
    // 成员证明：用户证明树和森林成员

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
        "Passport: Proving empty linkage",
        "Passport: Verifying empty linkage",
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
    pred_inputs.prepare_pred_checker(
        &agefaceexpiry_vk,
        &get_agefaceexpiry_checker(&personal_info),
    );
    user_link(
        &mut rng,
        c,
        "Passport: Proving agefaceexpiry linkage",
        "Passport: Verifying agefaceexpiry linkage",
        "阶段：年龄+人脸+到期链接",
        "谓词含年龄阈值、面部哈希绑定、护照未过期；与成员资格证明一并链接。",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![agefaceexpiry_vk],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![agefaceexpiry_proof],
    );

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(
        &agemultishowexpiry_vk,
        &get_agemultishowexpiry_checker(&personal_info),
    );
    user_link(
        &mut rng,
        c,
        "Passport: Proving agemultishowexpiry linkage",
        "Passport: Verifying agemultishowexpiry linkage",
        "阶段：年龄+多次展示+到期链接",
        "谓词含年龄、受控多次展示、护照未过期；与成员资格证明一并链接。",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![agemultishowexpiry_vk],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![agemultishowexpiry_proof],
    );

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&expiry_vk, &get_expiry_checker());
    user_link(
        &mut rng,
        c,
        "Passport: Proving expiry linkage",
        "Passport: Verifying expiry linkage",
        "阶段：到期日链接",
        "谓词仅校验护照未过期；与成员资格证明一并链接。",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![expiry_vk],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![expiry_proof],
    );

    let mut pred_inputs = PredPublicInputs::default();
    pred_inputs.prepare_pred_checker(&ageexpiry_vk, &get_ageexpiry_checker());
    pred_inputs.prepare_pred_checker(&multishow_vk, &get_multishow_checker(&personal_info));
    pred_inputs.prepare_pred_checker(&holdertag_vk, &get_holdertag_checker());
    user_link(
        &mut rng,
        c,
        "Passport: Proving ageexpiry+multishow linkage",
        "Passport: Verifying ageexpiry+multishow linkage",
        "阶段：年龄+到期+多次展示+持有者标签链接",
        "多份谓词证明与树/森林成员证明在同一承诺与 Merkle 根下链接验证。",
        &tree_vk,
        &forest_vk,
        &roots,
        pred_inputs,
        vec![ageexpiry_vk, multishow_vk, holdertag_vk],
        cred,
        &auth_path,
        &tree_proof,
        &forest_proof,
        vec![ageexpiry_proof, multishow_proof, holdertag_proof],
    );
}
