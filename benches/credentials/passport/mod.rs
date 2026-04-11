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

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
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

fn load_dump() -> PassportDump {
    let file = File::open("benches/credentials/passport/passport_dump.json").unwrap();
    serde_json::from_reader(file).unwrap()
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

    // 插入
    state.com_forest.trees[state.next_free_tree].insert(state.next_free_leaf, &req.attrs_com)
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
) -> TreeProof {
    c.bench_function("Passport: proving tree", |b| {
        b.iter(|| {
            auth_path
                .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
                .unwrap()
        })
    });
    auth_path
        .prove_membership(rng, tree_pk, &*MERKLE_CRH_PARAM, cred)
        .unwrap()
}

//用户证明森林成员
fn user_prove_forest_memb<R: Rng>(
    rng: &mut R,
    c: &mut Criterion,
    roots: &ComForestRoots,
    auth_path: &ComTreePath,
    forest_pk: &ForestProvingKey,
    cred: Com<PassportComScheme>,
) -> ForestProof {
    c.bench_function("Passport: proving forest", |b| {
        b.iter(|| {
            roots
                .prove_membership(rng, forest_pk, auth_path.root(), cred)
                .unwrap()
        })
    });
    roots
        .prove_membership(rng, forest_pk, auth_path.root(), cred)
        .unwrap()
}

// 用户构造年龄和面部的谓词证明
fn user_prove_pred<R, P>(
    rng: &mut R,
    c: &mut Criterion,
    bench_name: &str,
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

    proof
}

//用户链接凭证
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
    cred: Com<PassportComScheme>,
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

    println!("The bouncer unlatches the velvet rope. The user walks through.");
}

//护照验证基准测试
pub fn bench_passport(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

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
        &agefaceexpiry_pk,
        &get_agefaceexpiry_checker(&personal_info),
        &personal_info,
        &auth_path,
    );
    let agemultishowexpiry_proof = user_prove_pred(//用户证明年龄、多重展示和到期日
        &mut rng,
        c,
        "Passport: proving age+multishow+expiry",
        &agemultishowexpiry_pk,
        &get_agemultishowexpiry_checker(&personal_info),
        &personal_info,
        &auth_path,
    );
    let ageexpiry_proof = user_prove_pred(//用户证明年龄和到期日
        &mut rng,
        c,
        "Passport: proving age+expiry",
        &ageexpiry_pk,
        &get_ageexpiry_checker(),
        &personal_info,
        &auth_path,
    );
    let expiry_proof = user_prove_pred(//用户证明到期日
        &mut rng,
        c,
        "Passport: proving expiry",
        &expiry_pk,
        &get_expiry_checker(),
        &personal_info,
        &auth_path,
    );
    let multishow_proof = user_prove_pred(//用户证明多重展示
        &mut rng,
        c,
        "Passport: proving multishow",
        &multishow_pk,
        &get_multishow_checker(&personal_info),
        &personal_info,
        &auth_path,
    );
    let holdertag_proof = user_prove_pred(
        &mut rng,
        c,
        "Passport: proving holder tag",
        &holdertag_pk,
        &get_holdertag_checker(),
        &personal_info,
        &auth_path,
    );

    // 用户从发行方获取所有根
    let roots = issuer_state.com_forest.roots();
    // 成员证明：用户证明树和森林成员

    let tree_proof = user_prove_tree_memb(&mut rng, c, &auth_path, &tree_pk, cred);
    let forest_proof = user_prove_forest_memb(&mut rng, c, &roots, &auth_path, &forest_pk, cred);

    let pred_inputs = PredPublicInputs::default();
    user_link(
        &mut rng,
        c,
        "Passport: Proving empty linkage",
        "Passport: Verifying empty linkage",
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
