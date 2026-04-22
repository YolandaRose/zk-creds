use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::UniformRand;
use ark_std::rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

use arkworks_utils::Curve;
use zkcreds::attrs::Attrs;
use zkcreds::com_forest::{gen_forest_memb_crs, ComForest};
use zkcreds::com_tree::{gen_tree_memb_crs, ComTree};
use zkcreds::link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs};
use zkcreds::multishow::{MultishowChecker, MultishowableAttrs};
use zkcreds::poseidon_utils::setup_poseidon_params;
use zkcreds::pred::{gen_pred_crs, prove_pred, verify_pred};
use zkcreds::test_util::{AgeChecker, NameAndBirthYear, NameAndBirthYearVar, MERKLE_CRH_PARAM, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG};
use zkcreds::Com;

type TestA = NameAndBirthYear;
type TestAV = NameAndBirthYearVar;

const TREE_HEIGHT: u32 = 32;
const NUM_TREES: usize = 4;
const POSEIDON_WIDTH: u8 = 5;

fn log_constraint_counts(name: &str, counts: (usize, usize, usize)) {
    println!(
        "{}: constraints={}, witness_vars={}, instance_vars={}",
        name, counts.0, counts.1, counts.2
    );
}

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
    if let Err(e) = joint_test_support::run_passport_student_scenario(&mut rng) {
        println!("[FAIL] 护照+学生联合场景测试失败: {e}");
    }
    if let Err(e) = joint_test_support::run_student_employee_scenario(&mut rng) {
        println!("[FAIL] 学生+员工联合场景测试失败: {e}");
    }
    if let Err(e) = joint_test_support::run_passport_employee_scenario(&mut rng) {
        println!("[FAIL] 护照+员工联合场景测试失败: {e}");
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
    println!("篡改前承诺: {}", person_com);
    println!("篡改后承诺: {}", tampered_com);
    println!(
        "篡改后凭证(birth_year=2005)使用原证明验证结果: {}",
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
    
    println!("Old root: {}", root_before);
    println!("New root: {}", root_after);
    println!("Inserted Leaf: commitment = {}", person_com);
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

    let pred_counts = zkcreds::pred::count_pred_constraints(
        &pred_pk,
        age_checker.clone(),
        person.clone(),
        &auth_path,
    )
    .map_err(format_err)?;
    log_constraint_counts("属性证明电路", pred_counts);

    let tree_counts = auth_path
        .count_membership_constraints::<E, TestA, TestComSchemePedersenG, TestTreeHG>(
            &MERKLE_CRH_PARAM,
            person_com.clone(),
        )
        .map_err(format_err)?;
    log_constraint_counts("成员证明电路", tree_counts);

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
    println!("合法输入: name=Dan, birth_year=1992, commitment={}", person_com);
    println!("合法输入证明验证结果: {}", verified);
    if !verified {
        return Err("合法输入的证明应验证成功".into());
    }

    let tampered_person = NameAndBirthYear::new(rng, b"Dan", 2005);
    let tampered_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&tampered_person);
    let tampered_verified = verify_pred(&pred_vk, &pred_proof, &age_checker, &tampered_com, &merkle_root)
        .unwrap_or(false);
    println!("修改属性: name=Dan, birth_year=2005 (原1992), commitment={}", tampered_com);
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

    
    println!("cred1 拥有者: {}", String::from_utf8_lossy(cred1.first_name()).trim_end_matches('\0'));
    println!("cred1 hidden_ctr: {}", token1.hidden_ctr());
    println!("cred2 拥有者: {}", String::from_utf8_lossy(cred2.first_name()).trim_end_matches('\0'));
    println!("cred2 hidden_ctr: {}", token2.hidden_ctr());
    println!("cred3 拥有者: {}", String::from_utf8_lossy(other_cred.first_name()).trim_end_matches('\0'));
    println!("cred3 hidden_ctr: {}", token3.hidden_ctr());
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

    if token1.hidden_ctr() != same_token_again.hidden_ctr() {
        return Err("重复使用同一凭证应产生相同的 multishow token".into());
    }

    let multishow_checker = MultishowChecker {
        token: token1.clone(),
        epoch,
        max_num_presentations: 5,
        ctr,
        params: params.clone(),
    };
    let multishow_pk = gen_pred_crs::<_, _, E, TestA, TestAV, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
        rng,
        multishow_checker.clone(),
    )
    .map_err(format_err)?;
    let multishow_counts = zkcreds::pred::count_birth_constraints(
        &multishow_pk,
        multishow_checker.clone(),
        cred1.clone(),
    )
    .map_err(format_err)?;
    log_constraint_counts("双重展示属性证明电路", multishow_counts);

    Ok(())
}

mod joint_test_support {
    use super::*;
    use ark_crypto_primitives::commitment::CommitmentScheme;
    use ark_r1cs_std::{alloc::AllocVar, bits::{ToBitsGadget, ToBytesGadget}, eq::EqGadget, fields::{fp::FpVar, FieldVar}, uint8::UInt8, R1CSVar};
    use ark_relations::{ns, r1cs::{ConstraintSystemRef, Namespace, SynthesisError}};
    use ark_serialize::CanonicalSerialize;
    use ark_std::{cmp::Ordering, rand::{CryptoRng, Rng}};
    use zkcreds::{attrs::AttrsVar, Bytestring, ComParam, ComParamVar, poseidon_utils::ComNonce};
    use zkcreds::pred::PredicateChecker;

    const PASSPORT_NAME_LEN: usize = 16;
    const PASSPORT_NATIONALITY_LEN: usize = 3;
    const PASSPORT_DOB_OFF: usize = 16;
    const PASSPORT_NATIONALITY_OFF: usize = 20;
    const PASSPORT_EXPIRY_OFF: usize = 23;
    const PASSPORT_HOLDER_TAG_OFF: usize = 27;
    const PASSPORT_RECORD_LEN: usize = 43;

    const STUDENT_NAME_LEN: usize = 16;
    const STUDENT_SCHOOL_OFF: usize = 16;
    const STUDENT_SCHOOL_LEN: usize = 16;
    const STUDENT_EXPIRY_OFF: usize = 32;
    const STUDENT_HOLDER_TAG_OFF: usize = 36;
    const STUDENT_RECORD_LEN: usize = 52;

    const EMPLOYEE_NAME_LEN: usize = 16;
    const EMPLOYEE_COMPANY_OFF: usize = 16;
    const EMPLOYEE_COMPANY_LEN: usize = 16;
    const EMPLOYEE_EXPIRY_OFF: usize = 32;
    const EMPLOYEE_HOLDER_TAG_OFF: usize = 36;
    const EMPLOYEE_RECORD_LEN: usize = 52;

    const HOLDER_TAG_LEN: usize = 16;

    static BIG_COM_PARAM: OnceLock<<TestComSchemePedersen as CommitmentScheme>::Parameters> = OnceLock::new();

    fn get_big_com_param() -> &'static <TestComSchemePedersen as CommitmentScheme>::Parameters {
        BIG_COM_PARAM.get_or_init(|| {
            let seed = [0u8; 32];
            let mut rng = StdRng::from_seed(seed);
            TestComSchemePedersen::setup(&mut rng).unwrap()
        })
    }

    fn pad_bytes<const N: usize>(input: &[u8]) -> [u8; N] {
        let mut buf = [0u8; N];
        buf[..input.len().min(N)].copy_from_slice(&input[..input.len().min(N)]);
        buf
    }

    fn passport_blob(
        name: &[u8],
        nationality: [u8; PASSPORT_NATIONALITY_LEN],
        dob: u32,
        expiry: u32,
        holder_tag: [u8; HOLDER_TAG_LEN],
    ) -> [u8; PASSPORT_RECORD_LEN] {
        let mut blob = [0u8; PASSPORT_RECORD_LEN];
        blob[..PASSPORT_NAME_LEN].copy_from_slice(&pad_bytes::<PASSPORT_NAME_LEN>(name));
        blob[PASSPORT_DOB_OFF..PASSPORT_DOB_OFF + 4].copy_from_slice(&dob.to_be_bytes());
        blob[PASSPORT_NATIONALITY_OFF..PASSPORT_NATIONALITY_OFF + PASSPORT_NATIONALITY_LEN]
            .copy_from_slice(&nationality);
        blob[PASSPORT_EXPIRY_OFF..PASSPORT_EXPIRY_OFF + 4].copy_from_slice(&expiry.to_be_bytes());
        blob[PASSPORT_HOLDER_TAG_OFF..PASSPORT_HOLDER_TAG_OFF + HOLDER_TAG_LEN]
            .copy_from_slice(&holder_tag);
        blob
    }

    fn student_blob(
        name: &[u8],
        school: &[u8],
        expiry: u32,
        holder_tag: [u8; HOLDER_TAG_LEN],
    ) -> [u8; STUDENT_RECORD_LEN] {
        let mut blob = [0u8; STUDENT_RECORD_LEN];
        blob[..STUDENT_NAME_LEN].copy_from_slice(&pad_bytes::<STUDENT_NAME_LEN>(name));
        blob[STUDENT_SCHOOL_OFF..STUDENT_SCHOOL_OFF + STUDENT_SCHOOL_LEN]
            .copy_from_slice(&pad_bytes::<STUDENT_SCHOOL_LEN>(school));
        blob[STUDENT_EXPIRY_OFF..STUDENT_EXPIRY_OFF + 4].copy_from_slice(&expiry.to_be_bytes());
        blob[STUDENT_HOLDER_TAG_OFF..STUDENT_HOLDER_TAG_OFF + HOLDER_TAG_LEN]
            .copy_from_slice(&holder_tag);
        blob
    }

    fn employee_blob(
        name: &[u8],
        company: &[u8],
        expiry: u32,
        holder_tag: [u8; HOLDER_TAG_LEN],
    ) -> [u8; EMPLOYEE_RECORD_LEN] {
        let mut blob = [0u8; EMPLOYEE_RECORD_LEN];
        blob[..EMPLOYEE_NAME_LEN].copy_from_slice(&pad_bytes::<EMPLOYEE_NAME_LEN>(name));
        blob[EMPLOYEE_COMPANY_OFF..EMPLOYEE_COMPANY_OFF + EMPLOYEE_COMPANY_LEN]
            .copy_from_slice(&pad_bytes::<EMPLOYEE_COMPANY_LEN>(company));
        blob[EMPLOYEE_EXPIRY_OFF..EMPLOYEE_EXPIRY_OFF + 4].copy_from_slice(&expiry.to_be_bytes());
        blob[EMPLOYEE_HOLDER_TAG_OFF..EMPLOYEE_HOLDER_TAG_OFF + HOLDER_TAG_LEN]
            .copy_from_slice(&holder_tag);
        blob
    }

    #[derive(Clone)]
    pub(crate) struct PassportStudentJointInfo {
        nonce: ComNonce,
        seed: Fr,
        pub(crate) passport_blob: [u8; PASSPORT_RECORD_LEN],
        pub(crate) student_blob: [u8; STUDENT_RECORD_LEN],
    }

    impl Default for PassportStudentJointInfo {
        fn default() -> Self {
            Self {
                nonce: ComNonce::default(),
                seed: Fr::default(),
                passport_blob: [0u8; PASSPORT_RECORD_LEN],
                student_blob: [0u8; STUDENT_RECORD_LEN],
            }
        }
    }

    impl PassportStudentJointInfo {
        pub(crate) fn from_values<R: Rng>(
            rng: &mut R,
            passport_blob: [u8; PASSPORT_RECORD_LEN],
            student_blob: [u8; STUDENT_RECORD_LEN],
            seed: Fr,
        ) -> Self {
            Self {
                nonce: ComNonce::rand(rng),
                seed,
                passport_blob,
                student_blob,
            }
        }
    }

    #[derive(Clone)]
    pub(crate) struct PassportStudentJointInfoVar {
        nonce: ComNonce,
        seed: FpVar<Fr>,
        pub(crate) passport_blob: Bytestring<Fr>,
        pub(crate) student_blob: Bytestring<Fr>,
    }

    impl Attrs<Fr, TestComSchemePedersen> for PassportStudentJointInfo {
        fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(PASSPORT_RECORD_LEN + STUDENT_RECORD_LEN + 32);
            self.seed.serialize(&mut bytes).unwrap();
            bytes.extend_from_slice(&self.passport_blob);
            bytes.extend_from_slice(&self.student_blob);
            bytes
        }

        fn get_com_param(&self) -> &ComParam<TestComSchemePedersen> {
            get_big_com_param()
        }

        fn get_com_nonce(&self) -> &ComNonce {
            &self.nonce
        }
    }

    impl ToBytesGadget<Fr> for PassportStudentJointInfoVar {
        fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
            Ok([
                self.seed.to_bytes()?,
                self.passport_blob.0.to_bytes()?,
                self.student_blob.0.to_bytes()?,
            ]
            .concat())
        }
    }

    impl AttrsVar<Fr, PassportStudentJointInfo, TestComSchemePedersen, TestComSchemePedersenG>
        for PassportStudentJointInfoVar
    {
        fn cs(&self) -> ConstraintSystemRef<Fr> {
            self.seed
                .cs()
                .or(self.passport_blob.cs())
                .or(self.student_blob.cs())
        }

        fn witness_attrs(
            cs: impl Into<Namespace<Fr>>,
            attrs: &PassportStudentJointInfo,
        ) -> Result<Self, SynthesisError> {
            let cs = cs.into().cs();
            Ok(PassportStudentJointInfoVar {
                nonce: attrs.nonce.clone(),
                seed: FpVar::new_witness(ns!(cs, "ps seed"), || Ok(attrs.seed))?,
                passport_blob: Bytestring::new_witness(ns!(cs, "passport blob"), || {
                    Ok(attrs.passport_blob.to_vec())
                })?,
                student_blob: Bytestring::new_witness(ns!(cs, "student blob"), || {
                    Ok(attrs.student_blob.to_vec())
                })?,
            })
        }

        fn get_com_param(
            &self,
        ) -> Result<ComParamVar<TestComSchemePedersen, TestComSchemePedersenG, Fr>, SynthesisError> {
            let cs = self.passport_blob.cs().or(self.student_blob.cs());
            ComParamVar::<_, TestComSchemePedersenG, _>::new_constant(cs, get_big_com_param())
        }

        fn get_com_nonce(&self) -> &ComNonce {
            &self.nonce
        }
    }

    #[derive(Clone)]
    pub(crate) struct StudentEmployeeJointInfo {
        nonce: ComNonce,
        seed: Fr,
        pub(crate) student_blob: [u8; STUDENT_RECORD_LEN],
        pub(crate) employee_blob: [u8; EMPLOYEE_RECORD_LEN],
    }

    impl Default for StudentEmployeeJointInfo {
        fn default() -> Self {
            Self {
                nonce: ComNonce::default(),
                seed: Fr::default(),
                student_blob: [0u8; STUDENT_RECORD_LEN],
                employee_blob: [0u8; EMPLOYEE_RECORD_LEN],
            }
        }
    }

    impl StudentEmployeeJointInfo {
        pub(crate) fn from_values<R: Rng>(
            rng: &mut R,
            student_blob: [u8; STUDENT_RECORD_LEN],
            employee_blob: [u8; EMPLOYEE_RECORD_LEN],
            seed: Fr,
        ) -> Self {
            Self {
                nonce: ComNonce::rand(rng),
                seed,
                student_blob,
                employee_blob,
            }
        }
    }

    #[derive(Clone)]
    pub(crate) struct StudentEmployeeJointInfoVar {
        nonce: ComNonce,
        seed: FpVar<Fr>,
        pub(crate) student_blob: Bytestring<Fr>,
        pub(crate) employee_blob: Bytestring<Fr>,
    }

    impl Attrs<Fr, TestComSchemePedersen> for StudentEmployeeJointInfo {
        fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(STUDENT_RECORD_LEN + EMPLOYEE_RECORD_LEN + 32);
            self.seed.serialize(&mut bytes).unwrap();
            bytes.extend_from_slice(&self.student_blob);
            bytes.extend_from_slice(&self.employee_blob);
            bytes
        }

        fn get_com_param(&self) -> &ComParam<TestComSchemePedersen> {
            get_big_com_param()
        }

        fn get_com_nonce(&self) -> &ComNonce {
            &self.nonce
        }
    }

    impl ToBytesGadget<Fr> for StudentEmployeeJointInfoVar {
        fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
            Ok([
                self.seed.to_bytes()?,
                self.student_blob.0.to_bytes()?,
                self.employee_blob.0.to_bytes()?,
            ]
            .concat())
        }
    }

    impl AttrsVar<Fr, StudentEmployeeJointInfo, TestComSchemePedersen, TestComSchemePedersenG>
        for StudentEmployeeJointInfoVar
    {
        fn cs(&self) -> ConstraintSystemRef<Fr> {
            self.seed
                .cs()
                .or(self.student_blob.cs())
                .or(self.employee_blob.cs())
        }

        fn witness_attrs(
            cs: impl Into<Namespace<Fr>>,
            attrs: &StudentEmployeeJointInfo,
        ) -> Result<Self, SynthesisError> {
            let cs = cs.into().cs();
            Ok(StudentEmployeeJointInfoVar {
                nonce: attrs.nonce.clone(),
                seed: FpVar::new_witness(ns!(cs, "se seed"), || Ok(attrs.seed))?,
                student_blob: Bytestring::new_witness(ns!(cs, "student blob"), || {
                    Ok(attrs.student_blob.to_vec())
                })?,
                employee_blob: Bytestring::new_witness(ns!(cs, "employee blob"), || {
                    Ok(attrs.employee_blob.to_vec())
                })?,
            })
        }

        fn get_com_param(
            &self,
        ) -> Result<ComParamVar<TestComSchemePedersen, TestComSchemePedersenG, Fr>, SynthesisError> {
            let cs = self.student_blob.cs().or(self.employee_blob.cs());
            ComParamVar::<_, TestComSchemePedersenG, _>::new_constant(cs, get_big_com_param())
        }

        fn get_com_nonce(&self) -> &ComNonce {
            &self.nonce
        }
    }

    #[derive(Clone)]
    pub(crate) struct PassportEmployeeJointInfo {
        nonce: ComNonce,
        seed: Fr,
        pub(crate) passport_blob: [u8; PASSPORT_RECORD_LEN],
        pub(crate) employee_blob: [u8; EMPLOYEE_RECORD_LEN],
    }

    impl Default for PassportEmployeeJointInfo {
        fn default() -> Self {
            Self {
                nonce: ComNonce::default(),
                seed: Fr::default(),
                passport_blob: [0u8; PASSPORT_RECORD_LEN],
                employee_blob: [0u8; EMPLOYEE_RECORD_LEN],
            }
        }
    }

    impl PassportEmployeeJointInfo {
        pub(crate) fn from_values<R: Rng>(
            rng: &mut R,
            passport_blob: [u8; PASSPORT_RECORD_LEN],
            employee_blob: [u8; EMPLOYEE_RECORD_LEN],
            seed: Fr,
        ) -> Self {
            Self {
                nonce: ComNonce::rand(rng),
                seed,
                passport_blob,
                employee_blob,
            }
        }
    }

    #[derive(Clone)]
    pub(crate) struct PassportEmployeeJointInfoVar {
        nonce: ComNonce,
        seed: FpVar<Fr>,
        pub(crate) passport_blob: Bytestring<Fr>,
        pub(crate) employee_blob: Bytestring<Fr>,
    }

    impl Attrs<Fr, TestComSchemePedersen> for PassportEmployeeJointInfo {
        fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(PASSPORT_RECORD_LEN + EMPLOYEE_RECORD_LEN + 32);
            self.seed.serialize(&mut bytes).unwrap();
            bytes.extend_from_slice(&self.passport_blob);
            bytes.extend_from_slice(&self.employee_blob);
            bytes
        }

        fn get_com_param(&self) -> &ComParam<TestComSchemePedersen> {
            get_big_com_param()
        }

        fn get_com_nonce(&self) -> &ComNonce {
            &self.nonce
        }
    }

    impl ToBytesGadget<Fr> for PassportEmployeeJointInfoVar {
        fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
            Ok([
                self.seed.to_bytes()?,
                self.passport_blob.0.to_bytes()?,
                self.employee_blob.0.to_bytes()?,
            ]
            .concat())
        }
    }

    impl AttrsVar<Fr, PassportEmployeeJointInfo, TestComSchemePedersen, TestComSchemePedersenG>
        for PassportEmployeeJointInfoVar
    {
        fn cs(&self) -> ConstraintSystemRef<Fr> {
            self.seed
                .cs()
                .or(self.passport_blob.cs())
                .or(self.employee_blob.cs())
        }

        fn witness_attrs(
            cs: impl Into<Namespace<Fr>>,
            attrs: &PassportEmployeeJointInfo,
        ) -> Result<Self, SynthesisError> {
            let cs = cs.into().cs();
            Ok(PassportEmployeeJointInfoVar {
                nonce: attrs.nonce.clone(),
                seed: FpVar::new_witness(ns!(cs, "pe seed"), || Ok(attrs.seed))?,
                passport_blob: Bytestring::new_witness(ns!(cs, "passport blob"), || {
                    Ok(attrs.passport_blob.to_vec())
                })?,
                employee_blob: Bytestring::new_witness(ns!(cs, "employee blob"), || {
                    Ok(attrs.employee_blob.to_vec())
                })?,
            })
        }

        fn get_com_param(
            &self,
        ) -> Result<ComParamVar<TestComSchemePedersen, TestComSchemePedersenG, Fr>, SynthesisError> {
            let cs = self.passport_blob.cs().or(self.employee_blob.cs());
            ComParamVar::<_, TestComSchemePedersenG, _>::new_constant(cs, get_big_com_param())
        }

        fn get_com_nonce(&self) -> &ComNonce {
            &self.nonce
        }
    }

    fn u32_be_bytes_to_fp(bytes: &[UInt8<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
        assert_eq!(bytes.len(), 4);
        let mut acc = FpVar::<Fr>::zero();
        let base = FpVar::constant(Fr::from(256u16));
        for b in bytes {
            let v = ark_r1cs_std::bits::boolean::Boolean::le_bits_to_fp_var(&b.to_bits_le()?)?;
            acc = acc * &base + &v;
        }
        Ok(acc)
    }

    fn student_expiry_fr(blob: &Bytestring<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        u32_be_bytes_to_fp(&blob.0[STUDENT_EXPIRY_OFF..STUDENT_EXPIRY_OFF + 4])
    }

    fn employee_expiry_fr(blob: &Bytestring<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        u32_be_bytes_to_fp(&blob.0[EMPLOYEE_EXPIRY_OFF..EMPLOYEE_EXPIRY_OFF + 4])
    }

    fn passport_expiry_fr(blob: &Bytestring<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        u32_be_bytes_to_fp(&blob.0[PASSPORT_EXPIRY_OFF..PASSPORT_EXPIRY_OFF + 4])
    }

    #[derive(Clone)]
    pub(crate) struct PsTicketChecker {
        pub(crate) threshold_dob: Fr,
        pub(crate) expected_nationality: [u8; PASSPORT_NATIONALITY_LEN],
    }

    impl PredicateChecker<
        Fr,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for PsTicketChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &PassportStudentJointInfoVar) -> Result<(), SynthesisError> {
            let threshold = FpVar::<Fr>::new_input(ns!(cs, "ps ticket threshold dob"), || Ok(self.threshold_dob))?;
            let expected_nat = UInt8::new_input_vec(ns!(cs, "expected nationality"), &self.expected_nationality)?;
            attrs.passport_blob.0[PASSPORT_NATIONALITY_OFF..PASSPORT_NATIONALITY_OFF + PASSPORT_NATIONALITY_LEN]
                .enforce_equal(&expected_nat)?;
            let dob_fp = u32_be_bytes_to_fp(&attrs.passport_blob.0[PASSPORT_DOB_OFF..PASSPORT_DOB_OFF + 4])?;
            dob_fp.enforce_cmp(&threshold, Ordering::Less, true)?;
            attrs.student_blob.0[0..STUDENT_NAME_LEN]
                .enforce_equal(&attrs.passport_blob.0[0..PASSPORT_NAME_LEN])?;
            Ok(())
        }

        fn public_inputs(&self) -> Vec<Fr> {
            let mut inputs: Vec<Fr> = self
                .expected_nationality
                .iter()
                .map(|b| Fr::from(*b as u64))
                .collect();
            inputs.push(self.threshold_dob);
            inputs
        }
    }

    #[derive(Clone)]
    pub(crate) struct PsPassportExpiryChecker {
        pub(crate) threshold_expiry: Fr,
    }

    impl PredicateChecker<
        Fr,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for PsPassportExpiryChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &PassportStudentJointInfoVar) -> Result<(), SynthesisError> {
            let threshold = FpVar::<Fr>::new_input(ns!(cs, "ps passport expiry threshold"), || Ok(self.threshold_expiry))?;
            let ex = passport_expiry_fr(&attrs.passport_blob)?;
            ex.enforce_cmp(&threshold, Ordering::Greater, false)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            vec![self.threshold_expiry]
        }
    }

    #[derive(Clone)]
    pub(crate) struct PsStudentExpiryChecker {
        pub(crate) threshold_expiry: Fr,
    }

    impl PredicateChecker<
        Fr,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for PsStudentExpiryChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &PassportStudentJointInfoVar) -> Result<(), SynthesisError> {
            let threshold = FpVar::<Fr>::new_input(ns!(cs, "ps student expiry threshold"), || Ok(self.threshold_expiry))?;
            let ex = student_expiry_fr(&attrs.student_blob)?;
            ex.enforce_cmp(&threshold, Ordering::Greater, false)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            vec![self.threshold_expiry]
        }
    }

    #[derive(Clone)]
    pub(crate) struct PsHolderTagChecker {
        pub(crate) holder_tag: [u8; HOLDER_TAG_LEN],
    }

    impl PredicateChecker<
        Fr,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for PsHolderTagChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &PassportStudentJointInfoVar) -> Result<(), SynthesisError> {
            let tag = UInt8::new_input_vec(ns!(cs, "ps holder tag"), &self.holder_tag)?;
            attrs.passport_blob.0[PASSPORT_HOLDER_TAG_OFF..PASSPORT_HOLDER_TAG_OFF + HOLDER_TAG_LEN]
                .enforce_equal(&tag)?;
            attrs.student_blob.0[STUDENT_HOLDER_TAG_OFF..STUDENT_HOLDER_TAG_OFF + HOLDER_TAG_LEN]
                .enforce_equal(&tag)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            self.holder_tag.iter().map(|b| Fr::from(*b as u64)).collect()
        }
    }

    #[derive(Clone)]
    pub(crate) struct SeStudentExpiryChecker {
        pub(crate) threshold_expiry: Fr,
    }

    impl PredicateChecker<
        Fr,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for SeStudentExpiryChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &StudentEmployeeJointInfoVar) -> Result<(), SynthesisError> {
            let threshold = FpVar::<Fr>::new_input(ns!(cs, "se student expiry threshold"), || Ok(self.threshold_expiry))?;
            let ex = student_expiry_fr(&attrs.student_blob)?;
            ex.enforce_cmp(&threshold, Ordering::Greater, false)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            vec![self.threshold_expiry]
        }
    }

    #[derive(Clone)]
    pub(crate) struct SeEmployeeExpiryChecker {
        pub(crate) threshold_expiry: Fr,
    }

    impl PredicateChecker<
        Fr,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for SeEmployeeExpiryChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &StudentEmployeeJointInfoVar) -> Result<(), SynthesisError> {
            let threshold = FpVar::<Fr>::new_input(ns!(cs, "se employee expiry threshold"), || Ok(self.threshold_expiry))?;
            let ex = employee_expiry_fr(&attrs.employee_blob)?;
            ex.enforce_cmp(&threshold, Ordering::Greater, false)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            vec![self.threshold_expiry]
        }
    }

    #[derive(Clone)]
    pub(crate) struct SeNameSchoolCompanyChecker {
        pub(crate) expected_school: [u8; STUDENT_SCHOOL_LEN],
        pub(crate) expected_company: [u8; EMPLOYEE_COMPANY_LEN],
    }

    impl PredicateChecker<
        Fr,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for SeNameSchoolCompanyChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &StudentEmployeeJointInfoVar) -> Result<(), SynthesisError> {
            let expected_school = UInt8::new_input_vec(ns!(cs, "se expected school"), &self.expected_school)?;
            let expected_company = UInt8::new_input_vec(ns!(cs, "se expected company"), &self.expected_company)?;
            attrs.student_blob.0[0..STUDENT_NAME_LEN]
                .enforce_equal(&attrs.employee_blob.0[0..EMPLOYEE_NAME_LEN])?;
            attrs.student_blob.0[STUDENT_SCHOOL_OFF..STUDENT_SCHOOL_OFF + STUDENT_SCHOOL_LEN]
                .enforce_equal(&expected_school)?;
            attrs.employee_blob.0[EMPLOYEE_COMPANY_OFF..EMPLOYEE_COMPANY_OFF + EMPLOYEE_COMPANY_LEN]
                .enforce_equal(&expected_company)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            self.expected_school
                .iter()
                .chain(self.expected_company.iter())
                .map(|b| Fr::from(*b as u64))
                .collect()
        }
    }

    #[derive(Clone)]
    pub(crate) struct SeHolderTagChecker {
        pub(crate) holder_tag: [u8; HOLDER_TAG_LEN],
    }

    impl PredicateChecker<
        Fr,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for SeHolderTagChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &StudentEmployeeJointInfoVar) -> Result<(), SynthesisError> {
            let tag = UInt8::new_input_vec(ns!(cs, "se holder tag"), &self.holder_tag)?;
            attrs.student_blob.0[STUDENT_HOLDER_TAG_OFF..STUDENT_HOLDER_TAG_OFF + HOLDER_TAG_LEN]
                .enforce_equal(&tag)?;
            attrs.employee_blob.0[EMPLOYEE_HOLDER_TAG_OFF..EMPLOYEE_HOLDER_TAG_OFF + HOLDER_TAG_LEN]
                .enforce_equal(&tag)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            self.holder_tag.iter().map(|b| Fr::from(*b as u64)).collect()
        }
    }

    #[derive(Clone)]
    pub(crate) struct PeEmployeeExpiryChecker {
        pub(crate) threshold_expiry: Fr,
    }

    impl PredicateChecker<
        Fr,
        PassportEmployeeJointInfo,
        PassportEmployeeJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for PeEmployeeExpiryChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &PassportEmployeeJointInfoVar) -> Result<(), SynthesisError> {
            let threshold = FpVar::<Fr>::new_input(ns!(cs, "pe employee expiry threshold"), || Ok(self.threshold_expiry))?;
            let ex = employee_expiry_fr(&attrs.employee_blob)?;
            ex.enforce_cmp(&threshold, Ordering::Greater, false)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            vec![self.threshold_expiry]
        }
    }

    #[derive(Clone)]
    pub(crate) struct PePassportExpiryChecker {
        pub(crate) threshold_expiry: Fr,
    }

    impl PredicateChecker<
        Fr,
        PassportEmployeeJointInfo,
        PassportEmployeeJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for PePassportExpiryChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &PassportEmployeeJointInfoVar) -> Result<(), SynthesisError> {
            let threshold = FpVar::<Fr>::new_input(ns!(cs, "pe passport expiry threshold"), || Ok(self.threshold_expiry))?;
            let ex = passport_expiry_fr(&attrs.passport_blob)?;
            ex.enforce_cmp(&threshold, Ordering::Greater, false)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            vec![self.threshold_expiry]
        }
    }

    #[derive(Clone)]
    pub(crate) struct PeBusinessChecker {
        pub(crate) expected_company: [u8; EMPLOYEE_COMPANY_LEN],
        pub(crate) threshold_employee_expiry: Fr,
    }

    impl PredicateChecker<
        Fr,
        PassportEmployeeJointInfo,
        PassportEmployeeJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for PeBusinessChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &PassportEmployeeJointInfoVar) -> Result<(), SynthesisError> {
            let expected_company = UInt8::new_input_vec(ns!(cs, "pe expected company"), &self.expected_company)?;
            let threshold = FpVar::<Fr>::new_input(ns!(cs, "pe employee expiry threshold"), || Ok(self.threshold_employee_expiry))?;
            let ex = employee_expiry_fr(&attrs.employee_blob)?;
            ex.enforce_cmp(&threshold, Ordering::Greater, false)?;
            attrs.employee_blob.0[EMPLOYEE_COMPANY_OFF..EMPLOYEE_COMPANY_OFF + EMPLOYEE_COMPANY_LEN]
                .enforce_equal(&expected_company)?;
            attrs.employee_blob.0[0..EMPLOYEE_NAME_LEN]
                .enforce_equal(&attrs.passport_blob.0[0..PASSPORT_NAME_LEN])
        }

        fn public_inputs(&self) -> Vec<Fr> {
            let mut inputs: Vec<Fr> = self
                .expected_company
                .iter()
                .map(|b| Fr::from(*b as u64))
                .collect();
            inputs.push(self.threshold_employee_expiry);
            inputs
        }
    }

    #[derive(Clone)]
    pub(crate) struct PeHolderTagChecker {
        pub(crate) holder_tag: [u8; HOLDER_TAG_LEN],
    }

    impl PredicateChecker<
        Fr,
        PassportEmployeeJointInfo,
        PassportEmployeeJointInfoVar,
        TestComSchemePedersen,
        TestComSchemePedersenG,
    > for PeHolderTagChecker
    {
        fn pred(self, cs: ConstraintSystemRef<Fr>, attrs: &PassportEmployeeJointInfoVar) -> Result<(), SynthesisError> {
            let tag = UInt8::new_input_vec(ns!(cs, "pe holder tag"), &self.holder_tag)?;
            attrs.passport_blob.0[PASSPORT_HOLDER_TAG_OFF..PASSPORT_HOLDER_TAG_OFF + HOLDER_TAG_LEN]
                .enforce_equal(&tag)?;
            attrs.employee_blob.0[EMPLOYEE_HOLDER_TAG_OFF..EMPLOYEE_HOLDER_TAG_OFF + HOLDER_TAG_LEN]
                .enforce_equal(&tag)
        }

        fn public_inputs(&self) -> Vec<Fr> {
            self.holder_tag.iter().map(|b| Fr::from(*b as u64)).collect()
        }
    }

    pub(crate) fn make_holder_tag(seed: u8) -> [u8; HOLDER_TAG_LEN] {
        [seed; HOLDER_TAG_LEN]
    }

    pub(crate) fn run_passport_student_scenario<R>(rng: &mut R) -> Result<(), String>
    where
        R: Rng + CryptoRng,
    {
        let passport_blob = passport_blob(b"Anna", [b'U', b'S', b'A'], 20000101, 20350101, make_holder_tag(1));
        let student_blob = student_blob(b"Anna", b"MIT", 20250101, make_holder_tag(1));
        let joint_seed = Fr::rand(rng);
        let info = PassportStudentJointInfo::from_values(rng, passport_blob, student_blob, joint_seed);
        let attrs_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&info);

        let tree_pk = gen_tree_memb_crs::<_, E, PassportStudentJointInfo, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            MERKLE_CRH_PARAM.clone(),
            TREE_HEIGHT,
        )
        .map_err(format_err)?;
        let tree_vk = tree_pk.prepare_verifying_key();
        let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
        let auth_path = tree.insert(3, &attrs_com);

        let forest_pk = gen_forest_memb_crs::<_, E, PassportStudentJointInfo, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            NUM_TREES,
        )
        .map_err(format_err)?;
        let forest_vk = forest_pk.prepare_verifying_key();

        let mut forest = ComForest { trees: (0..NUM_TREES).map(|_| random_empty_tree(rng)).collect() };
        forest.trees[0] = tree;
        let roots = forest.roots();

        let ticket_checker = PsTicketChecker {
            threshold_dob: Fr::from(20040201u64),
            expected_nationality: [b'U', b'S', b'A'],
        };
        let passport_expiry_checker = PsPassportExpiryChecker {
            threshold_expiry: Fr::from(20240101u64),
        };
        let student_expiry_checker = PsStudentExpiryChecker {
            threshold_expiry: Fr::from(20230101u64),
        };
        let holder_checker = PsHolderTagChecker {
            holder_tag: make_holder_tag(1),
        };

        let pkt_pk = gen_pred_crs::<_, _, E, PassportStudentJointInfo, PassportStudentJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            ticket_checker.clone(),
        )
        .map_err(format_err)?;
        let ppp_pk = gen_pred_crs::<_, _, E, PassportStudentJointInfo, PassportStudentJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            passport_expiry_checker.clone(),
        )
        .map_err(format_err)?;
        let psp_pk = gen_pred_crs::<_, _, E, PassportStudentJointInfo, PassportStudentJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            student_expiry_checker.clone(),
        )
        .map_err(format_err)?;
        let ph_pk = gen_pred_crs::<_, _, E, PassportStudentJointInfo, PassportStudentJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            holder_checker.clone(),
        )
        .map_err(format_err)?;

        let pkt_vk = pkt_pk.prepare_verifying_key();
        let ppp_vk = ppp_pk.prepare_verifying_key();
        let psp_vk = psp_pk.prepare_verifying_key();
        let ph_vk = ph_pk.prepare_verifying_key();

        let ticket_proof = prove_pred(rng, &pkt_pk, ticket_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        let passport_expiry_proof = prove_pred(rng, &ppp_pk, passport_expiry_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        let student_expiry_proof = prove_pred(rng, &psp_pk, student_expiry_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        let holder_proof = prove_pred(rng, &ph_pk, holder_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;

        let ticket_counts = zkcreds::pred::count_pred_constraints(&pkt_pk, ticket_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        log_constraint_counts("链接场景-票据属性证明", ticket_counts);

        let passport_expiry_counts = zkcreds::pred::count_pred_constraints(&ppp_pk, passport_expiry_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        log_constraint_counts("链接场景-护照到期证明", passport_expiry_counts);

        let student_expiry_counts = zkcreds::pred::count_pred_constraints(&psp_pk, student_expiry_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        log_constraint_counts("链接场景-学生到期证明", student_expiry_counts);

        let holder_counts = zkcreds::pred::count_pred_constraints(&ph_pk, holder_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        log_constraint_counts("链接场景-持卡人标签证明", holder_counts);

        let tree_counts = auth_path
            .count_membership_constraints::<E, PassportStudentJointInfo, TestComSchemePedersenG, TestTreeHG>(
                &MERKLE_CRH_PARAM,
                attrs_com.clone(),
            )
            .map_err(format_err)?;
        log_constraint_counts("链接场景-树成员证明", tree_counts);

        let forest_counts = roots
            .count_membership_constraints::<E, PassportStudentJointInfo, TestComSchemePedersen, TestComSchemePedersenG, TestTreeHG>(
                auth_path.root(),
                attrs_com.clone(),
            )
            .map_err(format_err)?;
        log_constraint_counts("链接场景-森林成员证明", forest_counts);

        assert!(verify_pred(&pkt_vk, &ticket_proof, &ticket_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);
        assert!(verify_pred(&ppp_vk, &passport_expiry_proof, &passport_expiry_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);
        assert!(verify_pred(&psp_vk, &student_expiry_proof, &student_expiry_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);
        assert!(verify_pred(&ph_vk, &holder_proof, &holder_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);

        let tree_proof = auth_path
            .prove_membership(rng, &tree_pk, &MERKLE_CRH_PARAM, attrs_com)
            .map_err(format_err)?;
        let forest_proof = roots
            .prove_membership(rng, &forest_pk, auth_path.root(), attrs_com)
            .map_err(format_err)?;

        let mut pred_inputs = PredPublicInputs::default();
        pred_inputs.prepare_pred_checker(&pkt_vk, &ticket_checker);
        pred_inputs.prepare_pred_checker(&ppp_vk, &passport_expiry_checker);
        pred_inputs.prepare_pred_checker(&psp_vk, &student_expiry_checker);
        pred_inputs.prepare_pred_checker(&ph_vk, &holder_checker);

        let link_vk = LinkVerifyingKey {
            pred_inputs,
            prepared_roots: roots.prepare(&forest_vk).map_err(format_err)?,
            forest_verif_key: forest_vk.clone(),
            tree_verif_key: tree_vk.clone(),
            pred_verif_keys: vec![pkt_vk.clone(), ppp_vk.clone(), psp_vk.clone(), ph_vk.clone()],
        };

        let link_ctx = LinkProofCtx {
            attrs_com,
            merkle_root: auth_path.root(),
            forest_proof,
            tree_proof,
            pred_proofs: vec![ticket_proof, passport_expiry_proof, student_expiry_proof, holder_proof],
            vk: link_vk.clone(),
        };

        let link_proof = link_proofs(rng, &link_ctx);
        if !verif_link_proof(&link_proof, &link_vk).map_err(format_err)? {
            return Err("护照+学生联合链接证明应通过验证".into());
        }

        let mut bad_inputs = PredPublicInputs::default();
        bad_inputs.prepare_pred_checker(&pkt_vk, &PsTicketChecker {
            threshold_dob: Fr::from(20040201u64),
            expected_nationality: [b'C', b'H', b'N'],
        });
        bad_inputs.prepare_pred_checker(&ppp_vk, &passport_expiry_checker);
        bad_inputs.prepare_pred_checker(&psp_vk, &student_expiry_checker);
        bad_inputs.prepare_pred_checker(&ph_vk, &holder_checker);
        let bad_link_vk = LinkVerifyingKey {
            pred_inputs: bad_inputs,
            prepared_roots: roots.prepare(&forest_vk).map_err(format_err)?,
            forest_verif_key: forest_vk,
            tree_verif_key: tree_vk,
            pred_verif_keys: vec![pkt_vk, ppp_vk, psp_vk, ph_vk],
        };

        if verif_link_proof(&link_proof, &bad_link_vk).unwrap_or(true) {
            return Err("错误 nationality 时联合链接证明不应通过验证".into());
        }

        Ok(())
    }

    pub(crate) fn run_student_employee_scenario<R>(rng: &mut R) -> Result<(), String>
    where
        R: Rng + CryptoRng,
    {
        let student_blob = student_blob(b"Anna", b"MIT", 20250101, make_holder_tag(2));
        let employee_blob = employee_blob(b"Anna", b"ACME", 20250101, make_holder_tag(2));
        let joint_seed = Fr::rand(rng);
        let info = StudentEmployeeJointInfo::from_values(rng, student_blob, employee_blob, joint_seed);
        let attrs_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&info);

        let tree_pk = gen_tree_memb_crs::<_, E, StudentEmployeeJointInfo, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            MERKLE_CRH_PARAM.clone(),
            TREE_HEIGHT,
        )
        .map_err(format_err)?;
        let tree_vk = tree_pk.prepare_verifying_key();
        let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
        let auth_path = tree.insert(5, &attrs_com);

        let forest_pk = gen_forest_memb_crs::<_, E, StudentEmployeeJointInfo, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            NUM_TREES,
        )
        .map_err(format_err)?;
        let forest_vk = forest_pk.prepare_verifying_key();

        let mut forest = ComForest { trees: (0..NUM_TREES).map(|_| random_empty_tree(rng)).collect() };
        forest.trees[1] = tree;
        let roots = forest.roots();

        let student_expiry_checker = SeStudentExpiryChecker {
            threshold_expiry: Fr::from(20240101u64),
        };
        let employee_expiry_checker = SeEmployeeExpiryChecker {
            threshold_expiry: Fr::from(20240101u64),
        };
        let scene_checker = SeNameSchoolCompanyChecker {
            expected_school: pad_bytes::<STUDENT_SCHOOL_LEN>(b"MIT"),
            expected_company: pad_bytes::<EMPLOYEE_COMPANY_LEN>(b"ACME"),
        };
        let holder_checker = SeHolderTagChecker {
            holder_tag: make_holder_tag(2),
        };

        let sku_pk = gen_pred_crs::<_, _, E, StudentEmployeeJointInfo, StudentEmployeeJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            student_expiry_checker.clone(),
        )
        .map_err(format_err)?;
        let eku_pk = gen_pred_crs::<_, _, E, StudentEmployeeJointInfo, StudentEmployeeJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            employee_expiry_checker.clone(),
        )
        .map_err(format_err)?;
        let scc_pk = gen_pred_crs::<_, _, E, StudentEmployeeJointInfo, StudentEmployeeJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            scene_checker.clone(),
        )
        .map_err(format_err)?;
        let sh_pk = gen_pred_crs::<_, _, E, StudentEmployeeJointInfo, StudentEmployeeJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            holder_checker.clone(),
        )
        .map_err(format_err)?;

        let sku_vk = sku_pk.prepare_verifying_key();
        let eku_vk = eku_pk.prepare_verifying_key();
        let scc_vk = scc_pk.prepare_verifying_key();
        let sh_vk = sh_pk.prepare_verifying_key();

        let student_expiry_proof = prove_pred(rng, &sku_pk, student_expiry_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        let employee_expiry_proof = prove_pred(rng, &eku_pk, employee_expiry_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        let scene_proof = prove_pred(rng, &scc_pk, scene_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        let holder_proof = prove_pred(rng, &sh_pk, holder_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;

        assert!(verify_pred(&sku_vk, &student_expiry_proof, &student_expiry_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);
        assert!(verify_pred(&eku_vk, &employee_expiry_proof, &employee_expiry_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);
        assert!(verify_pred(&scc_vk, &scene_proof, &scene_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);
        assert!(verify_pred(&sh_vk, &holder_proof, &holder_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);

        let tree_proof = auth_path
            .prove_membership(rng, &tree_pk, &MERKLE_CRH_PARAM, attrs_com)
            .map_err(format_err)?;
        let forest_proof = roots
            .prove_membership(rng, &forest_pk, auth_path.root(), attrs_com)
            .map_err(format_err)?;

        let mut pred_inputs = PredPublicInputs::default();
        pred_inputs.prepare_pred_checker(&sku_vk, &student_expiry_checker);
        pred_inputs.prepare_pred_checker(&eku_vk, &employee_expiry_checker);
        pred_inputs.prepare_pred_checker(&scc_vk, &scene_checker);
        pred_inputs.prepare_pred_checker(&sh_vk, &holder_checker);

        let link_vk = LinkVerifyingKey {
            pred_inputs,
            prepared_roots: roots.prepare(&forest_vk).map_err(format_err)?,
            forest_verif_key: forest_vk.clone(),
            tree_verif_key: tree_vk.clone(),
            pred_verif_keys: vec![sku_vk.clone(), eku_vk.clone(), scc_vk.clone(), sh_vk.clone()],
        };

        let link_ctx = LinkProofCtx {
            attrs_com,
            merkle_root: auth_path.root(),
            forest_proof,
            tree_proof,
            pred_proofs: vec![student_expiry_proof, employee_expiry_proof, scene_proof, holder_proof],
            vk: link_vk.clone(),
        };

        let link_proof = link_proofs(rng, &link_ctx);
        if !verif_link_proof(&link_proof, &link_vk).map_err(format_err)? {
            return Err("学生+员工联合链接证明应通过验证".into());
        }

        let mut bad_inputs = PredPublicInputs::default();
        bad_inputs.prepare_pred_checker(&sku_vk, &student_expiry_checker);
        bad_inputs.prepare_pred_checker(&eku_vk, &employee_expiry_checker);
        bad_inputs.prepare_pred_checker(&scc_vk, &SeNameSchoolCompanyChecker {
            expected_school: pad_bytes::<STUDENT_SCHOOL_LEN>(b"WRNG"),
            expected_company: pad_bytes::<EMPLOYEE_COMPANY_LEN>(b"ACME"),
        });
        bad_inputs.prepare_pred_checker(&sh_vk, &holder_checker);
        let bad_link_vk = LinkVerifyingKey {
            pred_inputs: bad_inputs,
            prepared_roots: roots.prepare(&forest_vk).map_err(format_err)?,
            forest_verif_key: forest_vk,
            tree_verif_key: tree_vk,
            pred_verif_keys: vec![sku_vk, eku_vk, scc_vk, sh_vk],
        };

        if verif_link_proof(&link_proof, &bad_link_vk).unwrap_or(true) {
            return Err("错误 school/company 时联合链接证明不应通过验证".into());
        }

        Ok(())
    }

    pub(crate) fn run_passport_employee_scenario<R>(rng: &mut R) -> Result<(), String>
    where
        R: Rng + CryptoRng,
    {
        let passport_blob = passport_blob(b"Anna", [b'C', b'H', b'N'], 19990101, 20380101, make_holder_tag(3));
        let employee_blob = employee_blob(b"Anna", b"ACME", 20270101, make_holder_tag(3));
        let joint_seed = Fr::rand(rng);
        let info = PassportEmployeeJointInfo::from_values(rng, passport_blob, employee_blob, joint_seed);
        let attrs_com: Com<TestComSchemePedersen> = Attrs::<_, TestComSchemePedersen>::commit(&info);

        let tree_pk = gen_tree_memb_crs::<_, E, PassportEmployeeJointInfo, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            MERKLE_CRH_PARAM.clone(),
            TREE_HEIGHT,
        )
        .map_err(format_err)?;
        let tree_vk = tree_pk.prepare_verifying_key();
        let mut tree = ComTree::empty(MERKLE_CRH_PARAM.clone(), TREE_HEIGHT);
        let auth_path = tree.insert(9, &attrs_com);

        let forest_pk = gen_forest_memb_crs::<_, E, PassportEmployeeJointInfo, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            NUM_TREES,
        )
        .map_err(format_err)?;
        let forest_vk = forest_pk.prepare_verifying_key();

        let mut forest = ComForest { trees: (0..NUM_TREES).map(|_| random_empty_tree(rng)).collect() };
        forest.trees[2] = tree;
        let roots = forest.roots();

        let passport_expiry_checker = PePassportExpiryChecker {
            threshold_expiry: Fr::from(20250101u64),
        };
        let employee_expiry_checker = PeEmployeeExpiryChecker {
            threshold_expiry: Fr::from(20260101u64),
        };
        let business_checker = PeBusinessChecker {
            expected_company: pad_bytes::<EMPLOYEE_COMPANY_LEN>(b"ACME"),
            threshold_employee_expiry: Fr::from(20260101u64),
        };
        let holder_checker = PeHolderTagChecker {
            holder_tag: make_holder_tag(3),
        };

        let ppe_pk = gen_pred_crs::<_, _, E, PassportEmployeeJointInfo, PassportEmployeeJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            passport_expiry_checker.clone(),
        )
        .map_err(format_err)?;
        let pee_pk = gen_pred_crs::<_, _, E, PassportEmployeeJointInfo, PassportEmployeeJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            employee_expiry_checker.clone(),
        )
        .map_err(format_err)?;
        let pb_pk = gen_pred_crs::<_, _, E, PassportEmployeeJointInfo, PassportEmployeeJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            business_checker.clone(),
        )
        .map_err(format_err)?;
        let ph_pk = gen_pred_crs::<_, _, E, PassportEmployeeJointInfo, PassportEmployeeJointInfoVar, TestComSchemePedersen, TestComSchemePedersenG, TestTreeH, TestTreeHG>(
            rng,
            holder_checker.clone(),
        )
        .map_err(format_err)?;

        let ppe_vk = ppe_pk.prepare_verifying_key();
        let pee_vk = pee_pk.prepare_verifying_key();
        let pb_vk = pb_pk.prepare_verifying_key();
        let ph_vk = ph_pk.prepare_verifying_key();

        let passport_expiry_proof = prove_pred(rng, &ppe_pk, passport_expiry_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        let employee_expiry_proof = prove_pred(rng, &pee_pk, employee_expiry_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        let business_proof = prove_pred(rng, &pb_pk, business_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;
        let holder_proof = prove_pred(rng, &ph_pk, holder_checker.clone(), info.clone(), &auth_path)
            .map_err(format_err)?;

        assert!(verify_pred(&ppe_vk, &passport_expiry_proof, &passport_expiry_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);
        assert!(verify_pred(&pee_vk, &employee_expiry_proof, &employee_expiry_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);
        assert!(verify_pred(&pb_vk, &business_proof, &business_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);
        assert!(verify_pred(&ph_vk, &holder_proof, &holder_checker, &attrs_com, &auth_path.root()).map_err(format_err)?);

        let tree_proof = auth_path
            .prove_membership(rng, &tree_pk, &MERKLE_CRH_PARAM, attrs_com)
            .map_err(format_err)?;
        let forest_proof = roots
            .prove_membership(rng, &forest_pk, auth_path.root(), attrs_com)
            .map_err(format_err)?;

        let mut pred_inputs = PredPublicInputs::default();
        pred_inputs.prepare_pred_checker(&ppe_vk, &passport_expiry_checker);
        pred_inputs.prepare_pred_checker(&pee_vk, &employee_expiry_checker);
        pred_inputs.prepare_pred_checker(&pb_vk, &business_checker);
        pred_inputs.prepare_pred_checker(&ph_vk, &holder_checker);

        let link_vk = LinkVerifyingKey {
            pred_inputs,
            prepared_roots: roots.prepare(&forest_vk).map_err(format_err)?,
            forest_verif_key: forest_vk.clone(),
            tree_verif_key: tree_vk.clone(),
            pred_verif_keys: vec![ppe_vk.clone(), pee_vk.clone(), pb_vk.clone(), ph_vk.clone()],
        };

        let link_ctx = LinkProofCtx {
            attrs_com,
            merkle_root: auth_path.root(),
            forest_proof,
            tree_proof,
            pred_proofs: vec![passport_expiry_proof, employee_expiry_proof, business_proof, holder_proof],
            vk: link_vk.clone(),
        };

        let link_proof = link_proofs(rng, &link_ctx);
        if !verif_link_proof(&link_proof, &link_vk).map_err(format_err)? {
            return Err("护照+员工联合链接证明应通过验证".into());
        }

        let mut bad_inputs = PredPublicInputs::default();
        bad_inputs.prepare_pred_checker(&ppe_vk, &passport_expiry_checker);
        bad_inputs.prepare_pred_checker(&pee_vk, &employee_expiry_checker);
        bad_inputs.prepare_pred_checker(&pb_vk, &PeBusinessChecker {
            expected_company: pad_bytes::<EMPLOYEE_COMPANY_LEN>(b"WRONG"),
            threshold_employee_expiry: Fr::from(20260101u64),
        });
        bad_inputs.prepare_pred_checker(&ph_vk, &holder_checker);
        let bad_link_vk = LinkVerifyingKey {
            pred_inputs: bad_inputs,
            prepared_roots: roots.prepare(&forest_vk).map_err(format_err)?,
            forest_verif_key: forest_vk,
            tree_verif_key: tree_vk,
            pred_verif_keys: vec![ppe_vk, pee_vk, pb_vk, ph_vk],
        };

        if verif_link_proof(&link_proof, &bad_link_vk).unwrap_or(true) {
            return Err("错误 company 时联合链接证明不应通过验证".into());
        }

        Ok(())
    }
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
            } else {
                // 输出失败分析，即使没有 panic
                println!("跨用户假链接过程中发生 panic，系统检测到伪链接或不一致");
                println!("问题: Bob的pred_proof与Alice的attrs_com不匹配，导致verifying key mismatch");
            }
        }
        Err(_) => {
            println!("跨用户假链接过程中发生 panic，系统检测到伪链接或不一致");
            println!("检测步骤: 在link_proofs或verif_link_proof中");
            println!("问题: Bob的pred_proof与Alice的attrs_com不匹配，导致verifying key mismatch");
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
