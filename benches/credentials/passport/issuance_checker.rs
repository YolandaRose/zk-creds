use crate::credentials::passport::{
    ark_sha256::Sha256Gadget,
    params::{
        Fr, PassportComScheme, PassportComSchemeG, PredProof, DATE_LEN, DG1_HASH_OFFSET, DG1_LEN,
        DG2_HASH_OFFSET, DOB_OFFSET, ECONTENT_LEN, EXPIRY_OFFSET, HASH_LEN, ISSUER_OFFSET,
        NAME_LEN, NAME_OFFSET, NATIONALITY_OFFSET, PRE_ECONTENT_HASH_OFFSET, PRE_ECONTENT_LEN,
        SIG_HASH_LEN, STATE_ID_LEN,
    },
    passport_dump::PassportDump,
    passport_info::{PersonalInfo, PersonalInfoVar},
};

use zkcreds::{pred::PredicateChecker, Com};

use ark_ff::ToConstraintField;
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{uint8::UInt8, ToBitsGadget},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use sha2::{Digest, Sha256};

// 发出attrs_com的请求。这包括一个打开属性的证明和一个签名对应护照的内容散列
pub(crate) struct IssuanceReq {
    pub(crate) attrs_com: Com<PassportComScheme>,
    pub(crate) econtent_hash: [u8; HASH_LEN],
    pub(crate) sig: Vec<u8>,
    pub(crate) hash_proof: PredProof,
}

// 验证给定的护照内容散列是否正确，并且提供的`PersonalInfo`是否对应其内容。
#[derive(Clone)]
pub(crate) struct PassportHashChecker {
    // Public inputs
    econtent_hash: [u8; SIG_HASH_LEN],
    expected_issuer: [u8; STATE_ID_LEN],
    today: Fr,
    max_valid_years: Fr,

    // Private inputs
    dg1: [u8; DG1_LEN],
    pre_econtent: [u8; PRE_ECONTENT_LEN],
    econtent: [u8; ECONTENT_LEN],
}

impl Default for PassportHashChecker {
    fn default() -> PassportHashChecker {
        PassportHashChecker {
            econtent_hash: [0u8; SIG_HASH_LEN],
            expected_issuer: [0u8; STATE_ID_LEN],
            today: Fr::default(),
            max_valid_years: Fr::default(),
            dg1: [0u8; DG1_LEN],
            pre_econtent: [0u8; PRE_ECONTENT_LEN],
            econtent: [0u8; ECONTENT_LEN],
        }
    }
}

impl PassportHashChecker {
    // 从护照、3字母发行国和今天的日期（YYYYMMDD格式）创建一个颁发检查器。
    // `max_valid_years`是护照最长有效期，以年为单位。
    pub(crate) fn from_passport(
        dump: &PassportDump,
        expected_issuer: [u8; STATE_ID_LEN],
        today: u32,
        max_valid_years: u32,
    ) -> PassportHashChecker {
        let mut dg1 = [0u8; DG1_LEN];
        let mut pre_econtent = [0u8; PRE_ECONTENT_LEN];
        let mut econtent = [0u8; ECONTENT_LEN];
        let mut econtent_hash = [0u8; SIG_HASH_LEN];

        dg1.copy_from_slice(&dump.dg1);
        pre_econtent.copy_from_slice(&dump.pre_econtent);
        econtent.copy_from_slice(&dump.econtent);
        econtent_hash.copy_from_slice(&Sha256::digest(econtent));

        PassportHashChecker {
            econtent_hash,
            expected_issuer,
            today: Fr::from(today),
            max_valid_years: Fr::from(max_valid_years),
            dg1,
            pre_econtent,
            econtent,
        }
    }

    // 从颁发请求、3字母发行国和今天的日期（YYYYMMDD格式）创建一个颁发检查器。
    // `max_valid_years`是护照最长有效期，以年为单位。
    pub(crate) fn from_issuance_req(
        req: &IssuanceReq,
        expected_issuer: [u8; STATE_ID_LEN],
        today: u32,
        max_valid_years: u32,
    ) -> PassportHashChecker {
        PassportHashChecker {
            econtent_hash: req.econtent_hash,
            expected_issuer,
            today: Fr::from(today),
            max_valid_years: Fr::from(max_valid_years),
            ..Default::default()
        }
    }
}

// 将YYMMDD格式的日期字符串转换为字段元素，其规范的十进制表示为YYYYMMDD。
// `not_after`是21世纪最早的一天，在此之后输入将不符合逻辑，例如，出生日期如果超过今天将不符合逻辑，而护照有效期如果超过20年将不符合逻辑。
fn date_to_field_elem(
    date: &[UInt8<Fr>],
    not_after: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    assert_eq!(date.len(), DATE_LEN);

    // 常量
    let ten = Fr::from(10u16);
    let zero = FpVar::Constant(Fr::from(0u32));
    let century = FpVar::Constant(Fr::from(1000000u32));
    let twenty_first_century = &century * Fr::from(20u32);

    // 将ASCII数字转换为它们表示的数字。例如，int(b"9") = 9 (mod |Fr|)
    fn int(char: &UInt8<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        let char_fp = Boolean::le_bits_to_fp_var(char.to_bits_le()?.as_slice())?;
        Ok(char_fp - Fr::from(48u16))
    }

    // 分别转换年、月和日。b"YY"成为YY (mod |Fr|), etc.
    let year = (int(&date[0])? * ten) + int(&date[1])?;
    let month = (int(&date[2])? * ten) + int(&date[3])?;
    let day = (int(&date[4])? * ten) + int(&date[5])?;

    // 现在通过移位和添加来组合值。年份只给出为YY，所以我们不立即拥有年份的最高有效数字。目前假设它是21世纪
    let mut d =
        twenty_first_century + (year * Fr::from(10000u16)) + (month * Fr::from(100u16)) + day;

    // 如果日期不是21世纪，那么d将在未来。如果是这样的话，那就去掉100年    
    let overshot_century = d.is_cmp(not_after, core::cmp::Ordering::Greater, false)?;
    let delta = CondSelectGadget::conditionally_select(&overshot_century, &century, &zero)?;
    // 减去delta，如果超过世纪，则为100
    d -= delta;

    Ok(d)
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for PassportHashChecker
{
    // 强制给定的护照信息散列到给定的econtent散列。构造econtent的过程很复杂，所以这是多个步骤
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        // 见证公共输入
        let econtent_hash = UInt8::new_input_vec(ns!(cs, "econtent hash"), &self.econtent_hash)?;
        let expected_issuer =
            UInt8::new_input_vec(ns!(cs, "expected issuer"), &self.expected_issuer)?;
        let today = FpVar::<Fr>::new_input(ns!(cs, "DOB threshold"), || Ok(self.today))?;
        let max_valid_years =
            FpVar::<Fr>::new_input(ns!(cs, "max valid years"), || Ok(self.max_valid_years))?;

        // 最早的时间，在此之后有效期将不符合逻辑。这用于解析护照中的未定义日期格式
        let expiry_not_after = today.clone() + max_valid_years * Fr::from(10000u32);
        // 最早的时间，在此之后出生日期将不符合逻辑。这正是今天，因为你不能在未来出生 >.>
        let dob_not_after = today.clone();

        // 见证私有输入
        let dg1 = UInt8::new_witness_vec(ns!(cs, "dg1"), &self.dg1)?;
        let pre_econtent = UInt8::new_witness_vec(ns!(cs, "pre-econtent"), &self.pre_econtent)?;
        let econtent = UInt8::new_witness_vec(ns!(cs, "econtent"), &self.econtent)?;

        // 检查发行国是否是预期的，并且护照是否未过期
        dg1[ISSUER_OFFSET..ISSUER_OFFSET + STATE_ID_LEN].enforce_equal(&expected_issuer)?;
        let expiry = date_to_field_elem(
            &dg1[EXPIRY_OFFSET..EXPIRY_OFFSET + DATE_LEN],
            &expiry_not_after,
        )?;
        expiry.enforce_cmp(&today, core::cmp::Ordering::Greater, false)?;

        // 检查属性名称、国籍和出生日期是否与护照匹配
        dg1[NATIONALITY_OFFSET..NATIONALITY_OFFSET + STATE_ID_LEN]
            .enforce_equal(&attrs.nationality.0)?;
        dg1[NAME_OFFSET..NAME_OFFSET + NAME_LEN].enforce_equal(&attrs.name.0)?;
        let dob = date_to_field_elem(&dg1[DOB_OFFSET..DOB_OFFSET + DATE_LEN], &dob_not_after)?;
        dob.enforce_equal(&attrs.dob)?;

        // 检查pre-econtent结构，并检查生物特征散列是否与护照匹配
        let dg1_hash = Sha256Gadget::digest(&dg1)?;
        let dg2_hash = &attrs.biometric_hash.0;
        pre_econtent[DG1_HASH_OFFSET..DG1_HASH_OFFSET + HASH_LEN].enforce_equal(&dg1_hash.0)?;
        pre_econtent[DG2_HASH_OFFSET..DG2_HASH_OFFSET + HASH_LEN].enforce_equal(dg2_hash)?;

        // 检查econtent结构
        let pre_econtent_hash = Sha256Gadget::digest(&pre_econtent)?;
        econtent[PRE_ECONTENT_HASH_OFFSET..PRE_ECONTENT_HASH_OFFSET + HASH_LEN]
            .enforce_equal(&pre_econtent_hash.0)?;

        // 检查econtent散列是否与护照匹配
        econtent_hash.enforce_equal(&Sha256Gadget::digest(&econtent)?.0)?;

        // 全部完成
        Ok(())
    }

    // 公共输入是: econtent_hash, expected_issuer, today
    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.econtent_hash.to_field_elements().unwrap(),
            self.expected_issuer.to_field_elements().unwrap(),
            vec![self.today],
            vec![self.max_valid_years],
        ]
        .concat()
    }
}
