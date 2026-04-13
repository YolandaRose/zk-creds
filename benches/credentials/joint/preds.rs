//! 联合凭证谓词：跨凭证姓名一致 + 场景特定属性校验（按固定 blob 布局解析）。

use crate::credentials::joint::circuit_util::u32_be_bytes_to_fp;
use crate::credentials::joint::params::{
    Fr, JointComScheme, JointComSchemeG, PASSPORT_EXPIRY_OFFSET,
};
use crate::credentials::joint::passport_employee::PassportEmployeeJointInfoVar;
use crate::credentials::joint::passport_student::PassportStudentJointInfoVar;
use crate::credentials::joint::student_employee::StudentEmployeeJointInfoVar;

use zkcreds::pred::PredicateChecker;

use ark_ff::ToConstraintField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    uint8::UInt8,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use core::cmp::Ordering;

use zkcreds::Bytestring;

// --- 固定布局偏移（与各单凭证 params/info 一致）---
const STUDENT_NAME_OFF: usize = 0;
const STUDENT_NAME_LEN: usize = 32;
const STUDENT_SCHOOL_OFF: usize = 32;
const STUDENT_SCHOOL_LEN: usize = 32;

const EMPLOYEE_NAME_OFF: usize = 0;
const EMPLOYEE_NAME_LEN: usize = 32;
const EMPLOYEE_COMPANY_OFF: usize = 32;
const EMPLOYEE_COMPANY_LEN: usize = 32;

const PASSPORT_NATIONALITY_OFF: usize = 0;
const PASSPORT_NATIONALITY_LEN: usize = 3;
const PASSPORT_NAME_OFF: usize = 3;
const PASSPORT_NAME_LEN: usize = 39;
const PASSPORT_DOB_OFF: usize = 3 + 39;

fn card_expiry_tail_fr(blob: &Bytestring<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let n = blob.0.len();
    u32_be_bytes_to_fp(&blob.0[n - 4..n])
}

fn passport_expiry_fr(blob: &Bytestring<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    u32_be_bytes_to_fp(&blob.0[PASSPORT_EXPIRY_OFFSET..PASSPORT_EXPIRY_OFFSET + 4])
}

use crate::credentials::joint::passport_employee::PassportEmployeeJointInfo;
use crate::credentials::joint::passport_student::PassportStudentJointInfo;
use crate::credentials::joint::student_employee::StudentEmployeeJointInfo;

// --- 学生–员工（校企合作）：姓名一致 + 学校/公司名匹配 + 可选：有效期 ---
#[derive(Clone)]
pub(crate) struct SeNameSchoolCompanyChecker {
    pub(crate) expected_school: [u8; STUDENT_SCHOOL_LEN],
    pub(crate) expected_company: [u8; EMPLOYEE_COMPANY_LEN],
}

impl PredicateChecker<Fr, StudentEmployeeJointInfo, StudentEmployeeJointInfoVar, JointComScheme, JointComSchemeG>
    for SeNameSchoolCompanyChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &StudentEmployeeJointInfoVar,
    ) -> Result<(), SynthesisError> {
        // public: expected school/company (字节作为公共输入，便于不同场景复用)
        let expected_school =
            UInt8::new_input_vec(ns!(cs, "expected school"), &self.expected_school)?;
        let expected_company =
            UInt8::new_input_vec(ns!(cs, "expected company"), &self.expected_company)?;

        // name equality: student.name == employee.name
        attrs.student_blob.0[STUDENT_NAME_OFF..STUDENT_NAME_OFF + STUDENT_NAME_LEN]
            .enforce_equal(&attrs.employee_blob.0[EMPLOYEE_NAME_OFF..EMPLOYEE_NAME_OFF + EMPLOYEE_NAME_LEN])?;

        // student.school == expected_school
        attrs.student_blob.0[STUDENT_SCHOOL_OFF..STUDENT_SCHOOL_OFF + STUDENT_SCHOOL_LEN]
            .enforce_equal(&expected_school)?;

        // employee.company == expected_company
        attrs.employee_blob.0[EMPLOYEE_COMPANY_OFF..EMPLOYEE_COMPANY_OFF + EMPLOYEE_COMPANY_LEN]
            .enforce_equal(&expected_company)?;

        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.expected_school.to_field_elements().unwrap(),
            self.expected_company.to_field_elements().unwrap(),
        ]
        .concat()
    }
}

#[derive(Clone)]
pub(crate) struct SeStudentExpiryChecker {
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, StudentEmployeeJointInfo, StudentEmployeeJointInfoVar, JointComScheme, JointComSchemeG>
    for SeStudentExpiryChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &StudentEmployeeJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let threshold =
            FpVar::<Fr>::new_input(ns!(cs, "se student expiry threshold"), || {
                Ok(self.threshold_expiry)
            })?;
        let ex = card_expiry_tail_fr(&attrs.student_blob)?;
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

impl PredicateChecker<Fr, StudentEmployeeJointInfo, StudentEmployeeJointInfoVar, JointComScheme, JointComSchemeG>
    for SeEmployeeExpiryChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &StudentEmployeeJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let threshold =
            FpVar::<Fr>::new_input(ns!(cs, "se employee expiry threshold"), || {
                Ok(self.threshold_expiry)
            })?;
        let ex = card_expiry_tail_fr(&attrs.employee_blob)?;
        ex.enforce_cmp(&threshold, Ordering::Greater, false)
    }

    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_expiry]
    }
}

// --- 护照–学生（国际优惠/机票）：姓名一致 + 年龄(以阈值 DOB) + 国籍 ---
#[derive(Clone)]
pub(crate) struct PsTicketChecker {
    /// 年龄下限通过 `dob <= threshold_dob` 表达（threshold_dob 由验证者给出）
    pub(crate) threshold_dob: Fr,
    /// 允许的国籍（固定 3 字节国家码，例如 "CHN"）
    pub(crate) expected_nationality: [u8; PASSPORT_NATIONALITY_LEN],
}

impl PredicateChecker<Fr, PassportStudentJointInfo, PassportStudentJointInfoVar, JointComScheme, JointComSchemeG>
    for PsTicketChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PassportStudentJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let threshold_dob =
            FpVar::<Fr>::new_input(ns!(cs, "ticket threshold dob"), || Ok(self.threshold_dob))?;
        let expected_nat =
            UInt8::new_input_vec(ns!(cs, "expected nationality"), &self.expected_nationality)?;

        // passport nationality match
        attrs.passport_blob.0[PASSPORT_NATIONALITY_OFF..PASSPORT_NATIONALITY_OFF + PASSPORT_NATIONALITY_LEN]
            .enforce_equal(&expected_nat)?;

        // age: passport.dob <= threshold_dob
        let dob_fp = u32_be_bytes_to_fp(
            &attrs.passport_blob.0[PASSPORT_DOB_OFF..PASSPORT_DOB_OFF + 4],
        )?;
        dob_fp.enforce_cmp(&threshold_dob, Ordering::Less, true)?;

        // name equality: student.name == passport.name[0..32], and passport.name[32..] must be 0
        attrs.student_blob.0[STUDENT_NAME_OFF..STUDENT_NAME_OFF + STUDENT_NAME_LEN]
            .enforce_equal(&attrs.passport_blob.0[PASSPORT_NAME_OFF..PASSPORT_NAME_OFF + STUDENT_NAME_LEN])?;
        for b in &attrs.passport_blob.0[PASSPORT_NAME_OFF + STUDENT_NAME_LEN..PASSPORT_NAME_OFF + PASSPORT_NAME_LEN] {
            b.enforce_equal(&UInt8::constant(0u8))?;
        }

        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        [
            vec![self.threshold_dob],
            self.expected_nationality.to_field_elements().unwrap(),
        ]
        .concat()
    }
}

#[derive(Clone)]
pub(crate) struct PsPassportExpiryChecker {
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, PassportStudentJointInfo, PassportStudentJointInfoVar, JointComScheme, JointComSchemeG>
    for PsPassportExpiryChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PassportStudentJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let threshold =
            FpVar::<Fr>::new_input(ns!(cs, "ps passport expiry threshold"), || {
                Ok(self.threshold_expiry)
            })?;
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

impl PredicateChecker<Fr, PassportStudentJointInfo, PassportStudentJointInfoVar, JointComScheme, JointComSchemeG>
    for PsStudentExpiryChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PassportStudentJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let threshold =
            FpVar::<Fr>::new_input(ns!(cs, "ps student expiry threshold"), || {
                Ok(self.threshold_expiry)
            })?;
        let ex = card_expiry_tail_fr(&attrs.student_blob)?;
        ex.enforce_cmp(&threshold, Ordering::Greater, false)
    }

    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_expiry]
    }
}

// --- 护照–员工（跨境商务）：姓名一致 + 公司名匹配 + 工作证有效期 ---
#[derive(Clone)]
pub(crate) struct PeBusinessChecker {
    pub(crate) expected_company: [u8; EMPLOYEE_COMPANY_LEN],
    pub(crate) threshold_employee_expiry: Fr,
}

impl PredicateChecker<Fr, PassportEmployeeJointInfo, PassportEmployeeJointInfoVar, JointComScheme, JointComSchemeG>
    for PeBusinessChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PassportEmployeeJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let expected_company =
            UInt8::new_input_vec(ns!(cs, "expected company"), &self.expected_company)?;
        let threshold =
            FpVar::<Fr>::new_input(ns!(cs, "employee expiry threshold"), || {
                Ok(self.threshold_employee_expiry)
            })?;

        // employee expiry > threshold
        let ex = card_expiry_tail_fr(&attrs.employee_blob)?;
        ex.enforce_cmp(&threshold, Ordering::Greater, false)?;

        // employee company match
        attrs.employee_blob.0[EMPLOYEE_COMPANY_OFF..EMPLOYEE_COMPANY_OFF + EMPLOYEE_COMPANY_LEN]
            .enforce_equal(&expected_company)?;

        // name equality: employee.name == passport.name[0..32], and passport.name[32..] must be 0
        attrs.employee_blob.0[EMPLOYEE_NAME_OFF..EMPLOYEE_NAME_OFF + EMPLOYEE_NAME_LEN]
            .enforce_equal(&attrs.passport_blob.0[PASSPORT_NAME_OFF..PASSPORT_NAME_OFF + EMPLOYEE_NAME_LEN])?;
        for b in &attrs.passport_blob.0[PASSPORT_NAME_OFF + EMPLOYEE_NAME_LEN..PASSPORT_NAME_OFF + PASSPORT_NAME_LEN] {
            b.enforce_equal(&UInt8::constant(0u8))?;
        }

        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.expected_company.to_field_elements().unwrap(),
            vec![self.threshold_employee_expiry],
        ]
        .concat()
    }
}

#[derive(Clone)]
pub(crate) struct PePassportExpiryChecker {
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, PassportEmployeeJointInfo, PassportEmployeeJointInfoVar, JointComScheme, JointComSchemeG>
    for PePassportExpiryChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PassportEmployeeJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let threshold =
            FpVar::<Fr>::new_input(ns!(cs, "pe passport expiry threshold"), || {
                Ok(self.threshold_expiry)
            })?;
        let ex = passport_expiry_fr(&attrs.passport_blob)?;
        ex.enforce_cmp(&threshold, Ordering::Greater, false)
    }

    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_expiry]
    }
}

#[derive(Clone)]
pub(crate) struct PeEmployeeExpiryChecker {
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, PassportEmployeeJointInfo, PassportEmployeeJointInfoVar, JointComScheme, JointComSchemeG>
    for PeEmployeeExpiryChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PassportEmployeeJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let threshold =
            FpVar::<Fr>::new_input(ns!(cs, "pe employee expiry threshold"), || {
                Ok(self.threshold_expiry)
            })?;
        let ex = card_expiry_tail_fr(&attrs.employee_blob)?;
        ex.enforce_cmp(&threshold, Ordering::Greater, false)
    }

    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_expiry]
    }
}
