//! 联合记录 `SHA256(blob_a || blob_b)` 与见证一致（发行谓词）；不验证 RSA。

use crate::credentials::joint::params::{
    Fr, JointComScheme, JointComSchemeG, EMPLOYEE_RECORD_LEN, PASSPORT_RECORD_LEN, PE_JOINT_LEN,
    PS_JOINT_LEN, SE_JOINT_LEN, STUDENT_RECORD_LEN,
};
use crate::credentials::joint::passport_employee::{
    PassportEmployeeJointInfo, PassportEmployeeJointInfoVar,
};
use crate::credentials::joint::passport_student::{
    PassportStudentJointInfo, PassportStudentJointInfoVar,
};
use crate::credentials::joint::student_employee::{
    StudentEmployeeJointInfo, StudentEmployeeJointInfoVar,
};

use crate::credentials::passport::ark_sha256::Sha256Gadget;

use zkcreds::pred::PredicateChecker;

use ark_ff::ToConstraintField;
use ark_r1cs_std::{bits::uint8::UInt8, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use sha2::Digest;

#[derive(Clone)]
pub(crate) struct SeJointHashChecker {
    pub(crate) record_digest: [u8; 32],
    pub(crate) blob: [u8; SE_JOINT_LEN],
}

impl Default for SeJointHashChecker {
    fn default() -> Self {
        Self {
            record_digest: [0u8; 32],
            blob: [0u8; SE_JOINT_LEN],
        }
    }
}

impl SeJointHashChecker {
    pub(crate) fn from_info(info: &StudentEmployeeJointInfo) -> Self {
        let blob = info.joint_blob();
        let record_digest = sha2::Sha256::digest(&blob).into();
        Self {
            record_digest,
            blob,
        }
    }
}

impl
    PredicateChecker<
        Fr,
        StudentEmployeeJointInfo,
        StudentEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
    > for SeJointHashChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &StudentEmployeeJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let record_digest =
            UInt8::new_input_vec(ns!(cs, "se joint record digest"), &self.record_digest)?;
        let blob_w = UInt8::new_witness_vec(ns!(cs, "se joint blob"), &self.blob)?;
        let h = Sha256Gadget::digest(&blob_w)?;
        record_digest.enforce_equal(&h.0)?;
        attrs
            .student_blob
            .0
            .enforce_equal(&blob_w[..STUDENT_RECORD_LEN])?;
        attrs
            .employee_blob
            .0
            .enforce_equal(&blob_w[STUDENT_RECORD_LEN..SE_JOINT_LEN])?;
        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        self.record_digest.to_field_elements().unwrap()
    }
}

#[derive(Clone)]
pub(crate) struct PsJointHashChecker {
    pub(crate) record_digest: [u8; 32],
    pub(crate) blob: [u8; PS_JOINT_LEN],
}

impl Default for PsJointHashChecker {
    fn default() -> Self {
        Self {
            record_digest: [0u8; 32],
            blob: [0u8; PS_JOINT_LEN],
        }
    }
}

impl PsJointHashChecker {
    pub(crate) fn from_info(info: &PassportStudentJointInfo) -> Self {
        let blob = info.joint_blob();
        let record_digest = sha2::Sha256::digest(&blob).into();
        Self {
            record_digest,
            blob,
        }
    }
}

impl
    PredicateChecker<
        Fr,
        PassportStudentJointInfo,
        PassportStudentJointInfoVar,
        JointComScheme,
        JointComSchemeG,
    > for PsJointHashChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PassportStudentJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let record_digest =
            UInt8::new_input_vec(ns!(cs, "ps joint record digest"), &self.record_digest)?;
        let blob_w = UInt8::new_witness_vec(ns!(cs, "ps joint blob"), &self.blob)?;
        let h = Sha256Gadget::digest(&blob_w)?;
        record_digest.enforce_equal(&h.0)?;
        attrs
            .passport_blob
            .0
            .enforce_equal(&blob_w[..PASSPORT_RECORD_LEN])?;
        attrs
            .student_blob
            .0
            .enforce_equal(&blob_w[PASSPORT_RECORD_LEN..PS_JOINT_LEN])?;
        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        self.record_digest.to_field_elements().unwrap()
    }
}

#[derive(Clone)]
pub(crate) struct PeJointHashChecker {
    pub(crate) record_digest: [u8; 32],
    pub(crate) blob: [u8; PE_JOINT_LEN],
}

impl Default for PeJointHashChecker {
    fn default() -> Self {
        Self {
            record_digest: [0u8; 32],
            blob: [0u8; PE_JOINT_LEN],
        }
    }
}

impl PeJointHashChecker {
    pub(crate) fn from_info(info: &PassportEmployeeJointInfo) -> Self {
        let blob = info.joint_blob();
        let record_digest = sha2::Sha256::digest(&blob).into();
        Self {
            record_digest,
            blob,
        }
    }
}

impl
    PredicateChecker<
        Fr,
        PassportEmployeeJointInfo,
        PassportEmployeeJointInfoVar,
        JointComScheme,
        JointComSchemeG,
    > for PeJointHashChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PassportEmployeeJointInfoVar,
    ) -> Result<(), SynthesisError> {
        let record_digest =
            UInt8::new_input_vec(ns!(cs, "pe joint record digest"), &self.record_digest)?;
        let blob_w = UInt8::new_witness_vec(ns!(cs, "pe joint blob"), &self.blob)?;
        let h = Sha256Gadget::digest(&blob_w)?;
        record_digest.enforce_equal(&h.0)?;
        attrs
            .passport_blob
            .0
            .enforce_equal(&blob_w[..PASSPORT_RECORD_LEN])?;
        attrs
            .employee_blob
            .0
            .enforce_equal(&blob_w[PASSPORT_RECORD_LEN..PE_JOINT_LEN])?;
        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        self.record_digest.to_field_elements().unwrap()
    }
}
