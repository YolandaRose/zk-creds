use crate::credentials::passport::ark_sha256::Sha256Gadget;
use crate::credentials::student_id::params::{
    Fr, PredProof, StudentComScheme, StudentComSchemeG, COLLEGE_LEN, NAME_LEN, RECORD_BLOB_LEN,
    SCHOOL_LEN, STUDENT_NO_LEN,
};
use crate::credentials::student_id::student_info::{StudentInfo, StudentInfoVar};

use zkcreds::{pred::PredicateChecker, Com};

use ark_ff::ToConstraintField;
use ark_r1cs_std::{
    bits::{boolean::Boolean, uint8::UInt8, ToBitsGadget},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use sha2::{Digest, Sha256};

fn u32_be_bytes_to_fp(bytes: &[UInt8<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    assert_eq!(bytes.len(), 4);
    let mut acc = FpVar::<Fr>::zero();
    let base = FpVar::constant(Fr::from(256u16));
    for b in bytes {
        let v = Boolean::le_bits_to_fp_var(&b.to_bits_le()?)?;
        acc = acc * &base + &v;
    }
    Ok(acc)
}

pub(crate) struct StudentIssuanceReq {
    pub(crate) attrs_com: Com<StudentComScheme>,
    pub(crate) record_digest: [u8; 32],
    pub(crate) sig: Vec<u8>,
    pub(crate) hash_proof: PredProof,
}

#[derive(Clone)]
pub(crate) struct StudentRecordHashChecker {
    record_digest: [u8; 32],
    blob: [u8; RECORD_BLOB_LEN],
}

impl Default for StudentRecordHashChecker {
    fn default() -> Self {
        StudentRecordHashChecker {
            record_digest: [0u8; 32],
            blob: [0u8; RECORD_BLOB_LEN],
        }
    }
}

impl StudentRecordHashChecker {
    pub(crate) fn from_holder(info: &StudentInfo) -> Self {
        let blob = info.record_blob();
        let record_digest = Sha256::digest(&blob).into();
        StudentRecordHashChecker {
            record_digest,
            blob,
        }
    }

    pub(crate) fn from_issuance_req(req: &StudentIssuanceReq) -> Self {
        StudentRecordHashChecker {
            record_digest: req.record_digest,
            blob: [0u8; RECORD_BLOB_LEN],
        }
    }
}

impl PredicateChecker<Fr, StudentInfo, StudentInfoVar, StudentComScheme, StudentComSchemeG>
    for StudentRecordHashChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &StudentInfoVar,
    ) -> Result<(), SynthesisError> {
        let record_digest =
            UInt8::new_input_vec(ns!(cs, "student record digest"), &self.record_digest)?;
        let blob_w = UInt8::new_witness_vec(ns!(cs, "student record blob"), &self.blob)?;
        let h = Sha256Gadget::digest(&blob_w)?;
        record_digest.enforce_equal(&h.0)?;

        let mut o = 0usize;
        let name = &blob_w[o..o + NAME_LEN];
        o += NAME_LEN;
        let school = &blob_w[o..o + SCHOOL_LEN];
        o += SCHOOL_LEN;
        let college = &blob_w[o..o + COLLEGE_LEN];
        o += COLLEGE_LEN;
        let student_no = &blob_w[o..o + STUDENT_NO_LEN];
        o += STUDENT_NO_LEN;
        let ey_b = &blob_w[o..o + 4];
        o += 4;
        let ex_b = &blob_w[o..o + 4];

        name.enforce_equal(&attrs.name.0)?;
        school.enforce_equal(&attrs.school.0)?;
        college.enforce_equal(&attrs.college.0)?;
        student_no.enforce_equal(&attrs.student_no.0)?;

        let ey = u32_be_bytes_to_fp(ey_b)?;
        let ex = u32_be_bytes_to_fp(ex_b)?;
        ey.enforce_equal(&attrs.enrollment_year)?;
        ex.enforce_equal(&attrs.card_expiry)?;

        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        self.record_digest.to_field_elements().unwrap()
    }
}
