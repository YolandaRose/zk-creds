use crate::credentials::passport::ark_sha256::Sha256Gadget;
use crate::credentials::employee_id::params::{
    Fr, PredProof, EmployeeComScheme, EmployeeComSchemeG, DEPARTMENT_LEN, NAME_LEN, RECORD_BLOB_LEN,
    COMPANY_LEN, EMPLOYEE_NO_LEN,
};
use crate::credentials::employee_id::employee_info::{EmployeeInfo, EmployeeInfoVar};

use zkcreds::{pred::PredicateChecker, Com};

use ark_ff::ToConstraintField;
use ark_r1cs_std::{
    bits::{boolean::Boolean, uint8::UInt8, ToBitsGadget},
    eq::EqGadget,
    fields::fp::FpVar,
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

pub(crate) struct EmployeeIssuanceReq {
    pub(crate) attrs_com: Com<EmployeeComScheme>,
    pub(crate) record_digest: [u8; 32],
    pub(crate) sig: Vec<u8>,
    pub(crate) hash_proof: PredProof,
}

#[derive(Clone)]
pub(crate) struct EmployeeRecordHashChecker {
    record_digest: [u8; 32],
    blob: [u8; RECORD_BLOB_LEN],
}

impl Default for EmployeeRecordHashChecker {
    fn default() -> Self {
        EmployeeRecordHashChecker {
            record_digest: [0u8; 32],
            blob: [0u8; RECORD_BLOB_LEN],
        }
    }
}

impl EmployeeRecordHashChecker {
    pub(crate) fn from_holder(info: &EmployeeInfo) -> Self {
        let blob = info.record_blob();
        let record_digest = Sha256::digest(&blob).into();
        EmployeeRecordHashChecker {
            record_digest,
            blob,
        }
    }

    pub(crate) fn from_issuance_req(req: &EmployeeIssuanceReq) -> Self {
        EmployeeRecordHashChecker {
            record_digest: req.record_digest,
            blob: [0u8; RECORD_BLOB_LEN],
        }
    }
}

impl PredicateChecker<Fr, EmployeeInfo, EmployeeInfoVar, EmployeeComScheme, EmployeeComSchemeG>
    for EmployeeRecordHashChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &EmployeeInfoVar,
    ) -> Result<(), SynthesisError> {
        let record_digest =
            UInt8::new_input_vec(ns!(cs, "employee record digest"), &self.record_digest)?;
        let blob_w = UInt8::new_witness_vec(ns!(cs, "employee record blob"), &self.blob)?;
        let h = Sha256Gadget::digest(&blob_w)?;
        record_digest.enforce_equal(&h.0)?;

        let mut o = 0usize;
        let name = &blob_w[o..o + NAME_LEN];
        o += NAME_LEN;
        let company = &blob_w[o..o + COMPANY_LEN];
        o += COMPANY_LEN;
        let department = &blob_w[o..o + DEPARTMENT_LEN];
        o += DEPARTMENT_LEN;
        let employee_no = &blob_w[o..o + EMPLOYEE_NO_LEN];
        o += EMPLOYEE_NO_LEN;
        let ey_b = &blob_w[o..o + 4];
        o += 4;
        let ex_b = &blob_w[o..o + 4];

        name.enforce_equal(&attrs.name.0)?;
        company.enforce_equal(&attrs.company.0)?;
        department.enforce_equal(&attrs.department.0)?;
        employee_no.enforce_equal(&attrs.employee_no.0)?;

        let ey = u32_be_bytes_to_fp(ey_b)?;
        let ex = u32_be_bytes_to_fp(ex_b)?;
        ey.enforce_equal(&attrs.hire_year)?;
        ex.enforce_equal(&attrs.card_expiry)?;

        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        self.record_digest.to_field_elements().unwrap()
    }
}

