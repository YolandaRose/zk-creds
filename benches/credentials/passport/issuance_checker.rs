use crate::credentials::passport::{
    ark_sha256::Sha256Gadget,
    params::{
        Fr, PassportComScheme, PassportComSchemeG, PredProof, BIOMETRIC_RAW_MAX, HASH_LEN,
        NAME_LEN, RECORD_BLOB_LEN, STATE_ID_LEN,
    },
    passport_info::{PersonalInfo, PersonalInfoVar},
};

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

pub(crate) struct IssuanceReq {
    pub(crate) attrs_com: Com<PassportComScheme>,
    pub(crate) record_digest: [u8; HASH_LEN],
    pub(crate) sig: Vec<u8>,
    pub(crate) hash_proof: PredProof,
}

#[derive(Clone)]
pub(crate) struct PassportRecordHashChecker {
    record_digest: [u8; HASH_LEN],
    blob: [u8; RECORD_BLOB_LEN],
}

impl Default for PassportRecordHashChecker {
    fn default() -> Self {
        PassportRecordHashChecker {
            record_digest: [0u8; HASH_LEN],
            blob: [0u8; RECORD_BLOB_LEN],
        }
    }
}

impl PassportRecordHashChecker {
    pub(crate) fn from_holder(info: &PersonalInfo) -> Self {
        let blob = info.record_blob();
        let record_digest = Sha256::digest(&blob).into();
        PassportRecordHashChecker {
            record_digest,
            blob,
        }
    }

    pub(crate) fn from_issuance_req(req: &IssuanceReq) -> Self {
        PassportRecordHashChecker {
            record_digest: req.record_digest,
            blob: [0u8; RECORD_BLOB_LEN],
        }
    }
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for PassportRecordHashChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        let record_digest =
            UInt8::new_input_vec(ns!(cs, "passport record digest"), &self.record_digest)?;
        let blob_w = UInt8::new_witness_vec(ns!(cs, "passport record blob"), &self.blob)?;
        let h = Sha256Gadget::digest(&blob_w)?;
        record_digest.enforce_equal(&h.0)?;

        let mut o = 0usize;
        let nationality = &blob_w[o..o + STATE_ID_LEN];
        o += STATE_ID_LEN;
        let name = &blob_w[o..o + NAME_LEN];
        o += NAME_LEN;
        let dob_b = &blob_w[o..o + 4];
        o += 4;
        let exp_b = &blob_w[o..o + 4];
        o += 4;
        let bio_raw = &blob_w[o..o + BIOMETRIC_RAW_MAX];

        nationality.enforce_equal(&attrs.nationality.0)?;
        name.enforce_equal(&attrs.name.0)?;

        let dob = u32_be_bytes_to_fp(dob_b)?;
        let exp = u32_be_bytes_to_fp(exp_b)?;
        dob.enforce_equal(&attrs.dob)?;
        exp.enforce_equal(&attrs.passport_expiry)?;

        let bio_h = Sha256Gadget::digest(bio_raw)?;
        bio_h.0.enforce_equal(&attrs.biometric_hash.0)?;

        Ok(())
    }

    fn public_inputs(&self) -> Vec<Fr> {
        self.record_digest.to_field_elements().unwrap()
    }
}
