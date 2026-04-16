use crate::credentials::student_id::params::{
    StudentComScheme, StudentComSchemeG, COLLEGE_LEN, NAME_LEN, RECORD_BLOB_LEN, SCHOOL_LEN,
    STUDENT_COM_PARAM, STUDENT_NO_LEN,
};

use zkcreds::{
    attrs::{AccountableAttrs, AccountableAttrsVar, Attrs, AttrsVar},
    poseidon_utils::ComNonce,
    Bytestring, ComParam, ComParamVar,
};

use ark_ff::{to_bytes, UniformRand};
use ark_r1cs_std::{
    alloc::AllocVar, bits::ToBytesGadget, fields::fp::FpVar, uint8::UInt8, R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_std::rand::Rng;

#[derive(Clone)]
pub(crate) struct StudentInfo {
    nonce: ComNonce,
    pub(crate) seed: ark_bls12_381::Fr,
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) school: [u8; SCHOOL_LEN],
    pub(crate) college: [u8; COLLEGE_LEN],
    pub(crate) student_no: [u8; STUDENT_NO_LEN],
    pub(crate) enrollment_year: u32,
    pub(crate) card_expiry: u32,
}

impl Default for StudentInfo {
    fn default() -> Self {
        StudentInfo {
            nonce: ComNonce::default(),
            seed: ark_bls12_381::Fr::default(),
            name: [0u8; NAME_LEN],
            school: [0u8; SCHOOL_LEN],
            college: [0u8; COLLEGE_LEN],
            student_no: [0u8; STUDENT_NO_LEN],
            enrollment_year: 0,
            card_expiry: 0,
        }
    }
}

#[derive(Clone)]
pub(crate) struct StudentInfoVar {
    nonce: ComNonce,
    pub(crate) seed: FpVar<ark_bls12_381::Fr>,
    pub(crate) name: Bytestring<ark_bls12_381::Fr>,
    pub(crate) school: Bytestring<ark_bls12_381::Fr>,
    pub(crate) college: Bytestring<ark_bls12_381::Fr>,
    pub(crate) student_no: Bytestring<ark_bls12_381::Fr>,
    pub(crate) enrollment_year: FpVar<ark_bls12_381::Fr>,
    pub(crate) card_expiry: FpVar<ark_bls12_381::Fr>,
}

type Fr = ark_bls12_381::Fr;

impl StudentInfo {
    pub(crate) fn from_blob<R: Rng>(rng: &mut R, blob: &[u8; RECORD_BLOB_LEN]) -> StudentInfo {
        let mut off = 0usize;
        let mut take = |len: usize| -> &[u8] {
            let s = &blob[off..off + len];
            off += len;
            s
        };
        let mut name = [0u8; NAME_LEN];
        name.copy_from_slice(take(NAME_LEN));
        let mut school = [0u8; SCHOOL_LEN];
        school.copy_from_slice(take(SCHOOL_LEN));
        let mut college = [0u8; COLLEGE_LEN];
        college.copy_from_slice(take(COLLEGE_LEN));
        let mut student_no = [0u8; STUDENT_NO_LEN];
        student_no.copy_from_slice(take(STUDENT_NO_LEN));
        let ey = take(4);
        let enrollment_year = u32::from_be_bytes(ey.try_into().unwrap());
        let ex = take(4);
        let card_expiry = u32::from_be_bytes(ex.try_into().unwrap());

        StudentInfo {
            nonce: ComNonce::rand(rng),
            seed: Fr::rand(rng),
            name,
            school,
            college,
            student_no,
            enrollment_year,
            card_expiry,
        }
    }

    pub(crate) fn record_blob(&self) -> [u8; RECORD_BLOB_LEN] {
        let mut blob = [0u8; RECORD_BLOB_LEN];
        let mut off = 0usize;
        blob[off..off + NAME_LEN].copy_from_slice(&self.name);
        off += NAME_LEN;
        blob[off..off + SCHOOL_LEN].copy_from_slice(&self.school);
        off += SCHOOL_LEN;
        blob[off..off + COLLEGE_LEN].copy_from_slice(&self.college);
        off += COLLEGE_LEN;
        blob[off..off + STUDENT_NO_LEN].copy_from_slice(&self.student_no);
        off += STUDENT_NO_LEN;
        blob[off..off + 4].copy_from_slice(&self.enrollment_year.to_be_bytes());
        off += 4;
        blob[off..off + 4].copy_from_slice(&self.card_expiry.to_be_bytes());
        blob
    }
}

impl Attrs<Fr, StudentComScheme> for StudentInfo {
    fn to_bytes(&self) -> Vec<u8> {
        let ey = Fr::from(self.enrollment_year);
        let ex = Fr::from(self.card_expiry);
        to_bytes![
            self.seed,
            self.name,
            self.school,
            self.college,
            self.student_no,
            ey,
            ex
        ]
        .unwrap()
    }

    fn get_com_param(&self) -> &ComParam<StudentComScheme> {
        &*STUDENT_COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrs<Fr, StudentComScheme> for StudentInfo {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        self.student_no.to_vec()
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl ToBytesGadget<Fr> for StudentInfoVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([
            self.seed.to_bytes()?,
            self.name.0.to_bytes()?,
            self.school.0.to_bytes()?,
            self.college.0.to_bytes()?,
            self.student_no.0.to_bytes()?,
            self.enrollment_year.to_bytes()?,
            self.card_expiry.to_bytes()?,
        ]
        .concat())
    }
}

impl AttrsVar<Fr, StudentInfo, StudentComScheme, StudentComSchemeG> for StudentInfoVar {
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.seed
            .cs()
            .or(self.name.cs())
            .or(self.school.cs())
            .or(self.college.cs())
            .or(self.student_no.cs())
            .or(self.enrollment_year.cs())
            .or(self.card_expiry.cs())
    }

    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        attrs: &StudentInfo,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let nonce = attrs.nonce.clone();
        let seed = FpVar::<Fr>::new_witness(ns!(cs, "seed"), || Ok(attrs.seed))?;
        let name = Bytestring::new_witness(ns!(cs, "name"), || Ok(attrs.name.to_vec()))?;
        let school = Bytestring::new_witness(ns!(cs, "school"), || Ok(attrs.school.to_vec()))?;
        let college = Bytestring::new_witness(ns!(cs, "college"), || Ok(attrs.college.to_vec()))?;
        let student_no =
            Bytestring::new_witness(ns!(cs, "student_no"), || Ok(attrs.student_no.to_vec()))?;
        let enrollment_year = FpVar::<Fr>::new_witness(ns!(cs, "enrollment_year"), || {
            Ok(Fr::from(attrs.enrollment_year))
        })?;
        let card_expiry =
            FpVar::<Fr>::new_witness(ns!(cs, "card_expiry"), || Ok(Fr::from(attrs.card_expiry)))?;
        Ok(StudentInfoVar {
            nonce,
            seed,
            name,
            school,
            college,
            student_no,
            enrollment_year,
            card_expiry,
        })
    }

    fn get_com_param(
        &self,
    ) -> Result<ComParamVar<StudentComScheme, StudentComSchemeG, Fr>, SynthesisError> {
        let cs = self
            .name
            .cs()
            .or(self.school.cs())
            .or(self.college.cs())
            .or(self.student_no.cs())
            .or(self.enrollment_year.cs())
            .or(self.card_expiry.cs());
        ComParamVar::<_, StudentComSchemeG, _>::new_constant(cs, &*STUDENT_COM_PARAM)
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsVar<Fr, StudentInfo, StudentComScheme, StudentComSchemeG> for StudentInfoVar {
    type Id = Bytestring<Fr>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Bytestring<Fr>, SynthesisError> {
        Ok(self.student_no.clone())
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}
