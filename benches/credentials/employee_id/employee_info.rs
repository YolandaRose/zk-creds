use crate::credentials::employee_id::params::{
    EmployeeComScheme, EmployeeComSchemeG, COMPANY_LEN, DEPARTMENT_LEN, EMPLOYEE_COM_PARAM,
    EMPLOYEE_NO_LEN, NAME_LEN, RECORD_BLOB_LEN,
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
pub(crate) struct EmployeeInfo {
    nonce: ComNonce,
    pub(crate) seed: ark_bls12_381::Fr,
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) company: [u8; COMPANY_LEN],
    pub(crate) department: [u8; DEPARTMENT_LEN],
    pub(crate) employee_no: [u8; EMPLOYEE_NO_LEN],
    pub(crate) hire_year: u32,
    pub(crate) card_expiry: u32,
}

impl Default for EmployeeInfo {
    fn default() -> Self {
        EmployeeInfo {
            nonce: ComNonce::default(),
            seed: ark_bls12_381::Fr::default(),
            name: [0u8; NAME_LEN],
            company: [0u8; COMPANY_LEN],
            department: [0u8; DEPARTMENT_LEN],
            employee_no: [0u8; EMPLOYEE_NO_LEN],
            hire_year: 0,
            card_expiry: 0,
        }
    }
}

#[derive(Clone)]
pub(crate) struct EmployeeInfoVar {
    nonce: ComNonce,
    pub(crate) seed: FpVar<ark_bls12_381::Fr>,
    pub(crate) name: Bytestring<ark_bls12_381::Fr>,
    pub(crate) company: Bytestring<ark_bls12_381::Fr>,
    pub(crate) department: Bytestring<ark_bls12_381::Fr>,
    pub(crate) employee_no: Bytestring<ark_bls12_381::Fr>,
    pub(crate) hire_year: FpVar<ark_bls12_381::Fr>,
    pub(crate) card_expiry: FpVar<ark_bls12_381::Fr>,
}

type Fr = ark_bls12_381::Fr;

impl EmployeeInfo {
    pub(crate) fn from_blob<R: Rng>(rng: &mut R, blob: &[u8; RECORD_BLOB_LEN]) -> EmployeeInfo {
        let mut off = 0usize;
        let mut take = |len: usize| -> &[u8] {
            let s = &blob[off..off + len];
            off += len;
            s
        };
        let mut name = [0u8; NAME_LEN];
        name.copy_from_slice(take(NAME_LEN));
        let mut company = [0u8; COMPANY_LEN];
        company.copy_from_slice(take(COMPANY_LEN));
        let mut department = [0u8; DEPARTMENT_LEN];
        department.copy_from_slice(take(DEPARTMENT_LEN));
        let mut employee_no = [0u8; EMPLOYEE_NO_LEN];
        employee_no.copy_from_slice(take(EMPLOYEE_NO_LEN));
        let ey = take(4);
        let hire_year = u32::from_be_bytes(ey.try_into().unwrap());
        let ex = take(4);
        let card_expiry = u32::from_be_bytes(ex.try_into().unwrap());

        EmployeeInfo {
            nonce: ComNonce::rand(rng),
            seed: Fr::rand(rng),
            name,
            company,
            department,
            employee_no,
            hire_year,
            card_expiry,
        }
    }

    pub(crate) fn record_blob(&self) -> [u8; RECORD_BLOB_LEN] {
        let mut blob = [0u8; RECORD_BLOB_LEN];
        let mut off = 0usize;
        blob[off..off + NAME_LEN].copy_from_slice(&self.name);
        off += NAME_LEN;
        blob[off..off + COMPANY_LEN].copy_from_slice(&self.company);
        off += COMPANY_LEN;
        blob[off..off + DEPARTMENT_LEN].copy_from_slice(&self.department);
        off += DEPARTMENT_LEN;
        blob[off..off + EMPLOYEE_NO_LEN].copy_from_slice(&self.employee_no);
        off += EMPLOYEE_NO_LEN;
        blob[off..off + 4].copy_from_slice(&self.hire_year.to_be_bytes());
        off += 4;
        blob[off..off + 4].copy_from_slice(&self.card_expiry.to_be_bytes());
        blob
    }
}

impl Attrs<Fr, EmployeeComScheme> for EmployeeInfo {
    fn to_bytes(&self) -> Vec<u8> {
        let ey = Fr::from(self.hire_year);
        let ex = Fr::from(self.card_expiry);
        to_bytes![
            self.seed,
            self.name,
            self.company,
            self.department,
            self.employee_no,
            ey,
            ex
        ]
        .unwrap()
    }

    fn get_com_param(&self) -> &ComParam<EmployeeComScheme> {
        &*EMPLOYEE_COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrs<Fr, EmployeeComScheme> for EmployeeInfo {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        self.employee_no.to_vec()
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl ToBytesGadget<Fr> for EmployeeInfoVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([
            self.seed.to_bytes()?,
            self.name.0.to_bytes()?,
            self.company.0.to_bytes()?,
            self.department.0.to_bytes()?,
            self.employee_no.0.to_bytes()?,
            self.hire_year.to_bytes()?,
            self.card_expiry.to_bytes()?,
        ]
        .concat())
    }
}

impl AttrsVar<Fr, EmployeeInfo, EmployeeComScheme, EmployeeComSchemeG> for EmployeeInfoVar {
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.seed
            .cs()
            .or(self.name.cs())
            .or(self.company.cs())
            .or(self.department.cs())
            .or(self.employee_no.cs())
            .or(self.hire_year.cs())
            .or(self.card_expiry.cs())
    }

    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        attrs: &EmployeeInfo,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let nonce = attrs.nonce.clone();
        let seed = FpVar::<Fr>::new_witness(ns!(cs, "seed"), || Ok(attrs.seed))?;
        let name = Bytestring::new_witness(ns!(cs, "name"), || Ok(attrs.name.to_vec()))?;
        let company = Bytestring::new_witness(ns!(cs, "company"), || Ok(attrs.company.to_vec()))?;
        let department =
            Bytestring::new_witness(ns!(cs, "department"), || Ok(attrs.department.to_vec()))?;
        let employee_no =
            Bytestring::new_witness(ns!(cs, "employee_no"), || Ok(attrs.employee_no.to_vec()))?;
        let hire_year =
            FpVar::<Fr>::new_witness(ns!(cs, "hire_year"), || Ok(Fr::from(attrs.hire_year)))?;
        let card_expiry =
            FpVar::<Fr>::new_witness(ns!(cs, "card_expiry"), || Ok(Fr::from(attrs.card_expiry)))?;
        Ok(EmployeeInfoVar {
            nonce,
            seed,
            name,
            company,
            department,
            employee_no,
            hire_year,
            card_expiry,
        })
    }

    fn get_com_param(
        &self,
    ) -> Result<ComParamVar<EmployeeComScheme, EmployeeComSchemeG, Fr>, SynthesisError> {
        let cs = self
            .name
            .cs()
            .or(self.company.cs())
            .or(self.department.cs())
            .or(self.employee_no.cs())
            .or(self.hire_year.cs())
            .or(self.card_expiry.cs());
        ComParamVar::<_, EmployeeComSchemeG, _>::new_constant(cs, &*EMPLOYEE_COM_PARAM)
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsVar<Fr, EmployeeInfo, EmployeeComScheme, EmployeeComSchemeG>
    for EmployeeInfoVar
{
    type Id = Bytestring<Fr>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Bytestring<Fr>, SynthesisError> {
        Ok(self.employee_no.clone())
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}
