//! 护照–员工联合：跨境商务等场景。`passport_blob || employee_blob`。

use crate::credentials::joint::params::{
    Fr, JointComScheme, JointComSchemeG, EMPLOYEE_RECORD_LEN, JOINT_COM_PARAM, PASSPORT_RECORD_LEN,
};
use crate::credentials::joint::params::{H, HG, PE_JOINT_LEN};

use zkcreds::proof_data_structures::{
    ForestProof, ForestProvingKey, ForestVerifyingKey, PredProof, PredProvingKey, PredVerifyingKey,
    TreeProof, TreeProvingKey, TreeVerifyingKey,
};
use zkcreds::{
    attrs::{AccountableAttrs, AccountableAttrsVar, Attrs, AttrsVar},
    poseidon_utils::ComNonce,
    Bytestring, ComParam, ComParamVar,
};

use ark_bls12_381::Bls12_381;
use ark_ff::{to_bytes, UniformRand};
use ark_r1cs_std::{
    alloc::AllocVar, bits::ToBytesGadget, fields::fp::FpVar, uint8::UInt8, R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_std::rand::Rng;

pub(crate) type PePredPk = PredProvingKey<
    Bls12_381,
    PassportEmployeeJointInfo,
    PassportEmployeeJointInfoVar,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type PePredVk = PredVerifyingKey<
    Bls12_381,
    PassportEmployeeJointInfo,
    PassportEmployeeJointInfoVar,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type PeTreePk =
    TreeProvingKey<Bls12_381, PassportEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type PeTreeVk =
    TreeVerifyingKey<Bls12_381, PassportEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type PeForestPk =
    ForestProvingKey<Bls12_381, PassportEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type PeForestVk = ForestVerifyingKey<
    Bls12_381,
    PassportEmployeeJointInfo,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type PePredProof = PredProof<
    Bls12_381,
    PassportEmployeeJointInfo,
    PassportEmployeeJointInfoVar,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type PeTreeProof =
    TreeProof<Bls12_381, PassportEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type PeForestProof =
    ForestProof<Bls12_381, PassportEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;

#[derive(Clone)]
pub(crate) struct PassportEmployeeJointInfo {
    nonce: ComNonce,
    pub(crate) seed: Fr,
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
    pub(crate) fn joint_blob(&self) -> [u8; PE_JOINT_LEN] {
        let mut b = [0u8; PE_JOINT_LEN];
        b[..PASSPORT_RECORD_LEN].copy_from_slice(&self.passport_blob);
        b[PASSPORT_RECORD_LEN..].copy_from_slice(&self.employee_blob);
        b
    }

    pub(crate) fn from_blobs<R: Rng>(
        rng: &mut R,
        passport: &[u8; PASSPORT_RECORD_LEN],
        employee: &[u8; EMPLOYEE_RECORD_LEN],
        seed: Fr,
    ) -> Self {
        Self {
            nonce: ComNonce::rand(rng),
            seed,
            passport_blob: *passport,
            employee_blob: *employee,
        }
    }
}

#[derive(Clone)]
pub(crate) struct PassportEmployeeJointInfoVar {
    nonce: ComNonce,
    pub(crate) seed: FpVar<Fr>,
    pub(crate) passport_blob: Bytestring<Fr>,
    pub(crate) employee_blob: Bytestring<Fr>,
}

impl Attrs<Fr, JointComScheme> for PassportEmployeeJointInfo {
    fn to_bytes(&self) -> Vec<u8> {
        to_bytes![self.seed, self.passport_blob, self.employee_blob].unwrap()
    }

    fn get_com_param(&self) -> &ComParam<JointComScheme> {
        &*JOINT_COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrs<Fr, JointComScheme> for PassportEmployeeJointInfo {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.passport_blob[3..42]);
        v.extend_from_slice(&self.employee_blob[96..112]);
        v
    }

    fn get_seed(&self) -> Fr {
        self.seed
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

impl AttrsVar<Fr, PassportEmployeeJointInfo, JointComScheme, JointComSchemeG>
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
            seed: FpVar::new_witness(ns!(cs, "joint pe seed"), || Ok(attrs.seed))?,
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
    ) -> Result<ComParamVar<JointComScheme, JointComSchemeG, Fr>, SynthesisError> {
        let cs = self.passport_blob.cs().or(self.employee_blob.cs());
        ComParamVar::<_, JointComSchemeG, _>::new_constant(cs, &*JOINT_COM_PARAM)
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsVar<Fr, PassportEmployeeJointInfo, JointComScheme, JointComSchemeG>
    for PassportEmployeeJointInfoVar
{
    type Id = Bytestring<Fr>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Bytestring<Fr>, SynthesisError> {
        Ok(self.passport_blob.clone())
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}
