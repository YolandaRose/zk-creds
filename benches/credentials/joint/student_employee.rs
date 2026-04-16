//! 学生–员工联合：校企合作场景。单一承诺覆盖 `student_blob || employee_blob`。

use crate::credentials::joint::params::{
    Fr, JointComScheme, JointComSchemeG, EMPLOYEE_RECORD_LEN, JOINT_COM_PARAM, STUDENT_RECORD_LEN,
};
use crate::credentials::joint::params::{H, HG, SE_JOINT_LEN};

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

pub(crate) type SePredPk = PredProvingKey<
    Bls12_381,
    StudentEmployeeJointInfo,
    StudentEmployeeJointInfoVar,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type SePredVk = PredVerifyingKey<
    Bls12_381,
    StudentEmployeeJointInfo,
    StudentEmployeeJointInfoVar,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type SeTreePk =
    TreeProvingKey<Bls12_381, StudentEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type SeTreeVk =
    TreeVerifyingKey<Bls12_381, StudentEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type SeForestPk =
    ForestProvingKey<Bls12_381, StudentEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type SeForestVk =
    ForestVerifyingKey<Bls12_381, StudentEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type SePredProof = PredProof<
    Bls12_381,
    StudentEmployeeJointInfo,
    StudentEmployeeJointInfoVar,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type SeTreeProof =
    TreeProof<Bls12_381, StudentEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type SeForestProof =
    ForestProof<Bls12_381, StudentEmployeeJointInfo, JointComScheme, JointComSchemeG, H, HG>;

#[derive(Clone)]
pub(crate) struct StudentEmployeeJointInfo {
    nonce: ComNonce,
    pub(crate) seed: Fr,
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
    pub(crate) fn joint_blob(&self) -> [u8; SE_JOINT_LEN] {
        let mut b = [0u8; SE_JOINT_LEN];
        b[..STUDENT_RECORD_LEN].copy_from_slice(&self.student_blob);
        b[STUDENT_RECORD_LEN..].copy_from_slice(&self.employee_blob);
        b
    }

    pub(crate) fn from_blobs<R: Rng>(
        rng: &mut R,
        student: &[u8; STUDENT_RECORD_LEN],
        employee: &[u8; EMPLOYEE_RECORD_LEN],
        seed: Fr,
    ) -> Self {
        Self {
            nonce: ComNonce::rand(rng),
            seed,
            student_blob: *student,
            employee_blob: *employee,
        }
    }
}

#[derive(Clone)]
pub(crate) struct StudentEmployeeJointInfoVar {
    nonce: ComNonce,
    pub(crate) seed: FpVar<Fr>,
    pub(crate) student_blob: Bytestring<Fr>,
    pub(crate) employee_blob: Bytestring<Fr>,
}

impl Attrs<Fr, JointComScheme> for StudentEmployeeJointInfo {
    fn to_bytes(&self) -> Vec<u8> {
        to_bytes![self.seed, self.student_blob, self.employee_blob].unwrap()
    }

    fn get_com_param(&self) -> &ComParam<JointComScheme> {
        &*JOINT_COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrs<Fr, JointComScheme> for StudentEmployeeJointInfo {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        let mut v = Vec::new();
        // student_no / employee_no 各 16 字节，位于 enrollment/hire_year 与 expiry 之前
        v.extend_from_slice(&self.student_blob[96..112]);
        v.extend_from_slice(&self.employee_blob[96..112]);
        v
    }

    fn get_seed(&self) -> Fr {
        self.seed
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

impl AttrsVar<Fr, StudentEmployeeJointInfo, JointComScheme, JointComSchemeG>
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
            seed: FpVar::new_witness(ns!(cs, "joint se seed"), || Ok(attrs.seed))?,
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
    ) -> Result<ComParamVar<JointComScheme, JointComSchemeG, Fr>, SynthesisError> {
        let cs = self.student_blob.cs().or(self.employee_blob.cs());
        ComParamVar::<_, JointComSchemeG, _>::new_constant(cs, &*JOINT_COM_PARAM)
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsVar<Fr, StudentEmployeeJointInfo, JointComScheme, JointComSchemeG>
    for StudentEmployeeJointInfoVar
{
    type Id = Bytestring<Fr>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Bytestring<Fr>, SynthesisError> {
        Ok(self.student_blob.clone())
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}
