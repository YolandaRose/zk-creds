//! 护照–学生联合：国际优惠等场景。`passport_blob || student_blob`。

use crate::credentials::joint::params::{
    Fr, JointComScheme, JointComSchemeG, JOINT_COM_PARAM, PASSPORT_RECORD_LEN, STUDENT_RECORD_LEN,
};
use crate::credentials::joint::params::{H, HG, PS_JOINT_LEN};

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

pub(crate) type PsPredPk = PredProvingKey<
    Bls12_381,
    PassportStudentJointInfo,
    PassportStudentJointInfoVar,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type PsPredVk = PredVerifyingKey<
    Bls12_381,
    PassportStudentJointInfo,
    PassportStudentJointInfoVar,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type PsTreePk =
    TreeProvingKey<Bls12_381, PassportStudentJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type PsTreeVk =
    TreeVerifyingKey<Bls12_381, PassportStudentJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type PsForestPk =
    ForestProvingKey<Bls12_381, PassportStudentJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type PsForestVk =
    ForestVerifyingKey<Bls12_381, PassportStudentJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type PsPredProof = PredProof<
    Bls12_381,
    PassportStudentJointInfo,
    PassportStudentJointInfoVar,
    JointComScheme,
    JointComSchemeG,
    H,
    HG,
>;
pub(crate) type PsTreeProof =
    TreeProof<Bls12_381, PassportStudentJointInfo, JointComScheme, JointComSchemeG, H, HG>;
pub(crate) type PsForestProof =
    ForestProof<Bls12_381, PassportStudentJointInfo, JointComScheme, JointComSchemeG, H, HG>;

#[derive(Clone)]
pub(crate) struct PassportStudentJointInfo {
    nonce: ComNonce,
    pub(crate) seed: Fr,
    pub(crate) passport_blob: [u8; PASSPORT_RECORD_LEN],
    pub(crate) student_blob: [u8; STUDENT_RECORD_LEN],
}

impl Default for PassportStudentJointInfo {
    fn default() -> Self {
        Self {
            nonce: ComNonce::default(),
            seed: Fr::default(),
            passport_blob: [0u8; PASSPORT_RECORD_LEN],
            student_blob: [0u8; STUDENT_RECORD_LEN],
        }
    }
}

impl PassportStudentJointInfo {
    pub(crate) fn joint_blob(&self) -> [u8; PS_JOINT_LEN] {
        let mut b = [0u8; PS_JOINT_LEN];
        b[..PASSPORT_RECORD_LEN].copy_from_slice(&self.passport_blob);
        b[PASSPORT_RECORD_LEN..].copy_from_slice(&self.student_blob);
        b
    }

    pub(crate) fn from_blobs<R: Rng>(
        rng: &mut R,
        passport: &[u8; PASSPORT_RECORD_LEN],
        student: &[u8; STUDENT_RECORD_LEN],
        seed: Fr,
    ) -> Self {
        Self {
            nonce: ComNonce::rand(rng),
            seed,
            passport_blob: *passport,
            student_blob: *student,
        }
    }
}

#[derive(Clone)]
pub(crate) struct PassportStudentJointInfoVar {
    nonce: ComNonce,
    pub(crate) seed: FpVar<Fr>,
    pub(crate) passport_blob: Bytestring<Fr>,
    pub(crate) student_blob: Bytestring<Fr>,
}

impl Attrs<Fr, JointComScheme> for PassportStudentJointInfo {
    fn to_bytes(&self) -> Vec<u8> {
        to_bytes![self.seed, self.passport_blob, self.student_blob].unwrap()
    }

    fn get_com_param(&self) -> &ComParam<JointComScheme> {
        &*JOINT_COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrs<Fr, JointComScheme> for PassportStudentJointInfo {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.passport_blob[3..42]);
        v.extend_from_slice(&self.student_blob[96..112]);
        v
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl ToBytesGadget<Fr> for PassportStudentJointInfoVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([
            self.seed.to_bytes()?,
            self.passport_blob.0.to_bytes()?,
            self.student_blob.0.to_bytes()?,
        ]
        .concat())
    }
}

impl AttrsVar<Fr, PassportStudentJointInfo, JointComScheme, JointComSchemeG>
    for PassportStudentJointInfoVar
{
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.seed
            .cs()
            .or(self.passport_blob.cs())
            .or(self.student_blob.cs())
    }

    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        attrs: &PassportStudentJointInfo,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        Ok(PassportStudentJointInfoVar {
            nonce: attrs.nonce.clone(),
            seed: FpVar::new_witness(ns!(cs, "joint ps seed"), || Ok(attrs.seed))?,
            passport_blob: Bytestring::new_witness(ns!(cs, "passport blob"), || {
                Ok(attrs.passport_blob.to_vec())
            })?,
            student_blob: Bytestring::new_witness(ns!(cs, "student blob"), || {
                Ok(attrs.student_blob.to_vec())
            })?,
        })
    }

    fn get_com_param(
        &self,
    ) -> Result<ComParamVar<JointComScheme, JointComSchemeG, Fr>, SynthesisError> {
        let cs = self.passport_blob.cs().or(self.student_blob.cs());
        ComParamVar::<_, JointComSchemeG, _>::new_constant(cs, &*JOINT_COM_PARAM)
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsVar<Fr, PassportStudentJointInfo, JointComScheme, JointComSchemeG>
    for PassportStudentJointInfoVar
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
