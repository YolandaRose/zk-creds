use crate::credentials::passport::params::{
    Fr, PassportComScheme, PassportComSchemeG, BIOMETRIC_RAW_MAX, HASH_LEN, NAME_LEN,
    PASSPORT_COM_PARAM, RECORD_BLOB_LEN, STATE_ID_LEN,
};

use sha2::{Digest, Sha256};
use zkcreds::{
    attrs::{AccountableAttrs, AccountableAttrsVar, Attrs, AttrsVar},
    poseidon_utils::ComNonce,
    Bytestring, ComParam, ComParamVar,
};

use ark_ff::{to_bytes, UniformRand};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBytesGadget,
    fields::fp::FpVar,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_std::rand::Rng;

/// 生物特征原始字节（承诺与展示电路使用 SHA256(raw)）
#[derive(Clone, Default)]
pub(crate) struct Biometrics(pub(crate) Vec<u8>);

impl Biometrics {
    pub fn hash(&self) -> [u8; HASH_LEN] {
        Sha256::digest(&self.0).into()
    }
}

#[derive(Clone)]
pub(crate) struct PersonalInfo {
    nonce: ComNonce,
    pub(crate) seed: Fr,
    pub(crate) nationality: [u8; STATE_ID_LEN],
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) dob: u32,
    pub(crate) passport_expiry: u32,
    pub(crate) biometrics: Biometrics,
}

impl Default for PersonalInfo {
    fn default() -> PersonalInfo {
        PersonalInfo {
            nonce: ComNonce::default(),
            seed: Fr::default(),
            nationality: [0u8; STATE_ID_LEN],
            name: [0u8; NAME_LEN],
            dob: 0u32,
            passport_expiry: 0u32,
            biometrics: Biometrics::default(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct PersonalInfoVar {
    nonce: ComNonce,
    pub(crate) seed: FpVar<Fr>,
    pub(crate) nationality: Bytestring<Fr>,
    pub(crate) name: Bytestring<Fr>,
    pub(crate) dob: FpVar<Fr>,
    pub(crate) passport_expiry: FpVar<Fr>,
    pub(crate) biometric_hash: Bytestring<Fr>,
}

impl PersonalInfo {
    pub(crate) fn new<R: Rng>(
        rng: &mut R,
        nationality: [u8; STATE_ID_LEN],
        name: [u8; NAME_LEN],
        dob: u32,
        passport_expiry: u32,
        biometrics: Biometrics,
    ) -> PersonalInfo {
        let nonce = ComNonce::rand(rng);
        let seed = Fr::rand(rng);

        PersonalInfo {
            nonce,
            seed,
            nationality,
            name,
            dob,
            passport_expiry,
            biometrics,
        }
    }

    /// 从与 `PassportDump::write_blob` 一致的固定布局字节构造属性。
    pub(crate) fn from_blob<R: Rng>(rng: &mut R, blob: &[u8; RECORD_BLOB_LEN]) -> PersonalInfo {
        let mut off = 0usize;
        let mut take = |len: usize| -> &[u8] {
            let s = &blob[off..off + len];
            off += len;
            s
        };
        let mut nationality = [0u8; STATE_ID_LEN];
        nationality.copy_from_slice(take(STATE_ID_LEN));
        let mut name = [0u8; NAME_LEN];
        name.copy_from_slice(take(NAME_LEN));
        let dob_b = take(4);
        let dob = u32::from_be_bytes(dob_b.try_into().unwrap());
        let exp_b = take(4);
        let passport_expiry = u32::from_be_bytes(exp_b.try_into().unwrap());
        let bio_slice = take(BIOMETRIC_RAW_MAX);
        let biometrics = Biometrics(bio_slice.to_vec());

        PersonalInfo {
            nonce: ComNonce::rand(rng),
            seed: Fr::rand(rng),
            nationality,
            name,
            dob,
            passport_expiry,
            biometrics,
        }
    }

    pub(crate) fn record_blob(&self) -> [u8; RECORD_BLOB_LEN] {
        let mut blob = [0u8; RECORD_BLOB_LEN];
        let mut off = 0usize;
        blob[off..off + STATE_ID_LEN].copy_from_slice(&self.nationality);
        off += STATE_ID_LEN;
        blob[off..off + NAME_LEN].copy_from_slice(&self.name);
        off += NAME_LEN;
        blob[off..off + 4].copy_from_slice(&self.dob.to_be_bytes());
        off += 4;
        blob[off..off + 4].copy_from_slice(&self.passport_expiry.to_be_bytes());
        off += 4;
        let raw = self.biometrics.0.as_slice();
        let n = raw.len().min(BIOMETRIC_RAW_MAX);
        blob[off..off + n].copy_from_slice(&raw[..n]);
        blob
    }

    pub fn biometrics_hash(&self) -> [u8; HASH_LEN] {
        self.biometrics.hash()
    }
}

impl Attrs<Fr, PassportComScheme> for PersonalInfo {
    fn to_bytes(&self) -> Vec<u8> {
        let dob = Fr::from(self.dob);
        let passport_expiry = Fr::from(self.passport_expiry);
        let biometric_hash = self.biometrics.hash();
        to_bytes![
            self.seed,
            self.nationality,
            self.name,
            dob,
            passport_expiry,
            biometric_hash
        ]
        .unwrap()
    }

    fn get_com_param(&self) -> &ComParam<PassportComScheme> {
        &*PASSPORT_COM_PARAM
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrs<Fr, PassportComScheme> for PersonalInfo {
    type Id = Vec<u8>;
    type Seed = Fr;

    fn get_id(&self) -> Vec<u8> {
        self.name.to_vec()
    }

    fn get_seed(&self) -> Fr {
        self.seed
    }
}

impl ToBytesGadget<Fr> for PersonalInfoVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        Ok([
            self.seed.to_bytes()?,
            self.nationality.0.to_bytes()?,
            self.name.0.to_bytes()?,
            self.dob.to_bytes()?,
            self.passport_expiry.to_bytes()?,
            self.biometric_hash.0.to_bytes()?,
        ]
        .concat())
    }
}

impl AttrsVar<Fr, PersonalInfo, PassportComScheme, PassportComSchemeG> for PersonalInfoVar {
    fn cs(&self) -> ConstraintSystemRef<Fr> {
        self.seed
            .cs()
            .or(self.nationality.cs())
            .or(self.name.cs())
            .or(self.dob.cs())
            .or(self.passport_expiry.cs())
            .or(self.biometric_hash.cs())
    }

    fn witness_attrs(
        cs: impl Into<Namespace<Fr>>,
        attrs: &PersonalInfo,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let nonce = attrs.nonce.clone();

        let biometric_hash = attrs.biometrics.hash().to_vec();

        let seed = FpVar::<Fr>::new_witness(ns!(cs, "seed"), || Ok(attrs.seed))?;
        let nationality =
            Bytestring::new_witness(ns!(cs, "nationality"), || Ok(attrs.nationality.to_vec()))?;
        let name = Bytestring::new_witness(ns!(cs, "name"), || Ok(attrs.name.to_vec()))?;
        let dob = FpVar::<Fr>::new_witness(ns!(cs, "dob"), || Ok(Fr::from(attrs.dob)))?;
        let passport_expiry = FpVar::<Fr>::new_witness(ns!(cs, "passport expiry"), || {
            Ok(Fr::from(attrs.passport_expiry))
        })?;
        let biometric_hash =
            Bytestring::new_witness(ns!(cs, "biometric_hash"), || Ok(biometric_hash))?;

        Ok(PersonalInfoVar {
            nonce,
            seed,
            nationality,
            name,
            dob,
            passport_expiry,
            biometric_hash,
        })
    }

    fn get_com_param(
        &self,
    ) -> Result<ComParamVar<PassportComScheme, PassportComSchemeG, Fr>, SynthesisError> {
        let cs = self
            .nationality
            .cs()
            .or(self.name.cs())
            .or(self.dob.cs())
            .or(self.passport_expiry.cs())
            .or(self.biometric_hash.cs());
        ComParamVar::<_, PassportComSchemeG, _>::new_constant(cs, &*PASSPORT_COM_PARAM)
    }

    fn get_com_nonce(&self) -> &ComNonce {
        &self.nonce
    }
}

impl AccountableAttrsVar<Fr, PersonalInfo, PassportComScheme, PassportComSchemeG>
    for PersonalInfoVar
{
    type Id = Bytestring<Fr>;
    type Seed = FpVar<Fr>;

    fn get_id(&self) -> Result<Bytestring<Fr>, SynthesisError> {
        Ok(self.name.clone())
    }

    fn get_seed(&self) -> Result<FpVar<Fr>, SynthesisError> {
        Ok(self.seed.clone())
    }
}
