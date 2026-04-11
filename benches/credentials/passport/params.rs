use crate::credentials::passport::passport_info::{PersonalInfo, PersonalInfoVar};

use zkcreds::proof_data_structures::{
    ForestProof as ZkcredsForestProof, ForestProvingKey as ZkcredsForestPk,
    ForestVerifyingKey as ZkcredsForestVk, PredProof as ZkcredsPredProof,
    PredProvingKey as ZkcredsPredPk, PredVerifyingKey as ZkcredsPredVk,
    TreeProof as ZkcredsTreeProof, TreeProvingKey as ZkcredsTreePk,
    TreeVerifyingKey as ZkcredsTreeVk,
};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{commitment::CommitmentScheme, crh::TwoToOneCRH};
use ark_ec::PairingEngine;
use ark_std::{
    io::Write,
    rand::{rngs::StdRng, SeedableRng},
};
use lazy_static::lazy_static;

// 扁平 JSON + 固定布局 RECORD_BLOB（与 `PassportDump::write_blob` / `PersonalInfo::record_blob` 一致）
pub(crate) const NAME_LEN: usize = 39;
pub(crate) const STATE_ID_LEN: usize = 3;
pub(crate) const HASH_LEN: usize = 32;
/// 生物特征原始字节在记录中的最大长度（不足补 0；与电路见证一致）
pub(crate) const BIOMETRIC_RAW_MAX: usize = 128;

// nationality | name | dob (be u32 YYYYMMDD) | passport_expiry (be u32 YYYYMMDD) | biometrics raw (padded)
pub(crate) const RECORD_BLOB_LEN: usize =
    STATE_ID_LEN + NAME_LEN + 4 + 4 + BIOMETRIC_RAW_MAX;

pub(crate) type E = Bls12_381;
pub(crate) type Fr = <E as PairingEngine>::Fr;

pub(crate) type H = zkcreds::poseidon_utils::Bls12PoseidonCrh;
pub(crate) type HG = zkcreds::poseidon_utils::Bls12PoseidonCrh;

pub(crate) type PassportComScheme = zkcreds::poseidon_utils::Bls12PoseidonCommitter;
pub(crate) type PassportComSchemeG = zkcreds::poseidon_utils::Bls12PoseidonCommitter;

pub(crate) type ComTree = zkcreds::com_tree::ComTree<Fr, H, PassportComScheme>;
pub(crate) type ComForest = zkcreds::com_forest::ComForest<Fr, H, PassportComScheme>;
pub(crate) type ComTreePath = zkcreds::com_tree::ComTreePath<Fr, H, PassportComScheme>;
pub(crate) type ComForestRoots = zkcreds::com_forest::ComForestRoots<Fr, H>;

pub(crate) type PredProvingKey = ZkcredsPredPk<
    Bls12_381,
    PersonalInfo,
    PersonalInfoVar,
    PassportComScheme,
    PassportComSchemeG,
    H,
    HG,
>;
pub(crate) type PredVerifyingKey = ZkcredsPredVk<
    Bls12_381,
    PersonalInfo,
    PersonalInfoVar,
    PassportComScheme,
    PassportComSchemeG,
    H,
    HG,
>;
pub(crate) type TreeProvingKey =
    ZkcredsTreePk<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;
pub(crate) type TreeVerifyingKey =
    ZkcredsTreeVk<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;
pub(crate) type ForestProvingKey =
    ZkcredsForestPk<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;
pub(crate) type ForestVerifyingKey =
    ZkcredsForestVk<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;
pub(crate) type PredProof = ZkcredsPredProof<
    Bls12_381,
    PersonalInfo,
    PersonalInfoVar,
    PassportComScheme,
    PassportComSchemeG,
    H,
    HG,
>;
pub(crate) type TreeProof =
    ZkcredsTreeProof<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;
pub(crate) type ForestProof =
    ZkcredsForestProof<Bls12_381, PersonalInfo, PassportComScheme, PassportComSchemeG, H, HG>;

lazy_static! {
    pub(crate) static ref PASSPORT_COM_PARAM: <PassportComScheme as CommitmentScheme>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-commitment-param").unwrap();
            StdRng::from_seed(seed)
        };
        PassportComScheme::setup(&mut rng).unwrap()
    };
    pub(crate) static ref MERKLE_CRH_PARAM: <H as TwoToOneCRH>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-merkle-param").unwrap();
            StdRng::from_seed(seed)
        };
        <H as TwoToOneCRH>::setup(&mut rng).unwrap()
    };
}
