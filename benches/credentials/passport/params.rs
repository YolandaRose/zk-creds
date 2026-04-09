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

// 护照信息是电子机器可读旅行证件（eMRTD；又名“护照”）的逻辑数据结构1 （LDS1）的基本文件（EF）的数据组1 （DG1）。使用的格式是TD3（与TD1或TD2相对）。
pub(crate) const NAME_LEN: usize = 39;
pub(crate) const DATE_LEN: usize = 6;
pub(crate) const STATE_ID_LEN: usize = 3;
pub(crate) const DOCUMENT_NUMBER_LEN: usize = 9;
pub(crate) const DG1_LEN: usize = 93;
pub(crate) const ISSUER_OFFSET: usize = 7;
pub(crate) const NAME_OFFSET: usize = ISSUER_OFFSET + STATE_ID_LEN;
pub(crate) const DOCUMENT_NUMBER_OFFSET: usize = NAME_OFFSET + NAME_LEN;
pub(crate) const NATIONALITY_OFFSET: usize = DOCUMENT_NUMBER_OFFSET + DOCUMENT_NUMBER_LEN + 1;
pub(crate) const DOB_OFFSET: usize = NATIONALITY_OFFSET + STATE_ID_LEN;
pub(crate) const EXPIRY_OFFSET: usize = DOB_OFFSET + DATE_LEN + 2;

// 以下值特定于美国护照

// 美国护照使用SHA-256进行内部散列计算，并且还使用SHA-256进行最终签名（RSA-PKCS1v1.5-SHA256）
pub(crate) const HASH_LEN: usize = 32;
pub(crate) const SIG_HASH_LEN: usize = 32;

// 计算护照签名时计算的中间值
pub(crate) const PRE_ECONTENT_LEN: usize = 180;
pub(crate) const ECONTENT_LEN: usize = 104;
// DG1散列在pre-econtent中的位置
pub(crate) const DG1_HASH_OFFSET: usize = 31;
// DG2散列在pre-econtent中的位置
pub(crate) const DG2_HASH_OFFSET: usize = 70;
// pre-econtent散列在econtent中的位置
pub(crate) const PRE_ECONTENT_HASH_OFFSET: usize = 72;

// 选择一个配对引擎和一个定义在E::Fr上的曲线
pub(crate) type E = Bls12_381;
pub(crate) type Fr = <E as PairingEngine>::Fr;

// 选择一个两个到一的CRH
pub(crate) type H = zkcreds::poseidon_utils::Bls12PoseidonCrh;
pub(crate) type HG = zkcreds::poseidon_utils::Bls12PoseidonCrh;

// 选择一个承诺方案
pub(crate) type PassportComScheme = zkcreds::poseidon_utils::Bls12PoseidonCommitter;
pub(crate) type PassportComSchemeG = zkcreds::poseidon_utils::Bls12PoseidonCommitter;

pub(crate) type ComTree = zkcreds::com_tree::ComTree<Fr, H, PassportComScheme>;
pub(crate) type ComForest = zkcreds::com_forest::ComForest<Fr, H, PassportComScheme>;
pub(crate) type ComTreePath = zkcreds::com_tree::ComTreePath<Fr, H, PassportComScheme>;
pub(crate) type ComForestRoots = zkcreds::com_forest::ComForestRoots<Fr, H>;

// Groth16类型的别名
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

// 设置参数
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
