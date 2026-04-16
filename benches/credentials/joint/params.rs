//! 跨两凭证联合基准：共用曲线、Poseidon Merkle/承诺参数（与单凭证 bench 隔离的 param seed）。

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{commitment::CommitmentScheme, crh::TwoToOneCRH};
use ark_ec::PairingEngine;
use ark_std::{
    io::Write,
    rand::{rngs::StdRng, SeedableRng},
};
use lazy_static::lazy_static;

pub(crate) type E = Bls12_381;
pub(crate) type Fr = <E as PairingEngine>::Fr;
pub(crate) type H = zkcreds::poseidon_utils::Bls12PoseidonCrh;
pub(crate) type HG = zkcreds::poseidon_utils::Bls12PoseidonCrh;
pub(crate) type JointComScheme = zkcreds::poseidon_utils::Bls12PoseidonCommitter;
pub(crate) type JointComSchemeG = zkcreds::poseidon_utils::Bls12PoseidonCommitter;

pub(crate) type ComTree = zkcreds::com_tree::ComTree<Fr, H, JointComScheme>;
pub(crate) type ComForest = zkcreds::com_forest::ComForest<Fr, H, JointComScheme>;
pub(crate) type ComTreePath = zkcreds::com_tree::ComTreePath<Fr, H, JointComScheme>;
pub(crate) type ComForestRoots = zkcreds::com_forest::ComForestRoots<Fr, H>;

// 为了让 `joint` 不依赖其它 bench 模块的私有 `params`，这里直接复制固定布局长度。
// student: name(32) | school(32) | college(32) | student_no(16) | enrollment_year(4) | card_expiry(4)
pub(crate) const STUDENT_RECORD_LEN: usize = 32 + 32 + 32 + 16 + 4 + 4; // 120
                                                                        // employee: name(32) | company(32) | department(32) | employee_no(16) | hire_year(4) | card_expiry(4)
pub(crate) const EMPLOYEE_RECORD_LEN: usize = 32 + 32 + 32 + 16 + 4 + 4; // 120
                                                                         // passport: nationality(3) | name(39) | dob(4) | passport_expiry(4) | biometrics_raw(128)
pub(crate) const PASSPORT_RECORD_LEN: usize = 3 + 39 + 4 + 4 + 128; // 178

pub(crate) const SE_JOINT_LEN: usize = STUDENT_RECORD_LEN + EMPLOYEE_RECORD_LEN;
pub(crate) const PS_JOINT_LEN: usize = PASSPORT_RECORD_LEN + STUDENT_RECORD_LEN;
pub(crate) const PE_JOINT_LEN: usize = PASSPORT_RECORD_LEN + EMPLOYEE_RECORD_LEN;

/// 护照记录内 `passport_expiry`（be u32）起始字节偏移：nationality(3)+name(39)+dob(4)
pub(crate) const PASSPORT_EXPIRY_OFFSET: usize = 3 + 39 + 4;

pub(crate) const LOG2_NUM_LEAVES: u32 = 31;
pub(crate) const LOG2_NUM_TREES: u32 = 8;
pub(crate) const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
pub(crate) const NUM_TREES: usize = 1 << LOG2_NUM_TREES;

pub(crate) const HOLDER_TAG_RAW: u64 = 424242;
/// 学生证/工作证到期谓词用的基准日（8 位 YYYYMMDD）
pub(crate) const CARD_TODAY: u32 = 20220101;
/// 护照到期谓词用的基准日（与 passport bench 一致）
pub(crate) const PASSPORT_TODAY: u32 = 20220101;

lazy_static! {
    pub(crate) static ref JOINT_COM_PARAM: <JointComScheme as CommitmentScheme>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-joint-commit-param").unwrap();
            StdRng::from_seed(seed)
        };
        JointComScheme::setup(&mut rng).unwrap()
    };
    pub(crate) static ref MERKLE_CRH_PARAM: <H as TwoToOneCRH>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-joint-merkle-param").unwrap();
            StdRng::from_seed(seed)
        };
        <H as TwoToOneCRH>::setup(&mut rng).unwrap()
    };
}
