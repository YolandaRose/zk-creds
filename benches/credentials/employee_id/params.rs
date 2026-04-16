use crate::credentials::employee_id::employee_info::{EmployeeInfo, EmployeeInfoVar};

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

// 固定布局电路的UTF-8字节（填充/截断）
pub(crate) const NAME_LEN: usize = 32;
pub(crate) const COMPANY_LEN: usize = 32;
pub(crate) const DEPARTMENT_LEN: usize = 32;
pub(crate) const EMPLOYEE_NO_LEN: usize = 16;

// 固定记录：name | company | department | employee_no | hire_year (be u32) | card_expiry (be u32, YYYYMMDD)
pub(crate) const RECORD_BLOB_LEN: usize =
    NAME_LEN + COMPANY_LEN + DEPARTMENT_LEN + EMPLOYEE_NO_LEN + 4 + 4;

pub(crate) type E = Bls12_381;
pub(crate) type Fr = <E as PairingEngine>::Fr;
pub(crate) type H = zkcreds::poseidon_utils::Bls12PoseidonCrh;
pub(crate) type HG = zkcreds::poseidon_utils::Bls12PoseidonCrh;
pub(crate) type EmployeeComScheme = zkcreds::poseidon_utils::Bls12PoseidonCommitter;
pub(crate) type EmployeeComSchemeG = zkcreds::poseidon_utils::Bls12PoseidonCommitter;

pub(crate) type ComTree = zkcreds::com_tree::ComTree<Fr, H, EmployeeComScheme>;
pub(crate) type ComForest = zkcreds::com_forest::ComForest<Fr, H, EmployeeComScheme>;
pub(crate) type ComTreePath = zkcreds::com_tree::ComTreePath<Fr, H, EmployeeComScheme>;
pub(crate) type ComForestRoots = zkcreds::com_forest::ComForestRoots<Fr, H>;

pub(crate) type PredProvingKey = ZkcredsPredPk<
    Bls12_381,
    EmployeeInfo,
    EmployeeInfoVar,
    EmployeeComScheme,
    EmployeeComSchemeG,
    H,
    HG,
>;
pub(crate) type PredVerifyingKey = ZkcredsPredVk<
    Bls12_381,
    EmployeeInfo,
    EmployeeInfoVar,
    EmployeeComScheme,
    EmployeeComSchemeG,
    H,
    HG,
>;
pub(crate) type TreeProvingKey =
    ZkcredsTreePk<Bls12_381, EmployeeInfo, EmployeeComScheme, EmployeeComSchemeG, H, HG>;
pub(crate) type TreeVerifyingKey =
    ZkcredsTreeVk<Bls12_381, EmployeeInfo, EmployeeComScheme, EmployeeComSchemeG, H, HG>;
pub(crate) type ForestProvingKey =
    ZkcredsForestPk<Bls12_381, EmployeeInfo, EmployeeComScheme, EmployeeComSchemeG, H, HG>;
pub(crate) type ForestVerifyingKey =
    ZkcredsForestVk<Bls12_381, EmployeeInfo, EmployeeComScheme, EmployeeComSchemeG, H, HG>;
pub(crate) type PredProof = ZkcredsPredProof<
    Bls12_381,
    EmployeeInfo,
    EmployeeInfoVar,
    EmployeeComScheme,
    EmployeeComSchemeG,
    H,
    HG,
>;
pub(crate) type TreeProof =
    ZkcredsTreeProof<Bls12_381, EmployeeInfo, EmployeeComScheme, EmployeeComSchemeG, H, HG>;
pub(crate) type ForestProof =
    ZkcredsForestProof<Bls12_381, EmployeeInfo, EmployeeComScheme, EmployeeComSchemeG, H, HG>;

lazy_static! {
    pub(crate) static ref EMPLOYEE_COM_PARAM: <EmployeeComScheme as CommitmentScheme>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-employee-commit-param").unwrap();
            StdRng::from_seed(seed)
        };
        EmployeeComScheme::setup(&mut rng).unwrap()
    };
    pub(crate) static ref MERKLE_CRH_PARAM: <H as TwoToOneCRH>::Parameters = {
        let mut rng = {
            let mut seed = [0u8; 32];
            let mut writer = &mut seed[..];
            writer.write_all(b"zkcreds-employee-merkle-param").unwrap();
            StdRng::from_seed(seed)
        };
        <H as TwoToOneCRH>::setup(&mut rng).unwrap()
    };
}
