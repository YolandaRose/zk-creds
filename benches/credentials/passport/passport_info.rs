use crate::credentials::passport::{
    params::{
        Fr, PassportComScheme, PassportComSchemeG, DATE_LEN, DOB_OFFSET, EXPIRY_OFFSET, HASH_LEN,
        NAME_LEN, NAME_OFFSET, NATIONALITY_OFFSET, PASSPORT_COM_PARAM, STATE_ID_LEN,
    },
    passport_dump::PassportDump,
};

use core::borrow::Borrow;

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

// 包含用户生物特征的简单blob
#[derive(Clone, Default)]
pub(crate) struct Biometrics(Vec<u8>);

impl Biometrics {
    pub fn hash(&self) -> [u8; HASH_LEN] {
        Sha256::digest(&self.0).into()
    }
}

// 存储护照中数据组1和2中的子集信息
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

// 存储护照中数据组1和2中的子集信息
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

// 将YYMMDD形式的日期字符串转换为u32，其十进制表示为YYYYMMDD。
// `not_after`是21世纪最早的一天，之后输入将不再有意义，例如，出生日期如果晚于今天将不再有意义，护照到期日期如果超过20年将不再有意义。
fn date_to_u32(date: &[u8], not_after: u32) -> u32 {
    assert_eq!(date.len(), DATE_LEN);

    let century = 1000000;
    let twenty_first_century = 20 * century;

    // 将ASCII数字转换为它们表示的数字。例如，int(b"9") = 9 (mod |Fr|)
    fn int(char: u8) -> u32 {
        (char as u32) - 48
    }

    // 分别转换年、月和日。b"YY"成为YY (mod |Fr|), etc.
    let year = (int(date[0]) * 10) + int(date[1]);
    let month = (int(date[2]) * 10) + int(date[3]);
    let day = (int(date[4]) * 10) + int(date[5]);

    // 现在通过移位和添加来组合值。年份只给出为YY，所以我们不立即拥有年份的最高有效数字。目前假设它是21世纪
    let mut d = twenty_first_century + (year * 10000) + (month * 100) + day;

    // 如果日期不是21世纪，那么d超过`not_after`限制。如果是这样的话，那就去掉100年
    if d > not_after {
        d -= century;
    }

    d
}

impl PersonalInfo {
    // 构造一个新的`PersonalInfo`，采样一个随机nonce用于承诺
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

    // 将给定的护照dump转换为结构化属性结构。需要`today`作为整数，其十进制表示为YYYYMMDD形式。`max_valid_years`是护照最长有效期，以年为单位。
    pub fn from_passport<R: Rng>(
        rng: &mut R,
        dump: &PassportDump,
        today: u32,
        max_valid_years: u32,
    ) -> PersonalInfo {
        // 创建一个空的信息结构，我们将在其中填充数据
        let mut info = PersonalInfo {
            nonce: ComNonce::rand(rng),
            seed: Fr::rand(rng),
            ..Default::default()
        };

        // 最早的时间，之后到期将不再有意义。这用于解析护照中的未定义日期格式
        let expiry_not_after = today + max_valid_years * 10000u32;

        // 从DG1 blob中提取国籍、姓名和出生日期。生物特征被设置为整个DG2 blob
        info.nationality
            .copy_from_slice(&dump.dg1[NATIONALITY_OFFSET..NATIONALITY_OFFSET + STATE_ID_LEN]);
        info.name
            .copy_from_slice(&dump.dg1[NAME_OFFSET..NAME_OFFSET + NAME_LEN]);
        info.dob = date_to_u32(&dump.dg1[DOB_OFFSET..DOB_OFFSET + DATE_LEN], today);
        info.passport_expiry = date_to_u32(
            &dump.dg1[EXPIRY_OFFSET..EXPIRY_OFFSET + DATE_LEN],
            expiry_not_after,
        );
        info.biometrics.0 = dump.dg2.clone();

        info
    }

    pub fn biometrics_hash(&self) -> [u8; HASH_LEN] {
        self.biometrics.hash()
    }
}

impl Attrs<Fr, PassportComScheme> for PersonalInfo {
    // 将属性序列化为字节
    fn to_bytes(&self) -> Vec<u8> {
        // DOB字节需要匹配PersonalInfoVar版本，这是一个FpVar。在序列化之前转换为Fr
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

        // 返回见证的值
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
