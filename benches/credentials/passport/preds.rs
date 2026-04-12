use crate::credentials::passport::{
    params::{Fr, PassportComScheme, PassportComSchemeG, HASH_LEN},
    passport_info::{PersonalInfo, PersonalInfoVar},
};

use zkcreds::{pred::PredicateChecker, revealing_multishow::RevealingMultishowChecker};

use ark_ff::ToConstraintField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    uint8::UInt8,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

// 年龄检查器
#[derive(Clone, Default)]
pub(crate) struct AgeChecker {
    pub(crate) threshold_dob: Fr,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for AgeChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        // 断言 attrs.dob ≤ threshold_dob
        let threshold_dob =
            FpVar::<Fr>::new_input(ns!(cs, "threshold dob"), || Ok(self.threshold_dob))?;
        attrs
            .dob
            .enforce_cmp(&threshold_dob, core::cmp::Ordering::Less, true)
    }

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_dob]
    }
}

// 有效期检查器
#[derive(Clone, Default)]
pub(crate) struct ExpiryChecker {
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for ExpiryChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        // 断言 attrs.passport_expiry > threshold_expiry
        let threshold_expiry =
            FpVar::<Fr>::new_input(ns!(cs, "threshold expiry"), || Ok(self.threshold_expiry))?;
        attrs
            .passport_expiry
            .enforce_cmp(&threshold_expiry, core::cmp::Ordering::Greater, false)
    }

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_expiry]
    }
}

// 人脸特征检查器
#[derive(Clone, Default)]
pub(crate) struct FaceChecker {
    pub(crate) face_hash: [u8; HASH_LEN],
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for FaceChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        // 断言给定的面哈希与属性的人脸哈希相同
        let face_hash = UInt8::new_input_vec(ns!(cs, "face hash"), &self.face_hash)?;
        face_hash.enforce_equal(&attrs.biometric_hash.0)
    }

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        self.face_hash.to_field_elements().unwrap()
    }
}

// 年龄人脸有效期检查器
#[derive(Clone, Default)]
pub(crate) struct AgeFaceExpiryChecker {
    pub(crate) age_checker: AgeChecker,
    pub(crate) face_checker: FaceChecker,
    pub(crate) expiry_checker: ExpiryChecker,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for AgeFaceExpiryChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        self.age_checker.pred(cs.clone(), attrs)?;
        self.face_checker.pred(cs.clone(), attrs)?;
        self.expiry_checker.pred(cs.clone(), attrs)?;

        Ok(())
    }

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    /// This DOES NOT include `attrs`.
    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.age_checker.public_inputs(),
            self.face_checker.public_inputs(),
            self.expiry_checker.public_inputs(),
        ]
        .concat()
    }
}

// 年龄和有效期检查器
#[derive(Clone, Default)]
pub(crate) struct AgeAndExpiryChecker {
    pub(crate) age_checker: AgeChecker,
    pub(crate) expiry_checker: ExpiryChecker,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for AgeAndExpiryChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        self.age_checker.pred(cs.clone(), attrs)?;
        self.expiry_checker.pred(cs.clone(), attrs)?;

        Ok(())
    }

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.age_checker.public_inputs(),
            self.expiry_checker.public_inputs(),
        ]
        .concat()
    }
}

// 年龄多重展示有效期检查器
#[derive(Clone, Default)]
pub(crate) struct AgeMultishowExpiryChecker {
    pub(crate) age_checker: AgeChecker,
    pub(crate) multishow_checker: RevealingMultishowChecker<Fr>,
    pub(crate) expiry_checker: ExpiryChecker,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for AgeMultishowExpiryChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        self.age_checker.pred(cs.clone(), attrs)?;
        self.multishow_checker.pred(cs.clone(), attrs)?;
        self.expiry_checker.pred(cs.clone(), attrs)?;

        Ok(())
    }

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    fn public_inputs(&self) -> Vec<Fr> {
        [
            self.age_checker.public_inputs(),
            <RevealingMultishowChecker<Fr> as PredicateChecker<
                Fr,
                PersonalInfo,
                PersonalInfoVar,
                PassportComScheme,
                PassportComSchemeG,
            >>::public_inputs(&self.multishow_checker),
            self.expiry_checker.public_inputs(),
        ]
        .concat()
    }
}

// 持有者标签检查器
#[derive(Clone)]
pub(crate) struct HolderTagChecker {
    pub(crate) holder_tag: Fr,
}

impl PredicateChecker<Fr, PersonalInfo, PersonalInfoVar, PassportComScheme, PassportComSchemeG>
    for HolderTagChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &PersonalInfoVar,
    ) -> Result<(), SynthesisError> {
        let holder_tag = FpVar::<Fr>::new_input(ns!(cs, "holder tag"), || Ok(self.holder_tag))?;
        attrs.seed.enforce_equal(&holder_tag)
    }

    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.holder_tag]
    }
}
