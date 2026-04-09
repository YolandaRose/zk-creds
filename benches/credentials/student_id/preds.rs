use crate::credentials::student_id::params::{Fr, StudentComScheme, StudentComSchemeG};
use crate::credentials::student_id::student_info::{StudentInfo, StudentInfoVar};

use zkcreds::pred::PredicateChecker;

use ark_ff::ToConstraintField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

// 学生卡有效期检查器
#[derive(Clone)]
pub(crate) struct StudentCardExpiryChecker {
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, StudentInfo, StudentInfoVar, StudentComScheme, StudentComSchemeG>
    for StudentCardExpiryChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &StudentInfoVar,
    ) -> Result<(), SynthesisError> {
        // 断言学生卡有效期 > threshold_expiry
        let threshold =
            FpVar::<Fr>::new_input(ns!(cs, "student card expiry threshold"), || {
                Ok(self.threshold_expiry)
            })?;
        attrs
            .card_expiry
            .enforce_cmp(&threshold, core::cmp::Ordering::Greater, false)
    }

    // 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.threshold_expiry]
    }
}
