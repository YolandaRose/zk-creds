use crate::credentials::employee_id::params::{Fr, EmployeeComScheme, EmployeeComSchemeG};
use crate::credentials::employee_id::employee_info::{EmployeeInfo, EmployeeInfoVar};

use zkcreds::pred::PredicateChecker;

use ark_ff::ToConstraintField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};

// 员工卡有效期检查器
#[derive(Clone)]
pub(crate) struct EmployeeCardExpiryChecker {
    pub(crate) threshold_expiry: Fr,
}

impl PredicateChecker<Fr, EmployeeInfo, EmployeeInfoVar, EmployeeComScheme, EmployeeComSchemeG>
    for EmployeeCardExpiryChecker
{
    // 返回谓词是否满足
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &EmployeeInfoVar,
    ) -> Result<(), SynthesisError> {
        // 断言员工卡有效期 > threshold_expiry
        let threshold =
            FpVar::<Fr>::new_input(ns!(cs, "employee card expiry threshold"), || {
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

