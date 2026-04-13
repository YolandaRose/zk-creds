use crate::credentials::student_id::params::{Fr, StudentComScheme, StudentComSchemeG};
use crate::credentials::student_id::student_info::{StudentInfo, StudentInfoVar};

use ark_ff::ToConstraintField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use arkworks_r1cs_gadgets::poseidon::PoseidonParametersVar;
use arkworks_utils::Curve;

use zkcreds::{
    poseidon_utils::setup_poseidon_params,
    pred::PredicateChecker,
    pseudonymous_show::PseudonymousAttrsVar,
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

// 持有者标签检查器
#[derive(Clone)]
pub(crate) struct HolderTagChecker {
    pub(crate) holder_tag: Fr,
}

impl PredicateChecker<Fr, StudentInfo, StudentInfoVar, StudentComScheme, StudentComSchemeG>
    for HolderTagChecker
{
    fn pred(
        self,
        cs: ConstraintSystemRef<Fr>,
        attrs: &StudentInfoVar,
    ) -> Result<(), SynthesisError> {
        let params = setup_poseidon_params(Curve::Bls381, 3, 5);
        let params_var = PoseidonParametersVar::new_constant(ns!(cs, "prf param"), &params)?;
        let holder_tag = FpVar::<Fr>::new_input(ns!(cs, "holder tag"), || Ok(self.holder_tag))?;
        let token = attrs.compute_presentation_token(params_var)?;
        token.pseudonym.enforce_equal(&holder_tag)
    }

    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.holder_tag]
    }
}
