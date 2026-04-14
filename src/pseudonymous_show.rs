//! 定义了一个特性，允许服务提供者在其服务上实现伪匿名

use crate::{
    attrs::{AccountableAttrs, AccountableAttrsVar},
    pred::PredicateChecker,
};

use ark_crypto_primitives::{
    commitment::{constraints::CommitmentGadget, CommitmentScheme},
    Error as ArkError,
};
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, ToConstraintFieldGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon, PoseidonParameters};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget, PoseidonParametersVar};

// 我们所有使用Poseidon的域分隔符
const PRF1_DOMAIN_SEP: u8 = 123;

/// 一个伪随机字段元素对。如果两个令牌的 `hidden_ctr` 相同，它们可以组合起来推导出用户的 ID 的哈希值
#[derive(Clone, Default)]
pub struct PresentationToken<ConstraintF: PrimeField> {
    /// 这是 `PRFₛ(0)`，其中 s 是种子
    pub pseudonym: ConstraintF,
}

/// 可变版本的 presentation token
#[derive(Clone)]
pub struct PresentationTokenVar<ConstraintF: PrimeField> {
    pub pseudonym: FpVar<ConstraintF>,
}

/// 这个特性允许用户每次展示他们的凭据时创建一个 "presentation token"。
/// 这个令牌是常量，并且唯一地标识这个凭据。
pub trait PseudonymousAttrs<ConstraintF, AC>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// 从给定的可问责属性计算 presentation token
    fn compute_presentation_token(
        &self,
        params: PoseidonParameters<ConstraintF>,
    ) -> Result<PresentationToken<ConstraintF>, ArkError>;
}

impl<ConstraintF, A, AC> PseudonymousAttrs<ConstraintF, AC> for A
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// 从给定的可问责属性计算 presentation token
    fn compute_presentation_token(
        &self,
        params: PoseidonParameters<ConstraintF>,
    ) -> Result<PresentationToken<ConstraintF>, ArkError> {
        let h = Poseidon::new(params);
        let seed = self.get_seed();

        // hidden_ctr = PRFₛ(0)
        let pseudonym: ConstraintF = {
            let hash_input = [
                vec![ConstraintF::from(PRF1_DOMAIN_SEP)],
                seed.to_field_elements().unwrap(),
                vec![ConstraintF::from(0u8)],
            ]
            .concat();
            h.hash(&hash_input).unwrap()
        };

        Ok(PresentationToken { pseudonym })
    }
}

/// 实现 `compute_presentation_token` 对于所有 AccountableAttrsVar
pub trait PseudonymousAttrsVar<ConstraintF, A, AC, ACG>
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    /// 从给定的可问责属性计算 presentation token
    fn compute_presentation_token(
        &self,
        params: PoseidonParametersVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError>;
}

/// 实现 `compute_presentation_token` 对于所有 AccountableAttrsVar
impl<ConstraintF, A, AV, AC, ACG> PseudonymousAttrsVar<ConstraintF, A, AC, ACG> for AV
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AV: AccountableAttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    /// 从给定的可问责属性计算 presentation token
    fn compute_presentation_token(
        &self,
        params: PoseidonParametersVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError> {
        let h = PoseidonGadget { params };
        let seed = self.get_seed()?;

        // pseudonym = PRFₛ(0)
        let pseudonym = {
            let hash_input = [
                vec![FpVar::Constant(ConstraintF::from(PRF1_DOMAIN_SEP))],
                seed.to_constraint_field()?,
                vec![FpVar::Constant(ConstraintF::from(0u8))],
            ]
            .concat();

            h.hash(&hash_input)?
        };

        Ok(PresentationTokenVar { pseudonym })
    }
}

/// 证明 `token` 是使用验证者提供的 nonce 和属性 ID 以及随机种子进行 PRF 计算的结果
#[derive(Clone, Default)]
pub struct PseudonymousShowChecker<ConstraintF>
where
    ConstraintF: PrimeField,
{
    // 公共输入 //
    /// 与所有展示相关的伪随机值
    pub token: PresentationToken<ConstraintF>,

    // 常量 //
    /// Poseidon parameters
    pub params: PoseidonParameters<ConstraintF>,
}

impl<ConstraintF, A, AV, AC, ACG> PredicateChecker<ConstraintF, A, AV, AC, ACG>
    for PseudonymousShowChecker<ConstraintF>
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AV: AccountableAttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// 返回谓词是否满足
    fn pred(self, cs: ConstraintSystemRef<ConstraintF>, attrs: &AV) -> Result<(), SynthesisError> {
        // 见证波塞冬参数
        let params = PoseidonParametersVar::new_constant(ns!(cs, "prf param"), &self.params)?;

        // 见证公共输入
        let pseudonym =
            FpVar::<ConstraintF>::new_input(ns!(cs, "pseudonym"), || Ok(self.token.pseudonym))?;

        // 计算 presentation token
        let computed_token = attrs.compute_presentation_token(params)?;

        // 断言计算值的相等性
        computed_token.pseudonym.enforce_equal(&pseudonym)?;

        // 完成
        Ok(())
    }

    /// 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    fn public_inputs(&self) -> Vec<ConstraintF> {
        vec![self.token.pseudonym]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        attrs::Attrs,
        poseidon_utils::setup_poseidon_params,
        pred::{gen_pred_crs, prove_birth, verify_birth},
        test_util::{
            NameAndBirthYear, NameAndBirthYearVar, TestComSchemePedersen, TestComSchemePedersenG,
            TestTreeH, TestTreeHG,
        },
    };

    use ark_bls12_381::Bls12_381 as E;
    use arkworks_utils::Curve;

    const POSEIDON_WIDTH: u8 = 5;

    #[test]
    fn test_pseudonymous_show() {
        let mut rng = ark_std::test_rng();

        // 设置公共参数
        let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
        let placeholder_checker = PseudonymousShowChecker {
            params: params.clone(),
            ..Default::default()
        };
        let pk = gen_pred_crs::<
            _,
            _,
            E,
            _,
            NameAndBirthYearVar,
            TestComSchemePedersen,
            TestComSchemePedersenG,
            TestTreeH,
            TestTreeHG,
        >(&mut rng, placeholder_checker)
        .unwrap();

        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);

        // 用户计算一个伪匿名
        let token = PseudonymousAttrs::<_, TestComSchemePedersen>::compute_presentation_token(
            &person,
            params.clone(),
        )
        .unwrap();

        // 用户构造一个谓词的检查器
        let users_checker = PseudonymousShowChecker {
            token: token.clone(),
            params: params.clone(),
        };

        // 证明谓词
        let proof = prove_birth(&mut rng, &pk, users_checker, person.clone()).unwrap();

        // 验证谓词
        // 只用公共数据制作检查器
        let verifiers_checker = PseudonymousShowChecker { token, params };
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);
        let vk = pk.prepare_verifying_key();
        assert!(verify_birth(&vk, &proof, &verifiers_checker, &person_com).unwrap());
    }
}
