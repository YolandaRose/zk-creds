//! 定义了一个特性，允许服务提供者在其服务上实现速率限制

use crate::{
    attrs::{AccountableAttrs, AccountableAttrsVar},
    pred::PredicateChecker,
};

use core::cmp::Ordering;

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
    /// 这是 `PRFₛ(epoch || ctr)`，其中 s 是种子
    hidden_ctr: ConstraintF,
}

/// 可变版本的 presentation token
#[derive(Clone)]
pub struct PresentationTokenVar<ConstraintF: PrimeField> {
    hidden_ctr: FpVar<ConstraintF>,
}

/// 这个特性允许用户每次展示他们的凭据时创建一个 "presentation token"。如果验证者要求 `ctr` 有界，则可以用于速率限制。
pub trait MultishowableAttrs<ConstraintF, AC>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    /// 从给定的可问责属性计算 presentation token
    fn compute_presentation_token(
        &self,
        params: PoseidonParameters<ConstraintF>,
        epoch: u64,
        ctr: u16,
    ) -> Result<PresentationToken<ConstraintF>, ArkError>;
}

impl<ConstraintF, A, AC> MultishowableAttrs<ConstraintF, AC> for A
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
        epoch: u64,
        ctr: u16,
    ) -> Result<PresentationToken<ConstraintF>, ArkError> {
        let h = Poseidon::new(params);
        let seed = self.get_seed();

        // hidden_ctr = PRFₛ(epoch || ctr)
        let hidden_ctr: ConstraintF = {
            let hash_input = &[
                vec![ConstraintF::from(PRF1_DOMAIN_SEP)],
                seed.to_field_elements().unwrap(),
                vec![ConstraintF::from(epoch), ConstraintF::from(ctr)],
            ]
            .concat();

            h.hash(hash_input).unwrap()
        };

        Ok(PresentationToken { hidden_ctr })
    }
}

/// 实现 `compute_presentation_token` 对于所有 AccountableAttrsVar
pub trait MultishowableAttrsVar<ConstraintF, A, AC, ACG>
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
        epoch: &FpVar<ConstraintF>,
        ctr: &FpVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError>;
}

/// 实现 `compute_presentation_token` 对于所有 AccountableAttrsVar
impl<ConstraintF, A, AV, AC, ACG> MultishowableAttrsVar<ConstraintF, A, AC, ACG> for AV
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
        epoch: &FpVar<ConstraintF>,
        ctr: &FpVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError> {
        let h = PoseidonGadget { params };
        let seed = self.get_seed()?;

        // hidden_ctr = PRFₛ(epoch || ctr)
        let hidden_ctr = {
            let hash_input = [
                vec![FpVar::Constant(ConstraintF::from(PRF1_DOMAIN_SEP))],
                seed.to_constraint_field()?,
                epoch.to_constraint_field()?,
                ctr.to_constraint_field()?,
            ]
            .concat();

            h.hash(&hash_input)?
        };

        Ok(PresentationTokenVar { hidden_ctr })
    }
}

/// 证明 `token` 是使用随机种子进行 PRF 计算的结果
#[derive(Clone, Default)]
pub struct MultishowChecker<ConstraintF>
where
    ConstraintF: PrimeField,
{
    // 公共输入 //
    /// 与这个展示相关的伪随机值
    pub token: PresentationToken<ConstraintF>,
    // 当前展示的 epoch
    pub epoch: u64,
    /// 这个属性字符串可以展示的次数
    pub max_num_presentations: u16,

    // 私有输入 //
    /// 表示这个属性字符串已经展示的次数的计数器（从 0 开始）
    pub ctr: u16,

    // 常量 //
    /// 波塞冬参数
    pub params: PoseidonParameters<ConstraintF>,
}

impl<ConstraintF, A, AV, AC, ACG> PredicateChecker<ConstraintF, A, AV, AC, ACG>
    for MultishowChecker<ConstraintF>
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

        // 见证公共输入: epoch, nonce, token, 和最大计数器大小
        let epoch = FpVar::<ConstraintF>::new_input(ns!(cs, "epoch"), || Ok(ConstraintF::from(self.epoch)))?;
        let hidden_ctr = FpVar::<ConstraintF>::new_input(ns!(cs, "hidden ctr"), || Ok(self.token.hidden_ctr))?;
        let max_num_presentations = FpVar::<ConstraintF>::new_input(ns!(cs, "max #presentations"), || Ok(ConstraintF::from(self.max_num_presentations)))?;

        // 见证计数器私有输入
        let ctr =
            FpVar::<ConstraintF>::new_witness(ns!(cs, "ctr"), || Ok(ConstraintF::from(self.ctr)))?;

        // 断言计数器 < 最大展示次数
        ctr.enforce_cmp(&max_num_presentations, Ordering::Less, false)?;

        // 计算 presentation token
        let computed_token = attrs.compute_presentation_token(params, &epoch, &ctr)?;

        // 断言计算值的相等性
        computed_token.hidden_ctr.enforce_equal(&hidden_ctr)?;

        // 完成
        Ok(())
    }

    /// 输出与谓词公共输入对应的字段元素。这不包括 `attrs`。
    fn public_inputs(&self) -> Vec<ConstraintF> {
        vec![
            self.epoch.into(),
            self.token.hidden_ctr,
            self.max_num_presentations.into(),
        ]
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
    fn test_multishow() {
        let mut rng = ark_std::test_rng();

        // 设置公共参数
        let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
        let epoch = 5;
        let max_num_presentations: u16 = 128;
        let placeholder_checker = MultishowChecker {
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

        // 用户计算一个 multishow token
        let ctr: u16 = 1;
        let token = MultishowableAttrs::<_, TestComSchemePedersen>::compute_presentation_token(
            &person,
            params.clone(),
            epoch,
            ctr,
        )
        .unwrap();

        // 用户构造一个谓词的检查器
        let users_checker = MultishowChecker {
            token: token.clone(),
            epoch,
            max_num_presentations,
            ctr,
            params: params.clone(),
        };

        // 证明谓词
        let proof = prove_birth(&mut rng, &pk, users_checker, person.clone()).unwrap();

        // 现在验证谓词
        // 只用公共数据制作检查器
        let verifiers_checker = MultishowChecker {
            token,
            epoch,
            max_num_presentations,
            params,
            ..Default::default()
        };
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);
        let vk = pk.prepare_verifying_key();
        assert!(verify_birth(&vk, &proof, &verifiers_checker, &person_com).unwrap());
    }
}
