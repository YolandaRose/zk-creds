//! 定义一个trait，允许服务提供者对其服务实现速率限制。如果用户超过了这个限制，它将会去匿名化。

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

// 所有使用Poseidon的域分隔符
const PRF1_DOMAIN_SEP: u8 = 123;
const PRF2_DOMAIN_SEP: u8 = 124;
const HASH_DOMAIN_SEP: u8 = 125;

// 字段元素的伪随机对如果有两个具有相同`hidden_ctr`的token，则可以将它们组合起来以获得用户ID的（哈希）。
#[derive(Clone, Default)]
pub struct PresentationToken<ConstraintF: PrimeField> {
    // This is `PRFₛ(epoch || ctr)` where s is the seed
    hidden_ctr: ConstraintF,

    // 这是`H(ID) + H(n)·PRFₛ` (epoch || ctr)`，其中`ID`是用户ID， s是种子，n是表示nonce。
    // 请注意，如果`ctr`在一个epoch内重复，那么我们在`H(ID) + x·PRFₛ` (epoch || ctr)`上有两个元素。
    // 观察者可以求出y轴截距并恢复`H(ID)`。
    hidden_line_point: ConstraintF,
}

// 可变版本的presentation token
#[derive(Clone)]
pub struct PresentationTokenVar<ConstraintF: PrimeField> {
    hidden_ctr: FpVar<ConstraintF>,
    hidden_line_point: FpVar<ConstraintF>,
}

// 这个特性允许用户每次展示他们的凭据时创建一个 "presentation token"。如果验证者要求 `ctr` 有界，则可以用于速率限制。
// 当 `ctr` 在一个epoch内重复，presentation token将揭示相关 [`AccountableAttrs`] 的 `id` 值。
pub trait MultishowableAttrs<ConstraintF, AC>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 从给定的可问责属性计算 presentation token
    fn compute_presentation_token(
        &self,
        params: PoseidonParameters<ConstraintF>,
        epoch: u64,
        ctr: u16,
        nonce: ConstraintF,
    ) -> Result<PresentationToken<ConstraintF>, ArkError>;
}

impl<ConstraintF, A, AC> MultishowableAttrs<ConstraintF, AC> for A
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 从给定的可问责属性计算 presentation token
    fn compute_presentation_token(
        &self,
        params: PoseidonParameters<ConstraintF>,
        epoch: u64,
        ctr: u16,
        nonce: ConstraintF,
    ) -> Result<PresentationToken<ConstraintF>, ArkError> {
        let h = Poseidon::new(params);
        let id = self.get_id();
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

        // hidden_line_point = H(ID) + H(nonce)·PRFₛ'(epoch || ctr)
        let hidden_line_point = {
            // First hash the nonce
            let nonce_hash = {
                let hash_input = [
                    vec![ConstraintF::from(HASH_DOMAIN_SEP)],
                    nonce.to_field_elements().unwrap(),
                ]
                .concat();

                h.hash(&hash_input).unwrap()
            };

            // Then hash the ID
            let id_hash = {
                let hash_input = [
                    vec![ConstraintF::from(HASH_DOMAIN_SEP)],
                    id.to_field_elements().unwrap(),
                ]
                .concat();

                h.hash(&hash_input).unwrap()
            };

            // Now compute PRFₛ'(epoch || ctr)
            let prf_value = {
                let hash_input = [
                    vec![ConstraintF::from(PRF2_DOMAIN_SEP)],
                    seed.to_field_elements().unwrap(),
                    vec![ConstraintF::from(epoch), ConstraintF::from(ctr)],
                ]
                .concat();

                h.hash(&hash_input).unwrap()
            };

            // Now put it together
            id_hash + nonce_hash * prf_value
        };

        Ok(PresentationToken {
            hidden_ctr,
            hidden_line_point,
        })
    }
}

// 实现 `compute_presentation_token` 对于所有 AccountableAttrsVar
pub trait MultishowableAttrsVar<ConstraintF, A, AC, ACG>
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    // 从给定的可问责属性计算 presentation token
    fn compute_presentation_token(
        &self,
        params: PoseidonParametersVar<ConstraintF>,
        epoch: &FpVar<ConstraintF>,
        ctr: &FpVar<ConstraintF>,
        nonce: &FpVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError>;
}

// 实现 `compute_presentation_token` 对于所有 AccountableAttrsVar
impl<ConstraintF, A, AV, AC, ACG> MultishowableAttrsVar<ConstraintF, A, AC, ACG> for AV
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AV: AccountableAttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    // 从给定的可问责属性计算 presentation token
    fn compute_presentation_token(
        &self,
        params: PoseidonParametersVar<ConstraintF>,
        epoch: &FpVar<ConstraintF>,
        ctr: &FpVar<ConstraintF>,
        nonce: &FpVar<ConstraintF>,
    ) -> Result<PresentationTokenVar<ConstraintF>, SynthesisError> {
        let h = PoseidonGadget { params };
        let id = self.get_id()?;
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

        // hidden_line_point = H(ID) + H(nonce)·PRFₛ'(epoch || ctr)
        let hidden_line_point = {
            // First hash the nonce
            let nonce_hash = {
                let hash_input = [
                    vec![FpVar::Constant(ConstraintF::from(HASH_DOMAIN_SEP))],
                    nonce.to_constraint_field()?,
                ]
                .concat();

                h.hash(&hash_input)?
            };

            // Then hash the ID
            let id_hash = {
                let hash_input = [
                    vec![FpVar::Constant(ConstraintF::from(HASH_DOMAIN_SEP))],
                    id.to_constraint_field()?,
                ]
                .concat();

                h.hash(&hash_input)?
            };

            // Now compute PRFₛ'(epoch || ctr)
            let prf_value = {
                let hash_input = [
                    vec![FpVar::Constant(ConstraintF::from(PRF2_DOMAIN_SEP))],
                    seed.to_constraint_field()?,
                    epoch.to_constraint_field()?,
                    ctr.to_constraint_field()?,
                ]
                .concat();

                h.hash(&hash_input)?
            };

            // Now put it together
            id_hash + nonce_hash * prf_value
        };

        Ok(PresentationTokenVar {
            hidden_ctr,
            hidden_line_point,
        })
    }
}

// 证明 `token` 是使用验证者提供的 nonce 和属性 ID 以及随机种子进行 PRF 计算的结果
#[derive(Clone, Default)]
pub struct RevealingMultishowChecker<ConstraintF>
where
    ConstraintF: PrimeField,
{
    // 公共输入 //
    // 与这个展示相关的伪随机值
    pub token: PresentationToken<ConstraintF>,
    // 当前展示的 epoch
    pub epoch: u64,
    // 服务器提供的 nonce
    pub nonce: ConstraintF,
    // 这个属性字符串可以展示的次数
    pub max_num_presentations: u16,

    // 私有输入 //
    // 表示这个属性字符串已经展示的次数的计数器（从 0 开始）
    pub ctr: u16,

    // 常量 //
    // Poseidon parameters
    pub params: PoseidonParameters<ConstraintF>,
}

impl<ConstraintF, A, AV, AC, ACG> PredicateChecker<ConstraintF, A, AV, AC, ACG>
    for RevealingMultishowChecker<ConstraintF>
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AV: AccountableAttrsVar<ConstraintF, A, AC, ACG>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 返回是否满足谓词
    fn pred(self, cs: ConstraintSystemRef<ConstraintF>, attrs: &AV) -> Result<(), SynthesisError> {
        // Witness the Poseidon params
        let params = PoseidonParametersVar::new_constant(ns!(cs, "prf param"), &self.params)?;

        // Witness public inputs: epoch, nonce, token, and max counter size
        let epoch = FpVar::<ConstraintF>::new_input(ns!(cs, "epoch"), || {
            Ok(ConstraintF::from(self.epoch))
        })?;
        let nonce = FpVar::<ConstraintF>::new_input(ns!(cs, "nonce"), || Ok(self.nonce))?;
        let hidden_ctr =
            FpVar::<ConstraintF>::new_input(ns!(cs, "hidden ctr"), || Ok(self.token.hidden_ctr))?;
        let hidden_line_point =
            FpVar::<ConstraintF>::new_input(ns!(cs, "hidden line point"), || {
                Ok(self.token.hidden_line_point)
            })?;
        let max_num_presentations =
            FpVar::<ConstraintF>::new_input(ns!(cs, "max #presentations"), || {
                Ok(ConstraintF::from(self.max_num_presentations))
            })?;

        // Witness the counter private input
        let ctr =
            FpVar::<ConstraintF>::new_witness(ns!(cs, "ctr"), || Ok(ConstraintF::from(self.ctr)))?;

        // Assert counter < max_num_presentations
        ctr.enforce_cmp(&max_num_presentations, Ordering::Less, false)?;

        // Compute the presentation token
        let computed_token = attrs.compute_presentation_token(params, &epoch, &ctr, &nonce)?;

        // Assert the equality of the computed values
        computed_token.hidden_ctr.enforce_equal(&hidden_ctr)?;
        computed_token
            .hidden_line_point
            .enforce_equal(&hidden_line_point)?;

        Ok(())
    }

    // 输出与这个谓词的公共输入对应的字段元素。这 DOES NOT 包括 `attrs`。
    fn public_inputs(&self) -> Vec<ConstraintF> {
        vec![
            self.epoch.into(),
            self.nonce,
            self.token.hidden_ctr,
            self.token.hidden_line_point,
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

    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_ff::UniformRand;
    use arkworks_utils::Curve;

    const POSEIDON_WIDTH: u8 = 5;

    #[test]
    fn test_revealing_multishow() {
        let mut rng = ark_std::test_rng();

        // 设置公共参数
        let params = setup_poseidon_params(Curve::Bls381, 3, POSEIDON_WIDTH);
        let epoch = 5;
        let max_num_presentations: u16 = 128;
        let placeholder_checker = RevealingMultishowChecker {
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

        // 用户计算一个multishow token
        let nonce = Fr::rand(&mut rng);
        let ctr: u16 = 1;
        let token = MultishowableAttrs::<_, TestComSchemePedersen>::compute_presentation_token(
            &person,
            params.clone(),
            epoch,
            ctr,
            nonce,
        )
        .unwrap();

        // 用户构造一个谓词的检查器
        let users_checker = RevealingMultishowChecker {
            token: token.clone(),
            epoch,
            nonce,
            max_num_presentations,
            ctr,
            params: params.clone(),
        };

        // 证明谓词
        let proof = prove_birth(&mut rng, &pk, users_checker, person.clone()).unwrap();

        // 验证谓词
        // 只用公共数据制作检查器
        let verifiers_checker = RevealingMultishowChecker {
            token,
            epoch,
            nonce,
            max_num_presentations,
            params,
            ..Default::default()
        };
        let person_com = Attrs::<_, TestComSchemePedersen>::commit(&person);
        let vk = pk.prepare_verifying_key();
        assert!(verify_birth(&vk, &proof, &verifiers_checker, &person_com).unwrap());
    }
}
