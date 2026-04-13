//! 定义描述属性的特征，即凭证打算提交和隐藏的数据。

use crate::poseidon_utils::ComNonce;

use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, bits::ToBytesGadget, ToConstraintFieldGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

// 描述持有属性的对象：要求有承诺随机数
pub trait Attrs<ConstraintF, AC>: Default
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 序列化除了nonce和param之外的所有内容
    fn to_bytes(&self) -> Vec<u8>;

    // 获取承诺方案的参数
    fn get_com_param(&self) -> &AC::Parameters;

    // 获取nonce承诺随机数用于commitment
    fn get_com_nonce(&self) -> &ComNonce;

    // 使用nonce和承诺参数确定性地形成对属性集的承诺
    fn commit(&self) -> AC::Output {
        let param = self.get_com_param();

        // 使用给定的nonce作为种子生成随机数加入承诺中
        let nonce = {
            let nonce_seed = self.get_com_nonce();
            //生成伪随机nonce
            let mut rng = ChaCha12Rng::from_seed(nonce_seed.0);
            AC::Randomness::rand(&mut rng)
        };

        // AC：Commitment Scheme（承诺方案）
        AC::commit(param, &self.to_bytes(), &nonce).unwrap()
    }
}

// 描述ZK电路版本的属性`Attrs`：要求有承诺随机数，并且可以从其对应的`Attrs`对象构造
pub trait AttrsVar<ConstraintF, A, AC, ACG>: ToBytesGadget<ConstraintF> + Sized
where
    ConstraintF: PrimeField,
    A: Attrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    // 返回此var使用的约束系统
    fn cs(&self) -> ConstraintSystemRef<ConstraintF>;

    // 将attrs对象转换为AttrsVar对象
    fn witness_attrs(
        cs: impl Into<Namespace<ConstraintF>>,
        attrs: &A,
    ) -> Result<Self, SynthesisError>;

    // 获取承诺方案的参数
    fn get_com_param(&self) -> Result<ACG::ParametersVar, SynthesisError>;

    // 获取承诺随机数
    fn get_com_nonce(&self) -> &ComNonce;

    // 使用nonce和承诺参数确定性地形成对属性集的承诺
    fn commit(&self) -> Result<ACG::OutputVar, SynthesisError> {
        let cs = self.cs();
        let com_param = self.get_com_param()?;

        // 使用给定的nonce作为种子生成随机数
        let nonce_var = {
            let nonce_seed = self.get_com_nonce();
            let mut rng = ChaCha12Rng::from_seed(nonce_seed.0);
            let nonce = AC::Randomness::rand(&mut rng);
            ACG::RandomnessVar::new_witness(ns!(cs, "nonce_var"), || Ok(nonce))?
        };

        // ACG: CommitmentGadget（承诺gadget）
        ACG::commit(&com_param, &self.to_bytes()?, &nonce_var)
    }
}

//可追踪身份：增加一个标识用户的id以及一个可以用于在假名验证中限制速率的随机种子
pub trait AccountableAttrs<ConstraintF, AC>: Attrs<ConstraintF, AC>
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    type Id: ToConstraintField<ConstraintF>;
    type Seed: ToConstraintField<ConstraintF>;

    fn get_id(&self) -> Self::Id;
    fn get_seed(&self) -> Self::Seed;
}

// `AccountableAttrs`的电路gadget版本
pub trait AccountableAttrsVar<ConstraintF, A, AC, ACG>: AttrsVar<ConstraintF, A, AC, ACG>
where
    ConstraintF: PrimeField,
    A: AccountableAttrs<ConstraintF, AC>,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    type Id: ToConstraintFieldGadget<ConstraintF>;
    type Seed: ToConstraintFieldGadget<ConstraintF>;

    fn get_id(&self) -> Result<Self::Id, SynthesisError>;
    fn get_seed(&self) -> Result<Self::Seed, SynthesisError>;
}
