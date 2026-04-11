// 定义描述属性的特征，即凭证打算提交和隐藏的数据。

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

// 描述任何持有属性的对象。要求是它持有承诺随机数并定义一种方法来提交到自身。
pub trait Attrs<ConstraintF, AC>: Default
where
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
{
    // 序列化除了nonce和param之外的所有内容
    fn to_bytes(&self) -> Vec<u8>;

    // 获取承诺方案的参数。一般来说，属性不应该持有参数。相反，这个函数应该返回对某个全局值的引用。
    fn get_com_param(&self) -> &AC::Parameters;

    // 获取承诺随机数
    fn get_com_nonce(&self) -> &ComNonce;

    // 使用nonce和承诺参数确定性地形成对属性集的承诺
    fn commit(&self) -> AC::Output {
        let param = self.get_com_param();

        // 使用给定的nonce作为种子生成适当类型的nonce
        let nonce = {
            let nonce_seed = self.get_com_nonce();
            let mut rng = ChaCha12Rng::from_seed(nonce_seed.0);
            AC::Randomness::rand(&mut rng)
        };

        // 提交序列化的属性
        AC::commit(param, &self.to_bytes(), &nonce).unwrap()
    }
}

// 描述ZK电路版本的`Attrs`。唯一的要求是它持有承诺随机数，定义一种方法来提交到自身，并且可以从其对应的`Attrs`对象构造。
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

    // 见证ZK使用的秘密属性
    fn witness_attrs(
        cs: impl Into<Namespace<ConstraintF>>,
        attrs: &A,
    ) -> Result<Self, SynthesisError>;

    // 获取承诺方案的参数。一般来说，属性不应该持有参数。相反，这个函数应该返回对某个全局值的引用。
    fn get_com_param(&self) -> Result<ACG::ParametersVar, SynthesisError>;

    // 获取承诺随机数。不是变量，而是原生随机数。这是自动见证的。
    fn get_com_nonce(&self) -> &ComNonce;

    // 使用nonce和承诺参数确定性地形成对属性集的承诺
    fn commit(&self) -> Result<ACG::OutputVar, SynthesisError> {
        let cs = self.cs();
        let com_param = self.get_com_param()?;

        // 使用给定的nonce作为种子生成适当类型的nonce
        let nonce_var = {
            let nonce_seed = self.get_com_nonce();
            let mut rng = ChaCha12Rng::from_seed(nonce_seed.0);
            let nonce = AC::Randomness::rand(&mut rng);
            ACG::RandomnessVar::new_witness(ns!(cs, "nonce_var"), || Ok(nonce))?
        };

        // 提交序列化的属性
        ACG::commit(&com_param, &self.to_bytes()?, &nonce_var)
    }
}

// 一个`Attrs`特征，它有一个标识用户的东西以及一个我们可以用于速率限制的随机种子
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

// `AccountableAttrs`的gadget版本
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
