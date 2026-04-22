//! 用于在 arkworks 中制作零知识电路的实用工具

use core::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::{constraints::CRHGadget, CRH},
    Error as ArkError,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
    uint8::UInt8,
    R1CSVar, ToBytesGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, ConstraintSynthesizer, Namespace, SynthesisError};
use ark_std::rand::Rng;

pub fn count_constraints<ConstraintF, C>(circuit: C) -> Result<(usize, usize, usize), SynthesisError>
where
    ConstraintF: PrimeField,
    C: ConstraintSynthesizer<ConstraintF>,
{
    let cs = ConstraintSystem::<ConstraintF>::new_ref();
    circuit.generate_constraints(cs.clone())?;
    Ok((cs.num_constraints(), cs.num_witness_variables(), cs.num_instance_variables()))
}

// 这个CRH是输入的恒等函数
pub struct IdentityCRH;
impl CRH for IdentityCRH {
    const INPUT_SIZE_BITS: usize = 0;

    type Output = Vec<u8>;
    type Parameters = ();

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, ArkError> {
        Ok(())
    }

    // 返回输入
    fn evaluate(_parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, ArkError> {
        Ok(input.to_vec())
    }
}

// 这个CRH是输入的恒等函数
pub struct IdentityCRHGadget;
impl<ConstraintF: PrimeField> CRHGadget<IdentityCRH, ConstraintF> for IdentityCRHGadget {
    // `Bytestring` 只是一个 `Vec<UInt8<F>>` 的包装器
    type OutputVar = Bytestring<ConstraintF>;

    // `UnitVar` 是变量形式的单位类型
    type ParametersVar = UnitVar<ConstraintF>;

    // 返回输入
    fn evaluate(
        _parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        Ok(Bytestring(input.to_vec()))
    }
}

// 电路变量的单位类型
#[derive(Clone, Debug, Default)]
pub struct UnitVar<ConstraintF: PrimeField>(PhantomData<ConstraintF>);

impl<ConstraintF: PrimeField> AllocVar<(), ConstraintF> for UnitVar<ConstraintF> {
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<ConstraintF>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(UnitVar(PhantomData))
    }
}

// 这个类型是 `IdentityCRH` 的输出
// 它只是一个 `Vec<UInt8<F>>`
// 我们为什么需要一个新的类型是因为 `Vec<UInt8<F>>` 没有实现 `EqGadget` 或 `AllocVar`
#[derive(Clone, Debug)]
pub struct Bytestring<ConstraintF: PrimeField>(pub Vec<UInt8<ConstraintF>>);

// 实现所有必要的特征
// 实现 `EqGadget` 特征
impl<ConstraintF: PrimeField> EqGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.0.as_slice().is_eq(other.0.as_slice())
    }
}

// 实现 `ToBytesGadget` 特征
impl<ConstraintF: PrimeField> ToBytesGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        Ok(self.0.clone())
    }
}

// 实现 `ToConstraintFieldGadget` 特征
impl<ConstraintF: PrimeField> ToConstraintFieldGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<ConstraintF>>, SynthesisError> {
        self.0.to_constraint_field()
    }
}

// 实现 `CondSelectGadget` 特征
impl<ConstraintF: PrimeField> CondSelectGadget<ConstraintF> for Bytestring<ConstraintF> {
    fn conditionally_select(
        cond: &Boolean<ConstraintF>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        assert_eq!(true_value.0.len(), false_value.0.len());

        let bytes: Result<Vec<_>, _> = true_value
            .0
            .iter()
            .zip(false_value.0.iter())
            .map(|(t, f)| UInt8::conditionally_select(cond, t, f))
            .collect();
        bytes.map(Bytestring)
    }
}

// 实现 `AllocVar` 特征
impl<ConstraintF: PrimeField> AllocVar<Vec<u8>, ConstraintF> for Bytestring<ConstraintF> {
    // 分配一个UInt8向量。如果`f()`是`Err`，则会发生panic，因为我们不知道要分配多少字节
    fn new_variable<T: Borrow<Vec<u8>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f_output = f().expect("cannot allocate a Bytestring of indeterminate length");
        let native_bytes = f_output.borrow();

        let var_bytes: Result<Vec<_>, _> = native_bytes
            .iter()
            .map(|b| UInt8::new_variable(cs.clone(), || Ok(b), mode))
            .collect();

        var_bytes.map(Bytestring)
    }
}

// 实现 `R1CSVar` 特征
impl<ConstraintF: PrimeField> R1CSVar<ConstraintF> for Bytestring<ConstraintF> {
    type Value = Vec<u8>;

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        let mut result = ConstraintSystemRef::None;
        for var in &self.0 {
            result = var.cs().or(result);
        }
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.iter().map(|v| v.value()).collect()
    }
}
