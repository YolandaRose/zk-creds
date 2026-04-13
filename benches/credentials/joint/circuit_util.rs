use ark_bls12_381::Fr;
use ark_r1cs_std::{
    bits::{boolean::Boolean, uint8::UInt8, ToBitsGadget},
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::SynthesisError;

pub(crate) fn u32_be_bytes_to_fp(bytes: &[UInt8<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    assert_eq!(bytes.len(), 4);
    let mut acc = FpVar::<Fr>::zero();
    let base = FpVar::constant(Fr::from(256u16));
    for b in bytes {
        let v = Boolean::le_bits_to_fp_var(&b.to_bits_le()?)?;
        acc = acc * &base + &v;
    }
    Ok(acc)
}
