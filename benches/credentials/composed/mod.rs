use criterion::Criterion;

/// Runs passport + student + employee flows with the same holder_tag policy.
///
/// This is a multi-proof composition benchmark entrypoint (MVP): each credential proves
/// membership + attributes + holder_tag, and the verifier accepts all three bundles together.
pub fn bench_cross_credential(c: &mut Criterion) {
    crate::credentials::passport::bench_passport(c);
    crate::credentials::student_id::bench_student_id(c);
    crate::credentials::employee_id::bench_employee_id(c);
}
