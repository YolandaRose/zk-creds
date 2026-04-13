use criterion::Criterion;

// 使用 joint 模块的跨凭证场景：
// - 学生–员工：校企合作，验证姓名一致、学校名和公司名
// - 护照–学生：机票场景，验证年龄和国籍
// - 护照–员工：商务场景，验证公司名和工作证有效期
pub fn bench_cross_credential(c: &mut Criterion) {
    crate::credentials::joint::bench_joint_student_employee(c);
    crate::credentials::joint::bench_joint_passport_student(c);
    crate::credentials::joint::bench_joint_passport_employee(c);
}
