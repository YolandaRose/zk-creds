use criterion::Criterion;

//使用相同的holder_tag策略创建护照+学生+员工流。
// 这是一个多重证明的组合基准入口点（MVP）：每个凭证证明成员资格+属性+ holder_tag，验证器同时接受这三个捆绑包。
pub fn bench_cross_credential(c: &mut Criterion) {
    crate::credentials::passport::bench_passport(c);
    crate::credentials::student_id::bench_student_id(c);
    crate::credentials::employee_id::bench_employee_id(c);
}
