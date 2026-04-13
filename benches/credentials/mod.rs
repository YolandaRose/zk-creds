//多凭证基准测试：共享发行方助手（`common`）加上每个凭证模块。
// 当您想要在凭证之间链接相同的持有者时，在`PersonalInfo` / `StudentInfo`中使用相同的长期`seed`；
// 在链接谓词中证明相等性或强制在发行时执行。

pub mod common;
pub mod composed;
pub mod employee_id;
pub mod joint;
pub mod passport;
pub mod student_id;
