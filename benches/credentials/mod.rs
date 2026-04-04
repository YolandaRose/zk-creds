// 多凭证基准测试：共享发行方加密（`common`）和每个凭证模块。
// 计划：`student_id`，`employee_id` alongside `passport`。为了在凭证之间链接相同的持有者，在每个颁发中重用相同的长期秘密（例如`PersonalInfo::seed` / `AccountableAttrs::get_seed`）
// 凭证，重用相同的长期秘密（例如`PersonalInfo::seed` / `AccountableAttrs::get_seed`）
// 在每个颁发中并证明链接谓词中的相等性——发行方策略必须在那个检查之后只注册叶子。

pub mod common;
pub mod employee_id;
pub mod passport;
pub mod student_id;
