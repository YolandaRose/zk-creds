// Student ID凭证基准测试：定义`StudentInfo`，dump格式，颁发检查器和谓词。
// 相同RSA/PKCS#1 v1.5 + SHA-256模式。
// 为了链接与护照叶子相同的持有者，重用相同的长期秘密（例如相同的`seed`字段）在`PersonalInfo`和`StudentInfo`承诺之间并证明链接谓词中的相等性。

#[allow(dead_code)]
pub struct BenchPlaceholder;
