use rsa::{padding::PaddingScheme, pkcs8::FromPublicKey, Hash, PublicKey, RsaPublicKey};
use std::env;
use std::fs;
use std::path::Path;

// 用户提供的发行方密钥（默认：在`credentials/passport/`下与`passport_dump.json`一起）。
const USER_ISSUER_PUBKEY_PATH: &str = "benches/credentials/passport/issuer_pubkey.pem";
// 演示RSA公钥用于本地基准测试（与`issuer_demo_priv.pem`在同一文件夹中）。
const DEMO_ISSUER_PUBKEY_PATH: &str = "benches/credentials/passport/issuer_demo_pubkey.pem";

pub struct IssuerPubkey(RsaPublicKey);

// 加载用于验证签发请求里 RSA 签名的公钥（护照 / 学生证 / 工作证均对 **SHA256(规范 record blob)** 签名）。

// 解析顺序：
// 1. `ZKCREDS_ISSUER_PUBKEY_PEM` — PEM文本的公钥。
// 2. `ZKCREDS_ISSUER_PUBKEY_PATH` — PEM文件的路径。
// 3. `issuer_pubkey.pem` 如果存在（您的密钥）。
// 4. 否则 `issuer_demo_pubkey.pem`（与 `passport_dump.json` 等一起用演示私钥重签；见 `sign_passport_record.ps1` / `sign_student_record.ps1`）。
//
// 签名：OpenSSL `openssl dgst -sha256 -sign <priv.pem> -out sig.bin record_blob.bin`（与代码里 `record_digest` 一致）。
pub fn load_issuer_pubkey() -> IssuerPubkey {
    let pem = if let Ok(pem) = env::var("ZKCREDS_ISSUER_PUBKEY_PEM") {
        pem
    } else if let Ok(path) = env::var("ZKCREDS_ISSUER_PUBKEY_PATH") {
        fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "ZKCREDS_ISSUER_PUBKEY_PATH={path:?}: could not read issuer public key PEM: {e}"
            )
        })
    } else {
        let user_path = Path::new(USER_ISSUER_PUBKEY_PATH);
        let path: &Path = if user_path.exists() {
            user_path
        } else {
            Path::new(DEMO_ISSUER_PUBKEY_PATH)
        };
        fs::read_to_string(path).unwrap_or_else(|e| {
            panic!(
                "Could not read issuer public key from {}: {e}. \
                 Put your RSA public key PEM at {USER_ISSUER_PUBKEY_PATH}, \
                 or set ZKCREDS_ISSUER_PUBKEY_PEM / ZKCREDS_ISSUER_PUBKEY_PATH.",
                path.display()
            )
        })
    };
    let pubkey = RsaPublicKey::from_public_key_pem(&pem)
        .unwrap_or_else(|e| panic!("invalid issuer RSA public key PEM: {e}"));
    IssuerPubkey(pubkey)
}

impl IssuerPubkey {
    #[must_use]
    pub fn verify(&self, sig: &[u8], hash: &[u8]) -> bool {
        self.0
            .verify(
                PaddingScheme::PKCS1v15Sign {
                    hash: Some(Hash::SHA2_256),
                },
                hash,
                sig,
            )
            .is_ok()
    }
}
