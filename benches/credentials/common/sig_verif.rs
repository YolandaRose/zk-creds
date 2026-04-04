use rsa::{padding::PaddingScheme, pkcs8::FromPublicKey, Hash, PublicKey, RsaPublicKey};
use std::env;
use std::fs;
use std::path::Path;

// 用户提供的发行方密钥（默认：在`credentials/passport/`下与`passport_dump.json`一起）。
const USER_ISSUER_PUBKEY_PATH: &str = "benches/credentials/passport/issuer_pubkey.pem";
// 演示RSA公钥用于本地基准测试（与`issuer_demo_priv.pem`在同一文件夹中）。
const DEMO_ISSUER_PUBKEY_PATH: &str = "benches/credentials/passport/issuer_demo_pubkey.pem";

pub struct IssuerPubkey(RsaPublicKey);

// 加载用于验证`IssuanceReq.sig`的RSA公钥，使用SHA-256(`econtent`)。

// 解析顺序：
// 1. `ZKCREDS_ISSUER_PUBKEY_PEM` — PEM文本的公钥。
// 2. `ZKCREDS_ISSUER_PUBKEY_PATH` — PEM文件的路径。
// 3. `issuer_pubkey.pem` 如果存在（您的密钥）。
// 4. 否则 `issuer_demo_pubkey.pem`（重新签名`passport_dump.json`与匹配的演示私钥；见`sign_econtent_for_issuer.ps1`）。
//
// 签名必须是**OpenSSL兼容**RSASSA-PKCS1-v1_5 over SHA-256的原始`econtent`字节（与`Sha256::digest(&econtent)`相同）：
// `openssl dgst -sha256 -sign <priv.pem> -out sig.bin econtent.bin`
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
