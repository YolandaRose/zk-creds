// 从护照dump中的X.509证书加载RSA发行方密钥（真实ePassport）。

use crate::credentials::common::sig_verif::IssuerPubkey;
use crate::credentials::passport::passport_dump::PassportDump;

use rsa::pkcs8::FromPublicKey;
use rsa::RsaPublicKey;
use x509_parser::parse_x509_certificate;

pub fn load_pubkey_from_dump(dump: &PassportDump) -> IssuerPubkey {
    let cert = (parse_x509_certificate(&dump.cert).unwrap()).1;
    let pubkey = RsaPublicKey::from_public_key_der(cert.public_key().raw).unwrap();
    IssuerPubkey(pubkey)
}
