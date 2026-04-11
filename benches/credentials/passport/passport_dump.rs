//! Flat JSON for passport benchmarks (`passport_dump.json`): canonical RECORD_BLOB + RSA sig.

use crate::credentials::passport::params::{
    BIOMETRIC_RAW_MAX, NAME_LEN, RECORD_BLOB_LEN, STATE_ID_LEN,
};
use crate::credentials::passport::passport_info::PersonalInfo;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
pub(crate) struct PassportDump {
    /// 3-letter country code, e.g. `USA`.
    pub(crate) nationality: String,
    pub(crate) name: String,
    /// YYYYMMDD as integer, e.g. `19900101`.
    pub(crate) dob: u32,
    /// YYYYMMDD as integer, e.g. `20301231`.
    pub(crate) passport_expiry: u32,
    /// Raw biometric bytes (e.g. JPEG chunk); truncated/padded to `BIOMETRIC_RAW_MAX` in blob.
    #[serde(with = "serde_bytes_base64")]
    pub(crate) biometrics: Vec<u8>,
    #[serde(with = "serde_bytes_base64")]
    pub(crate) sig: Vec<u8>,
}

mod serde_bytes_base64 {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::decode(s.as_bytes()).map_err(|e| {
            serde::de::Error::custom(format!("base64 decode: {:?}", e))
        })
    }
}

fn copy_padded_utf8(src: &str, dst: &mut [u8]) {
    dst.fill(0);
    let b = src.as_bytes();
    let n = b.len().min(dst.len());
    dst[..n].copy_from_slice(&b[..n]);
}

fn copy_padded_bytes(src: &[u8], dst: &mut [u8]) {
    dst.fill(0);
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
}

impl PassportDump {
    pub(crate) fn record_digest(&self) -> [u8; 32] {
        let mut blob = [0u8; RECORD_BLOB_LEN];
        self.write_blob(&mut blob);
        Sha256::digest(&blob).into()
    }

    fn write_blob(&self, blob: &mut [u8; RECORD_BLOB_LEN]) {
        let mut o = 0usize;
        copy_padded_utf8(&self.nationality, &mut blob[o..o + STATE_ID_LEN]);
        o += STATE_ID_LEN;
        copy_padded_utf8(&self.name, &mut blob[o..o + NAME_LEN]);
        o += NAME_LEN;
        blob[o..o + 4].copy_from_slice(&self.dob.to_be_bytes());
        o += 4;
        blob[o..o + 4].copy_from_slice(&self.passport_expiry.to_be_bytes());
        o += 4;
        copy_padded_bytes(&self.biometrics, &mut blob[o..o + BIOMETRIC_RAW_MAX]);
    }

    pub(crate) fn to_personal_info<R: ark_std::rand::Rng>(
        &self,
        rng: &mut R,
    ) -> (PersonalInfo, [u8; RECORD_BLOB_LEN]) {
        let mut blob = [0u8; RECORD_BLOB_LEN];
        self.write_blob(&mut blob);
        let info = PersonalInfo::from_blob(rng, &blob);
        (info, blob)
    }
}

impl std::fmt::Debug for PassportDump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassportDump")
            .field("nationality", &self.nationality)
            .field("name", &self.name)
            .field("dob", &self.dob)
            .field("passport_expiry", &self.passport_expiry)
            .field("biometrics_len", &self.biometrics.len())
            .finish()
    }
}
