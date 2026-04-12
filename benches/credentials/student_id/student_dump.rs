//! JSON input for student-card benchmarks (`student_card.json`).

use crate::credentials::student_id::params::{
    COLLEGE_LEN, NAME_LEN, RECORD_BLOB_LEN, SCHOOL_LEN, STUDENT_NO_LEN,
};
use crate::credentials::student_id::student_info::StudentInfo;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
pub(crate) struct StudentDump {
    pub(crate) name: String,
    pub(crate) school: String,
    pub(crate) college: String,
    #[serde(rename = "student_id")]
    pub(crate) student_no: String,
    pub(crate) enrollment_year: u32,
    /// 到期日：须为 **8 位** `YYYYMMDD` 整数（与 `STUDENT_CARD_TODAY` 同形比较）；不足 8 位会导致整数值小于基准日而谓词失败。
    pub(crate) card_expiry: u32,
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
            serde::de::Error::custom(format!("base64 decode sig: {:?}", e))
        })
    }
}

fn copy_padded_utf8(src: &str, dst: &mut [u8]) {
    dst.fill(0);
    let b = src.as_bytes();
    let n = b.len().min(dst.len());
    dst[..n].copy_from_slice(&b[..n]);
}

impl StudentDump {
    pub(crate) fn record_digest(&self) -> [u8; 32] {
        let mut blob = [0u8; RECORD_BLOB_LEN];
        self.write_blob(&mut blob);
        Sha256::digest(&blob).into()
    }

    fn write_blob(&self, blob: &mut [u8; RECORD_BLOB_LEN]) {
        let mut o = 0usize;
        copy_padded_utf8(&self.name, &mut blob[o..o + NAME_LEN]);
        o += NAME_LEN;
        copy_padded_utf8(&self.school, &mut blob[o..o + SCHOOL_LEN]);
        o += SCHOOL_LEN;
        copy_padded_utf8(&self.college, &mut blob[o..o + COLLEGE_LEN]);
        o += COLLEGE_LEN;
        copy_padded_utf8(&self.student_no, &mut blob[o..o + STUDENT_NO_LEN]);
        o += STUDENT_NO_LEN;
        blob[o..o + 4].copy_from_slice(&self.enrollment_year.to_be_bytes());
        o += 4;
        blob[o..o + 4].copy_from_slice(&self.card_expiry.to_be_bytes());
    }

    pub(crate) fn to_student_info<R: ark_std::rand::Rng>(
        &self,
        rng: &mut R,
    ) -> (StudentInfo, [u8; RECORD_BLOB_LEN]) {
        let mut blob = [0u8; RECORD_BLOB_LEN];
        self.write_blob(&mut blob);
        let info = StudentInfo::from_blob(rng, &blob);
        (info, blob)
    }
}
