//! JSON input for student-card benchmarks (`employee_card.json`).

use crate::credentials::employee_id::employee_info::EmployeeInfo;
use crate::credentials::employee_id::params::{
    COMPANY_LEN, DEPARTMENT_LEN, EMPLOYEE_NO_LEN, NAME_LEN, RECORD_BLOB_LEN,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
pub(crate) struct EmployeeDump {
    pub(crate) name: String,
    pub(crate) company: String,
    pub(crate) department: String,
    #[serde(rename = "employee_id")]
    pub(crate) employee_no: String,
    pub(crate) hire_year: u32,
    /// YYYYMMDD as integer, e.g. `20301231`.
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
        base64::decode(s.as_bytes())
            .map_err(|e| serde::de::Error::custom(format!("base64 decode sig: {:?}", e)))
    }
}

fn copy_padded_utf8(src: &str, dst: &mut [u8]) {
    dst.fill(0);
    let b = src.as_bytes();
    let n = b.len().min(dst.len());
    dst[..n].copy_from_slice(&b[..n]);
}

impl EmployeeDump {
    pub(crate) fn record_digest(&self) -> [u8; 32] {
        let mut blob = [0u8; RECORD_BLOB_LEN];
        self.write_blob(&mut blob);
        Sha256::digest(&blob).into()
    }

    fn write_blob(&self, blob: &mut [u8; RECORD_BLOB_LEN]) {
        let mut o = 0usize;
        copy_padded_utf8(&self.name, &mut blob[o..o + NAME_LEN]);
        o += NAME_LEN;
        copy_padded_utf8(&self.company, &mut blob[o..o + COMPANY_LEN]);
        o += COMPANY_LEN;
        copy_padded_utf8(&self.department, &mut blob[o..o + DEPARTMENT_LEN]);
        o += DEPARTMENT_LEN;
        copy_padded_utf8(&self.employee_no, &mut blob[o..o + EMPLOYEE_NO_LEN]);
        o += EMPLOYEE_NO_LEN;
        blob[o..o + 4].copy_from_slice(&self.hire_year.to_be_bytes());
        o += 4;
        blob[o..o + 4].copy_from_slice(&self.card_expiry.to_be_bytes());
    }

    pub(crate) fn to_employee_info<R: ark_std::rand::Rng>(
        &self,
        rng: &mut R,
    ) -> (EmployeeInfo, [u8; RECORD_BLOB_LEN]) {
        let mut blob = [0u8; RECORD_BLOB_LEN];
        self.write_blob(&mut blob);
        let info = EmployeeInfo::from_blob(rng, &blob);
        (info, blob)
    }
}
