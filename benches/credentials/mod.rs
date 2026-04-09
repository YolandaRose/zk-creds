//! Multi-credential benchmarks: shared issuer helpers (`common`) plus per-credential modules.
//!
//! Use the same long-term `seed` in `PersonalInfo` / `StudentInfo` when you want to link the same
//! holder across credentials; prove equality in a link predicate and/or enforce at issuance.

pub mod common;
pub mod composed;
pub mod employee_id;
pub mod passport;
pub mod student_id;
