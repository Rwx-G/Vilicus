//! Spike for AD-36: a member public key in `wrappers.db` receives the household key (HK)
//! only after a MAC under a key an attacker who writes the disk without HK cannot hold.
//!
//! Normative source: `doc/key-management.md` section 2. Byte layouts: `README.md`.
#![forbid(unsafe_code)]
#![warn(clippy::all)]

mod ceremony;
mod encoding;
mod error;
#[cfg(test)]
mod known_answers;
mod primitives;
mod store;

pub use ceremony::{
    Alert, EnrollmentToken, FIRST_HK_VERSION, MemberSecrets, Refusal, TOKEN_LEN, UnlockReport,
    UnlockedAdult, adult_unlock_wrap_pending, create_first_member, enroll, member_add,
    rewrap_household_key, unlock,
};
pub use encoding::{FORMAT_VERSION, alg, label};
pub use error::Error;
pub use store::{Field, MAX_MEMBER_ID_LEN, MemberRecord, MemberState, Store};
