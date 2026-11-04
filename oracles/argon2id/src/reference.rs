//! The reference implementation, phc-winner-argon2, as Debian 13's `libargon2-dev` builds it from
//! the upstream tag 20190702 (the source package `argon2` 0~20190702+dfsg-4, whose `src/` is the
//! tag's; `run.sh` prints the evidence), linked through this one hand-written binding of
//! `argon2.h`: the raw Argon2id hash, which takes no secret and no associated data.

use std::ffi::{c_int, c_void};

#[link(name = "argon2")]
unsafe extern "C" {
    /// `argon2id_hash_raw` of `argon2.h`: Argon2id version 0x13, `parallelism` lanes on as many
    /// threads, `hashlen` bytes of output; `ARGON2_OK` (0) on success.
    fn argon2id_hash_raw(
        t_cost: u32,
        m_cost: u32,
        parallelism: u32,
        pwd: *const c_void,
        pwdlen: usize,
        salt: *const c_void,
        saltlen: usize,
        hash: *mut c_void,
        hashlen: usize,
    ) -> c_int;
}

/// Argon2id of `password` and `salt` with m KiB, t passes and p lanes, 32 bytes of output, by the
/// reference implementation; its error code when it refuses.
pub fn argon2id(
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    password: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], c_int> {
    let mut out = [0_u8; 32];
    // SAFETY: every pointer is valid for the length given beside it for the whole call, the output
    // is writable, and the library keeps none of them after it returns.
    let status = unsafe {
        argon2id_hash_raw(
            passes,
            memory_kib,
            lanes,
            password.as_ptr().cast(),
            password.len(),
            salt.as_ptr().cast(),
            salt.len(),
            out.as_mut_ptr().cast(),
            out.len(),
        )
    };
    if status == 0 { Ok(out) } else { Err(status) }
}
