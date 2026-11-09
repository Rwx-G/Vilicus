//! OpenSSL 3.5's `EVP_KDF-ARGON2`, the second oracle of D129, through its `openssl kdf` command:
//! one process per derivation, the password and salt in hex, one thread, 32 bytes out in binary.

use std::process::Command;

/// The version line of the `openssl` command.
pub fn version() -> Result<String, String> {
    let output = Command::new("openssl")
        .arg("version")
        .output()
        .map_err(|error| format!("openssl version: {error}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Argon2id of `password` and `salt` with m KiB, t passes and p lanes, by `openssl kdf`.
pub fn argon2id(
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    password: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], String> {
    let output = Command::new("openssl")
        .args(["kdf", "-keylen", "32", "-binary"])
        .args(["-kdfopt", &format!("hexpass:{}", hex(password))])
        .args(["-kdfopt", &format!("hexsalt:{}", hex(salt))])
        .args(["-kdfopt", &format!("iter:{passes}")])
        .args(["-kdfopt", &format!("memcost:{memory_kib}")])
        .args(["-kdfopt", &format!("lanes:{lanes}")])
        .args(["-kdfopt", "threads:1", "ARGON2ID"])
        .output()
        .map_err(|error| format!("openssl kdf: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "openssl kdf failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    output
        .stdout
        .as_slice()
        .try_into()
        .map_err(|_| format!("openssl kdf wrote {} bytes", output.stdout.len()))
}
