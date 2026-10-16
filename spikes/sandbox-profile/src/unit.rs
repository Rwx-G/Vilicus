//! Mapping between systemd unit names and cgroup v2 paths, and membership checks.

use std::path::{Path, PathBuf};

/// Where the unified cgroup hierarchy is mounted.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Test oracle only: the Core asks systemd for a unit's `ControlGroup` instead, which also
/// covers `Slice=` and escaping this function does not. The cgroup path systemd gives a system
/// service with no `Slice=` setting, relative to the hierarchy root: `/system.slice/<unit>` for a plain unit, and for a template instance
/// `/system.slice/system-<escaped template prefix>.slice/<unit>`.
///
/// Only names made of characters that systemd leaves unescaped in a cgroup path are accepted;
/// anything else returns `None`, so a surprising name is refused rather than guessed.
pub fn expected_cgroup(unit: &str) -> Option<String> {
    let stem = unit.strip_suffix(".service")?;
    if stem.is_empty() || stem.starts_with(['.', '_']) || !stem.chars().all(unit_char) {
        return None;
    }
    match stem.split_once('@') {
        None => Some(format!("/system.slice/{unit}")),
        Some((prefix, instance)) if !prefix.is_empty() && !instance.contains('@') => {
            let escaped = prefix.replace('-', "\\x2d");
            Some(format!("/system.slice/system-{escaped}.slice/{unit}"))
        }
        Some(_) => None,
    }
}

fn unit_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@')
}

/// Absolute directory of a cgroup path such as systemd's `ControlGroup` property.
pub fn cgroup_dir(cgroup: &str) -> PathBuf {
    Path::new(CGROUP_ROOT).join(cgroup.trim_start_matches('/'))
}

/// The cgroup v2 path in the text of `/proc/<pid>/cgroup` (the `0::<path>` line).
pub fn parse_proc_cgroup(text: &str) -> Option<&str> {
    text.lines().find_map(|line| line.strip_prefix("0::"))
}

/// The last component of a cgroup path, which is the unit name for a process directly in a
/// unit's cgroup. Reading only this component is the naive check the spoof test defeats.
pub fn leaf(cgroup: &str) -> &str {
    cgroup.rsplit('/').next().unwrap_or(cgroup)
}

/// True when `pid` is listed in the `cgroup.procs` text of a cgroup.
pub fn procs_contains(procs: &str, pid: i32) -> bool {
    procs
        .lines()
        .any(|line| line.trim().parse::<i32>() == Ok(pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_unit_lives_under_system_slice() {
        assert_eq!(
            expected_cgroup("vilicus-core.service").as_deref(),
            Some("/system.slice/vilicus-core.service")
        );
    }

    #[test]
    fn template_instance_lives_under_its_escaped_slice() {
        assert_eq!(
            expected_cgroup("vilicus-plugin@ref.service").as_deref(),
            Some("/system.slice/system-vilicus\\x2dplugin.slice/vilicus-plugin@ref.service")
        );
    }

    #[test]
    fn surprising_names_are_refused() {
        for name in [
            "vilicus-core",
            ".service",
            "_x.service",
            "a b.service",
            "a/b.service",
            "@x.service",
            "a@b@c.service",
            "a\\x2db.service",
        ] {
            assert_eq!(expected_cgroup(name), None, "{name}");
        }
    }

    #[test]
    fn proc_cgroup_line_and_leaf() {
        let text = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/vilicus-plugin@ref.service\n";
        let path = parse_proc_cgroup(text).unwrap();
        assert_eq!(leaf(path), "vilicus-plugin@ref.service");
        assert_ne!(
            Some(path),
            expected_cgroup("vilicus-plugin@ref.service").as_deref()
        );
        assert_eq!(parse_proc_cgroup("1:name=systemd:/x\n"), None);
    }

    #[test]
    fn procs_membership_is_exact() {
        let procs = "12\n345\n";
        assert!(procs_contains(procs, 345));
        assert!(!procs_contains(procs, 34));
        assert!(!procs_contains("", 1));
    }
}
