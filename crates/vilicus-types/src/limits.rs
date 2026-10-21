//! Confirmed V0.1 values (D113, PRD section 12) and the operator-tunable settings.
//!
//! Every security delay and cap is a compiled-in constant. The only values an operator may set
//! are the members of [`OperatorSetting`], read from `/etc/vilicus/vilicus.toml` (spine AD-22);
//! the `DEFAULT_*` constants are their values when the file leaves them out.

use std::time::Duration;

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

/// Lifetime of a capability token (PRD FR-27, D113).
pub const CAPABILITY_TOKEN_LIFETIME: Duration = Duration::from_secs(10 * MINUTE);

/// Budget of a capability token, in tool calls, when its task sets no other (PRD FR-27, D113).
pub const CAPABILITY_TOKEN_DEFAULT_BUDGET: u32 = 50;

/// Longest unlock window a member may choose; an extension ends no later than now plus this
/// (PRD FR-12, D113).
pub const UNLOCK_WINDOW_MAX: Duration = Duration::from_secs(24 * HOUR);

/// Unlock window proposed at unlock (PRD FR-12, D113).
pub const UNLOCK_WINDOW_DEFAULT: Duration = Duration::from_secs(12 * HOUR);

/// How long undo journal entries are kept, and undo offered, in personal and household
/// partitions; the audit log is not affected (PRD FR-29, D113).
pub const UNDO_JOURNAL_RETENTION: Duration = Duration::from_secs(30 * DAY);

/// How long journal entries are kept in the home partition, whose rules and adapters write far
/// more often than members do (spine AD-26, `[ASSUMPTION]`).
pub const HOME_JOURNAL_RETENTION: Duration = Duration::from_secs(24 * HOUR);

/// How long the outbox keeps a row once it is created: a delivered event, a registered or
/// refused link, a `done` effect intent. Rows are marked, never deleted on delivery, so a restore
/// can re-deliver every row newer than the oldest file copy of the backup (spine AD-26,
/// `[ASSUMPTION]`).
pub const OUTBOX_RETENTION: Duration = Duration::from_secs(30 * DAY);

/// How many failed deliveries of one event to one consumer move the event to that consumer's
/// dead letters (spine AD-29). A consumer that is not ready is not a failure (AD-54).
pub const EVENT_DELIVERY_ATTEMPTS: u32 = 5;

const _: () = assert!(UNLOCK_WINDOW_DEFAULT.as_secs() <= UNLOCK_WINDOW_MAX.as_secs());

closed_set! {
    /// A value the operator may set in `vilicus.toml`, by its key there; nothing else is
    /// operator-tunable (D113, spine AD-22). The configuration loader accepts exactly these keys
    /// and refuses any other, so a security delay or cap cannot become a setting by being
    /// written into the file.
    pub enum OperatorSetting {
        /// How often the unattended backup runs (PRD FR-53); default
        /// [`DEFAULT_BACKUP_INTERVAL`].
        BackupSchedule => "backup_schedule",
        /// How long before the instance certificate expires the alert is sent (PRD FR-65);
        /// default [`DEFAULT_CERTIFICATE_ALERT_LEAD_TIME`].
        CertificateAlertLeadTime => "certificate_alert_lead_time",
        /// How many audit entries the spool holds while the audit writer is down (PRD FR-31);
        /// default [`DEFAULT_AUDIT_SPOOL_ENTRIES`].
        AuditSpoolSize => "audit_spool_size",
    }
}

/// Default of [`OperatorSetting::BackupSchedule`]: daily (PRD section 12, assumption of FR-53).
pub const DEFAULT_BACKUP_INTERVAL: Duration = Duration::from_secs(DAY);

/// Default of [`OperatorSetting::CertificateAlertLeadTime`] (PRD section 12, assumption of FR-65).
pub const DEFAULT_CERTIFICATE_ALERT_LEAD_TIME: Duration = Duration::from_secs(14 * DAY);

/// Default of [`OperatorSetting::AuditSpoolSize`], in entries (PRD section 12, assumption of
/// FR-31).
pub const DEFAULT_AUDIT_SPOOL_ENTRIES: u32 = 10_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_values_of_d113() {
        assert_eq!(CAPABILITY_TOKEN_LIFETIME, Duration::from_secs(10 * 60));
        assert_eq!(CAPABILITY_TOKEN_DEFAULT_BUDGET, 50);
        assert_eq!(UNLOCK_WINDOW_MAX, Duration::from_secs(24 * 60 * 60));
        assert_eq!(UNLOCK_WINDOW_DEFAULT, Duration::from_secs(12 * 60 * 60));
        assert_eq!(
            UNDO_JOURNAL_RETENTION,
            Duration::from_secs(30 * 24 * 60 * 60)
        );
        assert_eq!(HOME_JOURNAL_RETENTION, Duration::from_secs(24 * 60 * 60));
    }

    #[test]
    fn outbox_values_of_ad_26_and_ad_29() {
        assert_eq!(OUTBOX_RETENTION, Duration::from_secs(30 * 24 * 60 * 60));
        assert_eq!(EVENT_DELIVERY_ATTEMPTS, 5);
    }

    #[test]
    fn operator_settings_are_the_three_of_d113() {
        let keys: Vec<&str> = OperatorSetting::ALL
            .iter()
            .map(|setting| setting.as_str())
            .collect();
        assert_eq!(
            keys,
            [
                "backup_schedule",
                "certificate_alert_lead_time",
                "audit_spool_size"
            ]
        );
    }

    #[test]
    fn operator_setting_defaults_of_prd_section_12() {
        assert_eq!(DEFAULT_BACKUP_INTERVAL, Duration::from_secs(24 * 60 * 60));
        assert_eq!(
            DEFAULT_CERTIFICATE_ALERT_LEAD_TIME,
            Duration::from_secs(14 * 24 * 60 * 60)
        );
        assert_eq!(DEFAULT_AUDIT_SPOOL_ENTRIES, 10_000);
    }
}
