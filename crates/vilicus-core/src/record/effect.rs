//! Outbound effects after their call committed (AD-28, NFR-3): the Core performs each `pending`
//! effect intent through its plugin, then records the outcome the plugin returns in the intent,
//! in the same file. An `unknown` outcome is reported to the member and never retried blindly;
//! only the Core retries, a `failed` intent, with the same key. The plugin call itself is the
//! pipeline's (Epic 10); this is the file's side of it.

use vilicus_storage::{EffectRow, EffectState, Handle, Write};
use vilicus_types::{EffectOutcome, Id, UtcMillis};

use super::RecordError;

/// An effect whose outcome is unknown: the Core reports it, and never performs it again on its
/// own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownEffect {
    /// The effect intent.
    pub intent: Id,
    /// Whom the report goes to.
    pub report_to: ReportTo,
}

/// Whom the report of an `unknown` effect goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportTo {
    /// The member who made or approved the call, or the one it acts for.
    Member(Id),
    /// Every adult of the household, when the call names no member (a rule, an event, an
    /// adapter, a display, a plugin acting for nobody): `first`, the adult who validated the
    /// rule or playbook, before the others, when the call has one.
    EveryAdult {
        /// The adult reported to first.
        first: Option<Id>,
    },
}

/// The effect intents of the file the Core is to perform, in commit order: every `pending` one.
pub fn effects_to_perform(handle: &Handle<Write>) -> Result<Vec<EffectRow>, RecordError> {
    Ok(handle.effects_in_state(EffectState::Pending)?)
}

/// Records `outcome`, which the plugin returned for the `pending` intent `intent`, at `at`, in a
/// transaction of its own. Returns the report the Core owes the member when the outcome is
/// `unknown`, and `None` otherwise.
pub fn record_effect_outcome(
    handle: &Handle<Write>,
    intent: Id,
    outcome: EffectOutcome,
    at: UtcMillis,
) -> Result<Option<UnknownEffect>, RecordError> {
    let recorded = handle.record_effect_outcome(intent, outcome, at)?;
    let report_to = match recorded.member {
        Some(member) => ReportTo::Member(member),
        None => ReportTo::EveryAdult {
            first: recorded.first_adult,
        },
    };
    Ok(
        (recorded.state == EffectState::Unknown).then_some(UnknownEffect {
            intent: recorded.id,
            report_to,
        }),
    )
}

/// Puts the `failed` intent `intent` back to `pending`, so the Core performs it again with the
/// same key. An intent in any other state is refused: an `unknown` one may have taken place.
pub fn retry_failed_effect(
    handle: &Handle<Write>,
    intent: Id,
    at: UtcMillis,
) -> Result<(), RecordError> {
    handle.retry_effect(intent, at)?;
    Ok(())
}
