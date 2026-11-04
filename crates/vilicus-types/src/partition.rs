//! The partitions of the household's data (spine AD-5, AD-37): the one name the storage layer,
//! which names a module file after its partition, and the key hierarchy, which binds a file key to
//! it, both read.

use core::fmt;

use crate::id::Id;

/// The partition a module file belongs to (AD-5, AD-37).
///
/// ```
/// use vilicus_types::{Id, Partition};
///
/// let member: Id = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse()?;
/// assert_eq!(Partition::Household.to_string(), "household");
/// assert_eq!(Partition::Home.to_string(), "home");
/// assert_eq!(Partition::Member(member).to_string(), "017f22e2-79b0-7cc3-98c4-dc0c0c07398f");
/// # Ok::<(), vilicus_types::IdError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Partition {
    /// The household partition.
    Household,
    /// The home partition, one per instance.
    Home,
    /// A member's personal partition, named by the member's id.
    Member(Id),
}

impl fmt::Display for Partition {
    /// The partition as it appears in a file name: `household`, `home` or the member id's text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Household => formatter.write_str("household"),
            Self::Home => formatter.write_str("home"),
            Self::Member(id) => write!(formatter, "{id}"),
        }
    }
}
