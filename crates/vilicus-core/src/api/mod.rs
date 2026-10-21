//! The typed APIs modules offer each other (AD-5, AD-9, I6): the queries a module declares,
//! served by the Core to the calls of other modules.
//!
//! A module never opens another module's file, and the Core never gives it a handle, a path or a
//! key. Inside a call, its code reads another module's record with
//! [`Records::read`](vilicus_module_api::Records::read), naming the module, the query and the
//! record's id; the Core then checks, in this order, that the module offers the query, that the
//! query's access list names the calling module, and, for each partition in the call's scope,
//! that the file read is ready (AD-54, the gate [`ModuleStates::check`]) before it looks the
//! record up on a read connection of that file ([`ApiFiles`]), never on its writer, so the read
//! never re-enters another writer thread (AD-9). A file that is not ready is skipped: a record is
//! found in another file of the scope, ids being unique, and a record found nowhere else is
//! answered `module_unavailable`, with the skipped file's retry class. The scope of a call is the partition of its own file,
//! and the household partition when that file is a member's personal partition ([`read_scope`]):
//! a household or home call reads no member's partition, and no call reads another member's
//! (FR-19), so the Core never asks for a file outside the scope.
//!
//! The query returns the fields it declares; the record's provenance stays with the Core, which
//! counts it as an input of every write the call makes afterwards (AD-7), so reading another
//! module's record never lowers what a write stores.

#[cfg(test)]
mod tests;

use vilicus_module_api::{ModuleDeclaration, ReadRecord};
use vilicus_storage::{Handle, Partition, Read};
use vilicus_types::{Id, ModuleName};

use crate::availability::{ModuleStates, ModuleUnavailable};
use crate::record::{RecordError, RecordProvenance, read_record};
use crate::registry::Registry;

/// The read connections of the module files the Core holds open, by module and partition.
pub trait ApiFiles {
    /// The read handle of `module`'s file in `partition`, when the Core holds one open. A file
    /// the availability states report ready whose read handle is not open is not ready.
    fn reader(&self, module: &ModuleName, partition: Partition) -> Option<&Handle<Read>>;
}

/// No read connection: every read is answered as a file that is not open.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoApiFiles;

impl ApiFiles for NoApiFiles {
    fn reader(&self, _: &ModuleName, _: Partition) -> Option<&Handle<Read>> {
        None
    }
}

/// The read connections of `first`, then of `then` for a file `first` does not hold: the files of
/// a member's partition, then those of the household partition.
#[derive(Clone, Copy)]
pub struct Layered<'a> {
    /// The files asked first.
    pub first: &'a dyn ApiFiles,
    /// The files asked when `first` holds none.
    pub then: &'a dyn ApiFiles,
}

impl ApiFiles for Layered<'_> {
    fn reader(&self, module: &ModuleName, partition: Partition) -> Option<&Handle<Read>> {
        self.first
            .reader(module, partition)
            .or_else(|| self.then.reader(module, partition))
    }
}

/// What the Core serves typed API reads from: the registry that declares the queries and the read
/// connections of the open files.
#[derive(Clone, Copy)]
pub struct Apis<'a> {
    /// The registered modules and their queries.
    pub registry: Registry,
    /// The read connections.
    pub files: &'a dyn ApiFiles,
}

/// The typed API reads of one call: what they are served from, and the availability states
/// that gate them.
#[derive(Clone, Copy)]
pub(crate) struct ApiReads<'a> {
    pub(crate) apis: Apis<'a>,
    pub(crate) states: &'a ModuleStates,
}

/// The partitions a call on a file of `partition` reads another module's records in, in the
/// order they are searched: its own partition, then the household partition when `partition` is
/// a member's (AD-5, FR-19). A household or home call reads its own partition only.
pub fn read_scope(partition: Partition) -> Vec<Partition> {
    match partition {
        Partition::Member(_) => vec![partition, Partition::Household],
        Partition::Household | Partition::Home => vec![partition],
    }
}

/// Serves the read of the record `id` through the query `query` of `module` to a call of
/// `caller` on a file of `partition`: the record the query returns and its provenance, read from
/// the first file of the call's scope that holds it, a file that is not ready or not open being
/// skipped. Refused when no registered module offers the query ([`RecordError::UnknownQuery`]),
/// when its access list does not name `caller` ([`RecordError::QueryNotAllowed`]), and when no
/// file of the scope it could search holds the record: [`RecordError::Unavailable`] for the first
/// file it skipped, whose record it cannot rule out, otherwise [`RecordError::RecordNotFound`].
pub(crate) fn read(
    reads: ApiReads<'_>,
    caller: &ModuleDeclaration,
    partition: Partition,
    module: &str,
    query: &str,
    id: Id,
) -> Result<(ReadRecord, RecordProvenance), RecordError> {
    let target = reads
        .apis
        .registry
        .modules()
        .iter()
        .copied()
        .find(|declared| declared.name == module)
        .ok_or(RecordError::UnknownQuery)?;
    let declared = target.query(query).ok_or(RecordError::UnknownQuery)?;
    if !declared.callers.contains(&caller.name) {
        return Err(RecordError::QueryNotAllowed {
            query: declared.name,
        });
    }
    let table = target
        .table(declared.table)
        .ok_or(RecordError::UnknownQuery)?;
    let name = ModuleName::from_static(target.name);
    let mut unavailable = None;
    for partition in read_scope(partition) {
        if let Err(state) = reads.states.check(&name, partition) {
            unavailable.get_or_insert(state);
            continue;
        }
        let Some(handle) = reads.apis.files.reader(&name, partition).filter(|handle| {
            *handle.file().module() == name && handle.file().partition() == partition
        }) else {
            unavailable.get_or_insert(ModuleUnavailable::not_open(name.clone(), partition));
            continue;
        };
        if let Some((provenance, values)) = read_record(handle, table, id)? {
            let fields = declared
                .fields
                .iter()
                .map(|field| {
                    let value = table
                        .fields
                        .iter()
                        .zip(&values)
                        .find(|(declared, _)| declared.name == *field)
                        .map(|(_, value)| value.clone())
                        .ok_or(RecordError::UnknownColumn { table: table.name })?;
                    Ok((*field, value))
                })
                .collect::<Result<_, RecordError>>()?;
            return Ok((ReadRecord { id, fields }, provenance));
        }
    }
    Err(match unavailable {
        Some(unavailable) => RecordError::Unavailable(unavailable),
        None => RecordError::RecordNotFound { table: table.name },
    })
}
