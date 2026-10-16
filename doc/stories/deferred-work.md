# Deferred work

- source_spec: `doc/stories/story-1.1-key-prototype-ad36-public-key-authentication.md`
  summary: Authenticate `wrappers.db` as a whole so that deleting a record or restoring an older copy (rollback of a vetoed or suspended member's valid record) is detected.
  evidence: The AD-36 construction authenticates each record, not the set; a disk writer can delete a record without alert or roll back the file. Candidate fix for the keys and storage epics: a monotonic counter and a MAC over the record set under an HK-derived key, cross-checked with `core.db`.
