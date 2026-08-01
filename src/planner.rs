use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Result,
    cli::Direction,
    manifest::{EntryKind, Manifest, ManifestEntry},
    path::RelativePath,
};

pub const MAX_PLAN_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Side {
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetadataPolicy {
    pub owner: bool,
    pub group: bool,
    pub numeric_ids: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    CreateDirectory { target: Side, entry: ManifestEntry },
    TransferFile { source: Side, entry: ManifestEntry },
    WriteSymlink { source: Side, entry: ManifestEntry },
    FinalizeDirectory { target: Side, entry: ManifestEntry },
}

impl Operation {
    #[must_use]
    pub fn path(&self) -> &RelativePath {
        match self {
            Self::CreateDirectory { entry, .. }
            | Self::TransferFile { entry, .. }
            | Self::WriteSymlink { entry, .. }
            | Self::FinalizeDirectory { entry, .. } => &entry.path,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    pub operations: Vec<Operation>,
    pub conflicts: Vec<RelativePath>,
    pub warnings: Vec<(RelativePath, String)>,
    pub skipped: usize,
    memory_bytes: usize,
    memory_limit: usize,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            operations: Vec::new(),
            conflicts: Vec::new(),
            warnings: Vec::new(),
            skipped: 0,
            memory_bytes: 0,
            memory_limit: MAX_PLAN_BYTES,
        }
    }
}

impl Plan {
    #[must_use]
    pub const fn estimated_memory_bytes(&self) -> usize {
        self.memory_bytes
    }

    fn charge(&mut self, amount: usize) -> Result<()> {
        self.memory_bytes = self
            .memory_bytes
            .checked_add(amount)
            .ok_or_else(|| crate::Error::entry("limit", None, "plan memory accounting overflow"))?;
        if self.memory_bytes > self.memory_limit {
            return Err(crate::Error::entry(
                "limit",
                None,
                "plan memory limit exceeded",
            ));
        }
        Ok(())
    }

    fn checked_auxiliary_total(&self, current: usize, amount: usize) -> Result<usize> {
        let next = current
            .checked_add(amount)
            .ok_or_else(|| crate::Error::entry("limit", None, "plan memory accounting overflow"))?;
        if self.memory_bytes.saturating_add(next) > self.memory_limit {
            return Err(crate::Error::entry(
                "limit",
                None,
                "plan memory limit exceeded",
            ));
        }
        Ok(next)
    }

    fn push_operation(&mut self, operation: Operation) -> Result<()> {
        let directory_auxiliary = if matches!(&operation, Operation::CreateDirectory { .. }) {
            128usize.saturating_add(operation.path().as_bytes().len())
        } else {
            0
        };
        self.charge(
            192usize
                .saturating_add(operation.path().as_bytes().len().saturating_mul(2))
                .saturating_add(match &operation {
                    Operation::CreateDirectory { entry, .. }
                    | Operation::TransferFile { entry, .. }
                    | Operation::WriteSymlink { entry, .. }
                    | Operation::FinalizeDirectory { entry, .. } => entry.estimated_wire_bytes(),
                })
                .saturating_add(directory_auxiliary),
        )?;
        self.operations.push(operation);
        Ok(())
    }

    fn push_conflict(&mut self, path: RelativePath) -> Result<()> {
        self.charge(64usize.saturating_add(path.as_bytes().len()))?;
        self.conflicts.push(path);
        Ok(())
    }

    fn push_warning(&mut self, path: RelativePath, warning: String) -> Result<()> {
        self.charge(
            96usize
                .saturating_add(path.as_bytes().len())
                .saturating_add(warning.len()),
        )?;
        self.warnings.push((path, warning));
        Ok(())
    }
}

pub type Digests = BTreeMap<(Side, RelativePath), [u8; 32]>;

pub fn ambiguous_paths(
    local: &Manifest,
    remote: &Manifest,
    modify_window_ns: i128,
) -> BTreeSet<RelativePath> {
    local
        .entries
        .iter()
        .filter_map(|(path, left)| {
            let right = remote.get(path)?;
            (left.kind == EntryKind::File
                && right.kind == EntryKind::File
                && left.size == right.size
                && times_equal(left, right, modify_window_ns))
            .then(|| path.clone())
        })
        .collect()
}

pub fn build_plan(
    local: &Manifest,
    remote: &Manifest,
    direction: Direction,
    modify_window_ns: i128,
    digests: Option<&Digests>,
) -> Result<Plan> {
    build_plan_with_budget(
        local,
        remote,
        direction,
        modify_window_ns,
        digests,
        MetadataPolicy::default(),
        MAX_PLAN_BYTES,
    )
}

pub fn build_plan_with_budget(
    local: &Manifest,
    remote: &Manifest,
    direction: Direction,
    modify_window_ns: i128,
    digests: Option<&Digests>,
    metadata_policy: MetadataPolicy,
    memory_limit: usize,
) -> Result<Plan> {
    local.validate(true)?;
    remote.validate(true)?;
    let mut plan = Plan {
        memory_limit,
        ..Plan::default()
    };
    let mut local_iter = local.entries.iter().peekable();
    let mut remote_iter = remote.entries.iter().peekable();
    let mut blocked: Option<RelativePath> = None;
    while local_iter.peek().is_some() || remote_iter.peek().is_some() {
        let path = match (local_iter.peek(), remote_iter.peek()) {
            (Some((left, _)), Some((right, _))) => (*left).min(*right).clone(),
            (Some((path, _)), None) | (None, Some((path, _))) => (*path).clone(),
            (None, None) => break,
        };
        let left = if local_iter.peek().is_some_and(|(key, _)| *key == &path) {
            local_iter.next().map(|(_, entry)| entry)
        } else {
            None
        };
        let right = if remote_iter.peek().is_some_and(|(key, _)| *key == &path) {
            remote_iter.next().map(|(_, entry)| entry)
        } else {
            None
        };
        if blocked
            .as_ref()
            .is_some_and(|parent| path.starts_with(parent) && path != *parent)
        {
            continue;
        }
        blocked = None;
        if left.is_some_and(|entry| entry.kind == EntryKind::Unsupported)
            || right.is_some_and(|entry| entry.kind == EntryKind::Unsupported)
        {
            let detail = left
                .and_then(|entry| entry.scan_error.as_deref())
                .or_else(|| right.and_then(|entry| entry.scan_error.as_deref()))
                .unwrap_or("unsupported file kind");
            plan.push_warning(path.clone(), format!("inventory barrier: {detail}"))?;
            blocked = Some(path);
            continue;
        }
        match (left, right) {
            (Some(entry), None) => plan_one_sided(&mut plan, Side::Local, entry, direction)?,
            (None, Some(entry)) => plan_one_sided(&mut plan, Side::Remote, entry, direction)?,
            (Some(left), Some(right)) if left.kind != right.kind => {
                plan.push_conflict(path.clone())?;
                blocked = Some(path);
            }
            (Some(left), Some(right)) => {
                plan_both(
                    &mut plan,
                    left,
                    right,
                    direction,
                    modify_window_ns,
                    digests,
                    metadata_policy,
                )?;
            }
            (None, None) => unreachable!(),
        }
    }
    add_touched_directory_finalizers(&mut plan, local, remote)?;
    plan.operations.sort_by(|left, right| {
        operation_rank(left)
            .cmp(&operation_rank(right))
            .then_with(|| match (left, right) {
                (Operation::FinalizeDirectory { .. }, Operation::FinalizeDirectory { .. }) => right
                    .path()
                    .depth()
                    .cmp(&left.path().depth())
                    .then_with(|| left.path().cmp(right.path())),
                (Operation::CreateDirectory { .. }, Operation::CreateDirectory { .. }) => left
                    .path()
                    .depth()
                    .cmp(&right.path().depth())
                    .then_with(|| left.path().cmp(right.path())),
                _ => left.path().cmp(right.path()),
            })
    });
    Ok(plan)
}

fn plan_one_sided(
    plan: &mut Plan,
    source: Side,
    entry: &ManifestEntry,
    direction: Direction,
) -> Result<()> {
    if entry.kind == EntryKind::Unsupported {
        plan.push_warning(entry.path.clone(), "unsupported file kind skipped".into())?;
        return Ok(());
    }
    if !permitted(source, direction) {
        plan.skipped += 1;
        return Ok(());
    }
    let operation = match entry.kind {
        EntryKind::Directory => {
            plan.push_operation(Operation::CreateDirectory {
                target: other(source),
                entry: entry.clone(),
            })?;
            plan.push_operation(Operation::FinalizeDirectory {
                target: other(source),
                entry: entry.clone(),
            })?;
            return Ok(());
        }
        EntryKind::File => Operation::TransferFile {
            source,
            entry: entry.clone(),
        },
        EntryKind::Symlink => Operation::WriteSymlink {
            source,
            entry: entry.clone(),
        },
        EntryKind::Unsupported => unreachable!(),
    };
    plan.push_operation(operation)?;
    Ok(())
}

fn plan_both(
    plan: &mut Plan,
    local: &ManifestEntry,
    remote: &ManifestEntry,
    direction: Direction,
    window: i128,
    digests: Option<&Digests>,
    metadata_policy: MetadataPolicy,
) -> Result<()> {
    match local.kind {
        EntryKind::File => {
            if times_equal(local, remote, window) {
                if local.size != remote.size || digest_differs(digests, local, remote)? {
                    plan.push_conflict(local.path.clone())?;
                } else if let Some(differences) =
                    metadata_differences(local, remote, metadata_policy, true)
                {
                    plan.push_warning(
                        local.path.clone(),
                        format!(
                            "equal-mtime file metadata differs: {differences}; neither side is newer, so metadata was left unchanged"
                        ),
                    )?;
                }
                return Ok(());
            }
            transfer_newer(plan, local, remote, direction, false)?;
        }
        EntryKind::Symlink => {
            if local.symlink_target == remote.symlink_target {
                if times_equal(local, remote, window) {
                    if let Some(differences) =
                        metadata_differences(local, remote, metadata_policy, false)
                    {
                        plan.push_warning(
                            local.path.clone(),
                            format!(
                                "equal-mtime symlink metadata differs: {differences}; neither side is newer, so metadata was left unchanged"
                            ),
                        )?;
                    }
                    return Ok(());
                }
                transfer_newer(plan, local, remote, direction, true)?;
                return Ok(());
            }
            if times_equal(local, remote, window) {
                plan.push_conflict(local.path.clone())?;
            } else {
                transfer_newer(plan, local, remote, direction, true)?;
            }
        }
        EntryKind::Directory => {
            if times_equal(local, remote, window) {
                if let Some(differences) =
                    metadata_differences(local, remote, metadata_policy, true)
                {
                    plan.push_warning(
                        local.path.clone(),
                        format!(
                            "equal-mtime directory metadata differs: {differences}; neither side is newer, so metadata was left unchanged"
                        ),
                    )?;
                }
            } else {
                let (source, entry) = newer(local, remote);
                if permitted(source, direction) {
                    plan.push_operation(Operation::FinalizeDirectory {
                        target: other(source),
                        entry: entry.clone(),
                    })?;
                } else {
                    plan.skipped += 1;
                }
            }
        }
        EntryKind::Unsupported => unreachable!("handled as an inventory barrier"),
    }
    Ok(())
}

fn metadata_differences(
    local: &ManifestEntry,
    remote: &ManifestEntry,
    policy: MetadataPolicy,
    compare_mode: bool,
) -> Option<String> {
    let mut differences = Vec::new();
    let local_mode = local.mode & 0o777;
    let remote_mode = remote.mode & 0o777;
    if compare_mode && local_mode != remote_mode {
        differences.push(format!(
            "mode local={local_mode:04o} remote={remote_mode:04o}"
        ));
    }
    if policy.owner
        && ownership_differs(
            local.owner_name.as_deref(),
            local.uid,
            remote.owner_name.as_deref(),
            remote.uid,
            policy.numeric_ids,
        )
    {
        differences.push(format!(
            "owner local={} remote={}",
            ownership_display(
                local.owner_name.as_deref(),
                local.uid,
                "uid",
                policy.numeric_ids
            ),
            ownership_display(
                remote.owner_name.as_deref(),
                remote.uid,
                "uid",
                policy.numeric_ids
            )
        ));
    }
    if policy.group
        && ownership_differs(
            local.group_name.as_deref(),
            local.gid,
            remote.group_name.as_deref(),
            remote.gid,
            policy.numeric_ids,
        )
    {
        differences.push(format!(
            "group local={} remote={}",
            ownership_display(
                local.group_name.as_deref(),
                local.gid,
                "gid",
                policy.numeric_ids
            ),
            ownership_display(
                remote.group_name.as_deref(),
                remote.gid,
                "gid",
                policy.numeric_ids
            )
        ));
    }
    (!differences.is_empty()).then(|| differences.join("; "))
}

fn ownership_differs(
    local_name: Option<&str>,
    local_id: u32,
    remote_name: Option<&str>,
    remote_id: u32,
    numeric_ids: bool,
) -> bool {
    if numeric_ids {
        return local_id != remote_id;
    }
    match (local_name, remote_name) {
        (Some(local), Some(remote)) => local != remote,
        _ => local_id != remote_id,
    }
}

fn ownership_display(name: Option<&str>, id: u32, id_label: &str, numeric_ids: bool) -> String {
    if numeric_ids {
        format!("{id_label}={id}")
    } else if let Some(name) = name {
        format!("{name:?} ({id_label}={id})")
    } else {
        format!("{id_label}={id} (name unavailable)")
    }
}

fn transfer_newer(
    plan: &mut Plan,
    local: &ManifestEntry,
    remote: &ManifestEntry,
    direction: Direction,
    symlink: bool,
) -> Result<()> {
    let (source, entry) = newer(local, remote);
    if !permitted(source, direction) {
        plan.skipped += 1;
        return Ok(());
    }
    plan.push_operation(if symlink {
        Operation::WriteSymlink {
            source,
            entry: entry.clone(),
        }
    } else {
        Operation::TransferFile {
            source,
            entry: entry.clone(),
        }
    })?;
    Ok(())
}

fn digest_differs(
    digests: Option<&Digests>,
    local: &ManifestEntry,
    remote: &ManifestEntry,
) -> Result<bool> {
    let Some(digests) = digests else {
        return Ok(false);
    };
    match (
        digests.get(&(Side::Local, local.path.clone())),
        digests.get(&(Side::Remote, remote.path.clone())),
    ) {
        (Some(left), Some(right)) => Ok(left != right),
        _ => Err(crate::Error::Protocol(format!(
            "checksum digest set is incomplete for {}",
            local.path
        ))),
    }
}

fn add_touched_directory_finalizers(
    plan: &mut Plan,
    local: &Manifest,
    remote: &Manifest,
) -> Result<()> {
    let mut finalizers = BTreeSet::<(Side, RelativePath)>::new();
    let mut temporary_bytes = 0usize;
    for operation in &plan.operations {
        if let Operation::FinalizeDirectory { target, entry } = operation {
            let key = (*target, entry.path.clone());
            if !finalizers.contains(&key) {
                temporary_bytes = plan
                    .checked_auxiliary_total(temporary_bytes, 64 + entry.path.as_bytes().len())?;
                finalizers.insert(key);
            }
        }
    }
    let mut mutations = BTreeSet::new();
    for operation in &plan.operations {
        if let Some(mutation) = match operation {
            Operation::CreateDirectory { target, entry } => Some((*target, entry.path.clone())),
            Operation::TransferFile { source, entry }
            | Operation::WriteSymlink { source, entry } => {
                Some((other(*source), entry.path.clone()))
            }
            Operation::FinalizeDirectory { .. } => None,
        } && !mutations.contains(&mutation)
        {
            temporary_bytes =
                plan.checked_auxiliary_total(temporary_bytes, 64 + mutation.1.as_bytes().len())?;
            mutations.insert(mutation);
        }
    }
    plan.charge(temporary_bytes)?;
    let mut additions = Vec::new();
    for (target, path) in mutations {
        let target_manifest = match target {
            Side::Local => local,
            Side::Remote => remote,
        };
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if let Some(entry) = target_manifest
                .get(&directory)
                .filter(|entry| entry.kind == EntryKind::Directory)
            {
                let key = (target, directory.clone());
                if !finalizers.contains(&key) {
                    plan.charge(
                        96usize
                            .saturating_add(directory.as_bytes().len())
                            .saturating_add(entry.estimated_wire_bytes()),
                    )?;
                    finalizers.insert(key);
                    additions.push(Operation::FinalizeDirectory {
                        target,
                        entry: entry.clone(),
                    });
                }
            }
            parent = directory.parent();
        }
    }
    for operation in additions {
        plan.push_operation(operation)?;
    }
    Ok(())
}

fn times_equal(left: &ManifestEntry, right: &ManifestEntry, window: i128) -> bool {
    (left.mtime.as_nanos() - right.mtime.as_nanos()).abs() <= window
}

fn newer<'a>(local: &'a ManifestEntry, remote: &'a ManifestEntry) -> (Side, &'a ManifestEntry) {
    if local.mtime.as_nanos() > remote.mtime.as_nanos() {
        (Side::Local, local)
    } else {
        (Side::Remote, remote)
    }
}

fn permitted(source: Side, direction: Direction) -> bool {
    match source {
        Side::Local => direction.permits_local_to_remote(),
        Side::Remote => direction.permits_remote_to_local(),
    }
}

const fn other(side: Side) -> Side {
    match side {
        Side::Local => Side::Remote,
        Side::Remote => Side::Local,
    }
}

const fn operation_rank(operation: &Operation) -> u8 {
    match operation {
        Operation::CreateDirectory { .. } => 0,
        Operation::TransferFile { .. } | Operation::WriteSymlink { .. } => 1,
        Operation::FinalizeDirectory { .. } => 2,
    }
}

#[cfg(test)]
mod tests {
    use crate::manifest::{Fingerprint, Timestamp};

    use super::*;

    fn entry(path: &str, kind: EntryKind, seconds: i64, size: u64) -> ManifestEntry {
        let path = RelativePath::new(path.as_bytes().to_vec()).unwrap();
        ManifestEntry {
            path,
            kind,
            mtime: Timestamp { seconds, nanos: 0 },
            mode: 0o644,
            uid: 1,
            gid: 1,
            owner_name: None,
            group_name: None,
            size,
            symlink_target: Vec::new(),
            scan_error: None,
            fingerprint: Fingerprint {
                device: 1,
                inode: 1,
                kind,
                size,
                mtime: Timestamp { seconds, nanos: 0 },
            },
        }
    }

    fn manifest(mut entries: Vec<ManifestEntry>) -> Manifest {
        if !entries.iter().any(|entry| entry.path.is_root()) {
            entries.push(entry("", EntryKind::Directory, 0, 0));
        }
        Manifest {
            entries: entries
                .into_iter()
                .map(|entry| (entry.path.clone(), entry))
                .collect(),
        }
    }

    fn plan_with_metadata_policy(
        local: ManifestEntry,
        remote: ManifestEntry,
        policy: MetadataPolicy,
    ) -> Plan {
        build_plan_with_budget(
            &manifest(vec![local]),
            &manifest(vec![remote]),
            Direction::InOut,
            0,
            None,
            policy,
            MAX_PLAN_BYTES,
        )
        .unwrap()
    }

    #[test]
    fn bidirectional_newer_wins_and_one_sided_copies() {
        let local = manifest(vec![
            entry("newer", EntryKind::File, 20, 2),
            entry("local-only", EntryKind::File, 1, 1),
        ]);
        let remote = manifest(vec![
            entry("newer", EntryKind::File, 10, 1),
            entry("remote-only", EntryKind::File, 1, 1),
        ]);
        let plan = build_plan(&local, &remote, Direction::InOut, 0, None).unwrap();
        assert_eq!(
            plan.operations
                .iter()
                .filter(|operation| matches!(operation, Operation::TransferFile { .. }))
                .count(),
            3
        );
        assert!(plan.operations.iter().any(|op| matches!(op, Operation::TransferFile { source: Side::Local, entry } if entry.path.as_bytes() == b"newer")));
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn direction_never_reverses_newer_winner_or_deletes() {
        let local = manifest(vec![entry("x", EntryKind::File, 1, 1)]);
        let remote = manifest(vec![
            entry("x", EntryKind::File, 2, 1),
            entry("remote-only", EntryKind::File, 1, 1),
        ]);
        let plan = build_plan(&local, &remote, Direction::Out, 0, None).unwrap();
        assert!(plan.operations.is_empty());
        assert_eq!(plan.skipped, 2);
    }

    #[test]
    fn equal_time_divergence_and_kind_collision_conflict() {
        let local = manifest(vec![
            entry("x", EntryKind::File, 1, 1),
            entry("parent", EntryKind::Directory, 1, 0),
            entry("parent/child", EntryKind::File, 1, 1),
        ]);
        let remote = manifest(vec![
            entry("x", EntryKind::File, 1, 2),
            entry("parent", EntryKind::File, 2, 1),
        ]);
        let plan = build_plan(&local, &remote, Direction::InOut, 0, None).unwrap();
        assert_eq!(plan.conflicts.len(), 2);
        assert!(
            !plan
                .operations
                .iter()
                .any(|op| op.path().as_bytes() == b"parent/child")
        );
    }

    #[test]
    fn checksum_resolves_equal_metadata() {
        let local = manifest(vec![entry("x", EntryKind::File, 1, 1)]);
        let remote = local.clone();
        assert_eq!(ambiguous_paths(&local, &remote, 0).len(), 1);
        let mut digests = Digests::new();
        digests.insert(
            (Side::Local, RelativePath::new(b"x".to_vec()).unwrap()),
            [1; 32],
        );
        digests.insert(
            (Side::Remote, RelativePath::new(b"x".to_vec()).unwrap()),
            [2; 32],
        );
        assert_eq!(
            build_plan(&local, &remote, Direction::InOut, 0, Some(&digests))
                .unwrap()
                .conflicts
                .len(),
            1
        );
    }

    #[test]
    fn incomplete_checksum_set_is_rejected() {
        let local = manifest(vec![entry("same", EntryKind::File, 1, 4)]);
        let remote = manifest(vec![entry("same", EntryKind::File, 1, 4)]);
        let mut digests = Digests::new();
        digests.insert(
            (Side::Local, RelativePath::new(b"same".to_vec()).unwrap()),
            [1; 32],
        );
        assert!(build_plan(&local, &remote, Direction::InOut, 0, Some(&digests)).is_err());
    }

    #[test]
    fn child_mutations_restore_each_touched_targets_directory_metadata() {
        let local = manifest(vec![entry("local", EntryKind::File, 1, 1)]);
        let remote = manifest(vec![entry("remote", EntryKind::File, 1, 1)]);
        let plan = build_plan(&local, &remote, Direction::InOut, 0, None).unwrap();
        assert!(plan.operations.iter().any(|operation| {
            matches!(operation, Operation::FinalizeDirectory { target: Side::Local, entry } if entry.path.is_root())
        }));
        assert!(plan.operations.iter().any(|operation| {
            matches!(operation, Operation::FinalizeDirectory { target: Side::Remote, entry } if entry.path.is_root())
        }));
    }

    #[test]
    fn modify_window_boundary_is_inclusive() {
        let mut left = entry("file", EntryKind::File, 1, 1);
        left.mtime.nanos = 100;
        left.fingerprint.mtime = left.mtime;
        let mut right = entry("file", EntryKind::File, 1, 1);
        right.mtime.nanos = 200;
        right.fingerprint.mtime = right.mtime;
        let plan = build_plan(
            &manifest(vec![left]),
            &manifest(vec![right]),
            Direction::InOut,
            100,
            None,
        )
        .unwrap();
        assert!(
            plan.operations
                .iter()
                .all(|operation| { !matches!(operation, Operation::TransferFile { .. }) })
        );
    }

    #[test]
    fn plan_memory_limit_is_binding() {
        let mut plan = Plan::default();
        assert!(plan.charge(MAX_PLAN_BYTES + 1).is_err());
    }

    #[test]
    fn unsupported_entries_warn_even_when_direction_disallows_copy() {
        let local = manifest(vec![entry("socket", EntryKind::Unsupported, 1, 0)]);
        let remote = manifest(Vec::new());
        let plan = build_plan(&local, &remote, Direction::In, 0, None).unwrap();
        assert_eq!(plan.warnings.len(), 1);
        assert!(
            plan.operations
                .iter()
                .all(|operation| operation.path().as_bytes() != b"socket")
        );
    }

    #[test]
    fn unreadable_subtree_is_blocked_while_independent_paths_continue() {
        let mut unreadable = entry("blocked", EntryKind::Unsupported, 0, 0);
        unreadable.scan_error = Some("permission denied".into());
        let local = manifest(vec![unreadable, entry("good", EntryKind::File, 2, 1)]);
        let remote = manifest(vec![
            entry("blocked", EntryKind::Directory, 0, 0),
            entry("blocked/child", EntryKind::File, 1, 1),
        ]);
        let plan = build_plan(&local, &remote, Direction::InOut, 0, None).unwrap();
        assert!(plan.warnings[0].1.contains("permission denied"));
        assert!(
            plan.operations
                .iter()
                .any(|operation| operation.path().as_bytes() == b"good")
        );
        assert!(
            plan.operations
                .iter()
                .all(|operation| { !operation.path().as_bytes().starts_with(b"blocked/") })
        );
    }

    #[test]
    fn equal_target_newer_symlink_is_rewritten_for_metadata() {
        let mut left = entry("link", EntryKind::Symlink, 2, 1);
        left.symlink_target = b"x".to_vec();
        let mut right = entry("link", EntryKind::Symlink, 1, 1);
        right.symlink_target = b"x".to_vec();
        let plan = build_plan(
            &manifest(vec![left]),
            &manifest(vec![right]),
            Direction::InOut,
            0,
            None,
        )
        .unwrap();
        assert!(plan.operations.iter().any(|operation| {
            matches!(
                operation,
                Operation::WriteSymlink {
                    source: Side::Local,
                    ..
                }
            )
        }));
    }

    #[test]
    fn equal_file_content_with_different_metadata_warns_without_choosing_a_side() {
        let left = entry("file", EntryKind::File, 10, 4);
        let mut right = left.clone();
        right.mode = 0o600;
        let local = manifest(vec![left]);
        let remote = manifest(vec![right]);
        let plan = build_plan(&local, &remote, Direction::InOut, 0, None).unwrap();
        assert!(plan.operations.is_empty());
        assert_eq!(
            plan.warnings[0].1,
            "equal-mtime file metadata differs: mode local=0644 remote=0600; neither side is newer, so metadata was left unchanged"
        );
    }

    #[test]
    fn unrequested_ownership_differences_do_not_warn() {
        let mut left = entry("file", EntryKind::File, 10, 4);
        left.uid = 1000;
        left.gid = 100;
        left.owner_name = Some("sean".into());
        left.group_name = Some("users".into());
        let mut right = left.clone();
        right.uid = 2000;
        right.gid = 200;
        right.owner_name = Some("other".into());
        right.group_name = Some("staff".into());

        let plan = plan_with_metadata_policy(left, right, MetadataPolicy::default());
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn name_based_ownership_differences_report_both_sides() {
        let mut left = entry("file", EntryKind::File, 10, 4);
        left.uid = 1000;
        left.gid = 100;
        left.owner_name = Some("sean".into());
        left.group_name = Some("users".into());
        let mut right = left.clone();
        right.uid = 2000;
        right.gid = 200;

        let policy = MetadataPolicy {
            owner: true,
            group: true,
            numeric_ids: false,
        };
        assert!(
            plan_with_metadata_policy(left.clone(), right.clone(), policy)
                .warnings
                .is_empty()
        );

        right.owner_name = Some("other".into());
        right.group_name = Some("staff".into());
        let plan = plan_with_metadata_policy(left, right, policy);
        assert_eq!(
            plan.warnings[0].1,
            "equal-mtime file metadata differs: owner local=\"sean\" (uid=1000) remote=\"other\" (uid=2000); group local=\"users\" (gid=100) remote=\"staff\" (gid=200); neither side is newer, so metadata was left unchanged"
        );
    }

    #[test]
    fn numeric_ownership_and_missing_name_fallback_are_compared_correctly() {
        let mut left = entry("file", EntryKind::File, 10, 4);
        left.uid = 1000;
        left.owner_name = Some("sean".into());
        let mut right = left.clone();
        right.owner_name = None;
        let name_policy = MetadataPolicy {
            owner: true,
            ..MetadataPolicy::default()
        };
        assert!(
            plan_with_metadata_policy(left.clone(), right.clone(), name_policy)
                .warnings
                .is_empty()
        );

        right.uid = 2000;
        right.owner_name = Some("sean".into());
        let numeric_policy = MetadataPolicy {
            owner: true,
            numeric_ids: true,
            ..MetadataPolicy::default()
        };
        let plan = plan_with_metadata_policy(left, right, numeric_policy);
        assert_eq!(
            plan.warnings[0].1,
            "equal-mtime file metadata differs: owner local=uid=1000 remote=uid=2000; neither side is newer, so metadata was left unchanged"
        );
    }

    #[test]
    fn equal_target_symlink_reports_requested_ownership_difference() {
        let mut left = entry("link", EntryKind::Symlink, 10, 1);
        left.symlink_target = b"x".to_vec();
        left.owner_name = Some("sean".into());
        let mut right = left.clone();
        right.owner_name = Some("other".into());
        let plan = plan_with_metadata_policy(
            left,
            right,
            MetadataPolicy {
                owner: true,
                ..MetadataPolicy::default()
            },
        );
        assert!(
            plan.warnings[0]
                .1
                .starts_with("equal-mtime symlink metadata differs: owner local=")
        );
    }

    #[test]
    fn operations_are_create_then_byte_order_then_deep_finalize() {
        let local = manifest(vec![
            entry("d", EntryKind::Directory, 1, 0),
            entry("d/z", EntryKind::File, 1, 1),
            entry("a", EntryKind::File, 1, 1),
        ]);
        let plan = build_plan(&local, &Manifest::default(), Direction::Out, 0, None).unwrap();
        let ranks: Vec<_> = plan.operations.iter().map(operation_rank).collect();
        assert!(ranks.windows(2).all(|pair| pair[0] <= pair[1]));
        let transfers: Vec<_> = plan
            .operations
            .iter()
            .filter(|operation| matches!(operation, Operation::TransferFile { .. }))
            .map(|operation| operation.path().as_bytes().to_vec())
            .collect();
        assert_eq!(transfers, [b"a".to_vec(), b"d/z".to_vec()]);
        let finalizer_depths: Vec<_> = plan
            .operations
            .iter()
            .filter(|operation| matches!(operation, Operation::FinalizeDirectory { .. }))
            .map(|operation| operation.path().depth())
            .collect();
        assert!(finalizer_depths.windows(2).all(|pair| pair[0] >= pair[1]));
    }
}
