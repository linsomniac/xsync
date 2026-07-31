use std::{
    collections::{BTreeMap, HashMap},
    fs,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
    sync::OnceLock,
};

use cap_fs_ext::DirExt;
#[cfg(test)]
use cap_std::ambient_authority;
use cap_std::fs::{Dir, MetadataExt as CapMetadataExt};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    exclude::Excludes,
    path::{MAX_DEPTH, RelativePath, TEMP_PREFIX},
};

pub const MAX_ENTRIES: usize = 1_000_000;
pub const MAX_MANIFEST_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}

impl Timestamp {
    #[must_use]
    pub fn as_nanos(self) -> i128 {
        i128::from(self.seconds) * 1_000_000_000 + i128::from(self.nanos)
    }

    pub fn validate(self) -> Result<()> {
        if self.nanos >= 1_000_000_000 {
            return Err(Error::Protocol(
                "timestamp nanoseconds are out of range".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub device: u64,
    pub inode: u64,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: RelativePath,
    pub kind: EntryKind,
    pub mtime: Timestamp,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub owner_name: Option<String>,
    pub group_name: Option<String>,
    pub size: u64,
    #[serde(with = "serde_bytes")]
    pub symlink_target: Vec<u8>,
    /// Inventory failure for this path. Such entries are opaque barriers: the
    /// planner reports them and performs no operation in their subtree.
    pub scan_error: Option<String>,
    pub fingerprint: Fingerprint,
}

impl ManifestEntry {
    pub fn validate(&self) -> Result<()> {
        self.mtime.validate()?;
        self.fingerprint.mtime.validate()?;
        if self.fingerprint.kind != self.kind
            || self.fingerprint.size != self.size
            || self.fingerprint.mtime != self.mtime
        {
            return Err(Error::Protocol(format!(
                "inconsistent manifest fingerprint for {}",
                self.path
            )));
        }
        if self.kind == EntryKind::Symlink {
            if self.symlink_target.len() as u64 != self.size {
                return Err(Error::Protocol(format!(
                    "inconsistent symlink length for {}",
                    self.path
                )));
            }
        } else if !self.symlink_target.is_empty() {
            return Err(Error::Protocol(format!(
                "non-symlink has a link target: {}",
                self.path
            )));
        }
        for name in [&self.owner_name, &self.group_name].into_iter().flatten() {
            if name.is_empty()
                || name.len() > 256
                || name
                    .bytes()
                    .any(|byte| byte == 0 || byte == b':' || byte.is_ascii_control())
            {
                return Err(Error::Protocol(format!(
                    "invalid ownership name for {}",
                    self.path
                )));
            }
        }
        if self.scan_error.as_ref().is_some_and(|error| {
            self.kind != EntryKind::Unsupported
                || error.is_empty()
                || error.len() > 4096
                || error.bytes().any(|byte| byte == 0)
        }) {
            return Err(Error::Protocol(format!(
                "invalid inventory error for {}",
                self.path
            )));
        }
        Ok(())
    }

    #[must_use]
    pub fn estimated_wire_bytes(&self) -> usize {
        estimate_entry_bytes(self)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub entries: BTreeMap<RelativePath, ManifestEntry>,
}

impl Manifest {
    #[must_use]
    pub fn get(&self, path: &RelativePath) -> Option<&ManifestEntry> {
        self.entries.get(path)
    }

    pub fn validate(&self, allow_empty: bool) -> Result<()> {
        if self.entries.is_empty() {
            return if allow_empty {
                Ok(())
            } else {
                Err(Error::Protocol("manifest has no root entry".into()))
            };
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(Error::Protocol("manifest entry limit exceeded".into()));
        }
        let root = RelativePath::root();
        if self.entries.get(&root).map(|entry| entry.kind) != Some(EntryKind::Directory) {
            return Err(Error::Protocol("manifest root is not a directory".into()));
        }
        let mut bytes = 0usize;
        for (path, entry) in &self.entries {
            if path != &entry.path {
                return Err(Error::Protocol("manifest key/path mismatch".into()));
            }
            entry.validate()?;
            bytes = bytes.saturating_add(entry.estimated_wire_bytes());
            if bytes > MAX_MANIFEST_BYTES {
                return Err(Error::Protocol("manifest byte limit exceeded".into()));
            }
            if !path.is_root() {
                let parent = path.parent().ok_or_else(|| {
                    Error::Protocol(format!("manifest path has no parent: {path}"))
                })?;
                if self.entries.get(&parent).map(|entry| entry.kind) != Some(EntryKind::Directory) {
                    return Err(Error::Protocol(format!(
                        "manifest parent is missing or not a directory: {path}"
                    )));
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn estimated_memory_bytes(&self) -> usize {
        self.entries
            .values()
            .map(ManifestEntry::estimated_wire_bytes)
            .fold(0usize, usize::saturating_add)
    }
}

#[cfg(test)]
pub fn scan(root: &Path, excludes: &Excludes) -> Result<Manifest> {
    let root_dir = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|e| Error::io(Some(root.to_path_buf()), e))?;
    scan_dir(&root_dir, root, excludes)
}

pub fn scan_dir(root_dir: &Dir, root: &Path, excludes: &Excludes) -> Result<Manifest> {
    scan_dir_with_limits(
        root_dir,
        root,
        excludes,
        MAX_ENTRIES,
        MAX_MANIFEST_BYTES,
        crate::path::MAX_RELATIVE_PATH_BYTES,
        MAX_DEPTH,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn scan_dir_with_limits(
    root_dir: &Dir,
    root: &Path,
    excludes: &Excludes,
    max_entries: usize,
    max_bytes: usize,
    max_path: usize,
    max_depth: usize,
) -> Result<Manifest> {
    struct Frame {
        dir: Dir,
        relative: RelativePath,
        names: Vec<std::ffi::OsString>,
        next: usize,
        charged_bytes: usize,
    }

    fn make_frame(
        dir: Dir,
        relative: RelativePath,
        root: &Path,
        memory_used: &mut usize,
        max_bytes: usize,
    ) -> Result<Frame> {
        let mut names = Vec::new();
        let mut charged_bytes = 256usize.saturating_add(relative.as_bytes().len());
        if memory_used.saturating_add(charged_bytes) > max_bytes {
            return Err(Error::entry(
                "limit",
                None,
                format!("manifest memory limit exceeded near {relative}"),
            ));
        }
        for entry in dir
            .entries()
            .map_err(|e| Error::io(Some(root.join(relative.to_path_buf())), e))?
        {
            let name = entry
                .map_err(|e| Error::io(Some(root.join(relative.to_path_buf())), e))?
                .file_name();
            let name_charge = 64usize.saturating_add(name.as_bytes().len());
            charged_bytes = charged_bytes.saturating_add(name_charge);
            if memory_used.saturating_add(charged_bytes) > max_bytes {
                return Err(Error::entry(
                    "limit",
                    None,
                    format!("manifest memory limit exceeded near {relative}"),
                ));
            }
            names.push(name);
        }
        names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        *memory_used = memory_used
            .checked_add(charged_bytes)
            .ok_or_else(|| Error::entry("limit", None, "manifest memory accounting overflow"))?;
        Ok(Frame {
            dir,
            relative,
            names,
            next: 0,
            charged_bytes,
        })
    }

    let metadata = root_dir
        .symlink_metadata(".")
        .map_err(|e| Error::io(Some(root.to_path_buf()), e))?;
    let root_path = RelativePath::root();
    let mut entries = BTreeMap::new();
    let root_entry = entry_from_cap_metadata(root_path.clone(), &metadata, Vec::new());
    let mut memory_used = estimate_entry_bytes(&root_entry);
    if memory_used > max_bytes || max_entries == 0 {
        return Err(Error::entry(
            "limit",
            Some(root.to_path_buf()),
            "manifest resource limit exceeded at root",
        ));
    }
    entries.insert(root_path.clone(), root_entry);
    let mut stack = vec![make_frame(
        root_dir
            .try_clone()
            .map_err(|e| Error::io(Some(root.to_path_buf()), e))?,
        root_path,
        root,
        &mut memory_used,
        max_bytes,
    )?];

    while let Some(current) = stack.last_mut() {
        if current.next == current.names.len() {
            if let Some(frame) = stack.pop() {
                memory_used = memory_used.saturating_sub(frame.charged_bytes);
            }
            continue;
        }
        let name = std::mem::take(&mut current.names[current.next]);
        current.next += 1;
        if name.as_bytes().starts_with(TEMP_PREFIX) {
            continue;
        }
        let child_relative = current.relative.join_name(&name)?;
        if child_relative.depth() > max_depth || child_relative.as_bytes().len() > max_path {
            return Err(Error::entry(
                "limit",
                Some(root.join(child_relative.to_path_buf())),
                "manifest path exceeds negotiated path/depth limit",
            ));
        }
        let display_path = root.join(child_relative.to_path_buf());
        let metadata = match current.dir.symlink_metadata(&name) {
            Ok(metadata) => metadata,
            Err(error) => {
                if excludes.is_excluded(&child_relative, false) {
                    continue;
                }
                let entry = scan_error_entry(
                    child_relative.clone(),
                    format!("could not inspect entry: {error}"),
                    max_path,
                );
                insert_scanned_entry(
                    &mut entries,
                    &mut memory_used,
                    max_entries,
                    max_bytes,
                    entry,
                    &display_path,
                )?;
                continue;
            }
        };
        let kind = classify_cap(&metadata);
        if excludes.is_excluded(&child_relative, kind == EntryKind::Directory) {
            continue;
        }
        let target = if kind == EntryKind::Symlink {
            let target_result = current.dir.read_link_contents(&name).and_then(|target| {
                let after = current.dir.symlink_metadata(&name)?;
                if cap_fingerprint_fields(&after) != cap_fingerprint_fields(&metadata) {
                    return Err(std::io::Error::other(
                        "symlink changed while reading its target",
                    ));
                }
                Ok(target.into_os_string().into_vec())
            });
            match target_result {
                Ok(target) if target.len() <= max_path => target,
                Ok(_) => {
                    return Err(Error::entry(
                        "limit",
                        Some(display_path),
                        "symlink target exceeds negotiated path/frame limit",
                    ));
                }
                Err(error) => {
                    let entry = scan_error_entry(
                        child_relative.clone(),
                        format!("could not safely read symlink: {error}"),
                        max_path,
                    );
                    insert_scanned_entry(
                        &mut entries,
                        &mut memory_used,
                        max_entries,
                        max_bytes,
                        entry,
                        &display_path,
                    )?;
                    continue;
                }
            }
        } else {
            Vec::new()
        };
        let mut entry = entry_from_cap_metadata(child_relative.clone(), &metadata, target);
        let mut child_frame = None;
        if kind == EntryKind::Directory {
            run_scan_open_hook(&child_relative);
            let opened = current.dir.open_dir_nofollow(&name).and_then(|child_dir| {
                let opened = child_dir.symlink_metadata(".")?;
                if cap_fingerprint_fields(&opened) != cap_fingerprint_fields(&metadata) {
                    return Err(std::io::Error::other(
                        "directory changed while opening it for inventory",
                    ));
                }
                Ok(child_dir)
            });
            match opened {
                Ok(child_dir) => match make_frame(
                    child_dir,
                    child_relative.clone(),
                    root,
                    &mut memory_used,
                    max_bytes,
                ) {
                    Ok(frame) => child_frame = Some(frame),
                    Err(error) if matches!(&error, Error::Entry { class, .. } if class == "limit") =>
                    {
                        return Err(error);
                    }
                    Err(error) => {
                        entry =
                            scan_error_entry(child_relative.clone(), error.to_string(), max_path);
                    }
                },
                Err(error) => {
                    entry = scan_error_entry(
                        child_relative.clone(),
                        format!("could not safely open directory: {error}"),
                        max_path,
                    );
                }
            }
        }
        insert_scanned_entry(
            &mut entries,
            &mut memory_used,
            max_entries,
            max_bytes,
            entry,
            &display_path,
        )?;
        if let Some(frame) = child_frame {
            stack.push(frame);
        }
    }
    let manifest = Manifest { entries };
    manifest.validate(false)?;
    Ok(manifest)
}

fn insert_scanned_entry(
    entries: &mut BTreeMap<RelativePath, ManifestEntry>,
    memory_used: &mut usize,
    max_entries: usize,
    max_bytes: usize,
    entry: ManifestEntry,
    display_path: &Path,
) -> Result<()> {
    charge_manifest(
        memory_used,
        estimate_entry_bytes(&entry),
        max_bytes,
        &entry.path,
    )?;
    if entries.len() >= max_entries {
        return Err(Error::entry(
            "limit",
            Some(display_path.to_path_buf()),
            "manifest entry limit exceeded",
        ));
    }
    entries.insert(entry.path.clone(), entry);
    Ok(())
}

fn charge_manifest(
    memory_used: &mut usize,
    amount: usize,
    max_bytes: usize,
    path: &RelativePath,
) -> Result<()> {
    *memory_used = memory_used
        .checked_add(amount)
        .ok_or_else(|| Error::entry("limit", None, "manifest memory accounting overflow"))?;
    if *memory_used > max_bytes {
        return Err(Error::entry(
            "limit",
            None,
            format!("manifest memory limit exceeded near {path}"),
        ));
    }
    Ok(())
}

fn scan_error_entry(path: RelativePath, error: String, max_diagnostic: usize) -> ManifestEntry {
    let mut error = error;
    let limit = 4096usize.min(max_diagnostic.max(1));
    if error.len() > limit {
        let mut end = limit;
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        error.truncate(end);
    }
    let mtime = Timestamp {
        seconds: 0,
        nanos: 0,
    };
    ManifestEntry {
        path,
        kind: EntryKind::Unsupported,
        mtime,
        mode: 0,
        uid: 0,
        gid: 0,
        owner_name: None,
        group_name: None,
        size: 0,
        symlink_target: Vec::new(),
        scan_error: Some(error),
        fingerprint: Fingerprint {
            device: 0,
            inode: 0,
            kind: EntryKind::Unsupported,
            size: 0,
            mtime,
        },
    }
}

#[cfg(test)]
type ScanOpenHook = (RelativePath, Box<dyn FnOnce() + Send>);

#[cfg(test)]
static SCAN_OPEN_HOOK: std::sync::Mutex<Option<ScanOpenHook>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn set_scan_open_hook(path: RelativePath, hook: impl FnOnce() + Send + 'static) {
    *SCAN_OPEN_HOOK.lock().unwrap() = Some((path, Box::new(hook)));
}

fn run_scan_open_hook(path: &RelativePath) {
    #[cfg(test)]
    {
        let hook = {
            let mut slot = SCAN_OPEN_HOOK.lock().unwrap();
            if slot.as_ref().is_some_and(|(target, _)| target == path) {
                slot.take().map(|(_, hook)| hook)
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook();
        }
    }
    #[cfg(not(test))]
    let _ = path;
}

fn cap_fingerprint_fields(
    metadata: &cap_std::fs::Metadata,
) -> (u64, u64, EntryKind, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        classify_cap(metadata),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

fn classify_cap(metadata: &cap_std::fs::Metadata) -> EntryKind {
    let file_type = metadata.file_type();
    if file_type.is_file() {
        EntryKind::File
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_symlink() {
        EntryKind::Symlink
    } else {
        EntryKind::Unsupported
    }
}

fn entry_from_cap_metadata(
    path: RelativePath,
    metadata: &cap_std::fs::Metadata,
    symlink_target: Vec<u8>,
) -> ManifestEntry {
    let kind = classify_cap(metadata);
    let mtime = Timestamp {
        seconds: metadata.mtime(),
        nanos: u32::try_from(metadata.mtime_nsec()).unwrap_or(0),
    };
    ManifestEntry {
        path,
        kind,
        mtime,
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        owner_name: ownership_database().users.get(&metadata.uid()).cloned(),
        group_name: ownership_database().groups.get(&metadata.gid()).cloned(),
        size: metadata.size(),
        symlink_target,
        scan_error: None,
        fingerprint: Fingerprint {
            device: metadata.dev(),
            inode: metadata.ino(),
            kind,
            size: metadata.size(),
            mtime,
        },
    }
}

fn estimate_entry_bytes(entry: &ManifestEntry) -> usize {
    192usize
        .saturating_add(entry.path.as_bytes().len().saturating_mul(2))
        .saturating_add(entry.symlink_target.len())
        .saturating_add(entry.scan_error.as_ref().map_or(0, String::len))
        .saturating_add(entry.owner_name.as_ref().map_or(0, String::len))
        .saturating_add(entry.group_name.as_ref().map_or(0, String::len))
}

struct OwnershipDatabase {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
    user_ids: HashMap<String, u32>,
    group_ids: HashMap<String, u32>,
}

fn ownership_database() -> &'static OwnershipDatabase {
    static DATABASE: OnceLock<OwnershipDatabase> = OnceLock::new();
    DATABASE.get_or_init(|| {
        let users = parse_name_database("/etc/passwd", 2);
        let groups = parse_name_database("/etc/group", 2);
        OwnershipDatabase {
            user_ids: users.iter().map(|(id, name)| (name.clone(), *id)).collect(),
            group_ids: groups
                .iter()
                .map(|(id, name)| (name.clone(), *id))
                .collect(),
            users,
            groups,
        }
    })
}

fn parse_name_database(path: &str, id_field: usize) -> HashMap<u32, String> {
    fs::read_to_string(path)
        .ok()
        .into_iter()
        .flat_map(|contents| {
            contents
                .lines()
                .filter_map(|line| {
                    let fields: Vec<_> = line.split(':').collect();
                    let name = fields.first()?.to_string();
                    let id = fields.get(id_field)?.parse().ok()?;
                    Some((id, name))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[must_use]
pub fn resolve_user(name: &str) -> Option<u32> {
    ownership_database().user_ids.get(name).copied()
}

#[must_use]
pub fn resolve_group(name: &str) -> Option<u32> {
    ownership_database().group_ids.get(name).copied()
}

#[cfg(test)]
mod tests {
    use std::{os::unix::ffi::OsStringExt, os::unix::fs::symlink};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn scans_deterministically_without_following_symlinks() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("b")).unwrap();
        fs::write(root.path().join("b/file"), b"data").unwrap();
        symlink("/", root.path().join("a-link")).unwrap();
        fs::write(root.path().join(".xsync.tmp.old"), b"partial").unwrap();
        let manifest = scan(root.path(), &Excludes::default()).unwrap();
        let paths: Vec<_> = manifest
            .entries
            .keys()
            .map(RelativePath::display_lossy)
            .collect();
        assert_eq!(paths, [".", "a-link", "b", "b/file"]);
        assert_eq!(
            manifest.entries[&RelativePath::new(b"a-link".to_vec()).unwrap()].kind,
            EntryKind::Symlink
        );
    }

    #[test]
    fn directory_replacement_becomes_a_barrier_and_other_entries_continue() {
        let root = tempdir().unwrap();
        let path = root.path().join("directory");
        let saved = root.path().join("saved");
        fs::create_dir(&path).unwrap();
        fs::write(root.path().join("good"), b"ok").unwrap();
        let relative = RelativePath::new(b"directory".to_vec()).unwrap();
        set_scan_open_hook(relative.clone(), move || {
            fs::rename(&path, saved).unwrap();
            fs::create_dir(&path).unwrap();
        });
        let manifest = scan(root.path(), &Excludes::default()).unwrap();
        assert!(manifest.get(&relative).unwrap().scan_error.is_some());
        assert!(
            manifest
                .get(&RelativePath::new(b"good".to_vec()).unwrap())
                .is_some()
        );
    }

    #[test]
    fn scans_non_utf8_names() {
        let root = tempdir().unwrap();
        let name = std::ffi::OsString::from_vec(vec![0xff]);
        fs::write(root.path().join(&name), b"x").unwrap();
        let manifest = scan(root.path(), &Excludes::default()).unwrap();
        assert!(
            manifest
                .entries
                .contains_key(&RelativePath::new(vec![0xff]).unwrap())
        );
    }

    #[test]
    fn excluded_directory_is_pruned() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("target")).unwrap();
        fs::write(root.path().join("target/file"), b"x").unwrap();
        let manifest = scan(root.path(), &Excludes::compile(&["target".into()]).unwrap()).unwrap();
        assert_eq!(manifest.entries.len(), 1);
    }

    #[test]
    fn manifest_validation_rejects_missing_parents_and_inconsistent_entries() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("file"), b"x").unwrap();
        let mut manifest = scan(root.path(), &Excludes::default()).unwrap();
        let path = RelativePath::new(b"file".to_vec()).unwrap();
        manifest.entries.get_mut(&path).unwrap().fingerprint.size = 99;
        assert!(manifest.validate(false).is_err());

        let mut manifest = scan(root.path(), &Excludes::default()).unwrap();
        let mut entry = manifest.entries.remove(&path).unwrap();
        entry.path = RelativePath::new(b"missing/file".to_vec()).unwrap();
        manifest.entries.insert(entry.path.clone(), entry);
        assert!(manifest.validate(false).is_err());
    }

    #[test]
    fn over_depth_scan_fails_before_opening_the_extra_directory() {
        let root = tempdir().unwrap();
        let mut current = root.path().to_path_buf();
        for _ in 0..=MAX_DEPTH {
            current.push("d");
            fs::create_dir(&current).unwrap();
        }
        let error = scan(root.path(), &Excludes::default()).unwrap_err();
        assert!(error.to_string().contains("depth"));
    }

    #[test]
    fn scanner_charges_pending_directory_names_against_memory_limit() {
        let root = tempdir().unwrap();
        for index in 0..20 {
            fs::write(root.path().join(format!("long-name-{index:04}")), b"x").unwrap();
        }
        let dir = Dir::open_ambient_dir(root.path(), ambient_authority()).unwrap();
        let error = scan_dir_with_limits(
            &dir,
            root.path(),
            &Excludes::default(),
            100,
            1024,
            crate::path::MAX_RELATIVE_PATH_BYTES,
            MAX_DEPTH,
        )
        .unwrap_err();
        assert!(error.to_string().contains("memory limit"));
    }

    #[test]
    fn inventory_errors_are_truncated_to_the_negotiated_record_budget() {
        let path = RelativePath::new(vec![b'p'; 200]).unwrap();
        let entry = scan_error_entry(path, "é".repeat(1000), 256);
        assert!(entry.scan_error.as_ref().unwrap().len() <= 256);
        let envelope = crate::protocol::Envelope {
            request_id: 1,
            job_id: 1,
            message: crate::protocol::Message::ManifestChunk(vec![entry]),
        };
        assert!(crate::protocol::encoded_envelope_len(&envelope).unwrap() <= 2048);
    }
}
