use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    os::unix::ffi::{OsStrExt, OsStringExt},
    os::unix::fs::{MetadataExt as StdMetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use cap_fs_ext::DirExt;
use cap_std::{
    ambient_authority,
    fs::{Dir, DirBuilder, DirBuilderExt, MetadataExt, OpenOptions, OpenOptionsExt, Permissions},
};
use rustix::fs::{
    AtFlags, FlockOperation, Gid, RenameFlags, Timespec, Timestamps, UTIME_OMIT, Uid, chownat,
    flock, renameat_with, utimensat,
};

use crate::{
    Error, Result,
    manifest::{EntryKind, Fingerprint, ManifestEntry, Timestamp},
    path::{RECOVERY_PREFIX, RelativePath, TEMP_PREFIX},
};

pub struct RootDir {
    path: PathBuf,
    dir: Dir,
    _lock: std::fs::File,
    directory_identities: Mutex<BTreeMap<RelativePath, Fingerprint>>,
    directory_identity_bytes: AtomicUsize,
    directory_identity_limit: AtomicUsize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnershipPolicy {
    pub owner: bool,
    pub group: bool,
    pub numeric_ids: bool,
}

pub enum BasisReader {
    File(cap_std::fs::File),
    Empty(Cursor<Vec<u8>>),
}

impl Read for BasisReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.read(buffer),
            Self::Empty(cursor) => cursor.read(buffer),
        }
    }
}

impl Seek for BasisReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        match self {
            Self::File(file) => file.seek(position),
            Self::Empty(cursor) => cursor.seek(position),
        }
    }
}

impl BasisReader {
    #[must_use]
    pub fn empty() -> Self {
        Self::Empty(Cursor::new(Vec::new()))
    }

    fn fingerprint(&self) -> Result<Option<Fingerprint>> {
        match self {
            Self::File(file) => file
                .metadata()
                .map(|metadata| Some(cap_fingerprint(&metadata)))
                .map_err(|error| Error::io(None, error)),
            Self::Empty(_) => Ok(None),
        }
    }
}

impl RootDir {
    pub fn open(path: &Path) -> Result<Self> {
        let dir = open_root_nofollow(path)?;
        Self::from_dir(path, dir)
    }

    fn from_dir(path: &Path, dir: Dir) -> Result<Self> {
        let lock = dir
            .open(".")
            .map_err(|e| Error::io(Some(path.to_path_buf()), e))?
            .into_std();
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|e| Error::io(Some(path.to_path_buf()), std::io::Error::from(e)))?;
        let dir_metadata = dir
            .symlink_metadata(".")
            .map_err(|e| Error::io(Some(path.to_path_buf()), e))?;
        let lock_metadata = lock
            .metadata()
            .map_err(|e| Error::io(Some(path.to_path_buf()), e))?;
        if dir_metadata.dev() != lock_metadata.dev() || dir_metadata.ino() != lock_metadata.ino() {
            return Err(Error::Io {
                path: Some(path.to_path_buf()),
                source: std::io::Error::other("job root changed while it was being opened"),
            });
        }
        let root_fingerprint = cap_fingerprint(&dir_metadata);
        Ok(Self {
            path: path.to_path_buf(),
            dir,
            _lock: lock,
            directory_identities: Mutex::new(BTreeMap::from([(
                RelativePath::root(),
                root_fingerprint,
            )])),
            directory_identity_bytes: AtomicUsize::new(96),
            directory_identity_limit: AtomicUsize::new(crate::manifest::MAX_MANIFEST_BYTES),
        })
    }

    pub fn create_and_open(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| Error::Usage("job root has no parent".into()))?;
        let name = path
            .file_name()
            .ok_or_else(|| Error::Usage("job root has no final component".into()))?;
        let parent_dir = Dir::open_ambient_dir(parent, ambient_authority()).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::entry(
                    "root-parent-missing",
                    Some(parent.to_path_buf()),
                    "job root parent is missing",
                )
            } else {
                Error::io(Some(parent.to_path_buf()), error)
            }
        })?;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent_dir
            .create_dir_with(name, &builder)
            .map_err(|e| Error::io(Some(path.to_path_buf()), e))?;
        let created = parent_dir
            .symlink_metadata(name)
            .map_err(|e| Error::io(Some(path.to_path_buf()), e))?;
        run_creation_hook(path);
        let dir = parent_dir
            .open_dir_nofollow(name)
            .map_err(|e| Error::io(Some(path.to_path_buf()), e))?;
        let opened = dir
            .symlink_metadata(".")
            .map_err(|e| Error::io(Some(path.to_path_buf()), e))?;
        if created.dev() != opened.dev() || created.ino() != opened.ino() {
            return Err(Error::Io {
                path: Some(path.to_path_buf()),
                source: std::io::Error::other("new job root was replaced during creation"),
            });
        }
        dir.set_permissions(
            ".",
            Permissions::from_std(std::fs::Permissions::from_mode(0o700)),
        )
        .map_err(|e| Error::io(Some(path.to_path_buf()), e))?;
        Self::from_dir(path, dir)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn scan(
        &self,
        excludes: &crate::exclude::Excludes,
        limits: crate::protocol::Limits,
    ) -> Result<crate::manifest::Manifest> {
        self.scan_with_budget(excludes, limits, crate::manifest::MAX_MANIFEST_BYTES)
    }

    pub fn scan_with_budget(
        &self,
        excludes: &crate::exclude::Excludes,
        limits: crate::protocol::Limits,
        max_bytes: usize,
    ) -> Result<crate::manifest::Manifest> {
        let manifest = crate::manifest::scan_dir_with_limits(
            &self.dir,
            &self.path,
            excludes,
            usize::try_from(limits.max_entries).unwrap_or(usize::MAX),
            max_bytes,
            limits.max_path as usize,
            limits.max_depth as usize,
        )?;
        let identity_bytes = manifest
            .entries
            .iter()
            .filter(|(_, entry)| entry.kind == EntryKind::Directory)
            .fold(0usize, |bytes, (path, _)| {
                bytes.saturating_add(96 + path.as_bytes().len())
            });
        let manifest_bytes = manifest.estimated_memory_bytes();
        let retained = manifest_bytes.saturating_add(identity_bytes);
        if retained > max_bytes {
            return Err(Error::entry(
                "limit",
                Some(self.path.clone()),
                "manifest and directory identity map exceed job memory budget",
            ));
        }
        let identities = manifest
            .entries
            .iter()
            .filter(|(_, entry)| entry.kind == EntryKind::Directory)
            .map(|(path, entry)| (path.clone(), entry.fingerprint))
            .collect();
        *self
            .directory_identities
            .lock()
            .map_err(|_| Error::Protocol("directory identity lock was poisoned".into()))? =
            identities;
        self.directory_identity_bytes
            .store(identity_bytes, Ordering::Release);
        self.directory_identity_limit
            .store(max_bytes.saturating_sub(manifest_bytes), Ordering::Release);
        Ok(manifest)
    }

    pub fn directory_identity_memory_bytes(&self) -> Result<usize> {
        Ok(self.directory_identity_bytes.load(Ordering::Acquire))
    }

    pub fn source_file(&self, entry: &ManifestEntry) -> Result<cap_std::fs::File> {
        if entry.kind != EntryKind::File {
            return Err(Error::Protocol(
                "attempted to read a non-file source".into(),
            ));
        }
        let (parent, name) = self.parent_dir(&entry.path)?;
        let before = parent
            .symlink_metadata(&name)
            .map_err(|e| self.io_at(&entry.path, e))?;
        if cap_fingerprint(&before) != entry.fingerprint {
            return Err(self.changed(&entry.path, "source changed before reading"));
        }
        run_open_hook("source", "before", &entry.path);
        let file = parent.open(&name).map_err(|e| self.io_at(&entry.path, e))?;
        run_open_hook("source", "after", &entry.path);
        let opened = file.metadata().map_err(|e| self.io_at(&entry.path, e))?;
        if cap_fingerprint(&opened) != entry.fingerprint {
            return Err(self.changed(&entry.path, "source changed while opening"));
        }
        Ok(file)
    }

    pub fn validate_source(&self, entry: &ManifestEntry, file: &cap_std::fs::File) -> Result<()> {
        let descriptor = file.metadata().map_err(|e| self.io_at(&entry.path, e))?;
        if cap_fingerprint(&descriptor) != entry.fingerprint {
            return Err(self.changed(&entry.path, "source descriptor changed while reading"));
        }
        self.validate_current(
            &entry.path,
            entry.fingerprint,
            "source changed while reading",
        )
    }

    pub fn digest_source(&self, entry: &ManifestEntry) -> Result<[u8; 32]> {
        let mut file = self.source_file(entry)?;
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut hasher).map_err(|e| self.io_at(&entry.path, e))?;
        self.validate_source(entry, &file)?;
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn validate_symlink_source(&self, entry: &ManifestEntry) -> Result<Vec<u8>> {
        if entry.kind != EntryKind::Symlink {
            return Err(Error::Protocol(
                "attempted to read a non-symlink source".into(),
            ));
        }
        let (parent, name) = self.parent_dir(&entry.path)?;
        let before = parent
            .symlink_metadata(&name)
            .map_err(|e| self.io_at(&entry.path, e))?;
        if cap_fingerprint(&before) != entry.fingerprint {
            return Err(self.changed(&entry.path, "symlink source changed before reading"));
        }
        let target = parent
            .read_link_contents(&name)
            .map_err(|e| self.io_at(&entry.path, e))?
            .into_os_string()
            .into_vec();
        let after = parent
            .symlink_metadata(&name)
            .map_err(|e| self.io_at(&entry.path, e))?;
        if cap_fingerprint(&after) != entry.fingerprint || target != entry.symlink_target {
            return Err(self.changed(&entry.path, "symlink source changed while reading"));
        }
        Ok(target)
    }

    pub fn basis_reader(
        &self,
        path: &RelativePath,
        expected: Option<Fingerprint>,
    ) -> Result<(BasisReader, u64)> {
        let Some(expected) = expected else {
            return Ok((BasisReader::Empty(Cursor::new(Vec::new())), 0));
        };
        if expected.kind != EntryKind::File {
            return Err(self.changed(path, "basis is not a regular file"));
        }
        let (parent, name) = self.parent_dir(path)?;
        let metadata = parent
            .symlink_metadata(&name)
            .map_err(|e| self.io_at(path, e))?;
        if cap_fingerprint(&metadata) != expected {
            return Err(self.changed(path, "basis changed"));
        }
        run_open_hook("basis", "before", path);
        let file = parent.open(&name).map_err(|e| self.io_at(path, e))?;
        run_open_hook("basis", "after", path);
        let opened = file.metadata().map_err(|e| self.io_at(path, e))?;
        if cap_fingerprint(&opened) != expected {
            return Err(self.changed(path, "basis changed while opening"));
        }
        Ok((BasisReader::File(file), expected.size))
    }

    pub fn validate_basis(
        &self,
        path: &RelativePath,
        expected: Option<Fingerprint>,
        reader: &BasisReader,
    ) -> Result<()> {
        if let Some(expected) = expected {
            if reader.fingerprint()? != Some(expected) {
                return Err(self.changed(path, "basis descriptor changed while reading"));
            }
            self.validate_current(path, expected, "basis changed while reading")?;
        } else if reader.fingerprint()?.is_some() {
            return Err(self.changed(path, "unexpected basis descriptor"));
        }
        Ok(())
    }

    pub fn validate_expected_path(&self, path: &RelativePath, expected: Fingerprint) -> Result<()> {
        self.validate_current(path, expected, "basis changed while reading")
    }

    pub fn create_directory(
        &self,
        entry: &ManifestEntry,
        expected: Option<Fingerprint>,
    ) -> Result<Fingerprint> {
        if entry.path.is_root() {
            return self.current_fingerprint(&entry.path);
        }
        let identity_charge = 96usize.saturating_add(entry.path.as_bytes().len());
        self.reserve_directory_identity(identity_charge)?;
        let result = (|| {
            let (parent, name) = self.parent_dir(&entry.path)?;
            self.validate_destination(&parent, &name, &entry.path, expected)?;
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            parent
                .create_dir_with(&name, &builder)
                .map_err(|e| self.io_at(&entry.path, e))?;
            let created = parent
                .symlink_metadata(&name)
                .map_err(|e| self.io_at(&entry.path, e))?;
            run_creation_hook(&self.path.join(entry.path.to_path_buf()));
            let directory = parent
                .open_dir_nofollow(&name)
                .map_err(|e| self.io_at(&entry.path, e))?;
            let opened = directory
                .symlink_metadata(".")
                .map_err(|e| self.io_at(&entry.path, e))?;
            if created.dev() != opened.dev() || created.ino() != opened.ino() {
                return Err(self.changed(&entry.path, "new directory was replaced during creation"));
            }
            directory
                .set_permissions(
                    ".",
                    Permissions::from_std(std::fs::Permissions::from_mode(0o700)),
                )
                .map_err(|e| self.io_at(&entry.path, e))?;
            let fingerprint = cap_fingerprint(&opened);
            self.directory_identities
                .lock()
                .map_err(|_| Error::Protocol("directory identity lock was poisoned".into()))?
                .insert(entry.path.clone(), fingerprint);
            Ok(fingerprint)
        })();
        if result.is_err() {
            self.directory_identity_bytes
                .fetch_sub(identity_charge, Ordering::AcqRel);
        }
        result
    }

    fn reserve_directory_identity(&self, charge: usize) -> Result<()> {
        self.directory_identity_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                let next = used.checked_add(charge)?;
                (next <= self.directory_identity_limit.load(Ordering::Acquire)).then_some(next)
            })
            .map(|_| ())
            .map_err(|_| {
                Error::entry(
                    "limit",
                    Some(self.path.clone()),
                    "directory identity map exceeds job memory budget",
                )
            })
    }

    pub fn current_fingerprint(&self, path: &RelativePath) -> Result<Fingerprint> {
        let metadata = if path.is_root() {
            self.dir
                .symlink_metadata(".")
                .map_err(|e| self.io_at(path, e))?
        } else {
            let (parent, name) = self.parent_dir(path)?;
            parent
                .symlink_metadata(name)
                .map_err(|e| self.io_at(path, e))?
        };
        Ok(cap_fingerprint(&metadata))
    }

    pub fn write_file_atomic(
        &self,
        entry: &ManifestEntry,
        expected: Option<Fingerprint>,
        contents: &[u8],
    ) -> Result<Option<String>> {
        self.write_file_atomic_with(entry, expected, OwnershipPolicy::default(), |file| {
            file.write_all(contents).map_err(|e| Error::io(None, e))?;
            Ok(())
        })
        .map(|(_, warning)| warning)
    }

    pub fn write_file_atomic_with<T, F>(
        &self,
        entry: &ManifestEntry,
        expected: Option<Fingerprint>,
        ownership: OwnershipPolicy,
        write_contents: F,
    ) -> Result<(T, Option<String>)>
    where
        F: FnOnce(&mut cap_std::fs::File) -> Result<T>,
    {
        let (parent, name) = self.parent_dir(&entry.path)?;
        self.validate_destination(&parent, &name, &entry.path, expected)?;
        let temp_name = temp_name();
        let mut created_identity = None;
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut file = parent
                .open_with(&temp_name, &options)
                .map_err(|e| self.io_at(&entry.path, e))?;
            created_identity = Some(
                file.metadata()
                    .map(|metadata| cap_fingerprint(&metadata))
                    .map_err(|error| self.io_at(&entry.path, error))?,
            );
            let value = write_contents(&mut file)?;
            file.flush().map_err(|e| self.io_at(&entry.path, e))?;
            file.sync_data().map_err(|e| self.io_at(&entry.path, e))?;
            let mut metadata_warning =
                apply_ownership(&parent, &temp_name, entry, ownership, false);
            if let Err(error) = parent.set_permissions(
                &temp_name,
                Permissions::from_std(std::fs::Permissions::from_mode(entry.mode & 0o777)),
            ) {
                metadata_warning = merge_warnings(
                    metadata_warning,
                    Some(format!("could not preserve permissions: {error}")),
                );
            }
            if let Err(error) = set_mtime(&parent, &temp_name, entry.mtime, false) {
                metadata_warning = merge_warnings(
                    metadata_warning,
                    Some(format!("could not preserve mtime: {error}")),
                );
            }
            let temp_identity = file
                .metadata()
                .map(|metadata| cap_fingerprint(&metadata))
                .map_err(|error| self.io_at(&entry.path, error))?;
            created_identity = Some(temp_identity);
            self.validate_destination(&parent, &name, &entry.path, expected)?;
            run_commit_hook(&entry.path);
            self.commit_temp(
                &parent,
                &temp_name,
                &name,
                &entry.path,
                expected,
                temp_identity,
            )?;
            Ok((value, metadata_warning))
        })();
        if result.is_err() {
            self.remove_if_identity(&parent, &temp_name, created_identity);
        }
        let (value, metadata_warning) = result?;
        Ok((
            value,
            merge_warnings(metadata_warning, special_bits_warning(entry)),
        ))
    }

    pub fn write_symlink_atomic(
        &self,
        entry: &ManifestEntry,
        expected: Option<Fingerprint>,
    ) -> Result<Option<String>> {
        self.write_symlink_atomic_with_policy(entry, expected, OwnershipPolicy::default())
    }

    pub fn write_symlink_atomic_with_policy(
        &self,
        entry: &ManifestEntry,
        expected: Option<Fingerprint>,
        ownership: OwnershipPolicy,
    ) -> Result<Option<String>> {
        let (parent, name) = self.parent_dir(&entry.path)?;
        self.validate_destination(&parent, &name, &entry.path, expected)?;
        let temp_name = temp_name();
        let target = PathBuf::from(OsString::from_vec(entry.symlink_target.clone()));
        let mut created_identity = None;
        let result = (|| {
            parent
                .symlink(&target, &temp_name)
                .map_err(|e| self.io_at(&entry.path, e))?;
            created_identity = Some(
                parent
                    .symlink_metadata(&temp_name)
                    .map(|metadata| cap_fingerprint(&metadata))
                    .map_err(|error| self.io_at(&entry.path, error))?,
            );
            let mut metadata_warning = apply_ownership(&parent, &temp_name, entry, ownership, true);
            if let Err(error) = set_mtime(&parent, &temp_name, entry.mtime, true) {
                metadata_warning = merge_warnings(
                    metadata_warning,
                    Some(format!("could not preserve symlink mtime: {error}")),
                );
            }
            self.validate_destination(&parent, &name, &entry.path, expected)?;
            run_commit_hook(&entry.path);
            let temp_identity = parent
                .symlink_metadata(&temp_name)
                .map(|metadata| cap_fingerprint(&metadata))
                .map_err(|error| self.io_at(&entry.path, error))?;
            created_identity = Some(temp_identity);
            self.commit_temp(
                &parent,
                &temp_name,
                &name,
                &entry.path,
                expected,
                temp_identity,
            )?;
            Ok(metadata_warning)
        })();
        if result.is_err() {
            self.remove_if_identity(&parent, &temp_name, created_identity);
        }
        result
    }

    pub fn finalize_directory(
        &self,
        entry: &ManifestEntry,
        expected: Fingerprint,
        ownership: OwnershipPolicy,
    ) -> Result<Option<String>> {
        let mode = entry.mode & 0o777;
        if entry.path.is_root() {
            let metadata = self
                .dir
                .symlink_metadata(".")
                .map_err(|e| self.io_at(&entry.path, e))?;
            self.validate_directory_identity(&entry.path, &metadata, expected)?;
            let mut metadata_warning =
                apply_ownership(&self.dir, Path::new("."), entry, ownership, false);
            if let Err(error) = self.dir.set_permissions(
                ".",
                Permissions::from_std(std::fs::Permissions::from_mode(mode)),
            ) {
                metadata_warning = merge_warnings(
                    metadata_warning,
                    Some(format!("could not preserve directory permissions: {error}")),
                );
            }
            if let Err(error) = set_mtime(&self.dir, Path::new("."), entry.mtime, false) {
                metadata_warning = merge_warnings(
                    metadata_warning,
                    Some(format!("could not preserve directory mtime: {error}")),
                );
            }
            Ok(merge_warnings(
                metadata_warning,
                special_bits_warning(entry),
            ))
        } else {
            let (parent, name) = self.parent_dir(&entry.path)?;
            let metadata = parent
                .symlink_metadata(&name)
                .map_err(|e| self.io_at(&entry.path, e))?;
            self.validate_directory_identity(&entry.path, &metadata, expected)?;
            let mut metadata_warning = apply_ownership(&parent, &name, entry, ownership, false);
            if let Err(error) = parent.set_permissions(
                &name,
                Permissions::from_std(std::fs::Permissions::from_mode(mode)),
            ) {
                metadata_warning = merge_warnings(
                    metadata_warning,
                    Some(format!("could not preserve directory permissions: {error}")),
                );
            }
            if let Err(error) = set_mtime(&parent, &name, entry.mtime, false) {
                metadata_warning = merge_warnings(
                    metadata_warning,
                    Some(format!("could not preserve directory mtime: {error}")),
                );
            }
            Ok(merge_warnings(
                metadata_warning,
                special_bits_warning(entry),
            ))
        }
    }

    fn commit_temp(
        &self,
        parent: &Dir,
        temp_name: &OsStr,
        name: &OsStr,
        path: &RelativePath,
        expected: Option<Fingerprint>,
        temp_identity: Fingerprint,
    ) -> Result<()> {
        if let Some(expected) = expected {
            // Move our payload to a recovery-visible name before the exchange.
            // If the process dies after the exchange, the displaced inode is
            // therefore never stranded under the scanner-pruned temp prefix.
            let recovery = self.preserve_recovery(parent, temp_name, path)?;
            if let Err(error) =
                renameat_with(parent, &recovery, parent, name, RenameFlags::EXCHANGE)
            {
                self.remove_if_identity(parent, &recovery, Some(temp_identity));
                return Err(self.io_at(path, std::io::Error::from(error)));
            }
            run_post_exchange_hook(path);
            let displaced = parent
                .symlink_metadata(&recovery)
                .map_err(|e| self.io_at(path, e));
            match displaced {
                Ok(metadata)
                    if cap_fingerprint(&metadata) == expected
                        && parent.symlink_metadata(name).is_ok_and(|installed| {
                            cap_fingerprint(&installed) == temp_identity
                        }) =>
                {
                    parent
                        .remove_file(&recovery)
                        .map_err(|e| self.io_at(path, e))
                }
                result => {
                    let installed_is_temp = parent
                        .symlink_metadata(name)
                        .is_ok_and(|metadata| cap_fingerprint(&metadata) == temp_identity);
                    if installed_is_temp
                        && renameat_with(parent, &recovery, parent, name, RenameFlags::EXCHANGE)
                            .is_ok()
                    {
                        let restored = parent
                            .symlink_metadata(name)
                            .ok()
                            .map(|metadata| cap_fingerprint(&metadata));
                        let temp = parent
                            .symlink_metadata(&recovery)
                            .ok()
                            .map(|metadata| cap_fingerprint(&metadata));
                        if restored == result.as_ref().ok().map(cap_fingerprint)
                            && temp == Some(temp_identity)
                        {
                            self.remove_if_identity(parent, &recovery, Some(temp_identity));
                            return Err(self.changed(path, "destination changed before commit"));
                        }
                    }
                    Err(self.changed(
                        path,
                        &format!(
                            "destination changed during commit; displaced data preserved as {}",
                            recovery.to_string_lossy()
                        ),
                    ))
                }
            }
        } else {
            renameat_with(parent, temp_name, parent, name, RenameFlags::NOREPLACE).map_err(
                |error| {
                    if error == rustix::io::Errno::EXIST {
                        self.changed(path, "destination appeared before commit")
                    } else {
                        self.io_at(path, std::io::Error::from(error))
                    }
                },
            )
        }
    }

    fn preserve_recovery(
        &self,
        parent: &Dir,
        name: &OsStr,
        path: &RelativePath,
    ) -> Result<OsString> {
        for _ in 0..16 {
            let recovery = recovery_name();
            match renameat_with(parent, name, parent, &recovery, RenameFlags::NOREPLACE) {
                Ok(()) => return Ok(recovery),
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(self.io_at(path, std::io::Error::from(error))),
            }
        }
        Err(Error::Protocol(format!(
            "could not allocate a recovery name for {path}"
        )))
    }

    fn remove_if_identity(&self, parent: &Dir, name: &OsStr, expected: Option<Fingerprint>) {
        if let Some(expected) = expected
            && parent
                .symlink_metadata(name)
                .is_ok_and(|metadata| same_object_identity(cap_fingerprint(&metadata), expected))
        {
            let _ = parent.remove_file(name);
        }
    }

    fn validate_directory_identity(
        &self,
        path: &RelativePath,
        metadata: &cap_std::fs::Metadata,
        expected: Fingerprint,
    ) -> Result<()> {
        let actual = cap_fingerprint(metadata);
        if actual.kind != EntryKind::Directory
            || expected.kind != EntryKind::Directory
            || actual.device != expected.device
            || actual.inode != expected.inode
        {
            return Err(self.changed(path, "directory changed before finalization"));
        }
        Ok(())
    }

    fn parent_dir(&self, relative: &RelativePath) -> Result<(Dir, OsString)> {
        if relative.is_root() {
            return Err(Error::Protocol("root path has no parent entry".into()));
        }
        let mut components = relative.as_bytes().split(|&byte| byte == b'/').peekable();
        let mut directory = self
            .dir
            .open_dir_nofollow(".")
            .map_err(|e| self.io_at(relative, e))?;
        let identities = self
            .directory_identities
            .lock()
            .map_err(|_| Error::Protocol("directory identity lock was poisoned".into()))?;
        let mut ancestor = RelativePath::root();
        let root_metadata = directory
            .symlink_metadata(".")
            .map_err(|error| self.io_at(relative, error))?;
        if !identities.get(&ancestor).is_some_and(|expected| {
            same_directory_identity(*expected, cap_fingerprint(&root_metadata))
        }) {
            return Err(self.changed(relative, "destination ancestor changed after inventory"));
        }
        while let Some(component) = components.next() {
            let name = OsStr::from_bytes(component);
            if components.peek().is_none() {
                return Ok((directory, name.to_os_string()));
            }
            directory = directory
                .open_dir_nofollow(name)
                .map_err(|e| self.io_at(relative, e))?;
            ancestor = ancestor.join_name(name)?;
            let opened = directory
                .symlink_metadata(".")
                .map_err(|error| self.io_at(relative, error))?;
            if !identities.get(&ancestor).is_some_and(|expected| {
                same_directory_identity(*expected, cap_fingerprint(&opened))
            }) {
                return Err(self.changed(relative, "destination ancestor changed after inventory"));
            }
        }
        Err(Error::Protocol("invalid empty relative path".into()))
    }

    fn validate_destination(
        &self,
        parent: &Dir,
        name: &OsStr,
        path: &RelativePath,
        expected: Option<Fingerprint>,
    ) -> Result<()> {
        match (parent.symlink_metadata(name), expected) {
            (Err(error), None) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            (Ok(metadata), Some(expected)) if cap_fingerprint(&metadata) == expected => Ok(()),
            (Err(error), Some(_)) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(self.changed(path, "destination disappeared after planning"))
            }
            (Ok(_), None) => Err(self.changed(path, "destination appeared after planning")),
            (Ok(_), Some(_)) => Err(self.changed(path, "destination changed after planning")),
            (Err(error), _) => Err(self.io_at(path, error)),
        }
    }

    fn validate_current(
        &self,
        path: &RelativePath,
        expected: Fingerprint,
        message: &str,
    ) -> Result<()> {
        let actual = self.current_fingerprint(path)?;
        if actual != expected {
            return Err(self.changed(path, message));
        }
        Ok(())
    }

    fn io_at(&self, relative: &RelativePath, source: std::io::Error) -> Error {
        Error::io(Some(self.path.join(relative.to_path_buf())), source)
    }

    fn changed(&self, relative: &RelativePath, message: &str) -> Error {
        let class = if message.starts_with("source") || message.starts_with("symlink source") {
            "source-changed"
        } else if message.starts_with("basis") || message.starts_with("unexpected basis") {
            "basis-changed"
        } else {
            "destination-changed"
        };
        Error::entry(class, Some(self.path.join(relative.to_path_buf())), message)
    }
}

fn open_root_nofollow(path: &Path) -> Result<Dir> {
    if path == Path::new("/") {
        return Dir::open_ambient_dir(path, ambient_authority())
            .map_err(|e| Error::io(Some(path.to_path_buf()), e));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::Usage("job root has no parent".into()))?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::Usage("job root has no final component".into()))?;
    let parent_dir = Dir::open_ambient_dir(parent, ambient_authority())
        .map_err(|e| Error::io(Some(parent.to_path_buf()), e))?;
    parent_dir
        .open_dir_nofollow(name)
        .map_err(|e| Error::io(Some(path.to_path_buf()), e))
}

fn cap_fingerprint(metadata: &cap_std::fs::Metadata) -> Fingerprint {
    let file_type = metadata.file_type();
    let kind = if file_type.is_file() {
        EntryKind::File
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_symlink() {
        EntryKind::Symlink
    } else {
        EntryKind::Unsupported
    };
    Fingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        kind,
        size: metadata.size(),
        mtime: Timestamp {
            seconds: metadata.mtime(),
            nanos: u32::try_from(metadata.mtime_nsec()).unwrap_or(0),
        },
    }
}

fn same_directory_identity(left: Fingerprint, right: Fingerprint) -> bool {
    left.kind == EntryKind::Directory
        && right.kind == EntryKind::Directory
        && left.device == right.device
        && left.inode == right.inode
}

fn same_object_identity(left: Fingerprint, right: Fingerprint) -> bool {
    left.device == right.device && left.inode == right.inode && left.kind == right.kind
}

fn set_mtime(
    dir: &Dir,
    path: impl AsRef<Path>,
    timestamp: Timestamp,
    symlink: bool,
) -> std::io::Result<()> {
    timestamp
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let times = Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        last_modification: Timespec {
            tv_sec: timestamp.seconds,
            tv_nsec: i64::from(timestamp.nanos),
        },
    };
    let flags = if symlink {
        AtFlags::SYMLINK_NOFOLLOW
    } else {
        AtFlags::empty()
    };
    utimensat(dir, path.as_ref(), &times, flags).map_err(std::io::Error::from)
}

#[cfg(test)]
type CommitHook = (RelativePath, Box<dyn FnOnce() + Send>);

#[cfg(test)]
static COMMIT_HOOK: std::sync::Mutex<Option<CommitHook>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn run_commit_hook(path: &RelativePath) {
    let mut hook = COMMIT_HOOK.lock().expect("commit hook lock");
    if hook.as_ref().is_some_and(|(target, _)| target == path)
        && let Some((_, hook)) = hook.take()
    {
        hook();
    }
}

#[cfg(not(test))]
fn run_commit_hook(_path: &RelativePath) {}

#[cfg(test)]
static POST_EXCHANGE_HOOK: std::sync::Mutex<Option<CommitHook>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn run_post_exchange_hook(path: &RelativePath) {
    let mut hook = POST_EXCHANGE_HOOK.lock().expect("post-exchange hook lock");
    if hook.as_ref().is_some_and(|(target, _)| target == path)
        && let Some((_, hook)) = hook.take()
    {
        hook();
    }
}

#[cfg(not(test))]
fn run_post_exchange_hook(_path: &RelativePath) {}

#[cfg(test)]
type CreationHook = (PathBuf, Box<dyn FnOnce() + Send>);

#[cfg(test)]
static CREATION_HOOK: std::sync::Mutex<Option<CreationHook>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn run_creation_hook(path: &Path) {
    let mut hook = CREATION_HOOK.lock().expect("creation hook lock");
    if hook.as_ref().is_some_and(|(target, _)| target == path)
        && let Some((_, hook)) = hook.take()
    {
        hook();
    }
}

#[cfg(not(test))]
fn run_creation_hook(_path: &Path) {}

#[cfg(test)]
type OpenHook = (
    &'static str,
    &'static str,
    RelativePath,
    Box<dyn FnOnce() + Send>,
);

#[cfg(test)]
static OPEN_HOOKS: std::sync::Mutex<Vec<OpenHook>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn run_open_hook(role: &'static str, stage: &'static str, path: &RelativePath) {
    let mut hooks = OPEN_HOOKS.lock().expect("open hook lock");
    if let Some(index) = hooks
        .iter()
        .position(|hook| hook.0 == role && hook.1 == stage && &hook.2 == path)
    {
        let (_, _, _, hook) = hooks.remove(index);
        hook();
    }
}

#[cfg(not(test))]
fn run_open_hook(_role: &'static str, _stage: &'static str, _path: &RelativePath) {}

fn temp_name() -> OsString {
    unique_internal_name(TEMP_PREFIX)
}

fn recovery_name() -> OsString {
    unique_internal_name(RECOVERY_PREFIX)
}

fn unique_internal_name(prefix: &[u8]) -> OsString {
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(std::process::id().to_string().as_bytes());
    bytes.push(b'.');
    bytes.extend_from_slice(format!("{:016x}", rand::random::<u64>()).as_bytes());
    OsString::from_vec(bytes)
}

fn apply_ownership(
    parent: &Dir,
    name: impl AsRef<Path>,
    entry: &ManifestEntry,
    policy: OwnershipPolicy,
    symlink: bool,
) -> Option<String> {
    if !policy.owner && !policy.group {
        return None;
    }
    let mut warnings = Vec::new();
    let owner = policy.owner.then(|| {
        if policy.numeric_ids {
            entry.uid
        } else if let Some(name) = entry.owner_name.as_deref() {
            crate::manifest::resolve_user(name).unwrap_or_else(|| {
                warnings.push(format!("owner {name:?} was not found; used numeric uid"));
                entry.uid
            })
        } else {
            warnings.push("source owner name is unavailable; used numeric uid".into());
            entry.uid
        }
    });
    let group = policy.group.then(|| {
        if policy.numeric_ids {
            entry.gid
        } else if let Some(name) = entry.group_name.as_deref() {
            crate::manifest::resolve_group(name).unwrap_or_else(|| {
                warnings.push(format!("group {name:?} was not found; used numeric gid"));
                entry.gid
            })
        } else {
            warnings.push("source group name is unavailable; used numeric gid".into());
            entry.gid
        }
    });
    if owner == Some(u32::MAX) || group == Some(u32::MAX) {
        warnings.push("ownership ID is the reserved -1 value and was not applied".into());
    } else {
        let flags = if symlink {
            AtFlags::SYMLINK_NOFOLLOW
        } else {
            AtFlags::empty()
        };
        if let Err(error) = chownat(
            parent,
            name.as_ref(),
            owner.map(Uid::from_raw),
            group.map(Gid::from_raw),
            flags,
        ) {
            warnings.push(format!("could not preserve ownership: {error}"));
        }
    }
    (!warnings.is_empty()).then(|| warnings.join("; "))
}

fn merge_warnings(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(format!("{left}; {right}")),
        (Some(warning), None) | (None, Some(warning)) => Some(warning),
        (None, None) => None,
    }
}

fn special_bits_warning(entry: &ManifestEntry) -> Option<String> {
    (entry.mode & 0o7000 != 0)
        .then(|| "special permission bits were intentionally cleared".to_owned())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, symlink},
        process::Command,
    };

    use tempfile::tempdir;

    use crate::manifest::{Fingerprint, Timestamp};

    use super::*;

    fn entry(path: &str, kind: EntryKind, mode: u32) -> ManifestEntry {
        let path = RelativePath::new(path.as_bytes().to_vec()).unwrap();
        let timestamp = Timestamp {
            seconds: 1_700_000_000,
            nanos: 123,
        };
        ManifestEntry {
            path,
            kind,
            mtime: timestamp,
            mode,
            uid: 0,
            gid: 0,
            owner_name: None,
            group_name: None,
            size: 0,
            symlink_target: Vec::new(),
            scan_error: None,
            fingerprint: Fingerprint {
                device: 0,
                inode: 0,
                kind,
                size: 0,
                mtime: timestamp,
            },
        }
    }

    #[test]
    fn atomic_file_has_final_content_mode_and_no_temp() {
        let root = tempdir().unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let mut file = entry("file", EntryKind::File, 0o6755);
        file.size = 4;
        let warning = receiver.write_file_atomic(&file, None, b"data").unwrap();
        assert_eq!(fs::read(root.path().join("file")).unwrap(), b"data");
        assert_eq!(
            fs::metadata(root.path().join("file")).unwrap().mode() & 0o7777,
            0o755
        );
        assert!(warning.is_some());
        assert!(!fs::read_dir(root.path()).unwrap().any(|item| {
            item.unwrap()
                .file_name()
                .as_bytes()
                .starts_with(TEMP_PREFIX)
        }));
    }

    #[test]
    fn partial_write_failure_removes_the_mutated_temporary() {
        let root = tempdir().unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let mut file = entry("partial", EntryKind::File, 0o644);
        file.size = 8;
        file.fingerprint.size = 8;
        let error = receiver
            .write_file_atomic_with(&file, None, OwnershipPolicy::default(), |temporary| {
                temporary
                    .write_all(b"some")
                    .map_err(|error| Error::io(None, error))?;
                Err::<(), _>(Error::entry("injected", None, "write failed"))
            })
            .unwrap_err();
        assert!(matches!(error, Error::Entry { class, .. } if class == "injected"));
        assert!(!root.path().join("partial").exists());
        assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .as_bytes()
                .starts_with(TEMP_PREFIX)
        }));
    }

    #[test]
    fn symlink_ancestor_cannot_escape_root() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        symlink(outside.path(), root.path().join("escape")).unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let file = entry("escape/file", EntryKind::File, 0o644);
        assert!(receiver.write_file_atomic(&file, None, b"bad").is_err());
        assert!(!outside.path().join("file").exists());
    }

    #[test]
    fn destination_race_is_rejected() {
        let root = tempdir().unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        fs::write(root.path().join("file"), b"surprise").unwrap();
        let file = entry("file", EntryKind::File, 0o644);
        assert!(receiver.write_file_atomic(&file, None, b"new").is_err());
        assert_eq!(fs::read(root.path().join("file")).unwrap(), b"surprise");
    }

    #[test]
    fn destination_swap_between_validation_and_rename_is_rolled_back() {
        let root = tempdir().unwrap();
        let path = root.path().join("race-file");
        let saved = root.path().join("saved");
        fs::write(&path, b"old").unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let expected = receiver
            .current_fingerprint(&RelativePath::new(b"race-file".to_vec()).unwrap())
            .unwrap();
        let mut file = entry("race-file", EntryKind::File, 0o644);
        file.size = 3;
        let hook_path = path.clone();
        COMMIT_HOOK.lock().unwrap().replace((
            RelativePath::new(b"race-file".to_vec()).unwrap(),
            Box::new(move || {
                fs::rename(&hook_path, &saved).unwrap();
                fs::write(&hook_path, b"attacker").unwrap();
            }),
        ));
        assert!(
            receiver
                .write_file_atomic(&file, Some(expected), b"new")
                .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), b"attacker");
        assert!(!fs::read_dir(root.path()).unwrap().any(|item| {
            item.unwrap()
                .file_name()
                .as_bytes()
                .starts_with(TEMP_PREFIX)
        }));
    }

    #[test]
    fn post_exchange_writer_is_never_unlinked_and_displaced_data_is_recovered() {
        let root = tempdir().unwrap();
        let destination = root.path().join("post-race");
        let attacker = root.path().join("attacker");
        let installed_temp = root.path().join("installed-xsync-temp");
        fs::write(&destination, b"original").unwrap();
        fs::write(&attacker, b"concurrent-writer").unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let relative = RelativePath::new(b"post-race".to_vec()).unwrap();
        let expected = receiver.current_fingerprint(&relative).unwrap();
        let mut replacement = entry("post-race", EntryKind::File, 0o644);
        replacement.size = 7;
        replacement.fingerprint.size = 7;
        let hook_destination = destination.clone();
        POST_EXCHANGE_HOOK.lock().unwrap().replace((
            relative,
            Box::new(move || {
                fs::rename(&hook_destination, installed_temp).unwrap();
                fs::rename(attacker, hook_destination).unwrap();
            }),
        ));
        assert!(
            receiver
                .write_file_atomic(&replacement, Some(expected), b"newdata")
                .is_err()
        );
        assert_eq!(fs::read(&destination).unwrap(), b"concurrent-writer");
        let recovery = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| entry.file_name().as_bytes().starts_with(RECOVERY_PREFIX))
            .expect("displaced destination recovery file");
        assert_eq!(fs::read(recovery.path()).unwrap(), b"original");
        assert_eq!(
            fs::read(root.path().join("installed-xsync-temp")).unwrap(),
            b"newdata"
        );
    }

    #[test]
    fn crash_after_exchange_keeps_displaced_data_recovery_visible() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("crash-race"), b"original").unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "filesystem::tests::crash_after_exchange_helper",
                "--nocapture",
            ])
            .env("XSYNC_CRASH_TEST_ROOT", root.path())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(99));
        assert_eq!(
            fs::read(root.path().join("crash-race")).unwrap(),
            b"newdata"
        );
        let recoveries: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_name().as_bytes().starts_with(RECOVERY_PREFIX))
            .collect();
        assert!(
            recoveries
                .iter()
                .any(|entry| fs::read(entry.path()).unwrap() == b"concurrent-writer")
        );
        assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .as_bytes()
                .starts_with(TEMP_PREFIX)
        }));
    }

    #[test]
    fn crash_after_exchange_helper() {
        let Some(root) = std::env::var_os("XSYNC_CRASH_TEST_ROOT").map(PathBuf::from) else {
            return;
        };
        let destination = root.join("crash-race");
        let saved = root.join("expected-saved");
        let attacker = root.join("attacker");
        fs::write(&attacker, b"concurrent-writer").unwrap();
        let receiver = RootDir::open(&root).unwrap();
        let relative = RelativePath::new(b"crash-race".to_vec()).unwrap();
        let expected = receiver.current_fingerprint(&relative).unwrap();
        COMMIT_HOOK.lock().unwrap().replace((
            relative.clone(),
            Box::new(move || {
                fs::rename(&destination, saved).unwrap();
                fs::rename(attacker, destination).unwrap();
            }),
        ));
        POST_EXCHANGE_HOOK
            .lock()
            .unwrap()
            .replace((relative, Box::new(|| std::process::exit(99))));
        let mut replacement = entry("crash-race", EntryKind::File, 0o644);
        replacement.size = 7;
        replacement.fingerprint.size = 7;
        let _ = receiver.write_file_atomic(&replacement, Some(expected), b"newdata");
        panic!("post-exchange crash hook did not terminate the subprocess");
    }

    #[test]
    fn root_lock_is_bound_to_the_open_capability() {
        let root = tempdir().unwrap();
        let _first = RootDir::open(root.path()).unwrap();
        assert!(RootDir::open(root.path()).is_err());
    }

    #[test]
    fn directory_replacement_during_creation_is_rejected() {
        let root = tempdir().unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let path = root.path().join("race-directory");
        let moved = root.path().join("created-directory");
        let hook_path = path.clone();
        CREATION_HOOK.lock().unwrap().replace((
            path.clone(),
            Box::new(move || {
                fs::rename(&hook_path, moved).unwrap();
                fs::create_dir(&hook_path).unwrap();
            }),
        ));
        let directory = entry("race-directory", EntryKind::Directory, 0o755);
        assert!(receiver.create_directory(&directory, None).is_err());
        assert!(path.is_dir());
    }

    #[test]
    fn inventoried_ancestor_replacement_blocks_child_creation() {
        let root = tempdir().unwrap();
        let ancestor = root.path().join("ancestor");
        let saved = root.path().join("saved-ancestor");
        fs::create_dir(&ancestor).unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        receiver
            .scan(
                &crate::exclude::Excludes::default(),
                crate::protocol::Limits::default(),
            )
            .unwrap();
        fs::rename(&ancestor, saved).unwrap();
        fs::create_dir(&ancestor).unwrap();
        let child = entry("ancestor/child", EntryKind::File, 0o644);
        let error = receiver
            .write_file_atomic(&child, None, b"blocked")
            .unwrap_err();
        assert!(error.to_string().contains("ancestor changed"));
        assert!(!ancestor.join("child").exists());
    }

    #[test]
    fn new_directories_are_never_broader_than_mode_0700() {
        let root = tempdir().unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let directory = entry("private-directory", EntryKind::Directory, 0o755);
        receiver.create_directory(&directory, None).unwrap();
        assert_eq!(
            fs::metadata(root.path().join("private-directory"))
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn post_scan_directory_identity_growth_obeys_the_retained_budget() {
        let root = tempdir().unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let excludes = crate::exclude::Excludes::default();
        let limits = crate::protocol::Limits::default();
        let manifest = receiver.scan(&excludes, limits).unwrap();
        let retained = manifest
            .estimated_memory_bytes()
            .saturating_add(receiver.directory_identity_memory_bytes().unwrap());
        // Leave only the scanner's transient frame allowance beyond retained
        // state; a maximum-length new name cannot fit in the identity map.
        receiver
            .scan_with_budget(&excludes, limits, retained.saturating_add(256))
            .unwrap();

        let long_name = "x".repeat(255);
        let directory = entry(&long_name, EntryKind::Directory, 0o755);
        let error = receiver.create_directory(&directory, None).unwrap_err();
        assert!(matches!(error, Error::Entry { class, .. } if class == "limit"));
        assert!(!root.path().join(long_name).exists());
    }

    #[test]
    fn negative_fractional_mtime_is_normalized() {
        let root = tempdir().unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let mut file = entry("file", EntryKind::File, 0o644);
        file.mtime = Timestamp {
            seconds: -1,
            nanos: 500_000_000,
        };
        file.fingerprint.mtime = file.mtime;
        receiver.write_file_atomic(&file, None, b"").unwrap();
        let metadata = fs::metadata(root.path().join("file")).unwrap();
        assert_eq!((metadata.mtime(), metadata.mtime_nsec()), (-1, 500_000_000));
    }

    #[test]
    fn source_swap_during_open_is_caught_by_descriptor_validation() {
        let root = tempdir().unwrap();
        let path = root.path().join("source-race");
        let saved = root.path().join("source-saved");
        let attacker = root.path().join("source-attacker");
        fs::write(&path, b"good").unwrap();
        fs::write(&attacker, b"evil").unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let manifest = receiver
            .scan(
                &crate::exclude::Excludes::default(),
                crate::protocol::Limits::default(),
            )
            .unwrap();
        let relative = RelativePath::new(b"source-race".to_vec()).unwrap();
        let entry = manifest.get(&relative).unwrap().clone();
        let before_path = path.clone();
        let before_saved = saved.clone();
        let before_attacker = attacker.clone();
        OPEN_HOOKS.lock().unwrap().push((
            "source",
            "before",
            relative.clone(),
            Box::new(move || {
                fs::rename(before_path, before_saved).unwrap();
                fs::rename(before_attacker, path).unwrap();
            }),
        ));
        let after_path = root.path().join("source-race");
        let after_attacker = root.path().join("source-attacker");
        OPEN_HOOKS.lock().unwrap().push((
            "source",
            "after",
            relative,
            Box::new(move || {
                fs::rename(&after_path, after_attacker).unwrap();
                fs::rename(saved, after_path).unwrap();
            }),
        ));
        assert!(receiver.source_file(&entry).is_err());
        assert_eq!(fs::read(root.path().join("source-race")).unwrap(), b"good");
    }

    #[test]
    fn basis_swap_during_open_is_caught_by_descriptor_validation() {
        let root = tempdir().unwrap();
        let path = root.path().join("basis-race");
        let saved = root.path().join("basis-saved");
        let attacker = root.path().join("basis-attacker");
        fs::write(&path, b"good").unwrap();
        fs::write(&attacker, b"evil").unwrap();
        let receiver = RootDir::open(root.path()).unwrap();
        let relative = RelativePath::new(b"basis-race".to_vec()).unwrap();
        let expected = receiver.current_fingerprint(&relative).unwrap();
        let before_path = path.clone();
        let before_saved = saved.clone();
        let before_attacker = attacker.clone();
        OPEN_HOOKS.lock().unwrap().push((
            "basis",
            "before",
            relative.clone(),
            Box::new(move || {
                fs::rename(before_path, before_saved).unwrap();
                fs::rename(before_attacker, path).unwrap();
            }),
        ));
        let after_path = root.path().join("basis-race");
        let after_attacker = root.path().join("basis-attacker");
        OPEN_HOOKS.lock().unwrap().push((
            "basis",
            "after",
            relative.clone(),
            Box::new(move || {
                fs::rename(&after_path, after_attacker).unwrap();
                fs::rename(saved, after_path).unwrap();
            }),
        ));
        assert!(receiver.basis_reader(&relative, Some(expected)).is_err());
        assert_eq!(fs::read(root.path().join("basis-race")).unwrap(), b"good");
    }
}
