use std::{
    ffi::{OsStr, OsString},
    fmt,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{Error, Result};

pub const MAX_RELATIVE_PATH_BYTES: usize = 8 * 1024;
pub const MAX_DEPTH: usize = 256;
pub const TEMP_PREFIX: &[u8] = b".xsync.tmp.";
pub const RECOVERY_PREFIX: &[u8] = b".xsync.recovery.";

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RelativePath(Vec<u8>);

impl Serialize for RelativePath {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelativePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ValidatedPathVisitor;

        impl<'de> de::Visitor<'de> for ValidatedPathVisitor {
            type Value = RelativePath;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a normalized, bounded relative Unix byte path")
            }

            fn visit_bytes<E: de::Error>(
                self,
                value: &[u8],
            ) -> std::result::Result<Self::Value, E> {
                RelativePath::new(value.to_vec()).map_err(E::custom)
            }

            fn visit_byte_buf<E: de::Error>(
                self,
                value: Vec<u8>,
            ) -> std::result::Result<Self::Value, E> {
                RelativePath::new(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(ValidatedPathVisitor)
    }
}

impl RelativePath {
    pub fn root() -> Self {
        Self(Vec::new())
    }

    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        validate_relative_bytes(&bytes)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            self.0.iter().filter(|&&b| b == b'/').count() + 1
        }
    }

    #[must_use]
    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(OsString::from_vec(self.0.clone()))
    }

    pub fn join_name(&self, name: &OsStr) -> Result<Self> {
        let raw = name.as_bytes();
        if raw.is_empty() || raw.contains(&b'/') || raw.contains(&0) {
            return Err(Error::Protocol("invalid path component".into()));
        }
        let mut bytes = self.0.clone();
        if !bytes.is_empty() {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(raw);
        Self::new(bytes)
    }

    #[must_use]
    pub fn starts_with(&self, parent: &Self) -> bool {
        parent.is_root()
            || self.0 == parent.0
            || (self.0.starts_with(&parent.0) && self.0.get(parent.0.len()).copied() == Some(b'/'))
    }

    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        let bytes = self
            .0
            .iter()
            .rposition(|&byte| byte == b'/')
            .map_or_else(Vec::new, |index| self.0[..index].to_vec());
        Some(Self(bytes))
    }

    #[must_use]
    pub fn display_lossy(&self) -> String {
        if self.0.is_empty() {
            return ".".to_owned();
        }
        let mut out = String::new();
        for &byte in &self.0 {
            match byte {
                b'\\' => out.push_str("\\\\"),
                0x20..=0x7e => out.push(char::from(byte)),
                _ => out.push_str(&format!("\\x{byte:02x}")),
            }
        }
        out
    }

    #[must_use]
    pub fn base64(&self) -> String {
        STANDARD.encode(&self.0)
    }
}

impl fmt::Debug for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelativePath")
            .field(&self.display_lossy())
            .finish()
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_lossy())
    }
}

pub fn validate_relative_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(Error::Protocol(format!(
            "relative path exceeds {MAX_RELATIVE_PATH_BYTES} bytes"
        )));
    }
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes[0] == b'/' || bytes.contains(&0) {
        return Err(Error::Protocol(
            "relative path is absolute or contains NUL".into(),
        ));
    }
    let mut depth = 0usize;
    for component in bytes.split(|&b| b == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(Error::Protocol("relative path is not normalized".into()));
        }
        depth += 1;
    }
    if depth > MAX_DEPTH {
        return Err(Error::Protocol(format!(
            "relative path exceeds maximum depth {MAX_DEPTH}"
        )));
    }
    Ok(())
}

pub fn lexical_absolute(path: &Path, cwd: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let mut result = PathBuf::from("/");
    for component in joined.components() {
        match component {
            Component::RootDir => result = PathBuf::from("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(part) => result.push(part),
            Component::Prefix(_) => {
                return Err(Error::Usage("Windows path prefixes are unsupported".into()));
            }
        }
    }
    Ok(result)
}

#[must_use]
pub fn paths_overlap(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}

#[must_use]
pub fn display_absolute(path: &Path) -> String {
    escape_bytes(path.as_os_str().as_bytes(), false)
}

#[must_use]
pub fn escape_bytes(bytes: &[u8], dot_for_empty: bool) -> String {
    if bytes.is_empty() && dot_for_empty {
        return ".".to_owned();
    }
    let mut out = String::new();
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_hostile_relative_paths() {
        for raw in [
            b"/abs".as_slice(),
            b"../up",
            b"a/../b",
            b"a//b",
            b"a/./b",
            b"a\0b",
        ] {
            assert!(RelativePath::new(raw.to_vec()).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn root_and_non_utf8_round_trip() {
        assert_eq!(RelativePath::root().display_lossy(), ".");
        let path = RelativePath::new(vec![b'a', b'/', 0xff]).unwrap();
        assert_eq!(path.to_path_buf().as_os_str().as_bytes(), b"a/\xff");
        assert_eq!(path.display_lossy(), "a/\\xff");
    }

    #[test]
    fn wire_deserialization_revalidates() {
        let mut encoded = Vec::new();
        ciborium::into_writer(
            &serde_bytes::ByteBuf::from(b"../escape".to_vec()),
            &mut encoded,
        )
        .unwrap();
        let decoded: std::result::Result<RelativePath, _> =
            ciborium::from_reader(encoded.as_slice());
        assert!(decoded.is_err());
    }

    #[test]
    fn wire_boundaries_and_non_utf8_round_trip() {
        let valid = RelativePath::new(vec![0xff, b'a']).unwrap();
        let mut encoded = Vec::new();
        ciborium::into_writer(&valid, &mut encoded).unwrap();
        let decoded: RelativePath = ciborium::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(decoded, valid);

        let invalid = [
            b"/absolute".to_vec(),
            b"a\0b".to_vec(),
            vec![b'a'; MAX_RELATIVE_PATH_BYTES + 1],
            (0..=MAX_DEPTH)
                .map(|_| "a")
                .collect::<Vec<_>>()
                .join("/")
                .into_bytes(),
        ];
        for raw in invalid {
            let mut encoded = Vec::new();
            ciborium::into_writer(&serde_bytes::ByteBuf::from(raw), &mut encoded).unwrap();
            let decoded: std::result::Result<RelativePath, _> =
                ciborium::from_reader(encoded.as_slice());
            assert!(decoded.is_err());
        }
        assert!(RelativePath::new(vec![b'a'; MAX_RELATIVE_PATH_BYTES]).is_ok());
    }

    #[test]
    fn absolute_display_escapes_terminal_controls() {
        let path = PathBuf::from(OsString::from_vec(b"/tmp/a\n\x1b\\\xff".to_vec()));
        assert_eq!(display_absolute(&path), "/tmp/a\\x0a\\x1b\\\\\\xff");
    }

    #[test]
    fn lexical_normalization_does_not_resolve_symlinks() {
        assert_eq!(
            lexical_absolute(Path::new("a/../b"), Path::new("/tmp/work")).unwrap(),
            Path::new("/tmp/work/b")
        );
    }
}
