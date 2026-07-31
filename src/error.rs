use std::{io, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Usage(String),
    #[error("I/O error{context}: {source}", context = display_context(.path.as_ref()))]
    Io {
        path: Option<PathBuf>,
        #[source]
        source: io::Error,
    },
    #[error("{class}{context}: {message}", context = display_context(.path.as_ref()))]
    Entry {
        class: String,
        path: Option<PathBuf>,
        message: String,
    },
    #[error("transport error: {0}")]
    Transport(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("one or more entries failed or conflicted")]
    Partial,
    #[error("operation interrupted")]
    Interrupted,
}

fn display_context(path: Option<&PathBuf>) -> String {
    path.map_or_else(String::new, |p| {
        format!(" at {}", crate::path::display_absolute(p))
    })
}

impl Error {
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Transport(_) | Self::Protocol(_) => 3,
            Self::Interrupted => 130,
            Self::Io { .. } | Self::Entry { .. } | Self::Partial => 1,
        }
    }

    #[must_use]
    pub fn io(path: impl Into<Option<PathBuf>>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    #[must_use]
    pub fn entry(
        class: impl Into<String>,
        path: impl Into<Option<PathBuf>>,
        message: impl Into<String>,
    ) -> Self {
        Self::Entry {
            class: class.into(),
            path: path.into(),
            message: message.into(),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
