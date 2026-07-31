use globset::{GlobBuilder, GlobMatcher};

use crate::{Error, Result, path::RelativePath};

#[derive(Clone, Debug)]
struct Rule {
    matchers: Vec<GlobMatcher>,
    directory_only: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Excludes {
    rules: Vec<Rule>,
}

impl Excludes {
    pub fn compile(patterns: &[String]) -> Result<Self> {
        let mut rules = Vec::with_capacity(patterns.len());
        for original in patterns {
            if original.is_empty() {
                return Err(Error::Usage("exclude pattern cannot be empty".into()));
            }
            if original.starts_with('!') {
                return Err(Error::Usage(
                    "exclude negation ('!') is not supported in version 1".into(),
                ));
            }
            let directory_only = original.ends_with('/');
            let rooted = original.starts_with('/');
            let pattern = original
                .trim_start_matches('/')
                .trim_end_matches('/')
                .to_owned();
            if pattern.is_empty() {
                return Err(Error::Usage(
                    "exclude pattern cannot match the job root".into(),
                ));
            }
            let pattern = pattern.replace('{', "\\{").replace('}', "\\}");
            let variants = if rooted {
                vec![pattern]
            } else {
                vec![pattern.clone(), format!("**/{pattern}")]
            };
            let matchers = variants
                .iter()
                .map(|variant| {
                    GlobBuilder::new(variant)
                        .literal_separator(true)
                        .backslash_escape(true)
                        .build()
                        .map(|glob| glob.compile_matcher())
                        .map_err(|e| {
                            Error::Usage(format!("invalid exclude pattern {original:?}: {e}"))
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            rules.push(Rule {
                matchers,
                directory_only,
            });
        }
        Ok(Self { rules })
    }

    #[must_use]
    pub fn is_excluded(&self, path: &RelativePath, is_directory: bool) -> bool {
        if path.is_root() {
            return false;
        }
        self.rules.iter().any(|rule| {
            (!rule.directory_only || is_directory)
                && rule
                    .matchers
                    .iter()
                    .any(|matcher| matcher.is_match(path.to_path_buf()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(value: &str) -> RelativePath {
        RelativePath::new(value.as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn basename_pattern_matches_at_any_depth() {
        let excludes = Excludes::compile(&["target".into()]).unwrap();
        assert!(excludes.is_excluded(&p("target"), true));
        assert!(excludes.is_excluded(&p("a/target"), true));
        assert!(!excludes.is_excluded(&p("targets"), true));
    }

    #[test]
    fn rooted_and_directory_only_are_respected() {
        let excludes = Excludes::compile(&["/build/".into()]).unwrap();
        assert!(excludes.is_excluded(&p("build"), true));
        assert!(!excludes.is_excluded(&p("build"), false));
        assert!(!excludes.is_excluded(&p("a/build"), true));
    }

    #[test]
    fn unrooted_multi_component_pattern_matches_at_any_depth() {
        let excludes = Excludes::compile(&["foo/b?r[0-9]".into()]).unwrap();
        assert!(excludes.is_excluded(&p("foo/bar1"), false));
        assert!(excludes.is_excluded(&p("a/foo/bar2"), false));
        assert!(!excludes.is_excluded(&p("a/foo/baz"), false));
    }

    #[test]
    fn comma_and_braces_are_literal_while_wildcards_work() {
        let excludes = Excludes::compile(&[
            "foo,bar".into(),
            "literal{brace}".into(),
            "logs/**/x*.txt".into(),
        ])
        .unwrap();
        assert!(excludes.is_excluded(&p("a/foo,bar"), false));
        assert!(!excludes.is_excluded(&p("foo"), false));
        assert!(excludes.is_excluded(&p("literal{brace}"), false));
        assert!(excludes.is_excluded(&p("a/logs/old/x1.txt"), false));
    }
}
