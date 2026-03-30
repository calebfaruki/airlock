use base64::Engine;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ScrubEntry {
    pub name: String,
    pub env: Option<String>,
    pub file: Option<String>,
}

pub struct ScrubSet {
    replacements: Vec<(String, String)>,
}

impl ScrubSet {
    pub fn from_env() -> Self {
        let json = match std::env::var("AIRLOCK_SCRUB_SECRETS") {
            Ok(v) if !v.is_empty() => v,
            _ => {
                return Self {
                    replacements: vec![],
                }
            }
        };

        let entries: Vec<ScrubEntry> = match serde_json::from_str(&json) {
            Ok(e) => e,
            Err(_) => {
                return Self {
                    replacements: vec![],
                }
            }
        };

        let mut replacements = Vec::new();

        for entry in &entries {
            let value = if let Some(ref env_name) = entry.env {
                std::env::var(env_name).unwrap_or_default()
            } else if let Some(ref file_path) = entry.file {
                std::fs::read_to_string(file_path).unwrap_or_default()
            } else {
                continue;
            };

            let value = value.trim().to_string();
            if value.is_empty() {
                continue;
            }

            let tag = format!("[REDACTED:{}]", entry.name);

            replacements.push((value.clone(), tag.clone()));

            let b64 = base64::engine::general_purpose::STANDARD.encode(&value);
            if b64 != value {
                replacements.push((b64, tag.clone()));
            }

            let url = urlencoding::encode(&value).into_owned();
            if url != value {
                replacements.push((url, tag));
            }
        }

        replacements.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Self { replacements }
    }

    pub fn apply(&self, input: &str) -> String {
        let mut result = input.to_string();
        for (pattern, replacement) in &self.replacements {
            result = result.replace(pattern, replacement);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::io::Write;

    fn with_env<F: FnOnce()>(key: &str, val: &str, f: F) {
        std::env::set_var(key, val);
        f();
        std::env::remove_var(key);
    }

    fn with_scrub_env<F: FnOnce()>(json: &str, f: F) {
        with_env("AIRLOCK_SCRUB_SECRETS", json, f);
    }

    #[test]
    #[serial]
    fn empty_env_returns_empty_set() {
        std::env::remove_var("AIRLOCK_SCRUB_SECRETS");
        let set = ScrubSet::from_env();
        assert_eq!(set.apply("hello secret world"), "hello secret world");
    }

    #[test]
    #[serial]
    fn single_env_secret_redacted() {
        with_env("TEST_SECRET_1", "s3cret-value", || {
            with_scrub_env(r#"[{"name":"my-secret","env":"TEST_SECRET_1"}]"#, || {
                let set = ScrubSet::from_env();
                assert_eq!(
                    set.apply("output contains s3cret-value here"),
                    "output contains [REDACTED:my-secret] here"
                );
            });
        });
    }

    #[test]
    #[serial]
    fn single_file_secret_redacted() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "file-secret-val").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        with_scrub_env(
            &format!(r#"[{{"name":"file-cred","file":"{path}"}}]"#),
            || {
                let set = ScrubSet::from_env();
                assert_eq!(
                    set.apply("got file-secret-val from disk"),
                    "got [REDACTED:file-cred] from disk"
                );
            },
        );
    }

    #[test]
    #[serial]
    fn base64_encoded_value_redacted() {
        with_env("TEST_SECRET_B64", "my-api-key", || {
            with_scrub_env(r#"[{"name":"api-key","env":"TEST_SECRET_B64"}]"#, || {
                let set = ScrubSet::from_env();
                let b64 = base64::engine::general_purpose::STANDARD.encode("my-api-key");
                assert_eq!(
                    set.apply(&format!("encoded: {b64}")),
                    "encoded: [REDACTED:api-key]"
                );
            });
        });
    }

    #[test]
    #[serial]
    fn url_encoded_value_redacted() {
        with_env("TEST_SECRET_URL", "key=val&foo=bar", || {
            with_scrub_env(r#"[{"name":"url-cred","env":"TEST_SECRET_URL"}]"#, || {
                let set = ScrubSet::from_env();
                let encoded = urlencoding::encode("key=val&foo=bar");
                assert_eq!(
                    set.apply(&format!("url: {encoded}")),
                    "url: [REDACTED:url-cred]"
                );
            });
        });
    }

    #[test]
    #[serial]
    fn multiple_secrets_all_redacted() {
        with_env("TEST_SEC_A", "alpha", || {
            with_env("TEST_SEC_B", "bravo", || {
                with_scrub_env(
                    r#"[{"name":"a","env":"TEST_SEC_A"},{"name":"b","env":"TEST_SEC_B"}]"#,
                    || {
                        let set = ScrubSet::from_env();
                        assert_eq!(
                            set.apply("alpha and bravo"),
                            "[REDACTED:a] and [REDACTED:b]"
                        );
                    },
                );
            });
        });
    }

    #[test]
    #[serial]
    fn partial_match_not_redacted() {
        with_env("TEST_SECRET_FULL", "fullmatch", || {
            with_scrub_env(r#"[{"name":"full","env":"TEST_SECRET_FULL"}]"#, || {
                let set = ScrubSet::from_env();
                assert_eq!(set.apply("fullmatch"), "[REDACTED:full]");
                assert_eq!(set.apply("no match here"), "no match here");
            });
        });
    }

    #[test]
    #[serial]
    fn empty_secret_value_skipped() {
        with_env("TEST_EMPTY", "", || {
            with_scrub_env(r#"[{"name":"empty","env":"TEST_EMPTY"}]"#, || {
                let set = ScrubSet::from_env();
                assert!(set.replacements.is_empty());
            });
        });
    }

    #[test]
    #[serial]
    fn replacement_tag_contains_name() {
        with_env("TEST_TAG", "secret123", || {
            with_scrub_env(r#"[{"name":"cred-name","env":"TEST_TAG"}]"#, || {
                let set = ScrubSet::from_env();
                let result = set.apply("secret123");
                assert_eq!(result, "[REDACTED:cred-name]");
            });
        });
    }

    #[test]
    #[serial]
    fn longest_match_first() {
        with_env("TEST_SHORT", "abc", || {
            with_env("TEST_LONG", "abcdef", || {
                with_scrub_env(
                    r#"[{"name":"short","env":"TEST_SHORT"},{"name":"long","env":"TEST_LONG"}]"#,
                    || {
                        let set = ScrubSet::from_env();
                        assert_eq!(set.apply("abcdef"), "[REDACTED:long]");
                    },
                );
            });
        });
    }
}
