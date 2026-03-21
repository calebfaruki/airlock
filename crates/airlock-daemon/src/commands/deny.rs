use globset::{Glob, GlobMatcher};

#[derive(Debug, PartialEq, Clone)]
pub enum ArgRole {
    Positional,
    Flag,
    MaybeValue,
}

#[derive(Debug, PartialEq)]
pub struct NormalizedArg {
    pub raw: String,
    pub flag: Option<String>,
    pub value: Option<String>,
    pub role: ArgRole,
}

#[derive(Debug, Clone)]
pub enum DenyRule {
    Arg(String),
    Sequence(Vec<DenyRule>),
    FlagValue {
        flag: String,
        pattern: String,
        matcher: GlobMatcher,
    },
}

fn is_glob_pattern(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

pub fn parse_deny_entry(entry: &str) -> Result<DenyRule, String> {
    parse_deny_entry_inner(entry, 0)
}

fn parse_deny_entry_inner(entry: &str, depth: u8) -> Result<DenyRule, String> {
    if depth == 0 && entry.contains(" & ") {
        let rules: Result<Vec<DenyRule>, String> = entry
            .split(" & ")
            .map(|e| parse_deny_entry_inner(e, depth + 1))
            .collect();
        Ok(DenyRule::Sequence(rules?))
    } else if entry.starts_with('-') && entry.contains('=') {
        let (flag, pattern) = entry.split_once('=').unwrap();
        let matcher = Glob::new(pattern)
            .map_err(|e| format!("invalid glob in deny entry '{}': {}", entry, e))?
            .compile_matcher();
        Ok(DenyRule::FlagValue {
            flag: flag.into(),
            pattern: pattern.into(),
            matcher,
        })
    } else {
        Ok(DenyRule::Arg(entry.into()))
    }
}

impl DenyRule {
    pub fn matches(&self, normalized: &[NormalizedArg]) -> Option<String> {
        match self {
            DenyRule::Arg(pattern) => {
                let pattern_is_flag = pattern.starts_with('-');
                for n in normalized {
                    if pattern_is_flag {
                        if n.raw == *pattern {
                            return Some(pattern.clone());
                        }
                        if let Some(ref flag) = n.flag {
                            if flag == pattern {
                                return Some(pattern.clone());
                            }
                        }
                    } else if n.role == ArgRole::Positional && n.raw == *pattern {
                        return Some(pattern.clone());
                    }
                }
                None
            }
            DenyRule::Sequence(rules) => {
                let all_match = rules.iter().all(|r| r.matches(normalized).is_some());
                if all_match {
                    let descriptions: Vec<String> = rules.iter().map(|r| r.entry_text()).collect();
                    Some(descriptions.join(" & "))
                } else {
                    None
                }
            }
            DenyRule::FlagValue {
                flag,
                pattern,
                matcher,
            } => {
                // Raw string fallback for post-`--` args (literal patterns only)
                if !is_glob_pattern(pattern) {
                    let raw_form = format!("{flag}={pattern}");
                    for n in normalized {
                        if n.raw == raw_form {
                            return Some(raw_form);
                        }
                    }
                }

                for (i, n) in normalized.iter().enumerate() {
                    if n.flag.as_deref() != Some(flag) {
                        continue;
                    }
                    if let Some(ref val) = n.value {
                        if matcher.is_match(val) {
                            return Some(format!("{flag}={pattern}"));
                        }
                    }
                    if n.value.is_none() {
                        if let Some(next) = normalized.get(i + 1) {
                            if next.raw != "--" && matcher.is_match(&next.raw) {
                                return Some(format!("{flag}={pattern}"));
                            }
                        }
                    }
                }
                None
            }
        }
    }

    fn entry_text(&self) -> String {
        match self {
            DenyRule::Arg(s) => s.clone(),
            DenyRule::FlagValue { flag, pattern, .. } => format!("{flag}={pattern}"),
            DenyRule::Sequence(rules) => rules
                .iter()
                .map(|r| r.entry_text())
                .collect::<Vec<_>>()
                .join(" & "),
        }
    }
}

pub fn normalize_args(args: &[String]) -> Vec<NormalizedArg> {
    let mut result = Vec::with_capacity(args.len());
    let mut options_ended = false;
    for arg in args {
        if arg == "--" {
            options_ended = true;
        }
        if options_ended {
            result.push(NormalizedArg {
                raw: arg.clone(),
                flag: None,
                value: None,
                role: ArgRole::Positional,
            });
        } else {
            result.push(normalize_one(arg));
        }
    }

    // Reclassify: non-flag args following a valueless flag become MaybeValue
    for i in 1..result.len() {
        if result[i].flag.is_none()
            && result[i].raw != "--"
            && result[i - 1].flag.is_some()
            && result[i - 1].value.is_none()
        {
            result[i].role = ArgRole::MaybeValue;
        }
    }

    result
}

fn normalize_one(arg: &str) -> NormalizedArg {
    if let Some(rest) = arg.strip_prefix("--") {
        if rest.is_empty() {
            return NormalizedArg {
                raw: arg.to_string(),
                flag: None,
                value: None,
                role: ArgRole::Positional,
            };
        }
        if let Some(eq_pos) = rest.find('=') {
            let flag = format!("--{}", &rest[..eq_pos]);
            let value = rest[eq_pos + 1..].to_string();
            NormalizedArg {
                raw: arg.to_string(),
                flag: Some(flag),
                value: Some(value),
                role: ArgRole::Flag,
            }
        } else {
            NormalizedArg {
                raw: arg.to_string(),
                flag: Some(arg.to_string()),
                value: None,
                role: ArgRole::Flag,
            }
        }
    } else if let Some(rest) = arg.strip_prefix('-') {
        if rest.is_empty() {
            return NormalizedArg {
                raw: arg.to_string(),
                flag: None,
                value: None,
                role: ArgRole::Positional,
            };
        }
        let mut chars = rest.chars();
        let flag_char = chars.next().unwrap();
        let remainder: String = chars.collect();
        let flag = format!("-{flag_char}");
        if remainder.is_empty() {
            NormalizedArg {
                raw: arg.to_string(),
                flag: Some(flag),
                value: None,
                role: ArgRole::Flag,
            }
        } else {
            NormalizedArg {
                raw: arg.to_string(),
                flag: Some(flag),
                value: Some(remainder),
                role: ArgRole::Flag,
            }
        }
    } else {
        NormalizedArg {
            raw: arg.to_string(),
            flag: None,
            value: None,
            role: ArgRole::Positional,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str) -> NormalizedArg {
        normalize_one(s)
    }

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- Normalization tests ---

    #[test]
    fn long_flag_with_equals() {
        assert_eq!(
            norm("--config=evil"),
            NormalizedArg {
                raw: "--config=evil".into(),
                flag: Some("--config".into()),
                value: Some("evil".into()),
                role: ArgRole::Flag,
            }
        );
    }

    #[test]
    fn long_flag_without_value() {
        assert_eq!(
            norm("--verbose"),
            NormalizedArg {
                raw: "--verbose".into(),
                flag: Some("--verbose".into()),
                value: None,
                role: ArgRole::Flag,
            }
        );
    }

    #[test]
    fn short_flag_alone() {
        assert_eq!(
            norm("-c"),
            NormalizedArg {
                raw: "-c".into(),
                flag: Some("-c".into()),
                value: None,
                role: ArgRole::Flag,
            }
        );
    }

    #[test]
    fn short_flag_with_attached_value() {
        assert_eq!(
            norm("-cevil"),
            NormalizedArg {
                raw: "-cevil".into(),
                flag: Some("-c".into()),
                value: Some("evil".into()),
                role: ArgRole::Flag,
            }
        );
    }

    #[test]
    fn double_dash_is_positional() {
        assert_eq!(
            norm("--"),
            NormalizedArg {
                raw: "--".into(),
                flag: None,
                value: None,
                role: ArgRole::Positional,
            }
        );
    }

    #[test]
    fn single_dash_is_positional() {
        assert_eq!(
            norm("-"),
            NormalizedArg {
                raw: "-".into(),
                flag: None,
                value: None,
                role: ArgRole::Positional,
            }
        );
    }

    #[test]
    fn positional_arg() {
        assert_eq!(
            norm("status"),
            NormalizedArg {
                raw: "status".into(),
                flag: None,
                value: None,
                role: ArgRole::Positional,
            }
        );
    }

    #[test]
    fn empty_string_is_positional() {
        assert_eq!(
            norm(""),
            NormalizedArg {
                raw: "".into(),
                flag: None,
                value: None,
                role: ArgRole::Positional,
            }
        );
    }

    #[test]
    fn long_flag_with_empty_value() {
        assert_eq!(
            norm("--config="),
            NormalizedArg {
                raw: "--config=".into(),
                flag: Some("--config".into()),
                value: Some("".into()),
                role: ArgRole::Flag,
            }
        );
    }

    #[test]
    fn long_flag_with_multiple_equals() {
        assert_eq!(
            norm("--config=key=value"),
            NormalizedArg {
                raw: "--config=key=value".into(),
                flag: Some("--config".into()),
                value: Some("key=value".into()),
                role: ArgRole::Flag,
            }
        );
    }

    #[test]
    fn normalize_preserves_order_and_count() {
        let a = args(&["push", "--force", "-v", "origin"]);
        let normalized = normalize_args(&a);
        assert_eq!(normalized.len(), a.len());
        let raws: Vec<&str> = normalized.iter().map(|n| n.raw.as_str()).collect();
        assert_eq!(raws, vec!["push", "--force", "-v", "origin"]);
    }

    #[test]
    fn unicode_arg_does_not_panic() {
        let n = norm("--émoji=🎉");
        assert_eq!(n.flag, Some("--émoji".into()));
        assert_eq!(n.value, Some("🎉".into()));
        assert_eq!(n.role, ArgRole::Flag);
    }

    fn flag_value(flag: &str, pattern: &str) -> DenyRule {
        parse_deny_entry(&format!("{flag}={pattern}")).unwrap()
    }

    // --- End-of-options (--) tests ---

    #[test]
    fn args_after_double_dash_are_positional() {
        let normalized = normalize_args(&args(&["checkout", "--", "--config=evil"]));
        assert_eq!(normalized[2].flag, None);
        assert_eq!(normalized[2].value, None);
        assert_eq!(normalized[2].raw, "--config=evil");
    }

    // --- parse_deny_entry tests ---

    #[test]
    fn parse_entry_plain_arg() {
        match parse_deny_entry("destroy").unwrap() {
            DenyRule::Arg(s) => assert_eq!(s, "destroy"),
            other => panic!("expected Arg, got {:?}", other),
        }
    }

    #[test]
    fn parse_entry_flag_value_long() {
        match parse_deny_entry("--pid=host").unwrap() {
            DenyRule::FlagValue { flag, pattern, .. } => {
                assert_eq!(flag, "--pid");
                assert_eq!(pattern, "host");
            }
            other => panic!("expected FlagValue, got {:?}", other),
        }
    }

    #[test]
    fn parse_entry_flag_value_short() {
        match parse_deny_entry("-v=/*:*").unwrap() {
            DenyRule::FlagValue { flag, pattern, .. } => {
                assert_eq!(flag, "-v");
                assert_eq!(pattern, "/*:*");
            }
            other => panic!("expected FlagValue, got {:?}", other),
        }
    }

    #[test]
    fn parse_entry_sequence() {
        match parse_deny_entry("apply & -auto-approve").unwrap() {
            DenyRule::Sequence(rules) => {
                assert_eq!(rules.len(), 2);
                assert!(matches!(&rules[0], DenyRule::Arg(s) if s == "apply"));
                assert!(matches!(&rules[1], DenyRule::Arg(s) if s == "-auto-approve"));
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn parse_entry_positional_with_equals() {
        match parse_deny_entry("not-a-flag=value").unwrap() {
            DenyRule::Arg(s) => assert_eq!(s, "not-a-flag=value"),
            other => panic!("expected Arg, got {:?}", other),
        }
    }

    #[test]
    fn parse_entry_sequence_with_flag_value() {
        match parse_deny_entry("run & -v=/*:*").unwrap() {
            DenyRule::Sequence(rules) => {
                assert_eq!(rules.len(), 2);
                assert!(matches!(&rules[0], DenyRule::Arg(s) if s == "run"));
                assert!(
                    matches!(&rules[1], DenyRule::FlagValue { flag, pattern, .. }
                    if flag == "-v" && pattern == "/*:*")
                );
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn parse_entry_sequence_depth_capped() {
        // Nested " & " inside a sequence element is treated as literal
        match parse_deny_entry("a & b & c").unwrap() {
            DenyRule::Sequence(rules) => {
                assert_eq!(rules.len(), 3);
                assert!(matches!(&rules[0], DenyRule::Arg(s) if s == "a"));
                assert!(matches!(&rules[1], DenyRule::Arg(s) if s == "b"));
                assert!(matches!(&rules[2], DenyRule::Arg(s) if s == "c"));
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn parse_entry_invalid_glob() {
        assert!(parse_deny_entry("-v=/*[:*").is_err());
    }

    #[test]
    fn invalid_glob_in_module_fails_parse() {
        let toml_str = r#"
[command]
bin = "docker"

[deny]
args = ["-v=/*[:*"]
"#;
        assert!(crate::commands::CommandModule::parse(toml_str).is_err());
    }

    // --- Arg rule tests ---

    #[test]
    fn arg_rule_exact_raw_match() {
        let rule = DenyRule::Arg("destroy".into());
        let normalized = normalize_args(&args(&["apply", "destroy"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn arg_rule_no_match() {
        let rule = DenyRule::Arg("destroy".into());
        let normalized = normalize_args(&args(&["apply", "plan"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn arg_rule_matches_normalized_long_flag() {
        let rule = DenyRule::Arg("--config".into());
        let normalized = normalize_args(&args(&["--config=evil", "status"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn arg_rule_matches_normalized_short_flag() {
        let rule = DenyRule::Arg("-c".into());
        let normalized = normalize_args(&args(&["-cevil", "status"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn arg_rule_does_not_match_unrelated_flag() {
        let rule = DenyRule::Arg("--config".into());
        let normalized = normalize_args(&args(&["--other=val"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn raw_deny_still_applies_after_double_dash() {
        let rule = DenyRule::Arg("--privileged".into());
        let normalized = normalize_args(&args(&["--", "run", "--privileged", "alpine"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn raw_deny_after_double_dash_no_false_positive() {
        let rule = DenyRule::Arg("--pid=host".into());
        let normalized = normalize_args(&args(&["--", "--pid=host"]));
        assert!(rule.matches(&normalized).is_some());

        let rule2 = DenyRule::Arg("--pid=evil".into());
        assert!(rule2.matches(&normalized).is_none());
    }

    // --- Sequence rule tests ---

    #[test]
    fn sequence_all_present() {
        let rule = parse_deny_entry("apply & -auto-approve").unwrap();
        let normalized = normalize_args(&args(&["apply", "-auto-approve"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn sequence_one_missing() {
        let rule = parse_deny_entry("apply & -auto-approve").unwrap();
        let normalized = normalize_args(&args(&["apply"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn sequence_order_independent() {
        let rule = parse_deny_entry("apply & -auto-approve").unwrap();
        let normalized = normalize_args(&args(&["-auto-approve", "apply"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn sequence_with_extra_args() {
        let rule = parse_deny_entry("apply & -auto-approve").unwrap();
        let normalized = normalize_args(&args(&["plan", "apply", "-auto-approve", "-input=false"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn sequence_with_flag_value_element() {
        let rule = parse_deny_entry("run & -v=/*:*").unwrap();
        let normalized = normalize_args(&args(&["run", "-v", "/:/host"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn sequence_with_flag_value_no_match() {
        let rule = parse_deny_entry("run & -v=/*:*").unwrap();
        let normalized = normalize_args(&args(&["run", "-v", "mydata:/data"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn sequence_with_flag_value_missing_positional() {
        let rule = parse_deny_entry("run & -v=/*:*").unwrap();
        let normalized = normalize_args(&args(&["-v", "/:/host"]));
        assert!(rule.matches(&normalized).is_none());
    }

    // --- FlagValue rule tests ---

    #[test]
    fn flag_value_attached_short() {
        let rule = flag_value("-v", "/*:*");
        let normalized = normalize_args(&args(&["run", "-v/:/host", "alpine"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn flag_value_detached() {
        let rule = flag_value("-v", "/*:*");
        let normalized = normalize_args(&args(&["run", "-v", "/:/host", "alpine"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn flag_value_long_with_equals() {
        let rule = flag_value("--volume", "/*:*");
        let normalized = normalize_args(&args(&["run", "--volume=/etc:/mnt", "alpine"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn flag_value_pattern_no_match() {
        let rule = flag_value("-v", "/*:*");
        let normalized = normalize_args(&args(&["run", "-v", "mydata:/data", "alpine"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn flag_value_no_value_present() {
        let rule = flag_value("-v", "/*:*");
        let normalized = normalize_args(&args(&["run", "-v"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn flag_value_wrong_flag() {
        let rule = flag_value("-v", "/*:*");
        let normalized = normalize_args(&args(&["run", "-p", "/:/host"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn flag_value_raw_fallback_after_double_dash() {
        let rule = flag_value("--pid", "host");
        let normalized = normalize_args(&args(&["--", "run", "--pid=host", "alpine"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn flag_value_raw_fallback_no_false_positive() {
        let rule = flag_value("--pid", "evil");
        let normalized = normalize_args(&args(&["--", "run", "--pid=host", "alpine"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn flag_value_lookahead_stops_at_double_dash() {
        let rule = flag_value("-v", "/*:*");
        let normalized = normalize_args(&args(&["-v", "--", "/:/host"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn flag_value_lookahead_does_not_match_double_dash() {
        let rule = flag_value("-v", "*");
        let normalized = normalize_args(&args(&["-v", "--", "/:/host"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn flag_value_glob_skips_raw_fallback() {
        // Glob patterns should NOT match via raw fallback after --
        let rule = flag_value("-v", "/*:*");
        let normalized = normalize_args(&args(&["--", "-v=/*:*"]));
        assert!(rule.matches(&normalized).is_none());
    }

    // --- matches() return value tests ---

    #[test]
    fn arg_match_returns_entry_text() {
        let rule = DenyRule::Arg("--privileged".into());
        let normalized = normalize_args(&args(&["--privileged"]));
        assert_eq!(rule.matches(&normalized).unwrap(), "--privileged");
    }

    #[test]
    fn flag_value_match_returns_entry_text() {
        let rule = flag_value("--pid", "host");
        let normalized = normalize_args(&args(&["--pid=host"]));
        assert_eq!(rule.matches(&normalized).unwrap(), "--pid=host");
    }

    #[test]
    fn sequence_match_returns_entry_text() {
        let rule = parse_deny_entry("apply & -auto-approve").unwrap();
        let normalized = normalize_args(&args(&["apply", "-auto-approve"]));
        assert_eq!(rule.matches(&normalized).unwrap(), "apply & -auto-approve");
    }

    // --- DenySection deserialization tests ---

    #[test]
    fn deserialize_args_only() {
        use crate::commands::module::DenySection;
        let toml_str = r#"args = ["--config", "-c"]"#;
        let deny: DenySection =
            toml::from_str(toml_str).expect("should parse args-only deny section");
        assert_eq!(deny.args, vec!["--config", "-c"]);
    }

    // --- Property-based tests ---

    use proptest::prelude::*;

    fn arb_arg() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z]{1,8}",
            "--[a-z]{1,8}",
            "--[a-z]{1,8}=[a-z0-9/:.]{1,12}",
            "-[a-z]",
            "-[a-z][a-z0-9/:.]{1,8}",
        ]
    }

    proptest! {
        #[test]
        fn normalization_is_lossless(args in prop::collection::vec(arb_arg(), 0..20)) {
            let normalized = normalize_args(&args);
            let raws: Vec<&str> = normalized.iter().map(|n| n.raw.as_str()).collect();
            let originals: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            prop_assert_eq!(raws, originals);
        }

        #[test]
        fn arg_rule_split_joined_equivalence(flag in "--[a-z]{1,8}", value in "[a-z0-9]{1,8}") {
            let rule = DenyRule::Arg(flag.clone());
            let joined = vec![format!("{flag}={value}")];
            let split = vec![flag.clone(), value];
            let norm_joined = normalize_args(&joined);
            let norm_split = normalize_args(&split);
            prop_assert_eq!(
                rule.matches(&norm_joined).is_some(),
                rule.matches(&norm_split).is_some(),
                "split and joined forms should produce identical Arg match results"
            );
        }

        #[test]
        fn no_flags_after_double_dash(
            before in prop::collection::vec(arb_arg(), 0..5),
            after in prop::collection::vec(arb_arg(), 1..5),
        ) {
            let mut all = before;
            all.push("--".to_string());
            all.extend(after);
            let normalized = normalize_args(&all);
            let dd_pos = normalized.iter().position(|n| n.raw == "--").unwrap();
            for n in &normalized[dd_pos + 1..] {
                prop_assert_eq!(&n.flag, &None, "args after -- should have no flag");
                prop_assert_eq!(&n.role, &ArgRole::Positional, "args after -- should be Positional");
            }
        }

        #[test]
        fn maybe_value_only_after_valueless_flag(args in prop::collection::vec(arb_arg(), 1..20)) {
            let normalized = normalize_args(&args);
            for (i, n) in normalized.iter().enumerate() {
                if n.role == ArgRole::MaybeValue {
                    prop_assert!(i > 0, "MaybeValue cannot be first arg");
                    let prev = &normalized[i - 1];
                    prop_assert!(prev.flag.is_some(), "MaybeValue must follow a flag");
                    prop_assert!(prev.value.is_none(), "MaybeValue must follow a valueless flag");
                }
            }
        }

        #[test]
        fn parse_entry_classification(entry in "[a-z\\-=&/ ]{1,20}") {
            let rule = parse_deny_entry(&entry);
            if entry.contains(" & ") {
                // Sequence elements with invalid globs produce Err
                if let Ok(r) = &rule {
                    prop_assert!(matches!(r, DenyRule::Sequence(_)),
                        "entry with ' & ' should be Sequence");
                }
            } else if entry.starts_with('-') && entry.contains('=') {
                // All patterns without glob chars are valid
                let r = rule.unwrap();
                let is_fv = matches!(r, DenyRule::FlagValue { .. });
                prop_assert!(is_fv, "entry starting with - containing = should be FlagValue");
            } else {
                let r = rule.unwrap();
                prop_assert!(matches!(r, DenyRule::Arg(_)),
                    "other entries should be Arg");
            }
        }
    }

    // --- Role classification tests ---

    #[test]
    fn role_leading_positionals() {
        let normalized = normalize_args(&args(&["s3", "ls", "--recursive"]));
        assert_eq!(normalized[0].role, ArgRole::Positional);
        assert_eq!(normalized[1].role, ArgRole::Positional);
        assert_eq!(normalized[2].role, ArgRole::Flag);
    }

    #[test]
    fn role_flag_value_after_valueless_flag() {
        let normalized = normalize_args(&args(&["--output", "s3", "iam"]));
        assert_eq!(normalized[0].role, ArgRole::Flag);
        assert_eq!(normalized[1].role, ArgRole::MaybeValue);
        assert_eq!(normalized[2].role, ArgRole::Positional);
    }

    #[test]
    fn role_attached_value_does_not_consume_next() {
        let normalized = normalize_args(&args(&["--output=json", "s3", "ls"]));
        assert_eq!(normalized[0].role, ArgRole::Flag);
        assert_eq!(normalized[1].role, ArgRole::Positional);
        assert_eq!(normalized[2].role, ArgRole::Positional);
    }

    #[test]
    fn role_short_flag_no_attached_value() {
        let normalized = normalize_args(&args(&["-o", "json", "s3"]));
        assert_eq!(normalized[0].role, ArgRole::Flag);
        assert_eq!(normalized[1].role, ArgRole::MaybeValue);
        assert_eq!(normalized[2].role, ArgRole::Positional);
    }

    #[test]
    fn role_short_flag_with_attached_value() {
        let normalized = normalize_args(&args(&["-ojson", "s3"]));
        assert_eq!(normalized[0].role, ArgRole::Flag);
        assert_eq!(normalized[1].role, ArgRole::Positional);
    }

    #[test]
    fn role_after_double_dash_all_positional() {
        let normalized = normalize_args(&args(&["cmd", "--", "--flag-looking", "value"]));
        assert_eq!(normalized[0].role, ArgRole::Positional);
        assert_eq!(normalized[1].role, ArgRole::Positional);
        assert_eq!(normalized[2].role, ArgRole::Positional);
        assert_eq!(normalized[3].role, ArgRole::Positional);
    }

    #[test]
    fn role_double_dash_not_consumed_as_value() {
        let normalized = normalize_args(&args(&["--output", "--", "positional"]));
        assert_eq!(normalized[0].role, ArgRole::Flag);
        assert_eq!(normalized[1].role, ArgRole::Positional);
        assert_eq!(normalized[2].role, ArgRole::Positional);
    }

    #[test]
    fn role_consecutive_flags() {
        let normalized = normalize_args(&args(&["--verbose", "--force", "target"]));
        assert_eq!(normalized[0].role, ArgRole::Flag);
        assert_eq!(normalized[1].role, ArgRole::Flag);
        assert_eq!(normalized[2].role, ArgRole::MaybeValue);
    }

    #[test]
    fn role_maybe_value_followed_by_positional() {
        let normalized = normalize_args(&args(&["-C", "/path", "push"]));
        assert_eq!(normalized[0].role, ArgRole::Flag);
        assert_eq!(normalized[1].role, ArgRole::MaybeValue);
        assert_eq!(normalized[2].role, ArgRole::Positional);
    }

    // --- Position-aware matching tests ---

    #[test]
    fn non_flag_pattern_skips_maybe_value() {
        let rule = DenyRule::Arg("s3".into());
        let normalized = normalize_args(&args(&["iam", "create-access-key", "--output", "s3"]));
        assert!(rule.matches(&normalized).is_none());
    }

    #[test]
    fn non_flag_pattern_matches_positional() {
        let rule = DenyRule::Arg("s3".into());
        let normalized = normalize_args(&args(&["s3", "ls", "--recursive"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn non_flag_pattern_matches_after_double_dash() {
        let rule = DenyRule::Arg("destroy".into());
        let normalized = normalize_args(&args(&["--", "destroy"]));
        assert!(rule.matches(&normalized).is_some());
    }

    #[test]
    fn sequence_positional_element_skips_maybe_value() {
        let rule = parse_deny_entry("destroy & --force").unwrap();
        let normalized = normalize_args(&args(&["plan", "--label", "destroy", "--force"]));
        assert!(rule.matches(&normalized).is_none());
    }

    // --- Built-in module integration tests ---

    #[test]
    fn builtin_git_deny_credential_still_works() {
        let module =
            crate::commands::CommandModule::parse(include_str!("builtins/git/module.toml"))
                .unwrap();
        assert!(module.check_deny(&args(&["credential", "fill"])).is_some());
        assert!(module.check_deny(&args(&["-cevil"])).is_some());
        assert!(module.check_deny(&args(&["--config=x"])).is_some());
        assert!(module.check_deny(&args(&["push"])).is_none());
    }

    #[test]
    fn builtin_terraform_deny_destroy_still_works() {
        let module =
            crate::commands::CommandModule::parse(include_str!("builtins/terraform/module.toml"))
                .unwrap();
        assert!(module.check_deny(&args(&["destroy"])).is_some());
        assert!(module
            .check_deny(&args(&["apply", "-auto-approve"]))
            .is_some());
        assert!(module.check_deny(&args(&["plan"])).is_none());
    }

    #[test]
    fn builtin_aws_deny_still_works() {
        let module =
            crate::commands::CommandModule::parse(include_str!("builtins/aws/module.toml"))
                .unwrap();
        assert!(module
            .check_deny(&args(&["ec2", "terminate-instances"]))
            .is_some());
        assert!(module.check_deny(&args(&["s3", "ls"])).is_none());
    }

    #[test]
    fn builtin_aws_false_positive_fixed() {
        let module =
            crate::commands::CommandModule::parse(include_str!("builtins/aws/module.toml"))
                .unwrap();
        assert!(module
            .check_deny(&args(&["s3", "ls", "--prefix", "delete-bucket"]))
            .is_none());
    }

    #[test]
    fn builtin_docker_deny_still_works() {
        let module =
            crate::commands::CommandModule::parse(include_str!("builtins/docker/module.toml"))
                .unwrap();
        assert!(module.check_deny(&args(&["run", "--privileged"])).is_some());
        assert!(module
            .check_deny(&args(&["run", "-v", "/:/host"]))
            .is_some());
        assert!(module.check_deny(&args(&["ps"])).is_none());
    }

    #[test]
    fn builtin_ssh_deny_still_works() {
        let module =
            crate::commands::CommandModule::parse(include_str!("builtins/ssh/module.toml"))
                .unwrap();
        assert!(module.check_deny(&args(&["-A", "host"])).is_some());
        assert!(module.check_deny(&args(&["host"])).is_none());
    }

    // --- Full module parse tests ---

    #[test]
    fn full_module_with_flat_deny_rules() {
        let toml_str = r#"
[command]
bin = "docker"

[deny]
args = ["--privileged", "-v=/*:*", "run & --net=host"]

[exec]
concurrent = true
"#;
        let module =
            crate::commands::CommandModule::parse(toml_str).expect("should parse full module");
        let deny = module.deny.as_ref().unwrap();
        assert_eq!(deny.args.len(), 3);
    }
}
