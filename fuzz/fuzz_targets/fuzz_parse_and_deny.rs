#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Split input: everything before first null byte is TOML, rest is args
        let (toml_part, args_part) = match s.find('\0') {
            Some(idx) => (&s[..idx], &s[idx + 1..]),
            None => (s, ""),
        };

        let module = match airlock_daemon::commands::CommandModule::parse(toml_part) {
            Ok(m) => m,
            Err(_) => return,
        };

        let args: Vec<String> = args_part
            .split('\0')
            .filter(|a| !a.is_empty())
            .map(|a| a.to_string())
            .collect();

        let _ = module.check_deny(&args);
    }
});
