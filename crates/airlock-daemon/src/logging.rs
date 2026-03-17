use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize)]
pub struct LogEntry {
    pub ts: String,
    pub id: u64,
    pub event: String,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub struct AuditLogger {
    path: PathBuf,
    max_size_bytes: u64,
    max_files: u32,
    mutex: std::sync::Mutex<()>,
}

impl AuditLogger {
    pub fn new(path: PathBuf, max_size_mb: u64, max_files: u32) -> Self {
        Self {
            path,
            max_size_bytes: max_size_mb * 1024 * 1024,
            max_files,
            mutex: std::sync::Mutex::new(()),
        }
    }

    pub fn log(&self, entry: &LogEntry) {
        let _guard = match self.mutex.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        if self.needs_rotation() {
            self.rotate();
        }

        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("airlock: failed to serialize log entry: {e}");
                return;
            }
        };

        let result = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut file| writeln!(file, "{json}"));

        if let Err(e) = result {
            eprintln!("airlock: failed to write log: {e}");
        }
    }

    fn needs_rotation(&self) -> bool {
        if self.max_size_bytes == 0 {
            return false;
        }
        match std::fs::metadata(&self.path) {
            Ok(meta) => meta.len() >= self.max_size_bytes,
            Err(_) => false,
        }
    }

    fn rotate(&self) {
        // Shift existing rotated files: .log.N → .log.N+1
        for i in (1..self.max_files).rev() {
            let from = rotated_path(&self.path, i);
            let to = rotated_path(&self.path, i + 1);
            if from.exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }

        // Rotate current log: .log → .log.1
        let first_rotated = rotated_path(&self.path, 1);
        let _ = std::fs::rename(&self.path, &first_rotated);

        // Delete files beyond max_files
        let overflow = rotated_path(&self.path, self.max_files + 1);
        if overflow.exists() {
            let _ = std::fs::remove_file(&overflow);
        }
    }
}

fn rotated_path(base: &std::path::Path, n: u32) -> PathBuf {
    let mut name = base.as_os_str().to_owned();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

pub fn now_utc() -> String {
    // Manual UTC timestamp without chrono dependency
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since epoch to Y-M-D (simplified Gregorian)
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(days_since_epoch: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days_since_epoch + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_rotation() {
        let dir = std::env::temp_dir().join(format!("airlock-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let log_path = dir.join("airlock.log");
        // max_size_bytes = 0 means no rotation based on size, but we want to test rotation
        // Use a very small size: 1 byte (any write triggers rotation)
        let logger = AuditLogger {
            path: log_path.clone(),
            max_size_bytes: 1,
            max_files: 3,
            mutex: std::sync::Mutex::new(()),
        };

        let entry = LogEntry {
            ts: "2026-03-17T00:00:00Z".to_string(),
            id: 1,
            event: "exec".to_string(),
            command: "git".to_string(),
            args: vec!["status".to_string()],
            cwd: "/workspace".to_string(),
            exit_code: Some(0),
            duration_ms: 100,
            outcome: "allowed".to_string(),
            reason: None,
        };

        // Write 5 entries — should trigger rotations
        for _ in 0..5 {
            logger.log(&entry);
        }

        // Current log should exist
        assert!(log_path.exists());
        // Rotated files up to max_files should exist
        assert!(rotated_path(&log_path, 1).exists());
        assert!(rotated_path(&log_path, 2).exists());
        assert!(rotated_path(&log_path, 3).exists());
        // Beyond max_files should not exist
        assert!(!rotated_path(&log_path, 4).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn now_utc_format() {
        let ts = now_utc();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20); // "2026-03-17T14:32:01Z"
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }
}
