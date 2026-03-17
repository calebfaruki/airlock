use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize)]
pub struct Request {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: &'static str,
    pub params: ExecParams,
}

#[derive(Serialize)]
pub struct ExecParams {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub container_id: Option<String>,
}

#[derive(Deserialize)]
pub struct Response {
    #[serde(rename = "id")]
    pub _id: Option<u64>,
    pub method: Option<String>,
    pub result: Option<ExecResult>,
    pub error: Option<RpcError>,
    pub params: Option<OutputParams>,
}

#[derive(Deserialize)]
pub struct ExecResult {
    pub exit_code: i32,
}

#[derive(Deserialize)]
pub struct RpcError {
    pub message: String,
}

#[derive(Deserialize)]
pub struct OutputParams {
    pub stream: String,
    pub data: String,
}

#[derive(Debug, PartialEq)]
pub enum OutputTarget {
    Stdout(String),
    Stderr(String),
    Ignored,
}

pub fn dispatch_output(stream: &str, data: &str) -> OutputTarget {
    match stream {
        "stdout" => OutputTarget::Stdout(data.to_string()),
        "stderr" => OutputTarget::Stderr(data.to_string()),
        _ => OutputTarget::Ignored,
    }
}

pub fn command_from_argv0(argv0: &str) -> Option<String> {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("airlock-shim");

    if name == "airlock-shim" {
        None
    } else {
        Some(name.to_string())
    }
}

pub fn parse_container_id(content: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(pos) = line.find("/docker/containers/") {
            let after = &line[pos + "/docker/containers/".len()..];
            if after.len() >= 64 && after[..64].chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(after[..64].to_string());
            }
        }
    }
    None
}

pub fn build_request(
    command: String,
    args: Vec<String>,
    cwd: String,
    container_id: Option<String>,
) -> Request {
    Request {
        jsonrpc: "2.0",
        id: 1,
        method: "exec",
        params: ExecParams {
            command,
            args,
            cwd,
            container_id,
        },
    }
}

#[cfg(test)]
mod container_awareness {
    use super::*;

    #[test]
    fn command_name_derived_from_argv0() {
        assert_eq!(
            command_from_argv0("/usr/local/airlock/bin/git"),
            Some("git".to_string())
        );
        assert_eq!(command_from_argv0("git"), Some("git".to_string()));
        assert_eq!(
            command_from_argv0("/usr/local/airlock/bin/terraform"),
            Some("terraform".to_string())
        );
        assert_eq!(
            command_from_argv0("/usr/local/airlock/bin/airlock-shim"),
            None
        );
        assert_eq!(command_from_argv0("airlock-shim"), None);
    }

    #[test]
    fn container_id_extracted_from_mountinfo() {
        // Valid mountinfo with docker container lines
        let mountinfo = "\
678 655 254:1 /docker/containers/7a0144cee1256c539fab790199527b7051aff1b603ebcf7ed3fd436440ef3b3a/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw
679 655 254:1 /docker/containers/7a0144cee1256c539fab790199527b7051aff1b603ebcf7ed3fd436440ef3b3a/hostname /etc/hostname rw,relatime - ext4 /dev/vda1 rw";
        assert_eq!(
            parse_container_id(mountinfo),
            Some("7a0144cee1256c539fab790199527b7051aff1b603ebcf7ed3fd436440ef3b3a".to_string())
        );

        // Not in a container — no /docker/containers/ lines
        let host_mountinfo = "\
22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
23 1 0:22 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw";
        assert_eq!(parse_container_id(host_mountinfo), None);

        // Invalid: not 64 hex chars
        let short = "678 655 254:1 /docker/containers/7a0144cee125/resolv.conf /etc/resolv.conf rw";
        assert_eq!(parse_container_id(short), None);

        // Invalid: non-hex characters
        let non_hex = "678 655 254:1 /docker/containers/zz0144cee1256c539fab790199527b7051aff1b603ebcf7ed3fd436440ef3b3a/resolv.conf /etc/resolv.conf rw";
        assert_eq!(parse_container_id(non_hex), None);
    }
}

#[cfg(test)]
mod faithful_proxy {
    use super::*;

    #[test]
    fn stdout_and_stderr_route_to_correct_streams() {
        assert_eq!(
            dispatch_output("stdout", "hello\n"),
            OutputTarget::Stdout("hello\n".to_string())
        );
        assert_eq!(
            dispatch_output("stderr", "error\n"),
            OutputTarget::Stderr("error\n".to_string())
        );
        assert_eq!(dispatch_output("unknown", "data"), OutputTarget::Ignored);
    }
}
