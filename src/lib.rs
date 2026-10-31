//! zzh: OpenSSH-backed, explicitly trusted remote access.
//!
//! This is a thin wrapper over upstream OpenSSH executables. It does not
//! implement SSH, a VPN, automatic pairing, or distributed scheduling.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const USAGE: &str = "zzh — secure access to trusted Nucleus nodes

USAGE
  zzh init
  zzh doctor
  zzh trust NAME USER@HOST SHA256:FINGERPRINT [--port PORT] [--identity FILE]
  zzh peers
  zzh connect NAME
  zzh remove NAME
  zzh help

SECURITY
  The fingerprint MUST be obtained from the remote machine through an
  independent trusted channel, not from ssh-keyscan itself.
  Authentication on the remote machine must already be configured.
";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Peer {
    target: String,
    port: u16,
    fingerprint: String,
    identity: Option<PathBuf>,
}

pub fn run(args: &[String]) -> Result<i32, String> {
    match args.first().map(String::as_str) {
        None | Some("help" | "--help" | "-h") => {
            println!("{USAGE}");
            Ok(0)
        }
        Some("--version" | "-V") => {
            println!("zzh {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Some("doctor") => {
            exact_args(args, 1)?;
            doctor()
        }
        Some("init") => {
            exact_args(args, 1)?;
            let root = initialize()?;
            println!("Initialized zzh at {}", root.display());
            println!("Existing OpenSSH keys and your SSH agent remain usable.");
            Ok(0)
        }
        Some("trust") => trust(&args[1..]),
        Some("peers") => {
            exact_args(args, 1)?;
            list_peers()
        }
        Some("connect") => {
            exact_args(args, 2)?;
            connect(&args[1])
        }
        Some("remove") => {
            exact_args(args, 2)?;
            remove(&args[1])
        }
        Some(other) => Err(format!("unknown command: {other}\n\n{USAGE}")),
    }
}

fn exact_args(args: &[String], expected: usize) -> Result<(), String> {
    if args.len() == expected {
        Ok(())
    } else {
        Err(format!("incorrect number of arguments\n\n{USAGE}"))
    }
}

fn config_root() -> Result<PathBuf, String> {
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            let path = PathBuf::from(xdg);
            if !path.is_absolute() {
                return Err("XDG_CONFIG_HOME must be an absolute path".into());
            }
            return Ok(path.join("zzh"));
        }
    }
    let home = env::var_os("HOME").ok_or("HOME must be set")?;
    Ok(PathBuf::from(home).join(".config").join("zzh"))
}

fn initialize() -> Result<PathBuf, String> {
    let root = config_root()?;
    for dir in [&root, &root.join("peers"), &root.join("hosts")] {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        #[cfg(unix)]
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("protect {}: {e}", dir.display()))?;
    }
    Ok(root)
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 48
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("peer name must be 1–48 ASCII letters, digits, - or _, starting with a letter or digit".into());
    }
    Ok(())
}

fn validate_target(target: &str) -> Result<&str, String> {
    let (user, host) = target.split_once('@')
        .ok_or("target must be USER@HOST (no SSH options or URLs)")?;
    if user.is_empty() || !user.as_bytes()[0].is_ascii_alphanumeric()
        || !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err("unsupported SSH user name".into());
    }
    if host.is_empty() || host.len() > 253
        || !host.as_bytes()[0].is_ascii_alphanumeric()
        || !host.as_bytes()[host.len() - 1].is_ascii_alphanumeric()
        || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err("use a DNS name or IPv4 address (IPv6 support is planned)".into());
    }
    Ok(host)
}

fn validate_fingerprint(fp: &str) -> Result<(), String> {
    let body = fp.strip_prefix("SHA256:").ok_or("expected a SHA256: host-key fingerprint")?;
    if body.len() != 43
        || !body.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
    {
        return Err("invalid SHA256 fingerprint; copy it from ssh-keygen -lf on the server".into());
    }
    Ok(())
}

fn trust(args: &[String]) -> Result<i32, String> {
    if args.len() < 3 {
        return Err(format!("trust requires NAME USER@HOST SHA256:FINGERPRINT\n\n{USAGE}"));
    }
    let name = &args[0];
    validate_name(name)?;
    let target = &args[1];
    let host = validate_target(target)?;
    let fingerprint = &args[2];
    validate_fingerprint(fingerprint)?;

    let mut port = 22u16;
    let mut identity = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                let value = args.get(i + 1).ok_or("--port requires a value")?;
                port = value.parse::<u16>().map_err(|_| "invalid SSH port")?;
                if port == 0 { return Err("port must be 1–65535".into()); }
                i += 2;
            }
            "--identity" => {
                let value = args.get(i + 1).ok_or("--identity requires a path")?;
                let path = PathBuf::from(value).canonicalize()
                    .map_err(|e| format!("SSH identity not found: {e}"))?;
                if !path.is_file() { return Err("SSH identity must be a regular file".into()); }
                identity = Some(path);
                i += 2;
            }
            other => return Err(format!("unknown trust option: {other}")),
        }
    }

    let root = initialize()?;
    let peer_file = peer_path(&root, name);
    let host_file = host_path(&root, name);
    if peer_file.exists() || host_file.exists() {
        return Err(format!("peer {name} already exists; remove it explicitly before replacing its host key"));
    }

    let scanned_key = scan_verified_host_key(host, port, fingerprint)?;
    let peer = Peer {
        target: target.to_owned(),
        port,
        fingerprint: fingerprint.to_owned(),
        identity,
    };

    // Per-peer known_hosts prevents altering SSH's normal trust database.
    create_private_file(&host_file, scanned_key.as_bytes())?;
    if let Err(e) = create_private_file(&peer_file, peer.encode().as_bytes()) {
        let _ = fs::remove_file(&host_file);
        return Err(e);
    }

    println!("Trusted {name} ({target}:{port}). Host key pinned.");
    println!("Remote login still requires a valid account and SSH authorization.");
    println!("Connect with: zzh connect {name}");
    Ok(0)
}

fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(format!("write {}: {e}", path.display()));
    }
    Ok(())
}

fn scan_verified_host_key(host: &str, port: u16, expected: &str) -> Result<String, String> {
    let output = Command::new("ssh-keyscan")
        .args(["-T", "5", "-t", "ed25519", "-p", &port.to_string(), host])
        .output().map_err(|e| format!("run ssh-keyscan: {e}"))?;
    if !output.status.success() || output.stdout.len() > 65536 {
        return Err("could not retrieve an ED25519 host key (or keyscan response was too large)".into());
    }
    let response = String::from_utf8(output.stdout)
        .map_err(|_| "invalid UTF-8 from ssh-keyscan")?;

    for line in response.lines().filter(|l| !l.starts_with('#')) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 || fields[1] != "ssh-ed25519" { continue; }

        let mut child = Command::new("ssh-keygen")
            .args(["-lf", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn().map_err(|e| format!("run ssh-keygen: {e}"))?;
        child.stdin.take().ok_or("ssh-keygen stdin unavailable")?
            .write_all(format!("{line}\n").as_bytes())
            .map_err(|e| format!("write host key to ssh-keygen: {e}"))?;
        let check = child.wait_with_output()
            .map_err(|e| format!("read ssh-keygen fingerprint: {e}"))?;
        if !check.status.success() { continue; }
        let text = String::from_utf8_lossy(&check.stdout);
        if text.split_whitespace().any(|word| word == expected) {
            return Ok(format!("{line}\n"));
        }
    }
    Err("HOST KEY MISMATCH: scan did not match the independently verified fingerprint; nothing was trusted".into())
}

impl Peer {
    fn encode(&self) -> String {
        let identity = self.identity.as_ref().map(|p| p.to_string_lossy()).unwrap_or_default();
        format!("version=1\ntarget={}\nport={}\nfingerprint={}\nidentity={}\n",
            self.target, self.port, self.fingerprint, identity)
    }

    fn decode(data: &str) -> Result<Self, String> {
        let mut version = None;
        let mut target = None;
        let mut port = None;
        let mut fingerprint = None;
        let mut identity = None;
        for line in data.lines() {
            let (key, value) = line.split_once('=').ok_or("invalid peer configuration")?;
            match key {
                "version" => version = Some(value),
                "target" => target = Some(value.to_owned()),
                "port" => port = Some(value.parse::<u16>().map_err(|_| "invalid port")?),
                "fingerprint" => fingerprint = Some(value.to_owned()),
                "identity" => identity = if value.is_empty() { None } else { Some(PathBuf::from(value)) },
                _ => return Err("unknown peer configuration field".into()),
            }
        }
        if version != Some("1") { return Err("unsupported peer configuration version".into()); }
        let target = target.ok_or("missing target")?;
        validate_target(&target)?;
        let fingerprint = fingerprint.ok_or("missing fingerprint")?;
        validate_fingerprint(&fingerprint)?;
        let port = port.ok_or("missing port")?;
        if port == 0 { return Err("invalid port".into()); }
        Ok(Peer { target, port, fingerprint, identity })
    }
}

fn peer_path(root: &Path, name: &str) -> PathBuf {
    root.join("peers").join(format!("{name}.conf"))
}

fn host_path(root: &Path, name: &str) -> PathBuf {
    root.join("hosts").join(format!("{name}.known_hosts"))
}

fn load_peer(name: &str) -> Result<(PathBuf, Peer), String> {
    validate_name(name)?;
    let root = config_root()?;
    let path = peer_path(&root, name);
    let data = fs::read_to_string(&path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let peer = Peer::decode(&data)?;
    let known_hosts = host_path(&root, name);
    if !known_hosts.is_file() {
        return Err(format!("trusted host key missing: {}", known_hosts.display()));
    }
    Ok((known_hosts, peer))
}

fn connect(name: &str) -> Result<i32, String> {
    let (known_hosts, peer) = load_peer(name)?;
    let mut ssh = Command::new("ssh");
    ssh.arg("-o").arg("StrictHostKeyChecking=yes")
        .arg("-o").arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .arg("-o").arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o").arg("UpdateHostKeys=no")
        .arg("-o").arg("CheckHostIP=no")
        .arg("-o").arg("ForwardAgent=no")
        .arg("-p").arg(peer.port.to_string());

    if let Some(key) = peer.identity {
        ssh.arg("-i").arg(key).arg("-o").arg("IdentitiesOnly=yes");
    }
    // Interactive shell: inherit the terminal, signals, and SSH agent.
    let status = ssh.arg("--").arg(&peer.target).status()
        .map_err(|e| format!("start OpenSSH: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

fn list_peers() -> Result<i32, String> {
    let root = initialize()?;
    let mut names = Vec::new();
    for entry in fs::read_dir(root.join("peers")).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.path().extension().and_then(|x| x.to_str()) == Some("conf") {
            if let Some(name) = entry.path().file_stem().and_then(|x| x.to_str()) {
                names.push(name.to_owned());
            }
        }
    }
    names.sort();
    if names.is_empty() { println!("No trusted peers. Use: zzh trust ..."); }
    for name in names {
        let (_, peer) = load_peer(&name)?;
        println!("{name:20} {}:{}  {}", peer.target, peer.port, peer.fingerprint);
    }
    Ok(0)
}

fn remove(name: &str) -> Result<i32, String> {
    validate_name(name)?;
    let root = config_root()?;
    let peer = peer_path(&root, name);
    fs::remove_file(&peer)
        .map_err(|e| format!("remove {}: {e}", peer.display()))?;
    let hosts = host_path(&root, name);
    if hosts.exists() {
        fs::remove_file(&hosts)
            .map_err(|e| format!("remove {}: {e}", hosts.display()))?;
    }
    println!("Removed local trust for {name}.");
    println!("This does NOT delete any SSH authorized_keys entry on the remote host.");
    Ok(0)
}

fn doctor() -> Result<i32, String> {
    for program in ["ssh", "ssh-keyscan", "ssh-keygen"] {
        // Executables are checked for presence only. Failure from a usage
        // flag is fine; failure to launch is not.
        let _ = Command::new(program).arg("-?").output()
            .map_err(|e| format!("{program} is missing: {e}"))?;
        println!("{program}: found");
    }
    let root = config_root()?;
    println!("config: {}", root.display());
    println!("transport: upstream OpenSSH (no embedded SSH implementation)");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_fp() -> String {
        format!("SHA256:{}", "A".repeat(43))
    }

    #[test]
    fn validates_aliases() {
        assert!(validate_name("dev-box_01").is_ok());
        assert!(validate_name("../bad").is_err());
        assert!(validate_name("-danger").is_err());
        assert!(validate_name("bad\nname").is_err());
    }

    #[test]
    fn validates_targets() {
        assert_eq!(validate_target("alice@example.com").unwrap(), "example.com");
        assert!(validate_target("-oProxyCommand=bad@host").is_err());
        assert!(validate_target("alice@-options").is_err());
        assert!(validate_target("alice@evil\nhost").is_err());
    }

    #[test]
    fn requires_sha256_fingerprint() {
        assert!(validate_fingerprint(&good_fp()).is_ok());
        assert!(validate_fingerprint("MD5:abcd").is_err());
        assert!(validate_fingerprint("SHA256:too-short").is_err());
    }

    #[test]
    fn peer_serialization_roundtrip() {
        let peer = Peer {
            target: "alice@host.example".into(),
            port: 2222,
            fingerprint: good_fp(),
            identity: Some(PathBuf::from("/home/alice/.ssh/id_ed25519")),
        };
        assert_eq!(Peer::decode(&peer.encode()).unwrap(), peer);
    }

    #[test]
    fn reject_unsupported_config_versions() {
        let data = format!("version=2\ntarget=alice@host\nport=22\nfingerprint={}\nidentity=\n", good_fp());
        assert!(Peer::decode(&data).is_err());
    }

    #[test]
    fn reject_ssh_option_injection() {
        for target in ["alice@-proxy", "alice@host -oBad=yes", "user@", "alice@host/evil"] {
            assert!(validate_target(target).is_err(), "{target}");
        }
    }

    #[test]
    fn reject_invalid_port() {
        let data = format!("version=1\ntarget=alice@host\nport=0\nfingerprint={}\nidentity=\n", good_fp());
        assert!(Peer::decode(&data).is_err());
    }
}
