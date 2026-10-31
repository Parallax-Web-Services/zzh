# zzh

**Secure remote access for Nucleus, the Parallax distributed private cloud.**

`sh → zh`, `ssh → zzh`. This is the **standalone `zzh` repository**, independent of the Nucleus starter. `zzh` is an early Rust CLI that deliberately calls **upstream OpenSSH executables**. It does not fork or reimplement SSH.

## What works in this scaffold

- Inspect installed OpenSSH prerequisites with `zzh doctor`.
- Initialize a private per-user configuration directory with `zzh init`.
- Explicitly pin a remote server's **ED25519 host key** after comparing it to a separately verified SHA-256 fingerprint.
- Name trusted peers with `zzh trust` and inspect them with `zzh peers`.
- Open an interactive shell with `zzh connect NAME` using OpenSSH, strict host-key checking, existing SSH identities/agents, and a peer-specific known_hosts file.
- Remove local trust with `zzh remove NAME`.
- Validate inputs, reject unverified host keys, and test core parsing logic.

**Not built:** invited pairing, automatic remote account authorization, peer discovery, encrypted overlay networking, NAT traversal, Positronic heartbeat/resource APIs, federation, workload dispatch, or a graphical map. OpenSSH provides encryption; `zzh` does not yet implement a private mesh.

## Requirements

- Rust stable and Cargo
- Linux or WSL2 (initial target; macOS is a possible follow-up)
- Installed OpenSSH client tools: `ssh`, `ssh-keyscan`, `ssh-keygen`
- A remote machine running `sshd`, with an SSH account and valid authentication already configured

## Get started

```bash
git clone --branch master https://github.com/Parallax-Web-Services/zzh.git
cd zzh
cargo test
cargo run -- doctor
cargo run -- init
cargo install --path .
zzh doctor
```

Use `cargo run --` in place of the installed `zzh` binary if you prefer.

## Two-machine walkthrough (LAN first)

1. On **machine B**, confirm SSH works and obtain the real host-key fingerprint **through a trusted channel**:

   ```bash
   sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

   Note the full `SHA256:...` value. Do not rely on the fingerprint printed by an unverified `ssh-keyscan` alone.

2. From **machine A**, confirm an authorized user can log into B using normal OpenSSH. This is standard SSH setup, not performed by `zzh`. If you use SSH public keys, configure B's `~/.ssh/authorized_keys` intentionally, with appropriate file permissions.

3. On A, pin B's verified host key (replace the placeholders):

   ```bash
   zzh trust workstation alice@192.168.1.25 SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT
   zzh peers
   zzh connect workstation
   ```

   For nondefault ports or explicit SSH identities:

   ```bash
   zzh trust workstation alice@host.example SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT --port 2222 --identity ~/.ssh/id_ed25519
   ```

4. Close the remote shell normally. Test rejection by attempting to trust a mismatching fingerprint; **nothing should be saved**. For local trust removal: `zzh remove workstation`. Revoking SSH access on B remains a separate administrative action.

## Files and architecture

```text
zzh/
├── Cargo.toml               # One crate, no external Rust dependencies
├── src/
│   ├── main.rs              # CLI entry point
│   └── lib.rs               # OpenSSH-backed core + unit tests
├── docs/
│   ├── SECURITY.md          # Threat model and limitations
│   └── INTEGRATION.md       # Boundary with zh and Positronic
└── .github/workflows/ci.yml
```

Persistent peer configuration lives in `$XDG_CONFIG_HOME/zzh` or `~/.config/zzh`. SSH host keys stay in per-peer files, separate from your regular `~/.ssh/known_hosts`. The shell is OpenSSH's remote interactive session, not an embedded implementation.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

CI checks the `master` branch. Code must be compiled and exercised on a real OpenSSH-equipped machine before treating the remote-shell path as validated.

## Roadmap

1. Complete and verify the OpenSSH-backed CLI on two machines (host pinning, SSH authentication, remote interactive shell).
2. Add controlled, explicit bilateral invitations and confirmation of peer identities, without trusting unauthenticated discovery.
3. Add versioned peer descriptors for Positronic; provide trusted node status to the Nucleus resource map.
4. Evaluate an established secure overlay for cross-network reachability. Keep a strict boundary between shell access and workload authorization.

See [security model](docs/SECURITY.md) and [integration notes](docs/INTEGRATION.md).

License: not yet selected. Repository visibility does not itself grant an open-source license.
