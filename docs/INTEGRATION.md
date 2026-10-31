# Nucleus / Parallax integration boundary

`zzh` is an independently versioned transport and remote-access CLI. It consumes system OpenSSH executables and does not depend on the Nucleus monorepo or Chromium.

| Concern | Owner |
| --- | --- |
| Secure remote terminal and peer key pinning | zzh |
| Native local shell, Bash compatibility, ZhQL | zh |
| Resource discovery, scheduling, self-healing, authorization | Positronic |
| Graph/peer relationships | Plexus |
| Chromium resource map | Helm / Parallax Browser |

## Next interoperability contract (not implemented)

Define a versioned JSON peer descriptor (peer id, SSH endpoint, host-key fingerprint, supported capabilities) rather than coupling the CLI to the Positronic database schema. Future `zzh` may expose it over stdout with `zzh peers --json`, never including private keys.

The first integration test is opening a shell on an independently authorized and pinned host. Only after that should Positronic consume peer metadata and telemetry. Do not promote trusted SSH clients into workload administrators automatically.
