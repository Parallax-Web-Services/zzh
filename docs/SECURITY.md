# zzh security model

Version 0.1 is an OpenSSH-backed remote-shell wrapper, **not** a secure mesh network, SSH server, VPN, or cryptographic protocol.

## Trust establishment

1. Obtain the server's ED25519 host-key fingerprint through an independently authenticated channel: local console, trusted management channel, or administrator-provided fingerprint. On the server run: `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
2. Run `zzh trust NAME USER@HOST SHA256:...`. The tool obtains the public host key with `ssh-keyscan`, calculates the fingerprint using upstream `ssh-keygen`, and **refuses to store a key unless the fingerprints match**.
3. Each peer gets its own pinned `known_hosts` file. Connections use OpenSSH with strict host-key checking, no global known-hosts fallback, and no automatic key updates.
4. Login still requires an authorized SSH account, key, password, or agent. `zzh trust` **does not** add a public key to the remote server.

## Revocation

`zzh remove NAME` removes the *local* trust record and pinned host key. It does **not** remove entries from remote `authorized_keys`, revoke SSH certificates, close active sessions, or block another SSH client. Revoke SSH authorization separately on the server.

## Limits

- No automated peer discovery, rendezvous, NAT traversal, VPN, tunnel, or federated identity.
- No remote commands, tunnels, file copying, workload execution, auto key distribution, or privilege escalation.
- Only DNS/IPv4 hostnames and ED25519 server host keys are supported in this initial scaffold.
- A host fingerprint displayed by the same unauthenticated network connection **is not an independent trust source**.
- User SSH configuration and agents remain available; agent forwarding is disabled for managed connections.
- Use separate SSH permissions and Positronic workload permissions; access to a shell must never imply permission to schedule third-party workloads.
- This code has not been independently security audited. Treat it as an alpha.

## Reporting a vulnerability

Open a private security report to the maintainers rather than posting secrets, private keys, or exploitable host details in a public issue.
