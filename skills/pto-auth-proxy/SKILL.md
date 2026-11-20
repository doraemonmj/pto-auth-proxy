---
name: pto-auth-proxy
description: Use and diagnose pto-auth-proxy on shared Linux hosts, including default automatic domain routing, manual proxy/direct overrides, current-user authd lifecycle, onboarding and logout. Use for this tool's commands and proxy failures; read the administration reference for deployment changes.
---

# pto-auth-proxy

Check `pto-auth-proxy --help` when the installed version is uncertain. If it
lacks `auto`, the routing feature is not deployed yet; do not assume the new
`off` semantics. If it lacks `on/off`, `exec`, `setup-shell` or `doctor`, the
older controls are also unavailable. Report the installed capability instead
of upgrading the service without deployment intent. Older `status` actively probes connectivity and does
not distinguish shell mode. Keep onboarding and logout explicit on old versions.

For a current installation, start with `pto-auth-proxy status`. It reports the current process environment,
new-shell default, enrollment and personal authd separately. `shell=direct`
is a valid user choice; it does not mean the proxy is broken. Run
`pto-auth-proxy doctor` when diagnosing connectivity: it actively checks
CONNECT, verified HTTPS, the guard and the configured upstream.

## Choose the smallest operation matching the request

| User intent | Command | Scope and effect |
| --- | --- | --- |
| Normal operation / finish troubleshooting | `pto-auth-proxy auto` | Default: selected domains use upstream; other public HTTP(S) targets connect directly |
| Force proxy in this terminal | `pto-auth-proxy on` | Force upstream, still subject to administrator whitelist |
| Force direct in this terminal | `pto-auth-proxy off` | Remove proxy variables; set NO_PROXY=*; keep credentials and authd |
| Restore original environment | `pto-auth-proxy restore` | Restore variables from before the tool took control, including an external proxy |
| Save future-shell default too | `pto-auth-proxy auto/on/off --default` | Persistent preference; other running processes keep their environment |
| Run one command with default routing | `pto-auth-proxy exec --auto -- COMMAND ARGS` | Child only; `exec -- COMMAND` also selects auto |
| Run one command directly | `pto-auth-proxy exec --direct -- COMMAND ARGS` | Child environment only; no proxy variables and NO_PROXY=* |
| Run one command through PTO proxy | `pto-auth-proxy exec --proxy -- COMMAND ARGS` | Child environment only; existing credential, no prompt |
| Start or recover personal authd | `pto-auth-proxy start` / `restart` | Current user's instance only; keep credentials and shell preference |
| Stop personal authd | `pto-auth-proxy stop` | Persistently deny new authentication, including after reboot; retain token |
| First enrollment or revoked/invalid credential | `pto-auth-proxy join` | Local interactive PAM verification, token issuance, shell integration |
| Revoke enrollment entirely | `pto-auth-proxy leave` | Revoke tokens, persist denial, remove generated shell configuration |

No saved preference means `auto`; explicit saved proxy/direct preferences remain
unchanged. Auto defaults route OpenAI/Codex/ChatGPT, Claude and core GitHub domains
to upstream. Other public HTTP(S) destinations use the server's direct network.
`on` is a temporary troubleshooting override; run `auto` afterward. Manual modes
without `--default` do not change the new-shell default. Forced proxy removes
external-domain NO_PROXY exceptions while keeping local/private bypasses; auto
restores the original bypass preferences. `off` means explicit
direct access; use `restore` to recover an original external proxy.

Routing rules in administrator-managed `config/proxy-domains.txt` select upstream
versus direct; `config/whitelist.txt` independently authorizes upstream access.
A selected but unauthorized domain is denied, and upstream failure never falls
back to direct. Do not turn arbitrary failures into new routes or expand the
whitelist without user intent. Auto's direct forwarding requires authentication,
allows only public resolved IPs and defaults to ports 80/443; local/internal
traffic should bypass the tool via NO_PROXY in the application. The forwarding
path cannot be used to reach the guarded loopback upstream.

Explicit application settings (e.g. Git http.proxy or VS Code settings) may take
precedence; diagnose without displaying proxy URLs. Do not silently edit these
settings. A direct route can still fail when the host has no direct Internet.

## Shell integration and existing applications

`auto/on/off/restore` need a shell function because a child process cannot change its parent.
`join` installs a credential-free hook in Bash/Zsh startup configuration. For
an existing terminal, have the user run (on older enrollments run
`pto-auth-proxy setup-shell` first; it reuses credentials without PAM/rotation):

```bash
source "${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/env.sh"
pto-auth-proxy auto
```

In an AI's non-interactive command environment, prefer `exec --auto` or an explicitly requested `--proxy/--direct`:
its scope is concrete and it needs no persistent shell setup. Do not print
credential-bearing shell code, use `eval "$(...)"`, or source arbitrary user
startup files just to switch modes. New terminals inherit the saved preference;
running VS Code/Codex needs a user-initiated Reload Window to change its environment.
Never kill user tools to apply a proxy change.

## Lifecycle and troubleshooting boundaries

- `start/stop/restart` operate only the caller's `pto-auth-proxy-authd@<user>.service`.
  They do not repair an unavailable shared listener, backend service or SSH tunnel.
  Normal users need the administrator to install `--install-user-controls` once.
  Keep the existing system instance authoritative; do not start a home watchdog
  beside it. `pto-auth-proxy-authd-members.service` handles boot startup and honors
  the user's persistent stop marker.
- `stop` and `leave` deny new authentication; established TCP streams continue.
  Immediate per-user disconnection and delegated shared-proxy restart are not
  implemented. Do not promise either behavior or substitute a shared restart.
- `start/restart` never clear a logout marker; after `leave`, use local `join`.
  A successful `join` issues a token with a ten-minute rotation grace. Do not use
  `join` as a routine restart or temporary proxy switch.
- `doctor` suggests personal restart for authd failure, local `join` for credential
  failure, and administrator diagnosis for shared listener/upstream/guard faults.
  A staged update may load at the next service restart; inspect the pending notice.
- Auto uses authenticated HTTP 20811 and SOCKS5 20810; forced proxy uses HTTP
  20809 and SOCKS5 20808. `status` reports `shell=auto/proxy/direct` separately
  from enrollment and daemon health. The
  SOCKS upstream is configured with `PTO_AUTH_PROXY_UPSTREAM_PORT`, without a
  default. Users must not bypass auth by connecting to guarded upstream ports.

Passwords are entered only by the user in their local interactive terminal.
Never request them in chat or place credentials in command arguments, logs,
repository files or tool configuration. Do not dump proxy environment variables,
secret files or expanded proxy URLs. Inspect only redacted diagnostic output.

Perform user-local switches or lifecycle operations when requested; existing user
authorization is sufficient. Shared service restart, egress rules, whitelist and
deployment changes require user intent covering those operations. For those
administrator tasks read [administration.md](references/administration.md).
The installer with `--enable-service` only enables boot startup; it does not
immediately start/restart the proxy. Updates remain staged until restart.
