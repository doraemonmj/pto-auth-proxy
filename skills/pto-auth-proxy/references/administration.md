# Administration and deployment

Read this only for administrator configuration, deployment or updater work.

## GitHub acceptance boundary

Core GitHub access includes:

- repository HTML at `github.com`;
- repository metadata from `api.github.com`;
- raw files from `raw.githubusercontent.com`;
- HTTPS Git smart protocol and codeload/assets hosts.

The repository's automated tests verify host policy. The interactive
`pto-auth-proxy test` command performs real GitHub content retrieval using a
password entered privately by the user in their own terminal. Never enter or
capture that password on the user's behalf.

Do not broaden the whitelist to GHCR, GitHub Pages, GitHub Codespaces, or other
products unless the user explicitly requests that scope and an administrator
accepts the additional egress.

## Configuration changes

Do not assume any backend product or port. Read `PTO_AUTH_PROXY_UPSTREAM_HOST`
and `PTO_AUTH_PROXY_UPSTREAM_PORT` from the installed config, then compare with
the backend listener and the latest proxy startup log. The upstream speaks
standard no-auth SOCKS5; a local mihomo mixed-port or an SSH tunnel is valid.
The upstream port has no default. Never discover it by probing arbitrary ports
or replace an existing configured port with a documentation example.
`PTO_AUTH_PROXY_GUARD_PORTS` defaults to the configured upstream port; an explicit
list must include that port. On older installations, remove obsolete guard
values when changing the upstream. Check `config/auto-update.env` too: new
templates read the same auth-proxy config, but upgrades preserve existing local
updater config, including any legacy fixed fetch proxy. Migrate that section
explicitly before relying on the updater. Backend service/tunnel lifecycle stays
with its own service manager.

Before proposing a change:

1. Read the current installed config and whitelist with secrets redacted.
2. Confirm whether the requested domain is already covered by an existing glob.
3. Prefer the narrowest domain pattern that supports the required workflow.
4. Run repository tests and `pto-auth-proxy validate` against the candidate
   configuration.
5. Report the exact diff. Do not signal or restart the running service unless
   separately requested.

## Deployment

The repository installer copies code into the standard `pypto-tools` layout.
By default it does not install, enable, start, stop, or restart services.
`--install-service` installs the shared proxy, per-user authd template, boot
member starter, and egress guard without enabling or starting them.
`--enable-service` explicitly enables these boot services, but still does not
start or restart them immediately. Individual authd instances do not need to be
enabled: `pto-auth-proxy-authd-members.service` discovers the authorized group
on every boot.

Keep the server timer enabled for persistent repository-state checks. Interpret
the main repository's `update/rollout.json` as follows:

- `enabled=false`: deployment is paused; polling may continue.
- `enabled=true` with an empty `target`: deployment is armed but idle. Treat
  this as healthy; do not test or install a candidate.
- `enabled=true` with a full commit ID: verify and stage that exact commit. Do
  not substitute the current branch HEAD.

For a targeted rollout, require the target to be an ancestor of the configured
main branch and increase `sequence`. Require `allow_rollback=true` for a
downgrade. Always merge code and tests before publishing the separate manifest
control commit. Never point `target` at the control commit itself unless that is
the version intentionally being deployed.

The updater fetches as the unprivileged proxy owner through the owner-only local
SOCKS upstream when root has no direct egress. It preserves local
configuration/state/logs and stages the candidate without restarting proxy or
authd services. The auth-proxy adapter stages matching service units and runs
daemon-reload, but does not enable, start, or restart them; an apply failure
restores both application files and units. Only `activation=next-restart` is accepted. Never change this
to remote forced restart behavior: uninterrupted authenticated proxy access
takes priority.

Keep updater installations compatible with `ProtectSystem=strict`. If the
global command symlink already points to the deployed application, the
installer must skip rewriting it instead of granting the updater broad write
access to `/usr/local/bin`.

The polling engine is the reusable `modules/repo_auto_update/` module. It must
remain tool-neutral. Auth-proxy-specific verification, backup, and installation
belong in `scripts/auto-update-adapter.sh`. Another tool should copy the module,
create its own root-owned config from `example.env`, and provide its own verify
and apply adapters; do not add other tools' behavior to the generic engine.

The egress guard uses IPv4/IPv6 owner rules so only the configured proxy owner
can connect directly to the configured loopback upstream ports. The authenticated
service remains
non-root and reaches the upstream as that owner. The guard continuously checks
and repairs rule drift, and the shared proxy verifies the rules before each
start. Verify the service and access matrix with `pto-auth-proxy doctor` after
deployment.

Client handshake, upstream connect/handshake, half-close relay, and writer-close timeouts are
local containment controls. They do not repair an unavailable remote tunnel;
they make it fail promptly and prevent abandoned relay tasks from accumulating.

Production cutover requires a shadow-port test and an explicit rollback plan;
follow the repository README and preserve the previous deployment until
acceptance passes. Treat the later `systemctl start` or `restart` as a separate
state-changing operation requiring explicit user intent.


## User lifecycle authorization

Use `scripts/install.sh --install-user-controls` only when user intent includes
installing personal service delegation. It installs the system template and a
polkit rule for start/stop/restart of the caller's exact escaped authd instance.
It grants no unit-file, other-user, shared-service or guard control, and does not
start anything. Ordinary installs and the staged updater do not install this
policy. The rule lives in `/etc/polkit-1/rules.d/50-pto-auth-proxy-self.rules`;
remove it to revoke delegation without changing enrollment or proxy defaults.

The authd unit's ExecCondition and boot member starter honor the account-home
`authd.stopped` marker. Do not remove it during upgrades. A local `start` or
explicit re-onboarding clears it; only successful PAM re-onboarding clears
`access.disabled`. Existing shell hooks can be upgraded with `setup-shell`
without issuing new tokens. Fresh `join` keeps the historical proxy-on default;
an explicitly saved `default-mode` is preserved by both join and setup-shell.
