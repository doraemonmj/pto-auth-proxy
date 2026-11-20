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
without issuing new tokens. Fresh `join` and users without a saved preference use auto;
an explicitly saved `default-mode` is preserved by both join and setup-shell.


## Automatic routing

`config/proxy-domains.txt` selects destinations sent to the SOCKS upstream;
`config/whitelist.txt` independently authorizes upstream use. Selected domains
missing from the whitelist fail closed, without direct fallback. SIGHUP reloads
both files. Keep provider API/login/asset domains narrow and review deliberate
changes. Defaults include the existing OpenAI, Claude and core GitHub host sets;
optional Google/npm whitelist entries do not automatically become proxy routes.

Auto listeners default to HTTP 20811 and SOCKS5 20810; forced proxy listeners
remain 20809/20808. Validate all four ports for collisions before shadow testing.
The auto direct path authenticates, resolves and checks all DNS results, and
connects only to checked numeric public addresses. It rejects private, loopback,
link-local and multicast destinations, and only permits DIRECT_PORTS (80,443 by
default). Keep the egress guard enabled: direct forwarding is not an upstream
bypass. Local/internal traffic should use application NO_PROXY under the user's
own identity. A routing selection never grants general service-owner access.

`--init-config` creates a routing file only if missing; upgrades preserve it.
An upgrade without a routing file uses the shipped defaults. An explicitly
configured missing routing file is an error rather than a silently different
policy. Update existing shell hooks with setup-shell without rotating credentials.
`off` now means forced direct; use restore for the former environment-restore
operation. Explicit saved proxy/direct defaults are kept; absent preference means
auto. No service is automatically restarted to apply these changes.


## Enrollment identity and rollback

Join verifies SO_PEERCRED on every authd connection before sending a request;
the peer must be the current UID. Inspect instance User= and socket ownership
if this fails; do not relax peer verification or switch to an unverified socket.
Join uses the account-database home for daemon paths and persistent stop/logout
markers. Shell environment files may still use the user's configured XDG path.
A failed or interrupted join restores prior stop/logout markers, including
failures after token issuance. Auth responses and shell tracing must not disclose
credentials; join and shell setup disable inherited xtrace/allexport.

There is no implicit loopback-IP whitelist allowance. Local OAuth callbacks use
NO_PROXY as the actual user. IP literals require exact public-address approval;
private/loopback targets and IPv6 forms embedding private IPv4 targets (including
well-known NAT64) are refused by forwarding policy.


Plain HTTP forwards one framed request per connection and requests origin close.
Content-Length and chunked bodies are bounded to their message boundaries;
proxy-auth headers/trailers are removed, and following pipelined requests are not
forwarded as tunnel data. CONNECT continues to carry opaque bidirectional TLS.
