#!/usr/bin/env bash
# join-proxy.sh — one-command onboarding for a new proxyusers member.
#
# Every user in `proxyusers` can run this safely. If the administrator enabled
# pto-auth-proxy-authd@<user>.service, join reuses that boot-persistent daemon
# and removes only the legacy per-home watchdog. Otherwise it installs and
# starts the legacy detached watchdog as a compatibility fallback.
#
# System-managed daemons use a protected /run socket; the compatibility daemon
# uses /tmp. The password is read once for PAM verification, then URL-encoded
# into a mode-0600 credential file. It never appears in argv or the environment.
#
# Prereqs (admin needs to do these once):
#   - `proxyusers` group exists and this user is a member
#   - python3-pam is installed system-wide OR in this user's site-packages
#
# Usage:  pto-auth-proxy join

set +ax  # Inherited tracing/allexport must not disclose or export credentials.
unset PW AUTH_RESULT PROXY_CREDENTIAL AUTH_MODE || exit 1
set -u
ME=$(id -un)
UID_NUM=$(id -u)
ACCOUNT_HOME=$(getent passwd "$ME" | cut -d: -f6)
[[ "$ACCOUNT_HOME" == /* ]] || {
  echo "Cannot resolve the current account home; ask the administrator." >&2
  exit 1
}

pass()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
fail()   { printf '\033[31m✗\033[0m %s\n' "$*"; }
info()   { printf '\033[36m•\033[0m %s\n' "$*"; }
header() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SRC_DIR=${PTO_AUTH_PROXY_SOURCE_DIR:-$SCRIPT_DIR}
BIN_DIR=$ACCOUNT_HOME/.local/bin
LOG_FILE=$ACCOUNT_HOME/.local/authproxy-authd.log
DISABLED_FILE=$ACCOUNT_HOME/.config/pto-auth-proxy/access.disabled
STOPPED_FILE=$ACCOUNT_HOME/.config/pto-auth-proxy/authd.stopped
WAS_STOPPED=0
WAS_DISABLED=0
[[ ! -e "$STOPPED_FILE" ]] || WAS_STOPPED=1
[[ ! -e "$DISABLED_FILE" ]] || WAS_DISABLED=1

finish_join() {
  local rc=$? marker temporary
  if ((rc != 0)); then
    # Issuing a token may already have resumed access. Failed onboarding must
    # restore the caller's previous stop/logout choice, including config errors.
    for marker in "$STOPPED_FILE:$WAS_STOPPED" "$DISABLED_FILE:$WAS_DISABLED"; do
      if [[ ${marker##*:} == 1 ]]; then
        marker=${marker%:*}
        mkdir -p -- "${marker%/*}"
        temporary=$(mktemp "${marker%/*}/.join-restore.XXXXXX") || continue
        printf '%s\n' 'disabled; previous join did not complete' >"$temporary"
        chmod 0600 "$temporary"
        mv -f -- "$temporary" "$marker"
      fi
    done
  fi
  unset PW AUTH_RESULT PROXY_CREDENTIAL
}
trap finish_join EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
PROXY_OWNER=${PTO_AUTH_PROXY_OWNER:-pypto}
PROXY_GROUP=${PTO_AUTH_PROXY_GROUP:-proxyusers}
PAM_SERVICE=${PTO_AUTH_PROXY_PAM_SERVICE:-sshd}
SYSTEMD_UNIT="pto-auth-proxy-authd@${ME}.service"
if command -v systemd-escape >/dev/null 2>&1; then
  ESCAPED_SYSTEMD_UNIT=$(systemd-escape \
    --template=pto-auth-proxy-authd@.service "$ME" 2>/dev/null || true)
  [ -z "$ESCAPED_SYSTEMD_UNIT" ] || SYSTEMD_UNIT=$ESCAPED_SYSTEMD_UNIT
fi
SYSTEMD_MANAGED=0
SYSTEMD_BOOT_ENABLED=0

# An installed system template is authoritative even while the user stopped
# its instance. Do not create a competing home watchdog; boot persistence is
# supplied by the member starter or an explicitly enabled individual instance.
if command -v systemctl >/dev/null 2>&1; then
  SYSTEMD_UNIT_STATE=$(systemctl is-enabled "$SYSTEMD_UNIT" 2>/dev/null || true)
  if [ "$SYSTEMD_UNIT_STATE" = enabled ]; then
    SYSTEMD_BOOT_ENABLED=1
  fi
  if [ "$(systemctl show --property=LoadState --value "$SYSTEMD_UNIT" 2>/dev/null)" = loaded ] \
     || systemctl is-active --quiet "$SYSTEMD_UNIT" 2>/dev/null \
     || [ "$SYSTEMD_UNIT_STATE" = enabled ] \
     || [ "$SYSTEMD_UNIT_STATE" = enabled-runtime ]; then
    SYSTEMD_MANAGED=1
  fi
fi

# The boot member starter creates this per-user directory as user:proxyusers
# mode 0750. Legacy joins retain /tmp for compatibility.
SYSTEM_SOCK="/run/pto-auth-proxy/${UID_NUM}/authd.sock"
if [ -d "${SYSTEM_SOCK%/*}" ]; then
  SOCK=$SYSTEM_SOCK
else
  SOCK="/tmp/authproxy-${ME}.sock"
fi

header "Step 1: group membership"
if id -nG "$ME" | tr ' ' '\n' | grep -qx "$PROXY_GROUP"; then
  pass "$ME is in $PROXY_GROUP"
else
  fail "$ME is NOT in $PROXY_GROUP. Ask admin: sudo usermod -aG $PROXY_GROUP $ME  (then log out and back in)"
  exit 1
fi

header "Step 2: python-pam available"
if python3 -c 'import pam' 2>/dev/null; then
  pass "python3 can import pam"
else
  fail "python3 lacks the python-pam module."
  info ""
  info "  Install it by running ONE of the following:"
  info ""
  info "    sudo dnf install -y python3-pam       # (recommended, system-wide)"
  info "    pip3 install --user python-pam        # (fallback, user only)"
  info ""
  info "  Then re-run onboarding:"
  info "    pto-auth-proxy join"
  info ""
  exit 1
fi

# join is explicit re-onboarding; it may resume a previously stopped authd.
# The access.disabled marker remains until PAM verification succeeds.
rm -f -- "$STOPPED_FILE"

if [ "$SYSTEMD_MANAGED" -eq 1 ]; then
  header "Step 3: systemd-managed authd"
  pass "$SYSTEMD_UNIT is installed and managed by systemd"
  info "Using the shared deployed authd; no per-home copy is needed."
else
  header "Step 3: install compatibility authd into your home"
  mkdir -p "$BIN_DIR"
  cp "$SRC_DIR/authd.py" "$BIN_DIR/authproxy-authd.py"
  chmod 700 "$BIN_DIR/authproxy-authd.py"

  # A tiny watchdog keeps authd alive with 3s backoff if it crashes. Persist
  # only non-sensitive daemon configuration; passwords never enter it.
  {
  printf '#!/usr/bin/env bash\n'
  printf 'export PTO_AUTH_PROXY_OWNER=%q\n' "$PROXY_OWNER"
  printf 'export PTO_AUTH_PROXY_GROUP=%q\n' "$PROXY_GROUP"
  printf 'export PTO_AUTH_PROXY_PAM_SERVICE=%q\n' "$PAM_SERVICE"
  cat << 'WD'
# authproxy-watchdog.sh -- keep authd alive
LOG="${HOME}/.local/authproxy-authd.log"
BIN="${HOME}/.local/bin/authproxy-authd.py"
echo "$(date '+%F %T') watchdog started (pid=$$)" >> "$LOG"
while [ ! -e "$HOME/.config/pto-auth-proxy/authd.stopped" ]; do
  python3 "$BIN" >> "$LOG" 2>&1
  rc=$?
  echo "$(date '+%F %T') authd exited rc=$rc, restarting in 3s" >> "$LOG"
  sleep 3
done
WD
  } > "$BIN_DIR/authproxy-watchdog.sh"
  chmod 700 "$BIN_DIR/authproxy-watchdog.sh"
  pass "$BIN_DIR/authproxy-authd.py + watchdog installed"
fi

if [ "$SYSTEMD_MANAGED" -eq 1 ]; then
  header "Step 4: use boot-persistent systemd authd"

  if ! systemctl is-active --quiet "$SYSTEMD_UNIT" 2>/dev/null; then
    # This may succeed under a local policy rule. Never prompt for privilege;
    # if it is not allowed, tell the user exactly what the administrator needs.
    systemctl --no-ask-password start "$SYSTEMD_UNIT" 2>/dev/null || true
  fi

  # Type=simple becomes active just before Python binds its socket. Give the
  # new process time to replace a possible legacy socket before checking it.
  sleep 0.5
  for _ in 1 2 3 4 5; do
    systemctl is-active --quiet "$SYSTEMD_UNIT" 2>/dev/null \
      && [ -S "$SOCK" ] && break
    sleep 0.2
  done

  if ! systemctl is-active --quiet "$SYSTEMD_UNIT" 2>/dev/null \
     || [ ! -S "$SOCK" ]; then
    fail "$SYSTEMD_UNIT is enabled but not ready"
    info "  Ask the administrator to run:"
    info "    sudo systemctl restart $SYSTEMD_UNIT"
    info "    sudo systemctl status $SYSTEMD_UNIT"
    exit 1
  fi

  # Select only exact legacy script arguments; preserve systemd and unrelated
  # user processes. Clean up only after systemd is healthy.
  python3 "$SRC_DIR/user_proxy.py" stop-compatibility || exit 1
  if [ "$SYSTEMD_BOOT_ENABLED" -eq 1 ]; then
    pass "$SYSTEMD_UNIT is active and enabled for server reboot"
  else
    pass "$SYSTEMD_UNIT is active; join did not start a duplicate daemon"
    info "  For boot persistence, ask the administrator to run:"
    info "    sudo systemctl enable $SYSTEMD_UNIT"
  fi
else
  header "Step 4: (re)start compatibility authd via watchdog"
  python3 "$SRC_DIR/user_proxy.py" stop-compatibility || exit 1
  sleep 0.5
  rm -f "$SOCK" 2>/dev/null || true

  HOME="$ACCOUNT_HOME" setsid nohup bash "$BIN_DIR/authproxy-watchdog.sh" </dev/null \
      >>"$LOG_FILE" 2>&1 &
  disown $! 2>/dev/null || true
  sleep 1

  if pgrep -u "$ME" -f authproxy-watchdog.sh >/dev/null \
     && pgrep -u "$ME" -f authproxy-authd.py >/dev/null; then
    pass "watchdog pid: $(pgrep -u "$ME" -f authproxy-watchdog.sh) / authd pid: $(pgrep -u "$ME" -f authproxy-authd.py)"
  else
    fail "authd or watchdog failed to start"
    tail -30 "$LOG_FILE"
    exit 1
  fi
fi

if [ ! -S "$SOCK" ]; then
  fail "socket $SOCK not present"
  [ "$SYSTEMD_MANAGED" -eq 1 ] || tail -20 "$LOG_FILE"
  exit 1
fi
pass "socket ready at $SOCK"
ls -l "$SOCK"

header "Step 5: verify authd and configure future shells"
info "Your Linux password is checked once over the local unix socket."
info "New authd versions exchange it for a revocable random proxy token."
read -r -s -p "Your Linux password: " PW
echo
# Pass only the socket and username via env. The password is fed over stdin so
# neither the Linux password nor issued token appears in argv or environment.
AUTH_RESULT=$(SOCK="$SOCK" USER_NAME="$ME" python3 -c '
import socket, sys, os, json, struct
pw = sys.stdin.read().rstrip("\n")

def request(payload):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(12)
    try:
        s.connect(os.environ["SOCK"])
        peer = s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                            struct.calcsize("iII"))
        _, peer_uid, _ = struct.unpack("iII", peer)
        if peer_uid != os.getuid():
            raise PermissionError("authd socket is not owned by the current user")
        s.sendall((json.dumps(payload) + "\n").encode())
        data = b""
        while b"\n" not in data and len(data) < 16384:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return json.loads(data.decode())
    finally:
        s.close()

user = os.environ["USER_NAME"]
capabilities = request({"op": "capabilities"})
if capabilities.get("ok") and "token-v1" in capabilities.get("capabilities", []):
    response = request({"op": "issue-token", "user": user, "pass": pw})
    if not response.get("ok") or not response.get("token"):
        print("authentication failed: " + str(response.get("reason", "unknown")),
              file=sys.stderr)
        raise SystemExit(1)
    print("token")
    print(response["token"], end="")
else:
    response = request({"user": user, "pass": pw})
    if not response.get("ok"):
        print("authentication failed: " + str(response.get("reason", "unknown")),
              file=sys.stderr)
        raise SystemExit(1)
    print("password")
    print(pw, end="")
' <<< "$PW" 2>&1)
AUTH_RC=$?
unset PW
if ((AUTH_RC != 0)); then
  unset AUTH_RESULT
  fail "authd identity or authentication check failed"
  info "  Verify your local password or ask the administrator to inspect authd/PAM logs."
  exit 1
fi

AUTH_MODE=${AUTH_RESULT%%$'\n'*}
PROXY_CREDENTIAL=${AUTH_RESULT#*$'\n'}
if [[ "$AUTH_RESULT" == "$PROXY_CREDENTIAL" || -z "$PROXY_CREDENTIAL" ]]; then
  unset AUTH_RESULT PROXY_CREDENTIAL
  fail "authd returned an invalid credential response"
  exit 1
fi
unset AUTH_RESULT
if [[ "$AUTH_MODE" == token ]]; then
  pass "Linux password verified; an independent proxy token was issued"
else
  pass "Linux password verified; legacy authd requires password compatibility mode"
fi

if ! printf '%s' "$PROXY_CREDENTIAL" | bash "$SRC_DIR/configure-shell.sh" "$ME"; then
  unset PROXY_CREDENTIAL
  fail "authd is healthy, but automatic shell configuration failed"
  info "  No running process was changed. Fix the reported shell file issue and re-run join."
  exit 1
fi
unset PROXY_CREDENTIAL
rm -f -- "$DISABLED_FILE"

if [[ "$AUTH_MODE" == token ]]; then
  pass "future shells use the proxy token; Linux password is not stored"
else
  info "Current authd will gain token support after its next system-managed start."
fi
unset AUTH_MODE

pass "future shells default to auto routing unless a manual preference was saved"

echo
echo "All set."
echo "  - authd is running as $ME, listening on $SOCK"
if [ "$SYSTEMD_MANAGED" -eq 1 ]; then
  echo "  - managed by systemd: $SYSTEMD_UNIT"
  if [ "$SYSTEMD_BOOT_ENABLED" -eq 1 ]; then
    echo "  - it starts automatically after a server reboot; join remains safe to re-run"
  else
    echo "  - join remains safe to re-run, but boot start requires administrator enablement"
  fi
else
  echo "  - compatibility log: $LOG_FILE"
  echo "  - this fallback is not boot-persistent; ask the administrator to enable:"
  echo "      sudo systemctl enable --now $SYSTEMD_UNIT"
fi
echo "  - proxy environment: ${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/env.sh"
echo '  - enable shell controls now: source "${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/env.sh"'
echo "  - or open a new terminal; use pto-auth-proxy auto/on/off to switch later"
echo "  - VS Code / Codex already running must use Reload Window when convenient"
echo "  - no running process was restarted by join"
echo
echo "  Optional end-to-end verification:"
echo "       pto-auth-proxy test"
echo
