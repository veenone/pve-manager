#!/usr/bin/env bash
# Regression tests for lxc_enable_root_ssh (remote SSH root access on an LXC).
# Self-contained: builds a function library from ../pve-manager.sh, stubs out
# the pct/ssh-touching primitives, and runs in a throwaway HOME.
#   bash tests/lxc-enable-root-ssh.test.sh
HERE=$(cd "$(dirname "$0")" && pwd)
LIB=$(mktemp); sed '$ d' "$HERE/../pve-manager.sh" > "$LIB"
export HOME=$(mktemp -d)
trap 'rm -rf "$HOME" "$LIB"' EXIT
source "$LIB"
init_config >/dev/null 2>&1

pass=0; fail=0
ck(){ if [[ "$2" == "$3" ]]; then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1 (exp [$2] got [$3])"; fail=$((fail+1)); fi; }
has(){ if (( $3 >= 1 )); then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1 (expected >=1, got $3)"; fail=$((fail+1)); fi; }
hasnot(){ if (( $3 == 0 )); then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1 (expected 0, got $3)"; fail=$((fail+1)); fi; }

# --- Stub every pct/ssh-touching primitive the function depends on ---
MOCK_CALLS=()
MOCK_OS=""
MOCK_SSHD_INSTALLED=0

lxc_exec() {
    local vmid="$1"; shift
    local cmd="$*"
    MOCK_CALLS+=("EXEC|$vmid|$cmd")
    if [[ "$cmd" == "command -v sshd" ]]; then
        [[ "$MOCK_SSHD_INSTALLED" == "1" ]] && return 0 || return 1
    fi
    return 0
}
lxc_exec_live() {
    local vmid="$1"; shift
    MOCK_CALLS+=("LIVE|$vmid|$*")
    MOCK_SSHD_INSTALLED=1   # simulate a successful package install
    return 0
}
lxc_exec_timeout() {
    local vmid="$1" t="$2"; shift 2
    MOCK_CALLS+=("TIMEOUT|$vmid|$*")
    echo "10.0.0.5"
}
detect_container_os() { echo "$MOCK_OS"; }
ssh_copy_to_container() { MOCK_CALLS+=("COPYKEY|$1"); return 0; }
ssh_generate_key() {
    MOCK_CALLS+=("GENKEY")
    local f="$SSH_DIR/id_${SSH_KEY_TYPE:-ed25519}"
    mkdir -p "$SSH_DIR"; touch "$f" "$f.pub"
}

reset_mocks() { MOCK_CALLS=(); }
calls_matching() { local pat="$1"; printf '%s\n' "${MOCK_CALLS[@]}" | grep -c "$pat"; }

# Run in the CURRENT shell (not a command-substitution subshell) so that
# MOCK_CALLS mutations made by the stubbed lxc_exec* survive, while still
# capturing stdout+rc for assertions. Also captures whatever password (if
# any) the function wrote to its pwfile, since it must never go to stdout.
run_enable() {
    local tmp pwtmp; tmp=$(mktemp); pwtmp=$(mktemp)
    lxc_enable_root_ssh "$1" "$2" "$pwtmp" > "$tmp" 2>&1
    rc=$?
    out=$(cat "$tmp")
    pwout=$(cat "$pwtmp" 2>/dev/null)
    rm -f "$tmp" "$pwtmp"
}

echo "--- key-only mode (debian, sshd missing) ---"
reset_mocks; MOCK_OS="debian"; MOCK_SSHD_INSTALLED=0
run_enable 101 key
ck "returns success"                 "0" "$rc"
has "installs openssh-server"        - "$(calls_matching 'openssh-server')"
has "sets PermitRootLogin prohibit-password" - "$(calls_matching 'PermitRootLogin prohibit-password')"
has "copies the SSH key to the container"    - "$(calls_matching 'COPYKEY\|101')"
hasnot "never calls chpasswd"        - "$(calls_matching 'chpasswd')"
has "enables the debian ssh service" - "$(calls_matching 'systemctl enable ssh ')"
has "prints the ssh connect command" - "$(echo "$out" | grep -c 'ssh -i .*root@10.0.0.5')"
hasnot "no password written to pwfile in key mode" - "$([[ -z "$pwout" ]] && echo 0 || echo 1)"
hasnot "never leaks the password onto stdout" - "$(echo "$out" | grep -cE '[A-Za-z0-9+/]{16,}')"

echo "--- password-only mode (alpine, sshd already present) ---"
reset_mocks; MOCK_OS="alpine"; MOCK_SSHD_INSTALLED=1
run_enable 102 password
ck "returns success"                 "0" "$rc"
hasnot "does not reinstall sshd"     - "$(calls_matching 'apk add openssh')"
has "sets PermitRootLogin yes"       - "$(calls_matching 'PermitRootLogin yes')"
hasnot "does not copy the SSH key"   - "$(calls_matching 'COPYKEY')"
has "sets a root password via chpasswd" - "$(calls_matching 'chpasswd')"
has "uses OpenRC to manage sshd on alpine" - "$(calls_matching 'rc-service sshd')"
ck "writes a non-empty password to pwfile" "1" "$([[ -n "$pwout" ]] && echo 1 || echo 0)"
hasnot "never leaks the password onto stdout" - "$(echo "$out" | grep -cF "$pwout")"

echo "--- both mode (centos) ---"
reset_mocks; MOCK_OS="centos"; MOCK_SSHD_INSTALLED=1
run_enable 103 both
has "sets PermitRootLogin yes for both mode" - "$(calls_matching 'PermitRootLogin yes')"
has "still copies the SSH key"       - "$(calls_matching 'COPYKEY\|103')"
has "still sets a root password"     - "$(calls_matching 'chpasswd')"
has "uses systemctl sshd on centos"  - "$(calls_matching 'systemctl enable sshd')"

echo "--- unsupported/undetected OS, no sshd available ---"
reset_mocks; MOCK_OS="plan9"; MOCK_SSHD_INSTALLED=0
run_enable 104 key
ck "fails"                           "1" "$rc"
has "reports an error"               - "$(echo "$out" | grep -c 'ERROR')"
hasnot "never touches sshd_config"   - "$(calls_matching 'PermitRootLogin')"

echo "--- unknown auth_mode falls back to key-only ---"
reset_mocks; MOCK_OS="debian"; MOCK_SSHD_INSTALLED=1
run_enable 105 bogus
has "defaults to prohibit-password"  - "$(calls_matching 'PermitRootLogin prohibit-password')"
has "still copies the SSH key"       - "$(calls_matching 'COPYKEY\|105')"

echo "--- menu wiring ---"
has "menu offers enabling root SSH on a container"     - "$(declare -f ssh_management_menu | grep -c 'lxc_enable_root_ssh')"
has "menu offers a bulk all-containers option"         - "$(declare -f ssh_management_menu | grep -c 'All Containers')"
has "bulk flow warns before enabling password auth"    - "$(declare -f ssh_management_menu | grep -c 'show_yesno')"

echo
echo "  PASS: $pass  FAIL: $fail"
[[ $fail -eq 0 ]]
