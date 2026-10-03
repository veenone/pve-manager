#!/usr/bin/env bash
# Regression tests for guest_create_user (create user + optional sudo +
# optional SSH key access, shared by the LXC and VM wizards).
# Self-contained: builds a function library from ../pve-manager.sh, stubs out
# the pct/qm-touching primitives, and runs in a throwaway HOME.
#   bash tests/guest-create-user.test.sh
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

# --- Stub every pct/qm/ssh-touching primitive the function depends on ---
MOCK_CALLS=()
MOCK_OS=""
MOCK_USER_EXISTS=0
MOCK_SUDO_INSTALLED=0
MOCK_SSHD_INSTALLED=0
MOCK_SUDO_GROUP="sudo"   # which group `getent group sudo` should report present

fake_exec() {
    local tag="$1"; shift
    local vmid="$1"; shift
    local cmd="$*"
    MOCK_CALLS+=("$tag|$vmid|$cmd")
    case "$cmd" in
        "id -u '"*"'")
            [[ "$MOCK_USER_EXISTS" == "1" ]] && return 0 || return 1
            ;;
        "command -v sudo")
            [[ "$MOCK_SUDO_INSTALLED" == "1" ]] && return 0 || return 1
            ;;
        "command -v sshd")
            [[ "$MOCK_SSHD_INSTALLED" == "1" ]] && return 0 || return 1
            ;;
        "getent group sudo")
            [[ "$MOCK_SUDO_GROUP" == "sudo" ]] && return 0 || return 1
            ;;
        useradd*|"adduser -D"*)
            MOCK_USER_EXISTS=1
            ;;
    esac
    return 0
}
lxc_exec()      { fake_exec EXEC "$@"; }
vm_exec()       { fake_exec EXEC "$@"; }
# Simulate a successful package install, matching only the package the real
# command line actually installs (sudo install must not also "install" sshd).
fake_exec_live() {
    fake_exec LIVE "$@"
    local cmd="$*"
    [[ "$cmd" == *sudo* ]] && MOCK_SUDO_INSTALLED=1
    [[ "$cmd" == *openssh* ]] && MOCK_SSHD_INSTALLED=1
}
lxc_exec_live() { fake_exec_live "$@"; }
vm_exec_live()  { fake_exec_live "$@"; }
detect_container_os() { echo "$MOCK_OS"; }
detect_vm_os()         { echo "$MOCK_OS"; }
ssh_get_pubkey() { echo "ssh-ed25519 AAAAFAKEKEY pve-manager@host"; }
ssh_generate_key() { MOCK_CALLS+=("GENKEY"); }

reset_mocks() {
    MOCK_CALLS=(); MOCK_USER_EXISTS=0; MOCK_SUDO_INSTALLED=0; MOCK_SSHD_INSTALLED=0; MOCK_SUDO_GROUP="sudo"
}
calls_matching() { local pat="$1"; printf '%s\n' "${MOCK_CALLS[@]}" | grep -c "$pat"; }

# Run in the CURRENT shell (not a command-substitution subshell) so MOCK_CALLS
# mutations survive, while still capturing stdout+rc for assertions. Also
# captures whatever password (if any) was written to the pwfile, since it
# must never go to stdout.
run_create() {
    local tmp pwtmp; tmp=$(mktemp); pwtmp=$(mktemp)
    guest_create_user "$@" "$pwtmp" > "$tmp" 2>&1
    rc=$?
    out=$(cat "$tmp")
    pwout=$(cat "$pwtmp" 2>/dev/null)
    rm -f "$tmp" "$pwtmp"
}

echo "--- LXC: plain user, no sudo, no ssh (debian) ---"
reset_mocks; MOCK_OS="debian"
run_create lxc_exec lxc_exec_live detect_container_os 101 alice 0 0
ck "returns success"             "0" "$rc"
has "creates the user with useradd" - "$(calls_matching "useradd -m -s /bin/bash 'alice'")"
has "sets a generated password"  - "$(calls_matching 'chpasswd')"
hasnot "does not touch sudo"     - "$(calls_matching 'usermod -aG')"
hasnot "does not install sshd"   - "$(calls_matching 'openssh-server')"
hasnot "does not touch authorized_keys" - "$(calls_matching 'authorized_keys')"
ck "emits a non-empty password to pwfile"  "1" "$([[ -n "$pwout" ]] && echo 1 || echo 0)"
hasnot "never leaks the password onto stdout" - "$(echo "$out" | grep -cF "$pwout")"

echo "--- LXC: sudo + ssh, sudo group present, sshd missing (debian) ---"
reset_mocks; MOCK_OS="debian"; MOCK_SUDO_INSTALLED=1
run_create lxc_exec lxc_exec_live detect_container_os 102 bob 1 1
ck "returns success"             "0" "$rc"
hasnot "does not reinstall sudo" - "$(calls_matching 'apt-get install -y sudo')"
has "adds bob to the sudo group" - "$(calls_matching "usermod -aG sudo 'bob'")"
has "installs openssh-server"    - "$(calls_matching 'openssh-server')"
has "appends the pve-manager pubkey" - "$(calls_matching 'AAAAFAKEKEY')"
has "fixes ownership of .ssh"    - "$(calls_matching "chown -R 'bob:bob'")"
has "enables the debian ssh service" - "$(calls_matching 'systemctl enable ssh ')"

echo "--- Alpine: sudo with only the wheel group present ---"
reset_mocks; MOCK_OS="alpine"; MOCK_SUDO_GROUP="wheel"
run_create lxc_exec lxc_exec_live detect_container_os 103 carol 1 0
has "uses adduser on alpine"     - "$(calls_matching "adduser -D -s /bin/ash 'carol'")"
has "falls back to the wheel group" - "$(calls_matching "usermod -aG wheel 'carol'")"
has "installs sudo via apk"      - "$(calls_matching 'apk.*sudo')"

echo "--- VM: same core logic via vm_exec/vm_exec_live (centos, both) ---"
reset_mocks; MOCK_OS="centos"
run_create vm_exec vm_exec_live detect_vm_os 201 dave 1 1
ck "returns success"             "0" "$rc"
has "creates the user via vm_exec" - "$(calls_matching "EXEC\|201\|useradd")"
has "installs sudo via dnf"      - "$(calls_matching 'dnf install -y sudo')"
has "installs sshd via dnf"      - "$(calls_matching 'dnf install -y openssh-server')"
has "uses systemctl sshd (non-debian)" - "$(calls_matching 'systemctl enable sshd')"

echo "--- refuses to recreate an existing user ---"
reset_mocks; MOCK_OS="debian"; MOCK_USER_EXISTS=1
run_create lxc_exec lxc_exec_live detect_container_os 104 eve 0 0
ck "fails"                       "1" "$rc"
has "reports the conflict"       - "$(echo "$out" | grep -c 'already exists')"
hasnot "never calls chpasswd"    - "$(calls_matching 'chpasswd')"

echo "--- menu wiring ---"
has "LXC menu offers user creation"  - "$(declare -f lxc_management_menu | grep -c 'lxc_create_user_wizard')"
has "VM menu offers user creation"   - "$(declare -f vm_management_menu | grep -c 'vm_create_user_wizard')"
has "VM wizard requires the guest agent" - "$(declare -f vm_create_user_wizard | grep -c 'vm_has_guest_agent')"
has "common wizard validates the username" - "$(declare -f guest_create_user_wizard_common | grep -c '\[a-z_\]')"

echo
echo "  PASS: $pass  FAIL: $fail"
[[ $fail -eq 0 ]]
