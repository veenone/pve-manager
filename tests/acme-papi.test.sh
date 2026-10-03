#!/usr/bin/env bash
# Regression tests for the Proxmox-product (PDM/PBS) certificate API target.
# Self-contained: builds a function library from ../pve-manager.sh and runs in a
# throwaway HOME, so it touches no real configuration.
#   bash tests/acme-papi.test.sh
HERE=$(cd "$(dirname "$0")" && pwd)
LIB=$(mktemp); sed '$ d' "$HERE/../pve-manager.sh" > "$LIB"
export HOME=$(mktemp -d)
trap 'rm -rf "$HOME" "$LIB"' EXIT
source "$LIB"
init_config >/dev/null 2>&1
ACME_DOMAIN=rumahcemara.top; ACME_SUBDOMAIN=lan
pass=0; fail=0
ck(){ if [[ "$2" == "$3" ]]; then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1 (exp [$2] got [$3])"; fail=$((fail+1)); fi; }
has(){ if (( $3 >= 1 )); then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1 (expected >=1, got $3)"; fail=$((fail+1)); fi; }
mkdir -p "$ACME_DIR/api"

echo "--- credential loading (must run in the CALLING shell) ---"
printf "PDM_URL='https://h:8443/'\nPDM_TOKEN_ID='root@pam!t'\nPDM_TOKEN_SECRET='s1'\n" > "$ACME_DIR/api/1.env"
printf "PBS_URL='https://p:8007'\nPBS_TOKEN_ID='root@pam!b'\nPBS_TOKEN_SECRET='s2'\n"   > "$ACME_DIR/api/2.env"
printf "PX_URL='https://x:1'\nPX_SCHEME='PVEAPIToken'\nPX_TOKEN_ID='a@b!c'\nPX_TOKEN_SECRET='s3'\n" > "$ACME_DIR/api/3.env"
acme_papi_load 1
ck "PDM aliases map to PX_*"   "https://h:8443|root@pam!t|s1|PDMAPIToken" "$PX_URL|$PX_TOKEN_ID|$PX_TOKEN_SECRET|$PX_SCHEME"
acme_papi_load 2
ck "PBS aliases + scheme"      "https://p:8007|root@pam!b|s2|PBSAPIToken" "$PX_URL|$PX_TOKEN_ID|$PX_TOKEN_SECRET|$PX_SCHEME"
acme_papi_load 3
ck "explicit PX_* win"         "https://x:1|a@b!c|s3|PVEAPIToken" "$PX_URL|$PX_TOKEN_ID|$PX_TOKEN_SECRET|$PX_SCHEME"
acme_papi_load 1; acme_papi_load 2
ck "no leakage between targets" "root@pam!b|s2" "$PX_TOKEN_ID|$PX_TOKEN_SECRET"
ck "trailing slash stripped"    "0" "$(acme_papi_load 1; [[ "$PX_URL" == */ ]] && echo 1 || echo 0)"
ck "missing file refused"       "1" "$(acme_papi_load 404 >/dev/null 2>&1; echo $?)"
printf "PX_URL='https://x:1'\n" > "$ACME_DIR/api/5.env"
has "incomplete file names what is missing" - "$(acme_papi_load 5 2>&1 | grep -c 'PX_TOKEN_ID PX_TOKEN_SECRET')"
ck "deploy does NOT load creds in a subshell" "0" "$(declare -f acme_deploy_proxmox_api | grep -c '=\$(acme_papi_load')"

echo "--- safety before a private key leaves the host ---"
has "checks the token authenticates"   - "$(declare -f acme_deploy_proxmox_api | grep -c 'GET /version')"
has "checks System.Modify first"       - "$(declare -f acme_deploy_proxmox_api | grep -c 'System.Modify\":true')"
has "explains token-vs-user permission" - "$(declare -f acme_deploy_proxmox_api | grep -c 'API Token Permission')"
has "validates local cert first"       - "$(declare -f acme_deploy_proxmox_api | grep -c 'acme_validate_local_cert')"
has "idempotent: skips if already served" - "$(declare -f acme_deploy_proxmox_api | grep -c 'nothing to do')"
has "verifies adoption on the live socket" - "$(declare -f acme_deploy_proxmox_api | grep -c 'acme_papi_live_serial')"
has "offers a rollback on non-adoption"  - "$(declare -f acme_deploy_proxmox_api | grep -c 'DELETE')"
ck "registration refuses a 0644 secret" "1" "$(chmod 644 "$ACME_DIR/api/1.env"; acme_register_proxmox_api 7 x "$ACME_DIR/api/1.env" >/dev/null 2>&1; echo $?)"
ck "curl never reads caller stdin"     "1" "$(declare -f acme_papi_call | grep -c '< /dev/null')"

echo "--- renewal wiring ---"
has "redeploy dispatches papi targets" - "$(declare -f acme_redeploy_targets | grep -c 'acme_deploy_proxmox_api')"
has "menu offers registration"         - "$(declare -f acme_menu | grep -c 'acme_register_proxmox_api')"

echo
echo "  PASS: $pass  FAIL: $fail"
[[ $fail -eq 0 ]]
