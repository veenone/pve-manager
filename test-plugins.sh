#!/bin/bash
# Plugin System Test Script
# Tests the plugin infrastructure without requiring actual PVE deployment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS++)) || true
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL++)) || true
}

info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

echo ""
echo "========================================"
echo "  Plugin System Test Suite"
echo "========================================"
echo ""

# Source the main script to get functions
info "Loading pve-manager.sh functions..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Create a temporary version that doesn't auto-run and removes trap/pipefail
TMP_SCRIPT=$(mktemp)
sed -e '/^main "\$@"$/d' \
    -e '/^trap cleanup EXIT$/d' \
    -e '/^set -o pipefail$/d' \
    "$SCRIPT_DIR/pve-manager.sh" > "$TMP_SCRIPT"

# Mock dialog detection
export DIALOG_TYPE="whiptail"

# Source without strict error checking
source "$TMP_SCRIPT" 2>/dev/null
rm -f "$TMP_SCRIPT"

info "Functions loaded successfully"

# Test 1: Initialize config and plugins
info "Test 1: Initializing config and plugins..."
init_config 2>/dev/null
if [[ -d "$PLUGINS_DIR" ]]; then
    pass "Plugins directory created: $PLUGINS_DIR"
else
    fail "Plugins directory not created"
fi

# Test 2: Create built-in plugins
info "Test 2: Creating built-in plugins..."
# Clear existing plugins for clean test
rm -rf "$PLUGINS_DIR"/* 2>/dev/null
create_builtin_plugins 2>/dev/null

PLUGIN_COUNT=$(find "$PLUGINS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
if [[ "$PLUGIN_COUNT" -eq 21 ]]; then
    pass "Created 21 plugins"
else
    fail "Expected 21 plugins, got $PLUGIN_COUNT"
fi

# Test 3: Load plugins
info "Test 3: Loading plugins..."
load_plugins 2>/dev/null
LOADED_COUNT=${#PLUGINS[@]}
if [[ "$LOADED_COUNT" -eq 21 ]]; then
    pass "Loaded 21 plugins into PLUGINS array"
else
    fail "Expected 21 loaded plugins, got $LOADED_COUNT"
fi

# Test 4: Verify all expected plugins exist
info "Test 4: Verifying all 21 plugins..."
EXPECTED_PLUGINS=(
    prometheus grafana loki alloy node-exporter monitoring-stack
    sonarqube nexus gitea jenkins harbor dependency-track
    kiwi-tcms selenium-grid testlink
    pihole keycloak freeipa postfix-relay traefik nginx
)

for plugin in "${EXPECTED_PLUGINS[@]}"; do
    if is_plugin_service "$plugin" 2>/dev/null; then
        pass "Plugin exists: $plugin"
    else
        fail "Plugin missing: $plugin"
    fi
done

# Test 5: Verify plugin.conf files
info "Test 5: Verifying plugin.conf files..."
for plugin in "${EXPECTED_PLUGINS[@]}"; do
    conf="${PLUGINS[$plugin]}/plugin.conf"
    if [[ -f "$conf" ]]; then
        # Check required fields
        plugin_id=$(get_plugin_value "$conf" "PLUGIN_ID")
        plugin_name=$(get_plugin_value "$conf" "PLUGIN_NAME")
        plugin_category=$(get_plugin_value "$conf" "PLUGIN_CATEGORY")

        if [[ -n "$plugin_id" && -n "$plugin_name" && -n "$plugin_category" ]]; then
            pass "plugin.conf valid: $plugin (Category=$plugin_category)"
        else
            fail "plugin.conf incomplete: $plugin"
        fi
    else
        fail "plugin.conf missing: $plugin"
    fi
done

# Test 6: Verify compose.yml files
info "Test 6: Verifying compose.yml files..."
for plugin in "${EXPECTED_PLUGINS[@]}"; do
    compose="${PLUGINS[$plugin]}/compose.yml"
    if [[ -f "$compose" ]]; then
        # Check it contains valid docker-compose structure
        if grep -q "version:" "$compose" && grep -q "services:" "$compose"; then
            pass "compose.yml valid: $plugin"
        else
            fail "compose.yml invalid structure: $plugin"
        fi
    else
        fail "compose.yml missing: $plugin"
    fi
done

# Test 7: Verify Docker support detection
info "Test 7: Verifying Docker support detection..."
for plugin in "${EXPECTED_PLUGINS[@]}"; do
    if plugin_supports_docker "$plugin" 2>/dev/null; then
        pass "Docker support detected: $plugin"
    else
        fail "Docker support not detected: $plugin"
    fi
done

# Test 8: Verify native support for specific services
info "Test 8: Verifying native support detection..."
NATIVE_PLUGINS=(prometheus grafana gitea jenkins kiwi-tcms testlink sonarqube pihole harbor)
for plugin in "${NATIVE_PLUGINS[@]}"; do
    if plugin_supports_native "$plugin" 2>/dev/null; then
        # Check install.sh exists
        if [[ -f "${PLUGINS[$plugin]}/install.sh" ]]; then
            pass "Native support + install.sh: $plugin"
        else
            fail "Native support but no install.sh: $plugin"
        fi
    else
        fail "Native support not detected: $plugin"
    fi
done

# Test 9: Verify non-native services don't claim native support
info "Test 9: Verifying non-native services..."
NON_NATIVE_PLUGINS=(loki alloy node-exporter monitoring-stack nexus dependency-track selenium-grid keycloak freeipa postfix-relay traefik)
for plugin in "${NON_NATIVE_PLUGINS[@]}"; do
    if ! plugin_supports_native "$plugin" 2>/dev/null; then
        pass "Correctly no native support: $plugin"
    else
        fail "Should not have native support: $plugin"
    fi
done

# Test 10: Test get_plugin_compose()
info "Test 10: Testing get_plugin_compose()..."
for plugin in prometheus grafana jenkins; do
    compose_content=$(get_plugin_compose "$plugin" 2>/dev/null)
    if [[ -n "$compose_content" ]] && echo "$compose_content" | grep -q "services:"; then
        pass "get_plugin_compose works: $plugin"
    else
        fail "get_plugin_compose failed: $plugin"
    fi
done

# Test 11: Test get_service_compose() with plugin-first logic
info "Test 11: Testing get_service_compose() plugin-first logic..."
for plugin in prometheus grafana jenkins; do
    compose_content=$(get_service_compose "$plugin" 2>/dev/null)
    if [[ -n "$compose_content" ]] && echo "$compose_content" | grep -q "services:"; then
        pass "get_service_compose (plugin-first) works: $plugin"
    else
        fail "get_service_compose (plugin-first) failed: $plugin"
    fi
done

# Test 12: Test access info functions
info "Test 12: Testing access info functions..."
TEST_IP="192.168.1.100"
for plugin in prometheus grafana jenkins; do
    docker_info=$(get_plugin_docker_access_info "$plugin" "$TEST_IP" 2>/dev/null)
    if [[ -n "$docker_info" ]] && echo "$docker_info" | grep -q "$TEST_IP"; then
        pass "Docker access info works: $plugin"
    else
        fail "Docker access info failed: $plugin"
    fi
done

for plugin in prometheus grafana; do
    native_info=$(get_plugin_native_access_info "$plugin" "$TEST_IP" 2>/dev/null)
    if [[ -n "$native_info" ]] && echo "$native_info" | grep -q "$TEST_IP"; then
        pass "Native access info works: $plugin"
    else
        fail "Native access info failed: $plugin"
    fi
done

# Test 13: Test category listing
info "Test 13: Testing category listing..."
MONITORING=$(list_plugins_by_category "monitoring" 2>/dev/null | wc -l)
DEVTOOLS=$(list_plugins_by_category "devtools" 2>/dev/null | wc -l)
TESTING=$(list_plugins_by_category "testing" 2>/dev/null | wc -l)
INFRASTRUCTURE=$(list_plugins_by_category "infrastructure" 2>/dev/null | wc -l)

if [[ "$MONITORING" -eq 6 ]]; then
    pass "Monitoring category: 6 plugins"
else
    fail "Monitoring category: expected 6, got $MONITORING"
fi

if [[ "$DEVTOOLS" -eq 6 ]]; then
    pass "Devtools category: 6 plugins"
else
    fail "Devtools category: expected 6, got $DEVTOOLS"
fi

if [[ "$TESTING" -eq 3 ]]; then
    pass "Testing category: 3 plugins"
else
    fail "Testing category: expected 3, got $TESTING"
fi

if [[ "$INFRASTRUCTURE" -eq 6 ]]; then
    pass "Infrastructure category: 6 plugins"
else
    fail "Infrastructure category: expected 6, got $INFRASTRUCTURE"
fi

# Test 14: Test get_plugin_name()
info "Test 14: Testing get_plugin_name()..."
for plugin in prometheus grafana jenkins; do
    name=$(get_plugin_name "$plugin" 2>/dev/null)
    if [[ -n "$name" ]]; then
        pass "get_plugin_name works: $plugin -> $name"
    else
        fail "get_plugin_name failed: $plugin"
    fi
done

# Test 15: Verify remove.sh exists for native plugins
info "Test 15: Verifying remove.sh for native plugins..."
for plugin in "${NATIVE_PLUGINS[@]}"; do
    if [[ -f "${PLUGINS[$plugin]}/remove.sh" ]]; then
        pass "remove.sh exists: $plugin"
    else
        fail "remove.sh missing: $plugin"
    fi
done

echo ""
echo "========================================"
echo "  Test Results"
echo "========================================"
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}All tests passed! Plugin system is working correctly.${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review the output above.${NC}"
    exit 1
fi
