# Plugin Architecture Refactoring - Corrected Plan

## Current State Analysis

The script currently has **NO plugin infrastructure**. All service configurations are embedded directly in case statements.

### Functions with Embedded Service Logic

| Function | Lines | Location | Content |
|----------|-------|----------|---------|
| `get_service_compose()` | ~824 | 3535-4358 | 21 Docker compose templates |
| `deploy_service_native()` | ~1036 | 4409-5444 | 8 native installation scripts |
| `remove_native_service()` | ~238 | 5999-6236 | 9 native removal scripts |
| `deploy_service_wizard()` | ~119 | 7410-7528 | 27 access info entries |
| **Total embedded code** | **~2,217** | | |

### Services Inventory

**21 Services Total:**

| Category | Services | Native Support |
|----------|----------|----------------|
| Monitoring | prometheus, grafana, loki, alloy, node-exporter, monitoring-stack | prometheus, grafana |
| DevTools | sonarqube, nexus, gitea, jenkins, harbor, dependency-track | sonarqube, gitea, jenkins |
| Testing | kiwi-tcms, selenium-grid, testlink | kiwi-tcms, testlink |
| Infrastructure | pihole, keycloak, freeipa, postfix-relay, traefik | pihole |

**8 services with native installation support** (require install.sh/remove.sh)

---

## Implementation Plan

### Phase 1: Add Plugin Infrastructure (~200 lines)

**1.1 Add Plugin Directory Configuration**

```bash
# Add to CONFIGURATION section (after line 32)
readonly PLUGINS_DIR="$CONFIG_DIR/plugins"

# Add to init_config() (line 67)
mkdir -p "$PLUGINS_DIR"
```

**1.2 Create Plugin Helper Functions**

Add after line 91 (after init_config):

```bash
# Declare plugin associative arrays
declare -gA PLUGINS
declare -gA PLUGIN_CATEGORIES

# Load plugins from directory
load_plugins() {
    PLUGINS=()
    PLUGIN_CATEGORIES=()
    [[ ! -d "$PLUGINS_DIR" ]] && return

    for plugin_dir in "$PLUGINS_DIR"/*/; do
        [[ -d "$plugin_dir" ]] || continue
        local plugin_id=$(basename "$plugin_dir")
        local conf="$plugin_dir/plugin.conf"

        if [[ -f "$conf" ]]; then
            PLUGINS["$plugin_id"]="$plugin_dir"
            local category=$(grep "^PLUGIN_CATEGORY=" "$conf" | cut -d= -f2 | tr -d '"')
            PLUGIN_CATEGORIES["$category"]=1
        fi
    done
}

# Get value from plugin.conf
get_plugin_value() {
    local conf="$1" key="$2"
    grep "^${key}=" "$conf" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'"
}

# Check if service is a plugin
is_plugin_service() {
    [[ -n "${PLUGINS[$1]}" ]]
}

# Check plugin capabilities
plugin_supports_docker() {
    local conf="${PLUGINS[$1]}/plugin.conf"
    [[ "$(get_plugin_value "$conf" "PLUGIN_DOCKER_SUPPORT")" == "true" ]]
}

plugin_supports_native() {
    local conf="${PLUGINS[$1]}/plugin.conf"
    [[ "$(get_plugin_value "$conf" "PLUGIN_NATIVE_SUPPORT")" == "true" ]]
}

# Get plugin compose content
get_plugin_compose() {
    local plugin_id="$1"
    local compose_file="${PLUGINS[$plugin_id]}/compose.yml"
    [[ -f "$compose_file" ]] && cat "$compose_file"
}

# Get plugin access info
get_plugin_docker_access_info() {
    local plugin_id="$1" ip="$2"
    local conf="${PLUGINS[$plugin_id]}/plugin.conf"
    local url=$(get_plugin_value "$conf" "PLUGIN_DOCKER_URL")
    local creds=$(get_plugin_value "$conf" "PLUGIN_DOCKER_CREDENTIALS")
    url="${url//\{IP\}/$ip}"
    [[ -n "$creds" ]] && echo -e "$url\n$creds" || echo "$url"
}

get_plugin_native_access_info() {
    local plugin_id="$1" ip="$2"
    local conf="${PLUGINS[$plugin_id]}/plugin.conf"
    local url=$(get_plugin_value "$conf" "PLUGIN_NATIVE_URL")
    local creds=$(get_plugin_value "$conf" "PLUGIN_NATIVE_CREDENTIALS")
    url="${url//\{IP\}/$ip}"
    [[ -n "$creds" ]] && echo -e "$url\n$creds" || echo "$url"
}
```

---

### Phase 2: Create Plugin Definitions (~1,500 lines)

Create functions to generate all 21 plugins with complete files.

**2.1 Plugin Directory Helper**

```bash
create_plugin_dir() {
    local plugin_id="$1"
    local plugin_dir="$PLUGINS_DIR/$plugin_id"
    mkdir -p "$plugin_dir"
    echo "$plugin_dir"
}
```

**2.2 Example Plugin Creation (Prometheus)**

```bash
create_plugin_prometheus() {
    local dir=$(create_plugin_dir "prometheus")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="prometheus"
PLUGIN_NAME="Prometheus"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="monitoring"
PLUGIN_DESCRIPTION="Metrics collection and alerting"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu alpine"
PLUGIN_DOCKER_PORT="9090"
PLUGIN_DOCKER_URL="http://{IP}:9090"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_NATIVE_URL="http://{IP}:9090"
PLUGIN_NATIVE_CREDENTIALS=""
PLUGIN_SYSTEMD_SERVICE="prometheus"
PLUGIN_DOCKER_CONTAINER="prometheus"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - prometheus_data:/prometheus
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
volumes:
  prometheus_data:
EOF

    # install.sh (native)
    cat > "$dir/install.sh" << 'EOF'
#!/bin/bash
case "$OS_TYPE" in
    debian|ubuntu)
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y prometheus"
        lxc_exec_live "$VMID" "systemctl enable prometheus"
        lxc_exec_live "$VMID" "systemctl start prometheus"
        ;;
    alpine)
        lxc_exec_live "$VMID" "apk add --no-cache prometheus"
        lxc_exec_live "$VMID" "rc-update add prometheus"
        lxc_exec_live "$VMID" "rc-service prometheus start"
        ;;
    *) echo "Unsupported OS: $OS_TYPE"; exit 1 ;;
esac
EOF

    # remove.sh (native)
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
case "$OS_TYPE" in
    debian|ubuntu)
        lxc_exec_live "$VMID" "systemctl stop prometheus || true"
        lxc_exec_live "$VMID" "apt-get purge -y prometheus"
        lxc_exec_live "$VMID" "rm -rf /var/lib/prometheus /etc/prometheus"
        ;;
    alpine)
        lxc_exec_live "$VMID" "rc-service prometheus stop || true"
        lxc_exec_live "$VMID" "apk del prometheus"
        ;;
esac
EOF

    # prometheus.yml (extra config)
    cat > "$dir/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF
}
```

**2.3 Services Requiring Full Native Scripts**

These need complete install.sh and remove.sh (copy from existing embedded code):

| Service | install.sh lines | remove.sh lines |
|---------|-----------------|-----------------|
| prometheus | ~20 | ~15 |
| grafana | ~25 | ~20 |
| gitea | ~40 | ~15 |
| jenkins | ~30 | ~20 |
| kiwi-tcms | ~200 | ~30 |
| testlink | ~350 | ~40 |
| sonarqube | ~100 | ~35 |
| pihole | ~60 | ~40 |

**2.4 Initialization Function**

```bash
init_builtin_plugins() {
    [[ $(find "$PLUGINS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l) -gt 0 ]] && return

    log_info "Initializing built-in plugins..."
    create_plugin_prometheus
    create_plugin_grafana
    # ... all 21 plugins
}
```

---

### Phase 3: Add Plugin-First Logic to Core Functions (~50 lines)

**3.1 Modify get_service_compose()**

```bash
get_service_compose() {
    local service="$1"

    # Try plugin first
    if is_plugin_service "$service"; then
        get_plugin_compose "$service"
        return
    fi

    # Fall back to legacy embedded templates
    case "$service" in
        # ... existing case statements unchanged
    esac
}
```

**3.2 Modify deploy_service_native()**

```bash
deploy_service_native() {
    local vmid="$1" service="$2" service_name="$3"

    # Try plugin first
    if is_plugin_service "$service" && plugin_supports_native "$service"; then
        local install_script="${PLUGINS[$service]}/install.sh"
        if [[ -f "$install_script" ]]; then
            # Run plugin install script
            export VMID="$vmid"
            export OS_TYPE=$(detect_container_os "$vmid")
            source "$install_script"
            return $?
        fi
    fi

    # Fall back to legacy
    # ... existing case statements unchanged
}
```

**3.3 Modify remove_native_service()**

Similar pattern - try plugin remove.sh first, fall back to legacy.

**3.4 Modify deploy_service_wizard()**

```bash
# Replace hardcoded access info with:
if is_plugin_service "$service"; then
    access_info=$(get_plugin_docker_access_info "$service" "$ip")
else
    # Legacy fallback case statements
fi
```

---

### Phase 4: Call Plugin Initialization (~5 lines)

Add to main script initialization (around line 7750):

```bash
# Initialize plugins before main menu
init_builtin_plugins
load_plugins
```

---

### Phase 5 (Optional): Remove Legacy Fallbacks

**Only after verifying all plugins work correctly:**

1. Remove legacy case statements from `get_service_compose()` (~800 lines)
2. Remove legacy case statements from `deploy_service_native()` (~1000 lines)
3. Remove legacy case statements from `remove_native_service()` (~200 lines)
4. Remove legacy access info from `deploy_service_wizard()` (~50 lines)

**Total potential reduction: ~2,050 lines**

---

## Implementation Order

1. **Phase 1**: Add plugin infrastructure (can't break anything)
2. **Phase 2**: Create all plugin definitions (can't break anything)
3. **Phase 3**: Add plugin-first logic with legacy fallback (safe)
4. **Phase 4**: Initialize plugins on startup
5. **Test thoroughly**
6. **Phase 5**: Remove legacy code (only after testing)

---

## Testing Checklist

Before removing legacy fallbacks:

- [ ] All 21 plugins created in ~/.pve-manager/plugins/
- [ ] Each plugin has: plugin.conf, compose.yml
- [ ] 8 native-support plugins have: install.sh, remove.sh
- [ ] Docker deployment works for all services
- [ ] Native deployment works for: prometheus, grafana, gitea, jenkins, kiwi-tcms, testlink, sonarqube, pihole
- [ ] Native removal works for all 8 services
- [ ] Access info displays correctly after deployment

---

## File Changes Summary

| File | Changes |
|------|---------|
| pve-manager.sh | +200 lines (plugin infra) |
| pve-manager.sh | +1500 lines (plugin creators) |
| pve-manager.sh | +50 lines (plugin-first logic) |
| pve-manager.sh | -2050 lines (Phase 5 only) |
| **Net change** | **-300 lines** (after Phase 5) |

The main benefit is not line reduction but **maintainability** - adding a new service becomes adding one function instead of modifying 4+ locations.
