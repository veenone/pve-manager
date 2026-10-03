# PVE Manager Plugin Architecture Plan

## Overview
Refactor the existing pve-manager.sh to support a plugin-based architecture for services, enabling easy addition of new services without modifying the core script.

## Current State Analysis
- **Script size**: 6,916 lines
- **Services supported**: 17 services
- **Touch points per new service**: 7-10 different locations
- **Pattern**: Cascading case statements for service-specific logic

## Problem Statement
Adding a new service currently requires modifications in:
1. `get_service_compose()` - Docker compose templates
2. Category menu function - Menu entry
3. `deploy_service_wizard()` - Docker/Native access info (2 places)
4. `deploy_service_native()` - Native installation logic
5. `deploy_service_with_progress()` - Config file writing
6. `remove_native_service()` - Removal logic
7. Native service detection regex

This creates maintenance burden and risk of inconsistency.

## Proposed Plugin Architecture

### Directory Structure
```
~/.pve-manager/
├── config.conf
├── profiles.conf
├── ca/
├── ssh/
└── plugins/                    # Plugin directory
    ├── prometheus/
    │   ├── plugin.conf         # Metadata & configuration
    │   ├── compose.yml         # Docker compose template
    │   ├── install.sh          # Native installation script
    │   └── remove.sh           # Removal script
    ├── grafana/
    │   └── ...
    └── custom-service/         # User-defined plugins
        └── ...
```

### Plugin Definition Format (plugin.conf)
```bash
# Plugin metadata
PLUGIN_ID="prometheus"
PLUGIN_NAME="Prometheus"
PLUGIN_VERSION="2.50"
PLUGIN_CATEGORY="monitoring"        # monitoring|devtools|testing|infrastructure
PLUGIN_DESCRIPTION="Metrics collection and alerting"

# Deployment options
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu"    # Supported OS for native install

# Access information
PLUGIN_DOCKER_PORT="9090"
PLUGIN_DOCKER_URL="http://{IP}:9090"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_NATIVE_URL="http://{IP}:9090"
PLUGIN_NATIVE_CREDENTIALS=""

# Service detection (for removal/status)
PLUGIN_SYSTEMD_SERVICE="prometheus"
PLUGIN_DOCKER_CONTAINER="prometheus"

# Dependencies
PLUGIN_REQUIRES=""                  # Other plugins required
PLUGIN_CONFLICTS=""                 # Plugins that conflict
```

### Core Script Changes

#### 1. Plugin Loader Function
```bash
# Load all plugins from plugins directory
load_plugins() {
    PLUGINS_DIR="${CONFIG_DIR}/plugins"
    declare -gA PLUGINS

    for plugin_dir in "$PLUGINS_DIR"/*/; do
        [[ -d "$plugin_dir" ]] || continue
        local plugin_id=$(basename "$plugin_dir")
        local conf="$plugin_dir/plugin.conf"

        if [[ -f "$conf" ]]; then
            PLUGINS["$plugin_id"]="$plugin_dir"
        fi
    done
}
```

#### 2. Dynamic Menu Generation
```bash
# Generate service menu dynamically from plugins
generate_category_menu() {
    local category="$1"
    local menu_items=()
    local idx=1

    for plugin_id in "${!PLUGINS[@]}"; do
        source "${PLUGINS[$plugin_id]}/plugin.conf"
        if [[ "$PLUGIN_CATEGORY" == "$category" ]]; then
            menu_items+=("$idx" "$PLUGIN_NAME")
            MENU_MAP[$idx]="$plugin_id"
            ((idx++))
        fi
    done

    menu_items+=("0" "Back")
    show_menu "${category^} Tools" "Select service:" "${menu_items[@]}"
}
```

#### 3. Unified Deployment
```bash
deploy_plugin_service() {
    local plugin_id="$1"
    local method="$2"  # docker|native
    local vmid="$3"

    local plugin_dir="${PLUGINS[$plugin_id]}"
    source "$plugin_dir/plugin.conf"

    if [[ "$method" == "docker" ]]; then
        # Read compose template
        local compose_file="$plugin_dir/compose.yml"
        if [[ -f "$compose_file" ]]; then
            deploy_docker_from_template "$vmid" "$plugin_id" "$compose_file"
        fi
    elif [[ "$method" == "native" ]]; then
        # Run native install script
        local install_script="$plugin_dir/install.sh"
        if [[ -f "$install_script" ]]; then
            run_plugin_script "$vmid" "$install_script"
        fi
    fi
}
```

### Plugin Script Interface

#### compose.yml (Docker deployment)
Standard docker-compose format with variable substitution:
```yaml
version: '3.8'
services:
  ${PLUGIN_ID}:
    image: prom/prometheus:${PLUGIN_VERSION}
    container_name: ${PLUGIN_ID}
    ports:
      - "${PLUGIN_DOCKER_PORT}:9090"
    volumes:
      - ${PLUGIN_ID}_data:/prometheus
```

#### install.sh (Native installation)
```bash
#!/bin/bash
# Native installation script for Prometheus
# Available variables: VMID, OS_TYPE, PLUGIN_DIR

install_debian() {
    lxc_exec_live "$VMID" "apt-get update"
    lxc_exec_live "$VMID" "apt-get install -y prometheus"
    lxc_exec_live "$VMID" "systemctl enable prometheus"
    lxc_exec_live "$VMID" "systemctl start prometheus"
}

install_alpine() {
    lxc_exec_live "$VMID" "apk add prometheus"
    lxc_exec_live "$VMID" "rc-update add prometheus"
    lxc_exec_live "$VMID" "rc-service prometheus start"
}

# Main entry point
case "$OS_TYPE" in
    debian|ubuntu) install_debian ;;
    alpine) install_alpine ;;
    *) echo "Unsupported OS"; exit 1 ;;
esac
```

#### remove.sh (Service removal)
```bash
#!/bin/bash
# Removal script for Prometheus

remove_debian() {
    lxc_exec_live "$VMID" "systemctl stop prometheus"
    lxc_exec_live "$VMID" "apt-get purge -y prometheus"
    lxc_exec_live "$VMID" "rm -rf /var/lib/prometheus"
}

case "$OS_TYPE" in
    debian|ubuntu) remove_debian ;;
esac
```

## Implementation Steps

### Phase 1: Core Plugin Infrastructure
**Files to modify:** `pve-manager.sh`
**Estimated lines:** ~200 new, ~100 refactored

1. Add plugin directory initialization in `init_config()`
2. Create `load_plugins()` function
3. Create `get_plugin_value()` helper to read plugin.conf
4. Add plugin validation function

### Phase 2: Refactor Menu System
**Files to modify:** `pve-manager.sh`
**Estimated lines:** ~150 refactored

1. Replace hardcoded `monitoring_menu()`, `devtools_menu()`, `testing_menu()`, `infrastructure_menu()` with single `generate_category_menu()`
2. Update `service_deployment_menu()` to use dynamic categories
3. Maintain backward compatibility with existing services

### Phase 3: Refactor Deployment Functions
**Files to modify:** `pve-manager.sh`
**Estimated lines:** ~300 refactored

1. Create `deploy_plugin_docker()` that reads compose.yml
2. Create `deploy_plugin_native()` that runs install.sh
3. Create `get_plugin_access_info()` to replace hardcoded cases
4. Update `deploy_service_wizard()` to use new functions

### Phase 4: Refactor Removal Functions
**Files to modify:** `pve-manager.sh`
**Estimated lines:** ~150 refactored

1. Create `remove_plugin_service()` that runs remove.sh
2. Update `remove_service_wizard()` to detect plugin vs legacy
3. Update native service detection to include plugins

### Phase 5: Extract Existing Services to Plugins
**Files to create:** `~/.pve-manager/plugins/<service>/`
**Services to extract:** 17 services

For each service, create:
- `plugin.conf` - Metadata
- `compose.yml` - Docker template (if docker support)
- `install.sh` - Native install script (if native support)
- `remove.sh` - Removal script (if native support)

### Phase 6: Create Plugin Management Menu
**Files to modify:** `pve-manager.sh`
**Estimated lines:** ~100 new

1. Add "Plugin Management" to Settings menu
2. List installed plugins
3. Enable/disable plugins
4. View plugin information

## Key New Functions

```bash
# Plugin System
load_plugins()              # Load plugins from directory
get_plugin_value()          # Read value from plugin.conf
validate_plugin()           # Validate plugin structure
list_plugins_by_category()  # Get plugins for a category

# Dynamic Menus
generate_category_menu()    # Build menu from plugins
get_plugin_categories()     # Get unique categories

# Deployment
deploy_plugin_docker()      # Deploy using compose.yml
deploy_plugin_native()      # Deploy using install.sh
get_plugin_access_info()    # Get URL/credentials

# Removal
remove_plugin_service()     # Remove using remove.sh
detect_plugin_services()    # Find installed plugin services
```

## Backward Compatibility

To maintain backward compatibility during transition:

1. **Fallback mechanism**: If plugin not found, fall back to embedded case statements
2. **Gradual migration**: Extract services one by one to plugins
3. **Legacy detection**: Check both plugins and hardcoded services

```bash
get_service_compose() {
    local service="$1"

    # Try plugin first
    if [[ -n "${PLUGINS[$service]}" ]]; then
        cat "${PLUGINS[$service]}/compose.yml"
        return
    fi

    # Fall back to legacy embedded templates
    case "$service" in
        prometheus) ... ;;
        # existing cases
    esac
}
```

## Benefits

| Aspect | Current | With Plugins |
|--------|---------|--------------|
| Add new service | 7-10 code locations | 1 plugin directory |
| Update service | Find all case statements | Edit plugin files |
| Remove service | Delete from multiple functions | Delete plugin folder |
| Share service | Copy code snippets | Share plugin folder |
| Test service | Test entire script | Test plugin in isolation |

## Files to Modify

| File | Changes |
|------|---------|
| `/root/pve-manager/pve-manager.sh` | Add plugin system, refactor menus |
| `~/.pve-manager/plugins/` | Create plugin structure |

## Verification Plan

1. **Plugin Loading**
   - Create test plugin
   - Verify `load_plugins()` discovers it
   - Verify `get_plugin_value()` reads metadata

2. **Dynamic Menus**
   - Verify plugins appear in correct category menus
   - Verify menu selection deploys correct plugin

3. **Deployment**
   - Deploy plugin via Docker
   - Deploy plugin via native install
   - Verify access info displays correctly

4. **Removal**
   - Remove plugin service
   - Verify cleanup runs correctly

5. **Backward Compatibility**
   - Test existing services still work
   - Test mixed plugin/legacy services
