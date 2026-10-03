# PVE Manager Enhancement Plans

---

# Plan 1: VM (QEMU) Support

## Overview
Extend the existing pve-manager.sh to support QEMU/KVM virtual machines alongside LXC containers, providing the same functionality for both.

## Current State
- **LXC Support**: Full support via `pct` commands
- **VM Support**: None
- **Key LXC functions**: ~35 functions handling containers

## Command Mapping: pct → qm

| Operation | Container (`pct`) | VM (`qm`) |
|-----------|-------------------|-----------|
| List | `pct list` | `qm list` |
| Create | `pct create <vmid> <template>` | `qm create <vmid>` + cloud-init |
| Start | `pct start <vmid>` | `qm start <vmid>` |
| Stop | `pct stop <vmid>` | `qm stop <vmid>` |
| Shutdown | `pct shutdown <vmid>` | `qm shutdown <vmid>` |
| Destroy | `pct destroy <vmid> --purge` | `qm destroy <vmid>` |
| Config | `pct config <vmid>` | `qm config <vmid>` |
| Status | `pct status <vmid>` | `qm status <vmid>` |
| Exec | `pct exec <vmid> -- cmd` | `qm guest exec <vmid> -- cmd` or SSH |
| Push file | `pct push <vmid> src dst` | SCP (no native equivalent) |

## Key Differences

| Aspect | Containers (LXC) | VMs (QEMU) |
|--------|------------------|------------|
| Command execution | Direct via `pct exec` | Guest agent or SSH required |
| File transfer | `pct push/pull` | SCP only |
| Boot time | Seconds | 30-120 seconds |
| Network ready | Immediate | Must wait for cloud-init/DHCP |
| OS support | Linux only | Any OS |
| Docker install | Direct exec | After SSH ready |

## Architecture Design

### Abstraction Layer
Create unified functions that work for both VMs and containers:

```bash
# Type detection
get_guest_type() {
    local vmid="$1"
    if pve_exec "pct status $vmid" &>/dev/null; then
        echo "lxc"
    elif pve_exec "qm status $vmid" &>/dev/null; then
        echo "vm"
    fi
}

# Unified operations
guest_start() {
    local vmid="$1"
    local type=$(get_guest_type "$vmid")
    case "$type" in
        lxc) pve_exec "pct start $vmid" ;;
        vm)  pve_exec "qm start $vmid" ;;
    esac
}

guest_exec() {
    local vmid="$1"
    local cmd="$2"
    local type=$(get_guest_type "$vmid")
    case "$type" in
        lxc) lxc_exec "$vmid" "$cmd" ;;
        vm)  vm_exec "$vmid" "$cmd" ;;  # Via SSH or guest agent
    esac
}
```

### VM-Specific Functions

| Function | Purpose | Implementation |
|----------|---------|----------------|
| `vm_create()` | Create VM from template | `qm clone` + cloud-init config |
| `vm_start()` | Start VM | `qm start` |
| `vm_stop()` | Stop VM | `qm shutdown` → `qm stop` fallback |
| `vm_delete()` | Delete VM | `qm destroy` |
| `vm_exec()` | Execute command | SSH or `qm guest exec` |
| `vm_exec_live()` | Execute with output | SSH with live output |
| `vm_wait_ready()` | Wait for SSH | Poll SSH connectivity |
| `vm_push_file()` | Transfer file to VM | SCP |
| `vm_pull_file()` | Transfer file from VM | SCP |
| `vm_get_ip()` | Get VM IP | Parse `qm guest cmd` or cloud-init |
| `vm_create_wizard()` | Interactive creation | Template selection + cloud-init |

### Cloud-Init Integration

```bash
vm_configure_cloudinit() {
    local vmid="$1"
    local hostname="$2"
    local ip="$3"
    local gateway="$4"
    local ssh_key="$5"

    pve_exec "qm set $vmid --ciuser root"
    pve_exec "qm set $vmid --ipconfig0 ip=$ip/24,gw=$gateway"
    pve_exec "qm set $vmid --sshkeys '$ssh_key'"
    pve_exec "qm set $vmid --agent enabled=1"
    pve_exec "qm cloudinit update $vmid"
}
```

### SSH-Based Execution for VMs

```bash
vm_exec() {
    local vmid="$1"
    local cmd="$2"
    local ip=$(vm_get_ip "$vmid")

    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        -i "$SSH_DIR/id_ed25519" "root@$ip" "$cmd"
}

vm_wait_ready() {
    local vmid="$1"
    local timeout="${2:-120}"  # VMs need longer timeout
    local ip=$(vm_get_ip "$vmid")

    local count=0
    while [[ $count -lt $timeout ]]; do
        if ssh -o ConnectTimeout=3 -o BatchMode=yes \
               -i "$SSH_DIR/id_ed25519" "root@$ip" "echo ok" &>/dev/null; then
            return 0
        fi
        sleep 2
        ((count+=2))
    done
    return 1
}
```

## Implementation Phases

### Phase 1: Core VM Functions (~400 lines)
**Files:** `pve-manager.sh`

1. Add VM listing: `pve_list_vms()`
2. Add VM lifecycle: `vm_start()`, `vm_stop()`, `vm_delete()`
3. Add VM execution: `vm_exec()`, `vm_exec_live()`, `vm_wait_ready()`
4. Add file transfer: `vm_push_file()`, `vm_pull_file()`
5. Add IP detection: `vm_get_ip()`

### Phase 2: VM Creation Wizard (~300 lines)
**Files:** `pve-manager.sh`

1. List available VM templates
2. Cloud-init configuration dialog
3. Resource allocation (CPU, RAM, disk)
4. Network configuration
5. SSH key injection

### Phase 3: Abstraction Layer (~200 lines)
**Files:** `pve-manager.sh`

1. Create `get_guest_type()` function
2. Create unified `guest_*` wrapper functions
3. Update existing menus to use abstraction

### Phase 4: Menu Integration (~150 lines)
**Files:** `pve-manager.sh`

1. Add "VM Management" menu alongside "LXC Management"
2. Update bulk operations to include VMs
3. Add VM/Container toggle in service deployment
4. Update Docker setup to support VMs

### Phase 5: Service Deployment for VMs (~200 lines)
**Files:** `pve-manager.sh`

1. Modify `deploy_service_wizard()` to support VMs
2. Update Docker installation for VMs (via SSH)
3. Update certificate deployment (via SCP)
4. Update SSH key distribution

## Menu Structure Changes

```
Current:
├── 2. LXC Container Management
│   ├── List containers
│   ├── Create container
│   └── ...

Proposed:
├── 2. Guest Management
│   ├── 1. LXC Containers
│   │   ├── List containers
│   │   ├── Create container
│   │   └── ...
│   ├── 2. Virtual Machines
│   │   ├── List VMs
│   │   ├── Create VM (from template)
│   │   └── ...
│   └── 3. Bulk Operations (All)
```

## Key Files to Modify

| File | Changes |
|------|---------|
| `/root/pve-manager/pve-manager.sh` | Add VM functions, modify menus |

## Functions to Add

```bash
# VM Core
pve_list_vms()           # Line ~1030 area
vm_create()              # New function
vm_start()               # New function
vm_stop()                # New function
vm_delete()              # New function
vm_exec()                # New function
vm_exec_live()           # New function
vm_wait_ready()          # New function
vm_push_file()           # New function
vm_pull_file()           # New function
vm_get_ip()              # New function
vm_create_wizard()       # New function
vm_management_menu()     # New function

# Abstraction
get_guest_type()         # New function
guest_start()            # New function
guest_stop()             # New function
guest_exec()             # New function
guest_push_file()        # New function
```

## Verification Plan

1. **VM Creation**
   - Create VM from cloud-init template
   - Verify cloud-init configuration applied
   - Verify SSH access works

2. **VM Operations**
   - Start/stop/restart VM
   - Execute commands via SSH
   - Transfer files via SCP

3. **Docker on VM**
   - Install Docker in VM
   - Deploy service to VM
   - Verify service accessible

4. **Certificates on VM**
   - Generate certificate for VM
   - Deploy via SCP
   - Verify HTTPS works

5. **Backward Compatibility**
   - All existing LXC functions still work
   - No regression in container operations

---

# Plan 2: Plugin Architecture

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
