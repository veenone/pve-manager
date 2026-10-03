#!/bin/bash
#
# PVE Manager - Proxmox VE Management TUI
# A single-file Bash application for managing Proxmox VE infrastructure
#
# Features:
# - LXC container management
# - Docker setup and configuration
# - SSH key management
# - Self-signed CA and certificate management
# - Publicly-trusted certificates via ACME (Let's Encrypt) + Cloudflare DNS-01,
#   deployable to LXC containers and VMs to replace self-signed certs
# - Service deployment (monitoring, dev tools, testing tools)
#
# Version: 1.0.0
# License: MIT
#

set -o pipefail

#######################################
# CONFIGURATION & VARIABLES
#######################################

readonly VERSION="2.1.0"
readonly SCRIPT_NAME="PVE Manager"
readonly CONFIG_DIR="$HOME/.pve-manager"
readonly CONFIG_FILE="$CONFIG_DIR/config.conf"
readonly PROFILES_FILE="$CONFIG_DIR/profiles.conf"
readonly CA_DIR="$CONFIG_DIR/ca"
readonly CERTS_DIR="$CA_DIR/certs"
readonly SSH_DIR="$CONFIG_DIR/ssh"
readonly LOG_DIR="/var/log/pve-manager"
readonly LOG_FILE="$LOG_DIR/pve-manager.log"
readonly OPERATIONS_LOG="$LOG_DIR/operations.log"
readonly ERROR_LOG="$LOG_DIR/error.log"
readonly TEMPLATES_DIR="$CONFIG_DIR/templates"
readonly PLUGINS_DIR="$CONFIG_DIR/plugins"
# ACME / Cloudflare (publicly-trusted certificates)
readonly ACME_DIR="$CONFIG_DIR/acme"
readonly ACME_TOKEN_FILE="$ACME_DIR/cloudflare.env"
readonly ACME_TARGETS_FILE="$ACME_DIR/targets.conf"
readonly PROGRESS_LOG="/tmp/pve-manager-progress-$$.log"

# Dialog dimensions
readonly DIALOG_HEIGHT=20
readonly DIALOG_WIDTH=76
readonly DIALOG_LIST_HEIGHT=12

# Colors for non-dialog output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
DIALOG_CMD=""
CURRENT_PVE=""
CURRENT_PVE_HOST=""
CURRENT_PVE_USER=""
CURRENT_PVE_PORT=""
IS_LOCAL_PVE=false

# Plugin system arrays
declare -gA PLUGINS
declare -gA PLUGIN_CATEGORIES

#######################################
# UTILITY FUNCTIONS
#######################################

# Cleanup on exit
cleanup() {
    rm -f "$PROGRESS_LOG" "/tmp/pve-manager-"*"-$$.txt" 2>/dev/null
}
trap cleanup EXIT

# Initialize configuration directories
init_config() {
    mkdir -p "$CONFIG_DIR" "$CA_DIR" "$CERTS_DIR" "$SSH_DIR" "$TEMPLATES_DIR" "$PLUGINS_DIR" "$ACME_DIR"
    chmod 700 "$CONFIG_DIR" "$CA_DIR" "$SSH_DIR" "$ACME_DIR"

    # Initialize logging directory
    if [[ ! -d "$LOG_DIR" ]]; then
        sudo mkdir -p "$LOG_DIR" 2>/dev/null || mkdir -p "$LOG_DIR"
        sudo chown "$(whoami):$(whoami)" "$LOG_DIR" 2>/dev/null || true
        chmod 755 "$LOG_DIR"
    fi
    touch "$LOG_FILE" "$OPERATIONS_LOG" "$ERROR_LOG" 2>/dev/null || true

    # Create default config if not exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" << 'EOF'
# PVE Manager Configuration
DEFAULT_PROFILE=""
DEFAULT_STORAGE="local"
DEFAULT_BRIDGE="vmbr0"
DEFAULT_CPU=2
DEFAULT_RAM=2048
DEFAULT_DISK=8
CA_VALID_DAYS=3650
CERT_VALID_DAYS=365
SSH_KEY_TYPE="ed25519"
LOG_LEVEL="INFO"
# ACME / Cloudflare certificates (see Certificate Management -> option C)
ACME_DOMAIN=""
ACME_SUBDOMAIN="lan"
ACME_EMAIL=""
ACME_KEY_TYPE="ec-256"
# Single-issuer model: leave ACME_ISSUER_HOST empty on the ONE host that issues;
# set it to that host on every other host, which then only deploys.
ACME_ISSUER_HOST=""
ACME_ISSUER_DIR=""
ACME_CERT_SOURCE_DIR=""
EOF
    fi

    # Create empty profiles file if not exists
    if [[ ! -f "$PROFILES_FILE" ]]; then
        touch "$PROFILES_FILE"
    fi
}

#######################################
# PLUGIN SYSTEM
#######################################

# Load plugins from plugins directory
load_plugins() {
    PLUGINS=()
    PLUGIN_CATEGORIES=()
    [[ ! -d "$PLUGINS_DIR" ]] && return

    for plugin_dir in "$PLUGINS_DIR"/*/; do
        [[ -d "$plugin_dir" ]] || continue
        local plugin_id
        plugin_id=$(basename "$plugin_dir")
        local conf="$plugin_dir/plugin.conf"

        if [[ -f "$conf" ]]; then
            PLUGINS["$plugin_id"]="$plugin_dir"
            local category
            category=$(get_plugin_value "$conf" "PLUGIN_CATEGORY")
            [[ -n "$category" ]] && PLUGIN_CATEGORIES["$category"]=1
        fi
    done

    log_debug "Loaded ${#PLUGINS[@]} plugins"
}

# Get a value from plugin.conf
get_plugin_value() {
    local conf="$1"
    local key="$2"
    grep "^${key}=" "$conf" 2>/dev/null | head -1 | cut -d'=' -f2- | tr -d '"' | tr -d "'"
}

# Check if a service is a plugin
is_plugin_service() {
    local service="$1"
    [[ -n "${PLUGINS[$service]}" ]]
}

# Check if plugin supports Docker deployment
plugin_supports_docker() {
    local service="$1"
    local conf="${PLUGINS[$service]}/plugin.conf"
    [[ "$(get_plugin_value "$conf" "PLUGIN_DOCKER_SUPPORT")" == "true" ]]
}

# Check if plugin supports native deployment
plugin_supports_native() {
    local service="$1"
    local conf="${PLUGINS[$service]}/plugin.conf"
    [[ "$(get_plugin_value "$conf" "PLUGIN_NATIVE_SUPPORT")" == "true" ]]
}

# Get plugin compose content
get_plugin_compose() {
    local plugin_id="$1"
    local compose_file="${PLUGINS[$plugin_id]}/compose.yml"
    [[ -f "$compose_file" ]] && cat "$compose_file"
}

# Get plugin Docker access info (substitutes {IP} placeholder)
get_plugin_docker_access_info() {
    local plugin_id="$1"
    local ip="$2"
    local conf="${PLUGINS[$plugin_id]}/plugin.conf"

    local url creds
    url=$(get_plugin_value "$conf" "PLUGIN_DOCKER_URL")
    creds=$(get_plugin_value "$conf" "PLUGIN_DOCKER_CREDENTIALS")

    # Substitute {IP} placeholder
    url="${url//\{IP\}/$ip}"

    if [[ -n "$creds" && "$creds" != "<"* ]]; then
        echo -e "$url\nCredentials: $creds"
    else
        echo "$url"
    fi
}

# Get plugin native access info (substitutes {IP} placeholder)
get_plugin_native_access_info() {
    local plugin_id="$1"
    local ip="$2"
    local conf="${PLUGINS[$plugin_id]}/plugin.conf"

    local url creds
    url=$(get_plugin_value "$conf" "PLUGIN_NATIVE_URL")
    creds=$(get_plugin_value "$conf" "PLUGIN_NATIVE_CREDENTIALS")

    # Substitute {IP} placeholder
    url="${url//\{IP\}/$ip}"

    if [[ -n "$creds" && "$creds" != "<"* ]]; then
        echo -e "$url\nCredentials: $creds"
    else
        echo "$url"
    fi
}

# List plugins by category
list_plugins_by_category() {
    local category="$1"
    for plugin_id in "${!PLUGINS[@]}"; do
        local conf="${PLUGINS[$plugin_id]}/plugin.conf"
        local plugin_category
        plugin_category=$(get_plugin_value "$conf" "PLUGIN_CATEGORY")
        [[ "$plugin_category" == "$category" ]] && echo "$plugin_id"
    done | sort
}

# Get plugin display name
get_plugin_name() {
    local plugin_id="$1"
    local conf="${PLUGINS[$plugin_id]}/plugin.conf"
    get_plugin_value "$conf" "PLUGIN_NAME"
}

#######################################
# PLUGIN CREATION
#######################################

# Helper to create a plugin directory
create_plugin_dir() {
    local plugin_id="$1"
    local plugin_dir="$PLUGINS_DIR/$plugin_id"
    mkdir -p "$plugin_dir"
    echo "$plugin_dir"
}

# Initialize built-in plugins (always regenerate to ensure latest versions)
init_builtin_plugins() {
    log_info "Initializing built-in plugins..."
    create_builtin_plugins
}

# Create all built-in plugins
create_builtin_plugins() {
    # Monitoring plugins
    create_plugin_prometheus
    create_plugin_grafana
    create_plugin_loki
    create_plugin_alloy
    create_plugin_node_exporter
    create_plugin_monitoring_stack

    # Development tools plugins
    create_plugin_sonarqube
    create_plugin_nexus
    create_plugin_gitea
    create_plugin_jenkins
    create_plugin_harbor
    create_plugin_dependency_track

    # Testing tools plugins
    create_plugin_kiwi_tcms
    create_plugin_selenium_grid
    create_plugin_testlink

    # Infrastructure plugins
    create_plugin_pihole
    create_plugin_keycloak
    create_plugin_freeipa
    create_plugin_postfix_relay
    create_plugin_traefik
    create_plugin_nginx

    # Database plugins
    create_plugin_mysql
    create_plugin_postgresql
    create_plugin_mongodb

    log_info "Created 24 built-in plugins"
}

#######################################
# MONITORING PLUGINS
#######################################

# Create prometheus plugin
create_plugin_prometheus() {
    local dir
    dir=$(create_plugin_dir "prometheus")

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
    security_opt:
      - apparmor:unconfined
    ports:
      - "9090:9090"
    volumes:
      - prometheus_data:/prometheus
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'

volumes:
  prometheus_data:
EOF

    # prometheus.yml (extra config)
    cat > "$dir/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
EOF

    # install.sh
    cat > "$dir/install.sh" << 'EOF'
#!/bin/bash
# Native installation script for Prometheus
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
    *)
        echo "ERROR: Unsupported OS for native Prometheus installation"
        exit 1
        ;;
esac
EOF

    # remove.sh
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for Prometheus
lxc_exec_live "$VMID" "systemctl stop prometheus 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl disable prometheus 2>/dev/null || true"
case "$OS_TYPE" in
    debian|ubuntu)
        lxc_exec_live "$VMID" "apt-get purge -y prometheus 2>/dev/null || true"
        lxc_exec_live "$VMID" "apt-get autoremove -y 2>/dev/null || true"
        ;;
    alpine)
        lxc_exec_live "$VMID" "apk del prometheus 2>/dev/null || true"
        ;;
esac
lxc_exec_live "$VMID" "rm -rf /var/lib/prometheus"
lxc_exec_live "$VMID" "rm -rf /etc/prometheus"
EOF
}

# Create grafana plugin
create_plugin_grafana() {
    local dir
    dir=$(create_plugin_dir "grafana")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="grafana"
PLUGIN_NAME="Grafana"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="monitoring"
PLUGIN_DESCRIPTION="Visualization and analytics platform"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu alpine"
PLUGIN_DOCKER_PORT="3000"
PLUGIN_DOCKER_URL="http://{IP}:3000"
PLUGIN_DOCKER_CREDENTIALS="admin/admin"
PLUGIN_NATIVE_URL="http://{IP}:3000"
PLUGIN_NATIVE_CREDENTIALS="admin/admin"
PLUGIN_SYSTEMD_SERVICE="grafana-server"
PLUGIN_DOCKER_CONTAINER="grafana"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
      - GF_SERVER_ROOT_URL=${GRAFANA_URL:-http://localhost:3000}
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  grafana_data:
EOF

    # install.sh
    cat > "$dir/install.sh" << 'EOF'
#!/bin/bash
# Native installation script for Grafana
case "$OS_TYPE" in
    debian|ubuntu)
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y apt-transport-https software-properties-common wget"
        lxc_exec_live "$VMID" "wget -q -O /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key"
        lxc_exec_live "$VMID" "echo 'deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main' | tee /etc/apt/sources.list.d/grafana.list"
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y grafana"
        lxc_exec_live "$VMID" "systemctl daemon-reload"
        lxc_exec_live "$VMID" "systemctl enable grafana-server"
        lxc_exec_live "$VMID" "systemctl start grafana-server"
        ;;
    alpine)
        lxc_exec_live "$VMID" "apk add --no-cache grafana"
        lxc_exec_live "$VMID" "rc-update add grafana"
        lxc_exec_live "$VMID" "rc-service grafana start"
        ;;
    *)
        echo "ERROR: Unsupported OS for native Grafana installation"
        exit 1
        ;;
esac
EOF

    # remove.sh
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for Grafana
lxc_exec_live "$VMID" "systemctl stop grafana-server 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl disable grafana-server 2>/dev/null || true"
case "$OS_TYPE" in
    debian|ubuntu)
        lxc_exec_live "$VMID" "apt-get purge -y grafana 2>/dev/null || true"
        lxc_exec_live "$VMID" "apt-get autoremove -y 2>/dev/null || true"
        lxc_exec_live "$VMID" "rm -f /etc/apt/sources.list.d/grafana.list"
        lxc_exec_live "$VMID" "rm -f /usr/share/keyrings/grafana.key"
        ;;
    alpine)
        lxc_exec_live "$VMID" "apk del grafana 2>/dev/null || true"
        ;;
esac
lxc_exec_live "$VMID" "rm -rf /var/lib/grafana"
lxc_exec_live "$VMID" "rm -rf /etc/grafana"
EOF
}

# Create loki plugin
create_plugin_loki() {
    local dir
    dir=$(create_plugin_dir "loki")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="loki"
PLUGIN_NAME="Loki"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="monitoring"
PLUGIN_DESCRIPTION="Log aggregation system"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="3100"
PLUGIN_DOCKER_URL="http://{IP}:3100"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_DOCKER_CONTAINER="loki"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  loki:
    image: grafana/loki:latest
    container_name: loki
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "3100:3100"
    volumes:
      - loki_data:/loki
    command: -config.file=/etc/loki/local-config.yaml

volumes:
  loki_data:
EOF
}

# Create alloy plugin
create_plugin_alloy() {
    local dir
    dir=$(create_plugin_dir "alloy")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="alloy"
PLUGIN_NAME="Grafana Alloy"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="monitoring"
PLUGIN_DESCRIPTION="OpenTelemetry collector"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="12345"
PLUGIN_DOCKER_URL="http://{IP}:12345"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_DOCKER_CONTAINER="alloy"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  alloy:
    image: grafana/alloy:latest
    container_name: alloy
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "12345:12345"
    volumes:
      - ./config.alloy:/etc/alloy/config.alloy:ro
      - /var/log:/var/log:ro
    command:
      - run
      - /etc/alloy/config.alloy
      - --server.http.listen-addr=0.0.0.0:12345
EOF

    # config.alloy (extra config)
    cat > "$dir/config.alloy" << 'EOF'
logging {
  level = "info"
}

prometheus.scrape "default" {
  targets = [
    {"__address__" = "localhost:9100"},
  ]
  forward_to = [prometheus.remote_write.default.receiver]
}

prometheus.remote_write "default" {
  endpoint {
    url = "http://prometheus:9090/api/v1/write"
  }
}

loki.source.journal "read" {
  forward_to = [loki.write.default.receiver]
}

loki.write "default" {
  endpoint {
    url = "http://loki:3100/loki/api/v1/push"
  }
}
EOF
}

# Create node-exporter plugin
create_plugin_node_exporter() {
    local dir
    dir=$(create_plugin_dir "node-exporter")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="node-exporter"
PLUGIN_NAME="Node Exporter"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="monitoring"
PLUGIN_DESCRIPTION="System metrics exporter for Prometheus"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="9100"
PLUGIN_DOCKER_URL="http://{IP}:9100"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_DOCKER_CONTAINER="node-exporter"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
EOF
}

# Create monitoring-stack plugin
create_plugin_monitoring_stack() {
    local dir
    dir=$(create_plugin_dir "monitoring-stack")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="monitoring-stack"
PLUGIN_NAME="Monitoring Stack"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="monitoring"
PLUGIN_DESCRIPTION="Complete monitoring stack: Prometheus, Grafana, Loki, Node Exporter with HTTPS"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="443"
PLUGIN_DOCKER_URL="Grafana: https://{IP}/\nPrometheus: https://{IP}/prometheus/"
PLUGIN_DOCKER_CREDENTIALS="Grafana: admin/admin"
PLUGIN_DOCKER_CONTAINER="nginx-proxy"
PLUGIN_HTTPS_ENABLED="true"
EOF

    # compose.yml with nginx reverse proxy for HTTPS
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  nginx-proxy:
    image: nginx:alpine
    container_name: nginx-proxy
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    depends_on:
      - grafana
      - prometheus
    networks:
      - monitoring

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    expose:
      - "9090"
    volumes:
      - prometheus_data:/prometheus
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'
      - '--web.external-url=/prometheus/'
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    expose:
      - "3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./provisioning/datasources:/etc/grafana/provisioning/datasources:ro
      - ./provisioning/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./dashboards:/var/lib/grafana/dashboards:ro
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    depends_on:
      - prometheus
    networks:
      - monitoring

  loki:
    image: grafana/loki:latest
    container_name: loki
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    expose:
      - "3100"
    volumes:
      - loki_data:/loki
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    command: -config.file=/etc/loki/local-config.yaml
    networks:
      - monitoring

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    expose:
      - "9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      - monitoring

networks:
  monitoring:
    driver: bridge

volumes:
  prometheus_data:
  grafana_data:
  loki_data:
EOF

    # nginx.conf for reverse proxy with HTTPS
    cat > "$dir/nginx.conf" << 'EOF'
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    # HTTPS server
    server {
        listen 443 ssl;
        server_name _;

        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;

        # Root redirect to Grafana
        location = / {
            return 302 /grafana/;
        }

        # Grafana
        location /grafana/ {
            proxy_pass http://grafana:3000/;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

        # Prometheus
        location /prometheus/ {
            proxy_pass http://prometheus:9090/prometheus/;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Loki (API access)
        location /loki/ {
            proxy_pass http://loki:3100/;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Node Exporter metrics
        location /node-metrics/ {
            proxy_pass http://node-exporter:9100/;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}
EOF

    # prometheus.yml (extra config)
    cat > "$dir/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
EOF

    # setup-ssl.sh - Script to generate SSL certificates
    cat > "$dir/setup-ssl.sh" << 'EOF'
#!/bin/bash
# Generate self-signed SSL certificate for monitoring stack
SSL_DIR="$1"
DOMAIN="${2:-localhost}"

mkdir -p "$SSL_DIR"

# Generate private key and self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$SSL_DIR/server.key" \
    -out "$SSL_DIR/server.crt" \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1"

chmod 600 "$SSL_DIR/server.key"
chmod 644 "$SSL_DIR/server.crt"

echo "SSL certificates generated in $SSL_DIR"
EOF
    chmod +x "$dir/setup-ssl.sh"
}

#######################################
# DEVTOOLS PLUGINS
#######################################

# Create sonarqube plugin
create_plugin_sonarqube() {
    local dir
    dir=$(create_plugin_dir "sonarqube")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="sonarqube"
PLUGIN_NAME="SonarQube"
PLUGIN_VERSION="community"
PLUGIN_CATEGORY="devtools"
PLUGIN_DESCRIPTION="Code quality and security analysis"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu"
PLUGIN_DOCKER_PORT="9000"
PLUGIN_DOCKER_URL="http://{IP}:9000"
PLUGIN_DOCKER_CREDENTIALS="admin/admin"
PLUGIN_NATIVE_URL="http://{IP}:9000"
PLUGIN_NATIVE_CREDENTIALS="admin/admin"
PLUGIN_SYSTEMD_SERVICE="sonarqube"
PLUGIN_DOCKER_CONTAINER="sonarqube"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  sonarqube:
    image: sonarqube:community
    container_name: sonarqube
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "9000:9000"
    environment:
      - SONAR_JDBC_URL=jdbc:postgresql://sonarqube-db:5432/sonar
      - SONAR_JDBC_USERNAME=sonar
      - SONAR_JDBC_PASSWORD=${SONAR_DB_PASSWORD:-sonar}
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
      - sonarqube_logs:/opt/sonarqube/logs
    depends_on:
      sonarqube-db:
        condition: service_healthy

  sonarqube-db:
    image: postgres:15
    container_name: sonarqube-db
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - POSTGRES_USER=sonar
      - POSTGRES_PASSWORD=${SONAR_DB_PASSWORD:-sonar}
      - POSTGRES_DB=sonar
    volumes:
      - sonarqube_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "sonar", "-d", "sonar"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

volumes:
  sonarqube_data:
  sonarqube_extensions:
  sonarqube_logs:
  sonarqube_db:
EOF

    # install.sh - sonarqube native requires complex setup
    cat > "$dir/install.sh" << 'INSTALLEOF'
#!/bin/bash
# Native installation script for SonarQube
case "$OS_TYPE" in
    debian|ubuntu)
        echo "Installing SonarQube dependencies..."
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y openjdk-17-jdk-headless postgresql wget unzip"

        # Configure system limits
        lxc_exec_live "$VMID" "echo 'vm.max_map_count=524288' >> /etc/sysctl.conf"
        lxc_exec_live "$VMID" "echo 'fs.file-max=131072' >> /etc/sysctl.conf"
        lxc_exec_live "$VMID" "sysctl -p"

        # Configure limits for sonarqube user
        lxc_exec_live "$VMID" "echo 'sonarqube - nofile 131072' >> /etc/security/limits.conf"
        lxc_exec_live "$VMID" "echo 'sonarqube - nproc 8192' >> /etc/security/limits.conf"

        # Setup PostgreSQL
        lxc_exec_live "$VMID" "systemctl start postgresql"
        lxc_exec_live "$VMID" "systemctl enable postgresql"
        lxc_exec_live "$VMID" "sudo -u postgres psql -c \"CREATE USER sonar WITH PASSWORD 'sonar';\""
        lxc_exec_live "$VMID" "sudo -u postgres psql -c 'CREATE DATABASE sonarqube OWNER sonar;'"

        # Create sonarqube user
        lxc_exec_live "$VMID" "useradd -r -s /bin/bash -d /opt/sonarqube sonarqube 2>/dev/null || true"

        # Download and install SonarQube
        echo "Downloading SonarQube..."
        lxc_exec_live "$VMID" "wget -q -O /tmp/sonarqube.zip https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-10.4.1.88267.zip"
        lxc_exec_live "$VMID" "unzip -q /tmp/sonarqube.zip -d /opt/"
        lxc_exec_live "$VMID" "mv /opt/sonarqube-* /opt/sonarqube"
        lxc_exec_live "$VMID" "chown -R sonarqube:sonarqube /opt/sonarqube"

        # Configure SonarQube
        lxc_exec_live "$VMID" "sed -i 's/#sonar.jdbc.username=/sonar.jdbc.username=sonar/' /opt/sonarqube/conf/sonar.properties"
        lxc_exec_live "$VMID" "sed -i 's/#sonar.jdbc.password=/sonar.jdbc.password=sonar/' /opt/sonarqube/conf/sonar.properties"
        lxc_exec_live "$VMID" "sed -i 's|#sonar.jdbc.url=jdbc:postgresql://localhost/sonarqube|sonar.jdbc.url=jdbc:postgresql://localhost/sonarqube|' /opt/sonarqube/conf/sonar.properties"

        # Create systemd service
        lxc_exec "$VMID" "cat > /etc/systemd/system/sonarqube.service << 'SVCEOF'
[Unit]
Description=SonarQube service
After=syslog.target network.target postgresql.service

[Service]
Type=forking
ExecStart=/opt/sonarqube/bin/linux-x86-64/sonar.sh start
ExecStop=/opt/sonarqube/bin/linux-x86-64/sonar.sh stop
User=sonarqube
Group=sonarqube
Restart=always
LimitNOFILE=131072
LimitNPROC=8192

[Install]
WantedBy=multi-user.target
SVCEOF"

        lxc_exec_live "$VMID" "systemctl daemon-reload"
        lxc_exec_live "$VMID" "systemctl enable sonarqube"
        lxc_exec_live "$VMID" "systemctl start sonarqube"
        ;;
    *)
        echo "ERROR: Unsupported OS for native SonarQube installation"
        exit 1
        ;;
esac
INSTALLEOF

    # remove.sh
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for SonarQube
lxc_exec_live "$VMID" "systemctl stop sonarqube 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl disable sonarqube 2>/dev/null || true"
lxc_exec_live "$VMID" "rm -f /etc/systemd/system/sonarqube.service"
lxc_exec_live "$VMID" "rm -rf /opt/sonarqube"
lxc_exec_live "$VMID" "sudo -u postgres psql -c 'DROP DATABASE IF EXISTS sonarqube;' 2>/dev/null || true"
lxc_exec_live "$VMID" "sudo -u postgres psql -c 'DROP USER IF EXISTS sonar;' 2>/dev/null || true"
lxc_exec_live "$VMID" "userdel -r sonarqube 2>/dev/null || true"
lxc_exec_live "$VMID" "sed -i '/vm.max_map_count=524288/d' /etc/sysctl.conf 2>/dev/null || true"
lxc_exec_live "$VMID" "sed -i '/fs.file-max=131072/d' /etc/sysctl.conf 2>/dev/null || true"
lxc_exec_live "$VMID" "sed -i '/sonarqube.*nofile/d' /etc/security/limits.conf 2>/dev/null || true"
lxc_exec_live "$VMID" "sed -i '/sonarqube.*nproc/d' /etc/security/limits.conf 2>/dev/null || true"
EOF
}

# Create nexus plugin
create_plugin_nexus() {
    local dir
    dir=$(create_plugin_dir "nexus")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="nexus"
PLUGIN_NAME="Nexus Repository"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="devtools"
PLUGIN_DESCRIPTION="Artifact repository manager"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="8081"
PLUGIN_DOCKER_URL="http://{IP}:8081"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_DOCKER_CONTAINER="nexus"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  nexus:
    image: sonatype/nexus3:latest
    container_name: nexus
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "8081:8081"
      - "8082:8082"
      - "8083:8083"
    volumes:
      - nexus_data:/nexus-data

volumes:
  nexus_data:
EOF
}

# Create gitea plugin
create_plugin_gitea() {
    local dir
    dir=$(create_plugin_dir "gitea")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="gitea"
PLUGIN_NAME="Gitea"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="devtools"
PLUGIN_DESCRIPTION="Lightweight Git service"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu"
PLUGIN_DOCKER_PORT="3000"
PLUGIN_DOCKER_URL="http://{IP}:3000"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_NATIVE_URL="http://{IP}:3000"
PLUGIN_NATIVE_CREDENTIALS=""
PLUGIN_SYSTEMD_SERVICE="gitea"
PLUGIN_DOCKER_CONTAINER="gitea"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  gitea:
    image: gitea/gitea:latest
    container_name: gitea
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "3000:3000"
      - "2222:22"
    environment:
      - USER_UID=1000
      - USER_GID=1000
      - GITEA__database__DB_TYPE=postgres
      - GITEA__database__HOST=gitea-db:5432
      - GITEA__database__NAME=gitea
      - GITEA__database__USER=gitea
      - GITEA__database__PASSWD=${GITEA_DB_PASSWORD:-gitea}
    volumes:
      - gitea_data:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    depends_on:
      gitea-db:
        condition: service_healthy

  gitea-db:
    image: postgres:15
    container_name: gitea-db
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - POSTGRES_USER=gitea
      - POSTGRES_PASSWORD=${GITEA_DB_PASSWORD:-gitea}
      - POSTGRES_DB=gitea
    volumes:
      - gitea_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "gitea", "-d", "gitea"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

volumes:
  gitea_data:
  gitea_db:
EOF

    # install.sh
    cat > "$dir/install.sh" << 'INSTALLEOF'
#!/bin/bash
# Native installation script for Gitea
case "$OS_TYPE" in
    debian|ubuntu)
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y git sqlite3"
        lxc_exec_live "$VMID" "wget -O /usr/local/bin/gitea https://dl.gitea.com/gitea/1.21/gitea-1.21-linux-amd64"
        lxc_exec_live "$VMID" "chmod +x /usr/local/bin/gitea"
        lxc_exec_live "$VMID" "useradd -r -s /bin/bash -d /var/lib/gitea -m gitea 2>/dev/null || true"
        lxc_exec_live "$VMID" "mkdir -p /var/lib/gitea/{custom,data,log} /etc/gitea"
        lxc_exec_live "$VMID" "chown -R gitea:gitea /var/lib/gitea /etc/gitea"
        lxc_exec_live "$VMID" "chmod 750 /var/lib/gitea/{custom,data,log} /etc/gitea"

        # Create systemd service
        lxc_exec "$VMID" "cat > /etc/systemd/system/gitea.service << 'GITEAEOF'
[Unit]
Description=Gitea
After=network.target

[Service]
Type=simple
User=gitea
Group=gitea
WorkingDirectory=/var/lib/gitea
ExecStart=/usr/local/bin/gitea web -c /etc/gitea/app.ini
Restart=always
Environment=USER=gitea HOME=/var/lib/gitea GITEA_WORK_DIR=/var/lib/gitea

[Install]
WantedBy=multi-user.target
GITEAEOF"

        lxc_exec_live "$VMID" "systemctl daemon-reload"
        lxc_exec_live "$VMID" "systemctl enable gitea"
        lxc_exec_live "$VMID" "systemctl start gitea"
        ;;
    *)
        echo "ERROR: Unsupported OS for native Gitea installation"
        exit 1
        ;;
esac
INSTALLEOF

    # remove.sh
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for Gitea
lxc_exec_live "$VMID" "systemctl stop gitea 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl disable gitea 2>/dev/null || true"
lxc_exec_live "$VMID" "rm -f /etc/systemd/system/gitea.service"
lxc_exec_live "$VMID" "rm -rf /var/lib/gitea"
lxc_exec_live "$VMID" "rm -rf /etc/gitea"
lxc_exec_live "$VMID" "rm -f /usr/local/bin/gitea"
lxc_exec_live "$VMID" "userdel -r gitea 2>/dev/null || true"
EOF
}

# Create jenkins plugin
create_plugin_jenkins() {
    local dir
    dir=$(create_plugin_dir "jenkins")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="jenkins"
PLUGIN_NAME="Jenkins"
PLUGIN_VERSION="lts"
PLUGIN_CATEGORY="devtools"
PLUGIN_DESCRIPTION="Automation server for CI/CD"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu"
PLUGIN_DOCKER_PORT="8080"
PLUGIN_DOCKER_URL="http://{IP}:8080"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_NATIVE_URL="http://{IP}:8080"
PLUGIN_NATIVE_CREDENTIALS="Initial password: cat /var/lib/jenkins/secrets/initialAdminPassword"
PLUGIN_SYSTEMD_SERVICE="jenkins"
PLUGIN_DOCKER_CONTAINER="jenkins"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  jenkins:
    image: jenkins/jenkins:lts
    container_name: jenkins
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "8080:8080"
      - "50000:50000"
    volumes:
      - jenkins_home:/var/jenkins_home
      - /var/run/docker.sock:/var/run/docker.sock

volumes:
  jenkins_home:
EOF

    # install.sh
    cat > "$dir/install.sh" << 'INSTALLEOF'
#!/bin/bash
# Native installation script for Jenkins
case "$OS_TYPE" in
    debian|ubuntu)
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y fontconfig openjdk-17-jre"
        lxc_exec_live "$VMID" "wget -O /usr/share/keyrings/jenkins-keyring.asc https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key"
        lxc_exec_live "$VMID" "echo 'deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/' | tee /etc/apt/sources.list.d/jenkins.list"
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y jenkins"
        lxc_exec_live "$VMID" "systemctl enable jenkins"
        lxc_exec_live "$VMID" "systemctl start jenkins"
        echo ""
        echo "Getting initial admin password..."
        sleep 10
        lxc_exec_live "$VMID" "cat /var/lib/jenkins/secrets/initialAdminPassword 2>/dev/null || echo 'Password not ready yet'"
        ;;
    *)
        echo "ERROR: Unsupported OS for native Jenkins installation"
        exit 1
        ;;
esac
INSTALLEOF

    # remove.sh
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for Jenkins
lxc_exec_live "$VMID" "systemctl stop jenkins 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl disable jenkins 2>/dev/null || true"
lxc_exec_live "$VMID" "apt-get purge -y jenkins 2>/dev/null || true"
lxc_exec_live "$VMID" "apt-get autoremove -y 2>/dev/null || true"
lxc_exec_live "$VMID" "rm -rf /var/lib/jenkins"
lxc_exec_live "$VMID" "rm -f /etc/apt/sources.list.d/jenkins.list"
lxc_exec_live "$VMID" "rm -f /usr/share/keyrings/jenkins-keyring.asc"
EOF
}

# Create harbor plugin
create_plugin_harbor() {
    local dir
    dir=$(create_plugin_dir "harbor")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="harbor"
PLUGIN_NAME="Harbor"
PLUGIN_VERSION="v2.14.2"
PLUGIN_CATEGORY="devtools"
PLUGIN_DESCRIPTION="Container registry with security scanning"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_DOCKER_PORT="443"
PLUGIN_DOCKER_URL="Portal: https://{IP}/ (admin/Harbor12345)\nRegistry: docker login {IP}"
PLUGIN_DOCKER_CREDENTIALS="admin/Harbor12345"
PLUGIN_DOCKER_CONTAINER="nginx"
PLUGIN_DOCKER_CUSTOM_DEPLOY="true"
EOF

    # compose.yml - placeholder, Harbor uses official installer
    cat > "$dir/compose.yml" << 'EOF'
# Harbor requires the official installer to generate proper docker-compose
# This file is a placeholder - actual deployment uses install.sh
version: '3.8'
services:
  placeholder:
    image: alpine
    command: echo "Harbor requires official installer"
EOF

    # install.sh - Harbor installation using official installer (works for both Docker and Native)
    cat > "$dir/install.sh" << 'INSTALLEOF'
#!/bin/bash
# Installation script for Harbor using official installer
HARBOR_VERSION="v2.14.2"

case "$OS_TYPE" in
    debian|ubuntu)
        echo "Installing Harbor dependencies..."
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y curl wget openssl tar"

        # Install Docker if not present (Harbor requires Docker)
        if ! lxc_exec "$VMID" "command -v docker" > /dev/null 2>&1; then
            echo "Installing Docker for Harbor..."
            lxc_exec_live "$VMID" "curl -fsSL https://get.docker.com | sh"
            lxc_exec_live "$VMID" "systemctl enable docker"
            lxc_exec_live "$VMID" "systemctl start docker"
        fi

        # Install docker-compose if not present
        if ! lxc_exec "$VMID" "command -v docker-compose" > /dev/null 2>&1; then
            echo "Installing docker-compose..."
            lxc_exec_live "$VMID" "ARCH=\$(uname -m) && curl -L https://github.com/docker/compose/releases/latest/download/docker-compose-linux-\${ARCH} -o /usr/local/bin/docker-compose"
            lxc_exec_live "$VMID" "chmod +x /usr/local/bin/docker-compose"
        fi

        # Download Harbor offline installer
        echo "Downloading Harbor ${HARBOR_VERSION}..."
        lxc_exec_live "$VMID" "mkdir -p /opt/harbor"
        lxc_exec_live "$VMID" "cd /opt && wget -q https://github.com/goharbor/harbor/releases/download/${HARBOR_VERSION}/harbor-offline-installer-${HARBOR_VERSION}.tgz"
        lxc_exec_live "$VMID" "cd /opt && tar xzf harbor-offline-installer-${HARBOR_VERSION}.tgz"
        lxc_exec_live "$VMID" "rm -f /opt/harbor-offline-installer-${HARBOR_VERSION}.tgz"

        # Get container IP for configuration
        CONTAINER_IP=$(lxc_exec "$VMID" "hostname -I | awk '{print \$1}'" | tr -d '[:space:]')

        # Generate SSL certificates
        echo "Generating SSL certificates..."
        lxc_exec_live "$VMID" "mkdir -p /opt/harbor/ssl"
        lxc_exec "$VMID" "openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /opt/harbor/ssl/server.key \
            -out /opt/harbor/ssl/server.crt \
            -subj '/C=US/ST=State/L=City/O=Harbor/CN=${CONTAINER_IP:-localhost}' \
            -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${CONTAINER_IP:-127.0.0.1}' 2>/dev/null"

        # Create harbor.yml configuration
        echo "Configuring Harbor..."
        lxc_exec "$VMID" "cat > /opt/harbor/harbor.yml << HARBORYCFG
hostname: ${CONTAINER_IP:-localhost}
http:
  port: 80
https:
  port: 443
  certificate: /opt/harbor/ssl/server.crt
  private_key: /opt/harbor/ssl/server.key
harbor_admin_password: Harbor12345
database:
  password: Harbor12345
  max_idle_conns: 50
  max_open_conns: 100
  conn_max_lifetime: 5m
  conn_max_idle_time: 0
data_volume: /data/harbor
trivy:
  ignore_unfixed: false
  skip_update: false
  offline_scan: false
  security_check: vuln
  insecure: false
jobservice:
  max_job_workers: 10
  job_loggers:
    - STD_OUTPUT
    - FILE
  logger_sweeper_duration: 1
notification:
  webhook_job_max_retry: 3
  webhook_job_http_client_timeout: 3
log:
  level: info
  local:
    rotate_count: 50
    rotate_size: 200M
    location: /var/log/harbor
_version: 2.14.0
proxy:
  http_proxy:
  https_proxy:
  no_proxy:
  components:
    - core
    - jobservice
    - trivy
upload_purging:
  enabled: true
  age: 168h
  interval: 24h
  dryrun: false
cache:
  enabled: false
  expire_hours: 24
HARBORYCFG"

        # Prepare data directory
        lxc_exec_live "$VMID" "mkdir -p /data/harbor"

        # Configure Docker to work in LXC environment
        echo "Configuring Docker for LXC environment..."
        lxc_exec "$VMID" 'mkdir -p /etc/docker && cat > /etc/docker/daemon.json << DAEMONJSON
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
DAEMONJSON'
        lxc_exec_live "$VMID" "systemctl restart docker"
        sleep 2

        # Run Harbor installer
        echo "Installing Harbor (this may take several minutes)..."
        lxc_exec_live "$VMID" "cd /opt/harbor && ./install.sh --with-trivy"

        # Fix AppArmor issues for LXC by adding security_opt to all services
        echo "Applying LXC compatibility fixes..."
        # Install PyYAML if not present, then add security_opt to disable AppArmor
        lxc_exec "$VMID" "apt-get install -y python3-yaml >/dev/null 2>&1 || pip3 install pyyaml >/dev/null 2>&1 || true"
        lxc_exec "$VMID" "cd /opt/harbor && python3 -c \"
import yaml
with open('docker-compose.yml', 'r') as f:
    data = yaml.safe_load(f)
for svc in data.get('services', {}).values():
    svc['security_opt'] = ['apparmor:unconfined']
with open('docker-compose.yml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
\""
        # Restart with fixed config
        lxc_exec_live "$VMID" "cd /opt/harbor && docker-compose down && docker-compose up -d"

        # Create symlink for service directory compatibility
        lxc_exec_live "$VMID" "ln -sf /opt/harbor /opt/services/harbor 2>/dev/null || true"

        echo "Harbor installation complete!"
        echo "Access Harbor at https://${CONTAINER_IP}/"
        echo "Default credentials: admin / Harbor12345"
        ;;
    *)
        echo "ERROR: Harbor installation only supported on Debian/Ubuntu"
        exit 1
        ;;
esac
INSTALLEOF

    # remove.sh
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for Harbor
echo "Stopping Harbor services..."
lxc_exec_live "$VMID" "cd /opt/harbor && docker-compose down -v 2>/dev/null || true"
lxc_exec_live "$VMID" "rm -rf /opt/harbor"
lxc_exec_live "$VMID" "rm -rf /opt/services/harbor"
lxc_exec_live "$VMID" "rm -rf /data/harbor"
echo "Harbor removed."
EOF
}

# Create dependency-track plugin
create_plugin_dependency_track() {
    local dir
    dir=$(create_plugin_dir "dependency-track")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="dependency-track"
PLUGIN_NAME="Dependency-Track"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="devtools"
PLUGIN_DESCRIPTION="Software composition analysis platform"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="8080"
PLUGIN_DOCKER_URL="Frontend: http://{IP}:8080\nAPI Server: http://{IP}:8081"
PLUGIN_DOCKER_CREDENTIALS="admin/admin"
PLUGIN_DOCKER_CONTAINER="dtrack-frontend"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  dtrack-apiserver:
    image: dependencytrack/apiserver:latest
    container_name: dtrack-apiserver
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - ALPINE_DATABASE_MODE=external
      - ALPINE_DATABASE_URL=jdbc:postgresql://dtrack-db:5432/dtrack
      - ALPINE_DATABASE_DRIVER=org.postgresql.Driver
      - ALPINE_DATABASE_USERNAME=dtrack
      - ALPINE_DATABASE_PASSWORD=${DTRACK_DB_PASSWORD:-dtrack}
      - ALPINE_SECRET_KEY_PATH=/data/.secret.key
      - JAVA_OPTIONS=-Xmx4g -Xms2g
    volumes:
      - dtrack_data:/data
    ports:
      - "8081:8080"
    depends_on:
      dtrack-db:
        condition: service_healthy

  dtrack-frontend:
    image: dependencytrack/frontend:latest
    container_name: dtrack-frontend
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - API_BASE_URL=http://localhost:8081
    ports:
      - "8080:8080"
    depends_on:
      - dtrack-apiserver

  dtrack-db:
    image: postgres:15-alpine
    container_name: dtrack-db
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - POSTGRES_USER=dtrack
      - POSTGRES_PASSWORD=${DTRACK_DB_PASSWORD:-dtrack}
      - POSTGRES_DB=dtrack
    volumes:
      - dtrack_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "dtrack", "-d", "dtrack"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

volumes:
  dtrack_data:
  dtrack_db:
EOF
}

#######################################
# TESTING PLUGINS
#######################################

# Create kiwi-tcms plugin
create_plugin_kiwi_tcms() {
    local dir
    dir=$(create_plugin_dir "kiwi-tcms")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="kiwi-tcms"
PLUGIN_NAME="Kiwi TCMS"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="testing"
PLUGIN_DESCRIPTION="Test case management system"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu"
PLUGIN_DOCKER_PORT="8443"
PLUGIN_DOCKER_URL="https://{IP}:8443"
PLUGIN_DOCKER_CREDENTIALS="(self-signed cert)"
PLUGIN_NATIVE_URL="http://{IP}/"
PLUGIN_NATIVE_CREDENTIALS="Create admin: /opt/kiwi/create_superuser.sh"
PLUGIN_SYSTEMD_SERVICE="kiwi"
PLUGIN_DOCKER_CONTAINER="kiwi-tcms"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  kiwi:
    image: kiwitcms/kiwi:latest
    container_name: kiwi-tcms
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      - KIWI_DB_ENGINE=django.db.backends.postgresql
      - KIWI_DB_HOST=kiwi-db
      - KIWI_DB_PORT=5432
      - KIWI_DB_NAME=kiwi
      - KIWI_DB_USER=kiwi
      - KIWI_DB_PASSWORD=${KIWI_DB_PASSWORD:-kiwi}
    volumes:
      - kiwi_uploads:/Kiwi/uploads
    depends_on:
      kiwi-db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-k", "-f", "https://localhost:8443/"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 120s

  kiwi-db:
    image: postgres:15
    container_name: kiwi-db
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - POSTGRES_USER=kiwi
      - POSTGRES_PASSWORD=${KIWI_DB_PASSWORD:-kiwi}
      - POSTGRES_DB=kiwi
    volumes:
      - kiwi_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "kiwi", "-d", "kiwi"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

volumes:
  kiwi_uploads:
  kiwi_db:
EOF

    # install.sh - kiwi-tcms native is complex
    cat > "$dir/install.sh" << 'INSTALLEOF'
#!/bin/bash
# Native installation script for Kiwi TCMS
# NOTE: This is a complex installation that may take 10-15 minutes
case "$OS_TYPE" in
    debian|ubuntu)
        echo "Setting up locales..."
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y locales"
        lxc_exec_live "$VMID" "sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen"
        lxc_exec_live "$VMID" "locale-gen en_US.UTF-8"
        lxc_exec_live "$VMID" "update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8"

        echo "Installing system dependencies..."
        lxc_exec_live "$VMID" "DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip python3-venv python3-dev gcc libpq-dev postgresql postgresql-contrib nginx git libxml2-dev libxslt1-dev libffi-dev libssl-dev cargo pkg-config curl nodejs npm default-libmysqlclient-dev pkg-config"

        lxc_exec_live "$VMID" "systemctl enable postgresql"
        lxc_exec_live "$VMID" "systemctl start postgresql"

        echo "Setting up PostgreSQL database..."
        lxc_exec_live "$VMID" "sudo -u postgres psql -c \"CREATE USER kiwi WITH PASSWORD 'kiwi';\""
        lxc_exec_live "$VMID" "sudo -u postgres psql -c 'CREATE DATABASE kiwi OWNER kiwi;'"

        echo "Creating kiwi user..."
        lxc_exec_live "$VMID" "useradd -r -s /bin/bash -d /opt/kiwi -m kiwi 2>/dev/null || true"

        echo "Setting up Python virtual environment..."
        lxc_exec_live "$VMID" "python3 -m venv /opt/kiwi/venv"

        echo "Installing Kiwi TCMS from GitHub..."
        lxc_exec_live "$VMID" "/opt/kiwi/venv/bin/pip install --upgrade pip wheel setuptools"
        lxc_exec_live "$VMID" "/opt/kiwi/venv/bin/pip install 'Django>=4.2,<5.0' gunicorn psycopg2-binary mysqlclient"

        # Clone Kiwi TCMS from GitHub and install
        echo "Cloning Kiwi TCMS repository..."
        lxc_exec_live "$VMID" "rm -rf /opt/kiwi/Kiwi"
        lxc_exec_live "$VMID" "git clone --depth 1 https://github.com/kiwitcms/Kiwi.git /opt/kiwi/Kiwi"

        echo "Installing Kiwi TCMS dependencies..."
        lxc_exec_live "$VMID" "/opt/kiwi/venv/bin/pip install -r /opt/kiwi/Kiwi/requirements/base.txt"

        # Verify tcms module installation
        echo "Verifying tcms module..."
        if ! lxc_exec "$VMID" "source /opt/kiwi/venv/bin/activate && PYTHONPATH=/opt/kiwi/Kiwi python -c 'import tcms; print(tcms)'"; then
            echo "ERROR: tcms module not found"
            exit 1
        fi

        echo "Configuring Kiwi TCMS..."
        lxc_exec_live "$VMID" "mkdir -p /Kiwi/uploads /Kiwi/static"
        lxc_exec_live "$VMID" "chown -R kiwi:kiwi /opt/kiwi /Kiwi"

        # Create local settings in the CORRECT location for product.py to find it
        # product.py imports from tcms.settings.local_settings, not tcms_local_settings.py
        lxc_exec "$VMID" "cat > /opt/kiwi/Kiwi/tcms/settings/local_settings.py << 'SETTINGSEOF'
import os
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'kiwi',
        'USER': 'kiwi',
        'PASSWORD': 'kiwi',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
SECRET_KEY = 'change-me-in-production'
ALLOWED_HOSTS = ['*']
STATIC_ROOT = '/Kiwi/static'
MEDIA_ROOT = '/Kiwi/uploads'
DEBUG = False
SETTINGSEOF"

        # Also create a copy at the old location for backwards compatibility
        lxc_exec_live "$VMID" "cp /opt/kiwi/Kiwi/tcms/settings/local_settings.py /opt/kiwi/Kiwi/tcms_local_settings.py"

        # Install npm packages for frontend dependencies (bootstrap, jquery, patternfly, etc.)
        echo "Installing frontend dependencies (npm packages)..."
        lxc_exec_live "$VMID" "cd /opt/kiwi/Kiwi/tcms && npm install"

        # Clear Python cache to avoid stale bytecode issues
        echo "Clearing Python cache..."
        lxc_exec_live "$VMID" "find /opt/kiwi/Kiwi -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true"

        # Set all Kiwi environment variables (database + static files + secret key)
        local kiwi_env="export KIWI_DB_ENGINE=django.db.backends.postgresql && export KIWI_DB_NAME=kiwi && export KIWI_DB_USER=kiwi && export KIWI_DB_PASSWORD=kiwi && export KIWI_DB_HOST=localhost && export KIWI_DB_PORT=5432 && export STATIC_ROOT=/Kiwi/static && export MEDIA_ROOT=/Kiwi/uploads && export SECRET_KEY=change-me-in-production-$(date +%s)"

        echo "Running Django migrations..."
        lxc_exec_live "$VMID" "source /opt/kiwi/venv/bin/activate && export PYTHONPATH=/opt/kiwi/Kiwi && export DJANGO_SETTINGS_MODULE=tcms.settings.product && export KIWI_SETTINGS_DIR=/opt/kiwi/Kiwi && $kiwi_env && cd /opt/kiwi/Kiwi && python -m django migrate"

        echo "Collecting static files (including npm packages)..."
        lxc_exec_live "$VMID" "source /opt/kiwi/venv/bin/activate && export PYTHONPATH=/opt/kiwi/Kiwi && export DJANGO_SETTINGS_MODULE=tcms.settings.product && export KIWI_SETTINGS_DIR=/opt/kiwi/Kiwi && $kiwi_env && cd /opt/kiwi/Kiwi && python -m django collectstatic --noinput --clear"

        # Verify static files were collected (including frontend packages)
        echo "Verifying static files..."
        lxc_exec_live "$VMID" "ls -la /Kiwi/static/ | head -20"
        lxc_exec_live "$VMID" "ls -la /Kiwi/static/admin/css/ 2>/dev/null | head -3 || echo 'WARNING: Admin CSS not found'"
        lxc_exec_live "$VMID" "ls /Kiwi/static/patternfly/dist/css/ 2>/dev/null | head -3 || echo 'WARNING: Patternfly CSS not found'"
        lxc_exec_live "$VMID" "ls /Kiwi/static/bootstrap/dist/js/ 2>/dev/null | head -3 || echo 'WARNING: Bootstrap JS not found'"
        lxc_exec_live "$VMID" "ls /Kiwi/static/jquery/dist/ 2>/dev/null | head -3 || echo 'WARNING: jQuery not found'"

        # Set proper permissions for static files (readable by nginx)
        echo "Setting static files permissions..."
        lxc_exec_live "$VMID" "chown -R kiwi:www-data /Kiwi/static /Kiwi/uploads"
        lxc_exec_live "$VMID" "chmod -R 755 /Kiwi/static"
        lxc_exec_live "$VMID" "chmod -R 755 /Kiwi/uploads"
        lxc_exec_live "$VMID" "find /Kiwi/static -type f -exec chmod 644 {} \\;"

        # Create systemd service using wrapper script for proper venv activation
        lxc_exec "$VMID" "cat > /opt/kiwi/start_kiwi.sh << 'STARTEOF'
#!/bin/bash
source /opt/kiwi/venv/bin/activate
export PYTHONPATH=/opt/kiwi/Kiwi
export DJANGO_SETTINGS_MODULE=tcms.settings.product
export KIWI_SETTINGS_DIR=/opt/kiwi/Kiwi
# PostgreSQL database configuration
export KIWI_DB_ENGINE=django.db.backends.postgresql
export KIWI_DB_NAME=kiwi
export KIWI_DB_USER=kiwi
export KIWI_DB_PASSWORD=kiwi
export KIWI_DB_HOST=localhost
export KIWI_DB_PORT=5432
# Static and media files
export STATIC_ROOT=/Kiwi/static
export MEDIA_ROOT=/Kiwi/uploads
export SECRET_KEY=change-me-in-production
cd /opt/kiwi/Kiwi
exec gunicorn --bind 127.0.0.1:8080 --workers 3 --timeout 120 tcms.wsgi:application
STARTEOF"
        lxc_exec_live "$VMID" "chmod +x /opt/kiwi/start_kiwi.sh"
        lxc_exec_live "$VMID" "chown kiwi:kiwi /opt/kiwi/start_kiwi.sh"

        # Create systemd service
        lxc_exec "$VMID" "cat > /etc/systemd/system/kiwi.service << 'SVCEOF'
[Unit]
Description=Kiwi TCMS
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=kiwi
Group=kiwi
WorkingDirectory=/opt/kiwi/Kiwi
ExecStart=/opt/kiwi/start_kiwi.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF"

        # Configure nginx with proper static file serving
        lxc_exec "$VMID" "cat > /etc/nginx/sites-available/kiwi << 'NGINXEOF'
server {
    listen 80 default_server;
    server_name _;
    client_max_body_size 100M;

    # Serve static files directly
    location /static/ {
        alias /Kiwi/static/;
        autoindex off;
        expires 30d;
        add_header Cache-Control public;

        # Ensure correct MIME types
        types {
            text/css css;
            application/javascript js;
            application/json json;
            image/svg+xml svg svgz;
            font/woff woff;
            font/woff2 woff2;
            application/vnd.ms-fontobject eot;
            font/ttf ttf;
            font/otf otf;
        }
    }

    # Media/uploads files
    location /uploads/ {
        alias /Kiwi/uploads/;
        autoindex off;
        expires 7d;
    }

    # Favicon
    location = /favicon.ico {
        alias /Kiwi/static/images/favicon.ico;
        expires 30d;
        access_log off;
        log_not_found off;
    }

    # Proxy to gunicorn
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
    }
}
NGINXEOF"

        lxc_exec_live "$VMID" "rm -f /etc/nginx/sites-enabled/default"
        lxc_exec_live "$VMID" "ln -sf /etc/nginx/sites-available/kiwi /etc/nginx/sites-enabled/kiwi"

        # Create superuser script
        lxc_exec "$VMID" "cat > /opt/kiwi/create_superuser.sh << 'SUPEREOF'
#!/bin/bash
source /opt/kiwi/venv/bin/activate
export PYTHONPATH=/opt/kiwi/Kiwi
export DJANGO_SETTINGS_MODULE=tcms.settings.product
export KIWI_SETTINGS_DIR=/opt/kiwi/Kiwi
# PostgreSQL database configuration
export KIWI_DB_ENGINE=django.db.backends.postgresql
export KIWI_DB_NAME=kiwi
export KIWI_DB_USER=kiwi
export KIWI_DB_PASSWORD=kiwi
export KIWI_DB_HOST=localhost
export KIWI_DB_PORT=5432
# Static and media files
export STATIC_ROOT=/Kiwi/static
export MEDIA_ROOT=/Kiwi/uploads
export SECRET_KEY=change-me-in-production
cd /opt/kiwi/Kiwi
python -m django createsuperuser
SUPEREOF"
        lxc_exec_live "$VMID" "chmod +x /opt/kiwi/create_superuser.sh"

        lxc_exec_live "$VMID" "systemctl daemon-reload"
        lxc_exec_live "$VMID" "systemctl enable kiwi nginx"
        lxc_exec_live "$VMID" "systemctl restart kiwi"
        lxc_exec_live "$VMID" "systemctl restart nginx"

        # Set the Kiwi TCMS domain to the container IP
        echo "Setting Kiwi TCMS domain..."
        local container_ip
        container_ip=$(lxc_exec "$VMID" "hostname -I | awk '{print \$1}'" 2>/dev/null | tr -d '[:space:]')
        if [ -n "$container_ip" ]; then
            lxc_exec_live "$VMID" "source /opt/kiwi/venv/bin/activate && export PYTHONPATH=/opt/kiwi/Kiwi && export DJANGO_SETTINGS_MODULE=tcms.settings.product && cd /opt/kiwi/Kiwi && python -m django set_domain $container_ip"
            echo "Kiwi TCMS domain set to: $container_ip"
        fi
        ;;
    *)
        echo "ERROR: Unsupported OS for native Kiwi TCMS installation"
        exit 1
        ;;
esac
INSTALLEOF

    # remove.sh
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for Kiwi TCMS
lxc_exec_live "$VMID" "systemctl stop kiwi 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl stop nginx 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl disable kiwi 2>/dev/null || true"
lxc_exec_live "$VMID" "rm -f /etc/systemd/system/kiwi.service"
lxc_exec_live "$VMID" "rm -f /etc/nginx/sites-enabled/kiwi"
lxc_exec_live "$VMID" "rm -f /etc/nginx/sites-available/kiwi"
lxc_exec_live "$VMID" "rm -rf /opt/kiwi"
lxc_exec_live "$VMID" "rm -rf /Kiwi"
lxc_exec_live "$VMID" "sudo -u postgres psql -c 'DROP DATABASE IF EXISTS kiwi;' 2>/dev/null || true"
lxc_exec_live "$VMID" "sudo -u postgres psql -c 'DROP USER IF EXISTS kiwi;' 2>/dev/null || true"
lxc_exec_live "$VMID" "userdel -r kiwi 2>/dev/null || true"
lxc_exec_live "$VMID" "ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl restart nginx 2>/dev/null || true"
EOF
}

# Create selenium-grid plugin
create_plugin_selenium_grid() {
    local dir
    dir=$(create_plugin_dir "selenium-grid")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="selenium-grid"
PLUGIN_NAME="Selenium Grid"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="testing"
PLUGIN_DESCRIPTION="Browser automation grid"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="4444"
PLUGIN_DOCKER_URL="http://{IP}:4444"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_DOCKER_CONTAINER="selenium-hub"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  selenium-hub:
    image: selenium/hub:latest
    container_name: selenium-hub
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "4442:4442"
      - "4443:4443"
      - "4444:4444"

  chrome:
    image: selenium/node-chrome:latest
    container_name: selenium-chrome
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    depends_on:
      - selenium-hub
    environment:
      - SE_EVENT_BUS_HOST=selenium-hub
      - SE_EVENT_BUS_PUBLISH_PORT=4442
      - SE_EVENT_BUS_SUBSCRIBE_PORT=4443
    shm_size: '2gb'

  firefox:
    image: selenium/node-firefox:latest
    container_name: selenium-firefox
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    depends_on:
      - selenium-hub
    environment:
      - SE_EVENT_BUS_HOST=selenium-hub
      - SE_EVENT_BUS_PUBLISH_PORT=4442
      - SE_EVENT_BUS_SUBSCRIBE_PORT=4443
    shm_size: '2gb'
EOF
}

# Create testlink plugin
create_plugin_testlink() {
    local dir
    dir=$(create_plugin_dir "testlink")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="testlink"
PLUGIN_NAME="TestLink"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="testing"
PLUGIN_DESCRIPTION="Test management and requirements tracking"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu"
PLUGIN_DOCKER_PORT="80"
PLUGIN_DOCKER_URL="http://{IP}/"
PLUGIN_DOCKER_CREDENTIALS="admin/admin123"
PLUGIN_NATIVE_URL="http://{IP}/"
PLUGIN_NATIVE_CREDENTIALS="Complete setup at install/index.php"
PLUGIN_SYSTEMD_SERVICE="nginx"
PLUGIN_DOCKER_CONTAINER="testlink"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  testlink:
    image: bitnami/testlink:latest
    container_name: testlink
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "80:8080"
      - "443:8443"
    environment:
      - TESTLINK_DATABASE_HOST=testlink-db
      - TESTLINK_DATABASE_PORT_NUMBER=3306
      - TESTLINK_DATABASE_NAME=testlink
      - TESTLINK_DATABASE_USER=testlink
      - TESTLINK_DATABASE_PASSWORD=${TESTLINK_DB_PASSWORD:-testlink123}
      - TESTLINK_USERNAME=admin
      - TESTLINK_PASSWORD=${TESTLINK_ADMIN_PASSWORD:-admin123}
      - TESTLINK_EMAIL=admin@example.com
      - ALLOW_EMPTY_PASSWORD=no
    volumes:
      - testlink_data:/bitnami/testlink
    depends_on:
      testlink-db:
        condition: service_healthy

  testlink-db:
    image: mariadb:10.11
    container_name: testlink-db
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - MARIADB_ROOT_PASSWORD=${TESTLINK_ROOT_PASSWORD:-rootpassword}
      - MARIADB_DATABASE=testlink
      - MARIADB_USER=testlink
      - MARIADB_PASSWORD=${TESTLINK_DB_PASSWORD:-testlink123}
    volumes:
      - testlink_db:/var/lib/mysql
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 60s

volumes:
  testlink_data:
  testlink_db:
EOF

    # install.sh - testlink native is complex
    cat > "$dir/install.sh" << 'INSTALLEOF'
#!/bin/bash
# Native installation script for TestLink
case "$OS_TYPE" in
    debian|ubuntu)
        echo "Installing TestLink dependencies..."
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y locales"
        lxc_exec_live "$VMID" "sed -i 's/# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen"
        lxc_exec_live "$VMID" "locale-gen en_US.UTF-8"

        echo "Installing MariaDB..."
        lxc_exec_live "$VMID" "DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client"
        lxc_exec_live "$VMID" "systemctl start mariadb"
        lxc_exec_live "$VMID" "systemctl enable mariadb"

        echo "Setting up database..."
        lxc_exec_live "$VMID" "mysql -e 'DROP DATABASE IF EXISTS testlink;' 2>/dev/null || true"
        lxc_exec_live "$VMID" "mysql -e \"DROP USER IF EXISTS 'testlink'@'localhost';\" 2>/dev/null || true"
        lxc_exec_live "$VMID" "mysql -e 'FLUSH PRIVILEGES;'"
        lxc_exec_live "$VMID" "mysql -e \"CREATE DATABASE testlink DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\""
        lxc_exec_live "$VMID" "mysql -e \"CREATE USER 'testlink'@'localhost' IDENTIFIED BY 'testlink123';\""
        lxc_exec_live "$VMID" "mysql -e \"GRANT ALL PRIVILEGES ON testlink.* TO 'testlink'@'localhost' WITH GRANT OPTION;\""
        lxc_exec_live "$VMID" "mysql -e 'FLUSH PRIVILEGES;'"

        echo "Installing Nginx and PHP-FPM..."
        lxc_exec_live "$VMID" "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx php-fpm php-mysql php-gd php-xml php-mbstring php-ldap php-curl php-zip php-cli wget unzip"

        echo "Downloading TestLink..."
        lxc_exec_live "$VMID" "rm -rf /var/www/testlink"
        lxc_exec_live "$VMID" "mkdir -p /var/www/testlink"
        lxc_exec_live "$VMID" "wget -q -O /tmp/testlink.tar.gz https://github.com/TestLinkOpenSourceTRMS/testlink-code/archive/refs/tags/1.9.20.tar.gz"
        lxc_exec_live "$VMID" "tar -xzf /tmp/testlink.tar.gz -C /var/www/testlink --strip-components=1"
        lxc_exec_live "$VMID" "rm /tmp/testlink.tar.gz"

        # Set permissions
        lxc_exec_live "$VMID" "mkdir -p /var/testlink/logs /var/testlink/upload_area"
        lxc_exec_live "$VMID" "chown -R www-data:www-data /var/www/testlink /var/testlink"
        lxc_exec_live "$VMID" "chmod -R 755 /var/www/testlink /var/testlink"

        # Get PHP version
        local php_version
        php_version=$(lxc_exec "$VMID" "php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;' 2>/dev/null")
        [[ -z "$php_version" ]] && php_version="8.2"

        # Configure nginx
        lxc_exec "$VMID" "cat > /etc/nginx/sites-available/testlink << 'NGINXEOF'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/testlink;
    index index.php index.html;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \\.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${php_version}-fpm.sock;
    }
}
NGINXEOF"

        lxc_exec_live "$VMID" "rm -f /etc/nginx/sites-enabled/default"
        lxc_exec_live "$VMID" "ln -sf /etc/nginx/sites-available/testlink /etc/nginx/sites-enabled/testlink"
        lxc_exec_live "$VMID" "systemctl restart nginx"
        lxc_exec_live "$VMID" "systemctl restart php${php_version}-fpm"

        echo ""
        echo "TestLink installed. Complete setup at http://<ip>/install/index.php"
        echo "DB: testlink, User: testlink, Password: testlink123"
        ;;
    *)
        echo "ERROR: Unsupported OS for native TestLink installation"
        exit 1
        ;;
esac
INSTALLEOF

    # remove.sh
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for TestLink
lxc_exec_live "$VMID" "systemctl stop nginx 2>/dev/null || true"
lxc_exec_live "$VMID" "rm -f /etc/nginx/sites-enabled/testlink"
lxc_exec_live "$VMID" "rm -f /etc/nginx/sites-available/testlink"
lxc_exec_live "$VMID" "rm -rf /var/www/testlink"
lxc_exec_live "$VMID" "rm -rf /var/testlink"
lxc_exec_live "$VMID" "mysql -e 'DROP DATABASE IF EXISTS testlink;' 2>/dev/null || true"
lxc_exec_live "$VMID" "mysql -e \"DROP USER IF EXISTS 'testlink'@'localhost';\" 2>/dev/null || true"
lxc_exec_live "$VMID" "mysql -e 'FLUSH PRIVILEGES;' 2>/dev/null || true"
lxc_exec_live "$VMID" "ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl restart nginx 2>/dev/null || true"
EOF
}

#######################################
# INFRASTRUCTURE PLUGINS
#######################################

# Create pihole plugin
create_plugin_pihole() {
    local dir
    dir=$(create_plugin_dir "pihole")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="pihole"
PLUGIN_NAME="Pi-hole"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="infrastructure"
PLUGIN_DESCRIPTION="Network-wide ad blocking"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu"
PLUGIN_DOCKER_PORT="80"
PLUGIN_DOCKER_URL="Admin: http://{IP}/admin"
PLUGIN_DOCKER_CREDENTIALS="admin"
PLUGIN_NATIVE_URL="Admin: http://{IP}/admin"
PLUGIN_NATIVE_CREDENTIALS="admin (change with: pihole -a -p)"
PLUGIN_SYSTEMD_SERVICE="pihole-FTL"
PLUGIN_DOCKER_CONTAINER="pihole"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  pihole:
    image: pihole/pihole:latest
    container_name: pihole
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "80:80/tcp"
    environment:
      - TZ=${PIHOLE_TZ:-UTC}
      - WEBPASSWORD=${PIHOLE_PASSWORD:-admin}
      - FTLCONF_LOCAL_IPV4=${PIHOLE_IP:-}
      - DNSMASQ_LISTENING=all
    volumes:
      - pihole_data:/etc/pihole
      - pihole_dnsmasq:/etc/dnsmasq.d
    cap_add:
      - NET_ADMIN

volumes:
  pihole_data:
  pihole_dnsmasq:
EOF

    # install.sh
    cat > "$dir/install.sh" << 'INSTALLEOF'
#!/bin/bash
# Native installation script for Pi-hole
case "$OS_TYPE" in
    debian|ubuntu)
        echo "Installing Pi-hole..."
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "apt-get install -y curl"

        # Create setup vars for unattended install
        lxc_exec "$VMID" "mkdir -p /etc/pihole"
        lxc_exec "$VMID" "cat > /etc/pihole/setupVars.conf << 'SETUPEOF'
PIHOLE_INTERFACE=eth0
IPV4_ADDRESS=0.0.0.0
IPV6_ADDRESS=
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=all
WEBPASSWORD=admin
BLOCKING_ENABLED=true
PIHOLE_DNS_1=8.8.8.8
PIHOLE_DNS_2=8.8.4.4
SETUPEOF"

        # Run Pi-hole installer
        lxc_exec_live "$VMID" "curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended"

        echo ""
        echo "Pi-hole installed. Admin password: admin"
        echo "Change password with: pihole -a -p <newpassword>"
        ;;
    *)
        echo "ERROR: Unsupported OS for native Pi-hole installation"
        exit 1
        ;;
esac
INSTALLEOF

    # remove.sh
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for Pi-hole
if lxc_exec "$VMID" "test -f /etc/.pihole/automated\ install/uninstall.sh" 2>/dev/null; then
    lxc_exec_live "$VMID" "pihole uninstall --unattended 2>/dev/null || true"
else
    lxc_exec_live "$VMID" "systemctl stop pihole-FTL 2>/dev/null || true"
    lxc_exec_live "$VMID" "systemctl stop lighttpd 2>/dev/null || true"
    lxc_exec_live "$VMID" "systemctl disable pihole-FTL 2>/dev/null || true"
    lxc_exec_live "$VMID" "systemctl disable lighttpd 2>/dev/null || true"
    lxc_exec_live "$VMID" "rm -rf /etc/pihole /etc/.pihole /opt/pihole /var/www/html/admin"
    lxc_exec_live "$VMID" "rm -f /usr/local/bin/pihole"
    lxc_exec_live "$VMID" "rm -rf /etc/lighttpd"
    lxc_exec_live "$VMID" "apt-get purge -y pihole-FTL lighttpd 2>/dev/null || true"
    lxc_exec_live "$VMID" "apt-get autoremove -y 2>/dev/null || true"
fi
lxc_exec_live "$VMID" "rm -f /etc/resolv.conf"
lxc_exec_live "$VMID" "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
EOF
}

# Create keycloak plugin
create_plugin_keycloak() {
    local dir
    dir=$(create_plugin_dir "keycloak")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="keycloak"
PLUGIN_NAME="Keycloak"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="infrastructure"
PLUGIN_DESCRIPTION="Identity and access management"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="8080"
PLUGIN_DOCKER_URL="http://{IP}:8080"
PLUGIN_DOCKER_CREDENTIALS="admin/admin"
PLUGIN_DOCKER_CONTAINER="keycloak"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    container_name: keycloak
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - KEYCLOAK_ADMIN=admin
      - KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:-admin}
      - KC_DB=postgres
      - KC_DB_URL=jdbc:postgresql://keycloak-db:5432/keycloak
      - KC_DB_USERNAME=keycloak
      - KC_DB_PASSWORD=${KEYCLOAK_DB_PASSWORD:-keycloak}
      - KC_HOSTNAME_STRICT=false
      - KC_HTTP_ENABLED=true
      - KC_PROXY=edge
    command:
      - start-dev
    ports:
      - "8080:8080"
    depends_on:
      keycloak-db:
        condition: service_healthy

  keycloak-db:
    image: postgres:15-alpine
    container_name: keycloak-db
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - POSTGRES_USER=keycloak
      - POSTGRES_PASSWORD=${KEYCLOAK_DB_PASSWORD:-keycloak}
      - POSTGRES_DB=keycloak
    volumes:
      - keycloak_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "keycloak", "-d", "keycloak"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

volumes:
  keycloak_db:
EOF
}

# Create freeipa plugin
create_plugin_freeipa() {
    local dir
    dir=$(create_plugin_dir "freeipa")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="freeipa"
PLUGIN_NAME="FreeIPA"
PLUGIN_VERSION="fedora-43-4.13.0"
PLUGIN_CATEGORY="infrastructure"
PLUGIN_DESCRIPTION="Identity management system"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="443"
PLUGIN_DOCKER_URL="Web UI: https://{IP}/\nLDAP: ldap://{IP}:389\nKerberos: {IP}:88\n\nDefault admin password: Admin123\nNote: First startup takes 5-10 minutes\nCheck logs: docker logs -f freeipa"
PLUGIN_DOCKER_CREDENTIALS="admin / Admin123"
PLUGIN_DOCKER_CONTAINER="freeipa"
EOF

    # compose.yml - Note: FreeIPA is deployed via custom docker run in deploy_service_with_progress
    # This compose.yml is kept for reference but the deploy function uses docker run directly
    # to handle --add-host for hostname resolution
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  freeipa:
    image: freeipa/freeipa-server:fedora-43-4.13.0
    container_name: freeipa
    hostname: ipa.srv.local
    restart: unless-stopped
    privileged: true
    stdin_open: true
    tty: true
    security_opt:
      - seccomp:unconfined
      - apparmor:unconfined
    cgroup: host
    environment:
      - PASSWORD=Admin123
    command:
      - -U
      - --realm=SRV.LOCAL
      - --domain=srv.local
      - --ds-password=Admin123
      - --admin-password=Admin123
      - --no-ntp
      - --no-host-dns
      - --setup-dns
      - --no-forwarders
      - --allow-zone-overlap
    ports:
      - "80:80"
      - "443:443"
      - "389:389"
      - "636:636"
      - "88:88"
      - "88:88/udp"
      - "464:464"
      - "464:464/udp"
      - "53:53"
      - "53:53/udp"
    volumes:
      - freeipa_data:/data
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
    tmpfs:
      - /run
      - /tmp

volumes:
  freeipa_data:
EOF

    # Create a helper script for manual docker run
    cat > "$dir/run.sh" << 'RUNEOF'
#!/bin/bash
# Manual FreeIPA deployment script
# Usage: ./run.sh [FQDN] [CONTAINER_IP]
# Example: ./run.sh ipa.home.lab 192.168.1.100

FQDN="${1:-ipa.srv.local}"
CONTAINER_IP="${2:-$(hostname -I | awk '{print $1}')}"
DOMAIN="${FQDN#*.}"
REALM="${DOMAIN^^}"

echo "FreeIPA deployment:"
echo "  FQDN:   $FQDN"
echo "  Domain: $DOMAIN"
echo "  Realm:  $REALM"
echo "  IP:     $CONTAINER_IP"
echo ""

# Update /etc/hosts
grep -q "$FQDN" /etc/hosts || echo "${CONTAINER_IP} ${FQDN} ${FQDN%%.*}" >> /etc/hosts

# Clean up previous instance and stale networking state
echo "Cleaning up previous deployment..."
docker rm -f freeipa 2>/dev/null || true
docker volume rm freeipa_data 2>/dev/null || true
docker network prune -f 2>/dev/null || true
docker container prune -f 2>/dev/null || true

# Disable systemd start rate limiting for docker
echo "Preparing Docker daemon..."
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/no-rate-limit.conf << 'SVCEOF'
[Unit]
StartLimitIntervalSec=0
StartLimitBurst=0
[Service]
RestartSec=3
SVCEOF
systemctl daemon-reload
systemctl reset-failed docker.service containerd.service 2>/dev/null || true

# Full stop and clean
systemctl stop docker.socket docker containerd 2>/dev/null || true
rm -rf /var/run/docker /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null || true

# Start clean
echo "Starting Docker daemon..."
systemctl start containerd
sleep 2
systemctl start docker
sleep 3

if ! docker info >/dev/null 2>&1; then
    echo "Docker failed to start. Retrying..."
    systemctl stop docker.socket docker containerd 2>/dev/null || true
    rm -rf /var/run/docker /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null || true
    systemctl reset-failed docker.service containerd.service 2>/dev/null || true
    sleep 5
    systemctl start containerd
    sleep 2
    systemctl start docker
    sleep 5
    if ! docker info >/dev/null 2>&1; then
        echo "ERROR: Docker daemon failed to start."
        echo "Check: journalctl -u docker.service -n 20"
        exit 1
    fi
fi
echo "Docker daemon is healthy."
echo ""

docker run -d \
    --name freeipa \
    --hostname "${FQDN}" \
    --privileged \
    --security-opt seccomp=unconfined \
    --security-opt apparmor=unconfined \
    --cgroupns=host \
    --add-host "${FQDN}:${CONTAINER_IP}" \
    -e PASSWORD=Admin123 \
    -p 80:80 -p 443:443 \
    -p 389:389 -p 636:636 \
    -p 88:88 -p 88:88/udp \
    -p 464:464 -p 464:464/udp \
    -p 53:53 -p 53:53/udp \
    -v freeipa_data:/data \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /tmp \
    freeipa/freeipa-server:fedora-43-4.13.0 \
    -U "--realm=${REALM}" "--domain=${DOMAIN}" \
    --ds-password=Admin123 --admin-password=Admin123 \
    --no-ntp --no-host-dns \
    --setup-dns --no-forwarders --allow-zone-overlap

echo ""
echo "FreeIPA container started. Check logs with: docker logs -f freeipa"
echo "First startup takes 5-10 minutes for initial configuration."
echo "Access: https://${CONTAINER_IP}/ (admin / Admin123)"
RUNEOF
    chmod +x "$dir/run.sh"
}

# Create postfix-relay plugin
create_plugin_postfix_relay() {
    local dir
    dir=$(create_plugin_dir "postfix-relay")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="postfix-relay"
PLUGIN_NAME="Postfix Relay"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="infrastructure"
PLUGIN_DESCRIPTION="SMTP relay server"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="25"
PLUGIN_DOCKER_URL="SMTP: {IP}:25\nSubmission: {IP}:587"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_DOCKER_CONTAINER="postfix-relay"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  postfix:
    image: boky/postfix:latest
    container_name: postfix-relay
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - ALLOWED_SENDER_DOMAINS=${POSTFIX_ALLOWED_DOMAINS:-example.com}
      - HOSTNAME=${POSTFIX_HOSTNAME:-mail.example.com}
      - RELAYHOST=${POSTFIX_RELAYHOST:-}
      - RELAYHOST_USERNAME=${POSTFIX_RELAY_USER:-}
      - RELAYHOST_PASSWORD=${POSTFIX_RELAY_PASS:-}
      - SMTP_TLS_SECURITY_LEVEL=may
      - MESSAGE_SIZE_LIMIT=52428800
    ports:
      - "25:25"
      - "587:587"
    volumes:
      - postfix_spool:/var/spool/postfix
      - postfix_logs:/var/log

volumes:
  postfix_spool:
  postfix_logs:
EOF
}

# Create traefik plugin
create_plugin_traefik() {
    local dir
    dir=$(create_plugin_dir "traefik")

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="traefik"
PLUGIN_NAME="Traefik"
PLUGIN_VERSION="latest"
PLUGIN_CATEGORY="infrastructure"
PLUGIN_DESCRIPTION="Modern reverse proxy and load balancer"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_DOCKER_PORT="8080"
PLUGIN_DOCKER_URL="Dashboard: http://{IP}:8080\nHTTP: http://{IP}\nHTTPS: https://{IP}"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_DOCKER_CONTAINER="traefik"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  traefik:
    image: traefik:latest
    container_name: traefik
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yml:/etc/traefik/traefik.yml:ro
      - ./dynamic:/etc/traefik/dynamic:ro
      - /etc/ssl/pve-manager:/etc/ssl/certs:ro
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--providers.file.directory=/etc/traefik/dynamic"
EOF

    # traefik.yml (extra config)
    cat > "$dir/traefik.yml" << 'EOF'
api:
  dashboard: true
  insecure: true

entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
  file:
    directory: "/etc/traefik/dynamic"
    watch: true
EOF
}

# Create nginx plugin (reverse proxy / web server)
create_plugin_nginx() {
    local dir
    dir=$(create_plugin_dir "nginx")
    mkdir -p "$dir/conf.d"

    # plugin.conf
    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="nginx"
PLUGIN_NAME="Nginx"
PLUGIN_VERSION="stable"
PLUGIN_CATEGORY="infrastructure"
PLUGIN_DESCRIPTION="Reverse proxy and web server"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="true"
PLUGIN_NATIVE_OS="debian ubuntu alpine"
PLUGIN_DOCKER_PORT="80"
PLUGIN_DOCKER_URL="HTTP: http://{IP}\nHTTPS: https://{IP}"
PLUGIN_DOCKER_CREDENTIALS=""
PLUGIN_NATIVE_URL="HTTP: http://{IP}\nHTTPS: https://{IP}"
PLUGIN_NATIVE_CREDENTIALS=""
PLUGIN_SYSTEMD_SERVICE="nginx"
PLUGIN_DOCKER_CONTAINER="nginx"
EOF

    # compose.yml
    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  nginx:
    image: nginx:stable
    container_name: nginx
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./conf.d:/etc/nginx/conf.d:ro
      - ./ssl:/etc/nginx/ssl:ro
      - /etc/ssl/pve-manager:/etc/ssl/pve-manager:ro
EOF

    # nginx.conf (main config)
    cat > "$dir/nginx.conf" << 'EOF'
user  nginx;
worker_processes  auto;
error_log  /var/log/nginx/error.log  warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;

    sendfile           on;
    keepalive_timeout  65;
    client_max_body_size 100M;

    # Reverse proxy sites live in conf.d/*.conf
    include /etc/nginx/conf.d/*.conf;
}
EOF

    # conf.d/default.conf (reverse proxy site template, shared by docker + native)
    cat > "$dir/conf.d/default.conf" << 'EOF'
# ============================================================================
# PVE Manager - Nginx reverse proxy site
# Edit the server/location blocks below to route to your backends.
# Apply changes:  Docker  -> docker compose restart nginx
#                 Native  -> nginx -t && systemctl reload nginx
# ============================================================================

# Optional: define reusable upstreams for load balancing
# upstream app_backend {
#     server 10.0.0.50:8080;
#     # server 10.0.0.51:8080;
# }

# HTTP -> health check + redirect to HTTPS
server {
    listen 80 default_server;
    server_name _;

    location /healthz {
        default_type text/plain;
        return 200 "ok\n";
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS reverse proxy
server {
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate     /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # ------------------------------------------------------------------
    # REVERSE PROXY EXAMPLE - uncomment and point at your service, then
    # remove the placeholder "location /" block below.
    # ------------------------------------------------------------------
    # location / {
    #     proxy_pass http://10.0.0.50:8080;            # <-- backend IP:port
    #     proxy_set_header Host              $host;
    #     proxy_set_header X-Real-IP         $remote_addr;
    #     proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    #     proxy_set_header X-Forwarded-Proto $scheme;
    #     proxy_http_version 1.1;
    #     proxy_set_header Upgrade           $http_upgrade;
    #     proxy_set_header Connection        "upgrade";
    # }

    location / {
        default_type text/plain;
        return 200 "PVE Manager nginx reverse proxy is running.\nEdit conf.d/default.conf to add your backends.\n";
    }
}
EOF

    # install.sh (native installation)
    cat > "$dir/install.sh" << 'INSTALLEOF'
#!/bin/bash
# Native installation script for Nginx reverse proxy
# Reuses the same reverse proxy site template as the Docker deployment.
site_content=$(cat "${PLUGINS[nginx]}/conf.d/default.conf")

case "$OS_TYPE" in
    debian|ubuntu)
        lxc_exec_live "$VMID" "apt-get update"
        lxc_exec_live "$VMID" "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx openssl"
        lxc_exec_live "$VMID" "mkdir -p /etc/nginx/ssl"
        lxc_exec "$VMID" "test -f /etc/nginx/ssl/server.crt || openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt -subj '/CN=pve-nginx-reverse-proxy' 2>/dev/null"
        lxc_exec "$VMID" "rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true"
        lxc_exec "$VMID" "cat > /etc/nginx/conf.d/pve-reverse-proxy.conf << 'SITEEOF'
${site_content}
SITEEOF"
        lxc_exec_live "$VMID" "nginx -t"
        lxc_exec_live "$VMID" "systemctl enable nginx"
        lxc_exec_live "$VMID" "systemctl restart nginx"
        ;;
    alpine)
        lxc_exec_live "$VMID" "apk add --no-cache nginx openssl"
        lxc_exec_live "$VMID" "mkdir -p /etc/nginx/ssl /run/nginx /etc/nginx/http.d"
        lxc_exec "$VMID" "test -f /etc/nginx/ssl/server.crt || openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt -subj '/CN=pve-nginx-reverse-proxy' 2>/dev/null"
        lxc_exec "$VMID" "rm -f /etc/nginx/http.d/default.conf 2>/dev/null || true"
        lxc_exec "$VMID" "cat > /etc/nginx/http.d/pve-reverse-proxy.conf << 'SITEEOF'
${site_content}
SITEEOF"
        lxc_exec_live "$VMID" "nginx -t"
        lxc_exec_live "$VMID" "rc-update add nginx default"
        lxc_exec_live "$VMID" "rc-service nginx restart"
        ;;
    *)
        echo "ERROR: Unsupported OS for native Nginx installation"
        exit 1
        ;;
esac
INSTALLEOF

    # remove.sh (native removal)
    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal script for Nginx
lxc_exec_live "$VMID" "systemctl stop nginx 2>/dev/null || rc-service nginx stop 2>/dev/null || true"
lxc_exec_live "$VMID" "systemctl disable nginx 2>/dev/null || rc-update del nginx default 2>/dev/null || true"
lxc_exec "$VMID" "rm -f /etc/nginx/conf.d/pve-reverse-proxy.conf /etc/nginx/http.d/pve-reverse-proxy.conf 2>/dev/null || true"
lxc_exec "$VMID" "rm -rf /etc/nginx/ssl 2>/dev/null || true"
lxc_exec_live "$VMID" "apt-get remove -y nginx nginx-common 2>/dev/null || apk del nginx 2>/dev/null || true"
EOF
}

#######################################
# DATABASE PLUGINS
#######################################

# Create MySQL plugin
create_plugin_mysql() {
    local dir
    dir=$(create_plugin_dir "mysql")

    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="mysql"
PLUGIN_NAME="MySQL"
PLUGIN_VERSION="8"
PLUGIN_CATEGORY="database"
PLUGIN_DESCRIPTION="MySQL relational database server"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_NATIVE_OS=""
PLUGIN_DOCKER_PORT="3306"
PLUGIN_DOCKER_URL="{IP}:3306"
PLUGIN_DOCKER_CREDENTIALS="See deployment output"
PLUGIN_NATIVE_URL=""
PLUGIN_NATIVE_CREDENTIALS=""
PLUGIN_SYSTEMD_SERVICE=""
PLUGIN_DOCKER_CONTAINER="mysql"
EOF

    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  mysql:
    image: mysql:8
    container_name: mysql
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    command: --default-authentication-plugin=mysql_native_password
    ports:
      - "${DB_PORT:-3306}:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD:-changeme}
      - MYSQL_DATABASE=${MYSQL_DATABASE:-appdb}
      - MYSQL_USER=${MYSQL_USER:-appuser}
      - MYSQL_PASSWORD=${MYSQL_PASSWORD:-changeme}
    volumes:
      - mysql_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-uroot", "-p${MYSQL_ROOT_PASSWORD:-changeme}"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

volumes:
  mysql_data:
EOF

    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal handled by generic docker compose down; native not supported.
true
EOF
}

# Create PostgreSQL plugin
create_plugin_postgresql() {
    local dir
    dir=$(create_plugin_dir "postgresql")

    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="postgresql"
PLUGIN_NAME="PostgreSQL"
PLUGIN_VERSION="16"
PLUGIN_CATEGORY="database"
PLUGIN_DESCRIPTION="PostgreSQL relational database server"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_NATIVE_OS=""
PLUGIN_DOCKER_PORT="5432"
PLUGIN_DOCKER_URL="{IP}:5432"
PLUGIN_DOCKER_CREDENTIALS="See deployment output"
PLUGIN_NATIVE_URL=""
PLUGIN_NATIVE_CREDENTIALS=""
PLUGIN_SYSTEMD_SERVICE=""
PLUGIN_DOCKER_CONTAINER="postgresql"
EOF

    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  postgresql:
    image: postgres:16
    container_name: postgresql
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "${DB_PORT:-5432}:5432"
    environment:
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-changeme}
      - POSTGRES_USER=${POSTGRES_USER:-appuser}
      - POSTGRES_DB=${POSTGRES_DB:-appdb}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-appuser} -d ${POSTGRES_DB:-appdb}"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

volumes:
  postgres_data:
EOF

    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal handled by generic docker compose down; native not supported.
true
EOF
}

# Create MongoDB plugin
create_plugin_mongodb() {
    local dir
    dir=$(create_plugin_dir "mongodb")

    cat > "$dir/plugin.conf" << 'EOF'
PLUGIN_ID="mongodb"
PLUGIN_NAME="MongoDB"
PLUGIN_VERSION="7"
PLUGIN_CATEGORY="database"
PLUGIN_DESCRIPTION="MongoDB NoSQL document database server"
PLUGIN_DOCKER_SUPPORT="true"
PLUGIN_NATIVE_SUPPORT="false"
PLUGIN_NATIVE_OS=""
PLUGIN_DOCKER_PORT="27017"
PLUGIN_DOCKER_URL="{IP}:27017"
PLUGIN_DOCKER_CREDENTIALS="See deployment output"
PLUGIN_NATIVE_URL=""
PLUGIN_NATIVE_CREDENTIALS=""
PLUGIN_SYSTEMD_SERVICE=""
PLUGIN_DOCKER_CONTAINER="mongodb"
EOF

    cat > "$dir/compose.yml" << 'EOF'
version: '3.8'
services:
  mongodb:
    image: mongo:7
    container_name: mongodb
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "${DB_PORT:-27017}:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=${MONGO_ROOT_USER:-admin}
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD:-changeme}
      - MONGO_INITDB_DATABASE=${MONGO_DB:-appdb}
    volumes:
      - mongo_data:/data/db
    healthcheck:
      test: ["CMD", "mongosh", "--quiet", "--eval", "db.adminCommand('ping')"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s

volumes:
  mongo_data:
EOF

    cat > "$dir/remove.sh" << 'EOF'
#!/bin/bash
# Removal handled by generic docker compose down; native not supported.
true
EOF
}

#######################################
# CONFIGURATION FUNCTIONS
#######################################

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
}

# Save configuration value
save_config() {
    local key="$1"
    local value="$2"

    if grep -q "^${key}=" "$CONFIG_FILE" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=\"${value}\"|" "$CONFIG_FILE"
    else
        echo "${key}=\"${value}\"" >> "$CONFIG_FILE"
    fi
}

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] $message"

    # Write to main log file
    echo "$log_entry" >> "$LOG_FILE" 2>/dev/null || true

    # Write errors to error log
    if [[ "$level" == "ERROR" ]]; then
        echo "$log_entry" >> "$ERROR_LOG" 2>/dev/null || true
    fi
}

# Log operation with details (for operations log)
log_operation() {
    local operation="$1"
    shift
    local details="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local user="${SUDO_USER:-$(whoami)}"
    local log_entry="[$timestamp] [USER:$user] [OP:$operation] $details"

    echo "$log_entry" >> "$OPERATIONS_LOG" 2>/dev/null || true
    echo "$log_entry" >> "$LOG_FILE" 2>/dev/null || true
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { [[ "${LOG_LEVEL:-INFO}" == "DEBUG" ]] && log "DEBUG" "$@"; }

# Log container operations
log_container_op() {
    local vmid="$1"
    local operation="$2"
    shift 2
    log_operation "CONTAINER" "vmid=$vmid action=$operation $*"
}

# Log service/plugin operations
log_service_op() {
    local service="$1"
    local operation="$2"
    shift 2
    log_operation "SERVICE" "service=$service action=$operation $*"
}

# Log SSH operations
log_ssh_op() {
    local operation="$1"
    shift
    log_operation "SSH" "action=$operation $*"
}

# Log certificate operations
log_cert_op() {
    local operation="$1"
    shift
    log_operation "CERT" "action=$operation $*"
}

# Log installation section header
log_install_section() {
    local section="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "" >> "$OPERATIONS_LOG" 2>/dev/null
    echo "[$timestamp] ========== $section ==========" >> "$OPERATIONS_LOG" 2>/dev/null
}

# Log raw output (for capturing command output)
log_output() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    while IFS= read -r line; do
        echo "[$timestamp] [OUTPUT] $line" >> "$OPERATIONS_LOG" 2>/dev/null
        echo "$line"
    done
}

# Detect dialog command (prefer dialog over whiptail)
detect_dialog() {
    if command -v dialog &>/dev/null; then
        DIALOG_CMD="dialog"
    elif command -v whiptail &>/dev/null; then
        DIALOG_CMD="whiptail"
    else
        echo -e "${RED}Error: Neither 'dialog' nor 'whiptail' found.${NC}"
        echo "Please install dialog: apt-get install dialog"
        exit 1
    fi
    log_info "Using dialog command: $DIALOG_CMD"
}

# Check dependencies
check_dependencies() {
    local missing=()
    local deps=("ssh" "scp" "openssl" "bash")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    # Check bash version
    if [[ "${BASH_VERSION%%.*}" -lt 4 ]]; then
        echo -e "${RED}Error: Bash 4.0+ required (found: $BASH_VERSION)${NC}"
        exit 1
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Error: Missing dependencies: ${missing[*]}${NC}"
        exit 1
    fi
}

# Check if running on PVE host
is_pve_host() {
    [[ -f /etc/pve/local/pve-ssl.key ]] || command -v pveversion &>/dev/null
}

#######################################
# DIALOG WRAPPER FUNCTIONS
#######################################

# Show a menu and return selection
show_menu() {
    local title="$1"
    local text="$2"
    shift 2
    local options=("$@")

    local result
    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        result=$($DIALOG_CMD --clear --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --menu "$text" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_LIST_HEIGHT \
            "${options[@]}" 2>&1 >/dev/tty)
    else
        result=$($DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --menu "$text" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_LIST_HEIGHT \
            "${options[@]}" 3>&1 1>&2 2>&3)
    fi
    echo "$result"
}

# Show a checklist and return selections
show_checklist() {
    local title="$1"
    local text="$2"
    shift 2
    local options=("$@")

    local result
    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        result=$($DIALOG_CMD --clear --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --checklist "$text" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_LIST_HEIGHT \
            "${options[@]}" 2>&1 >/dev/tty)
    else
        result=$($DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --checklist "$text" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_LIST_HEIGHT \
            "${options[@]}" 3>&1 1>&2 2>&3)
    fi
    echo "$result"
}

# Show input dialog
show_input() {
    local title="$1"
    local text="$2"
    local default="${3:-}"

    local result
    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        result=$($DIALOG_CMD --clear --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --inputbox "$text" \
            10 $DIALOG_WIDTH "$default" 2>&1 >/dev/tty)
    else
        result=$($DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --inputbox "$text" \
            10 $DIALOG_WIDTH "$default" 3>&1 1>&2 2>&3)
    fi
    echo "$result"
}

# Show password input dialog
show_password() {
    local title="$1"
    local text="$2"

    local result
    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        result=$($DIALOG_CMD --clear --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --passwordbox "$text" \
            10 $DIALOG_WIDTH 2>&1 >/dev/tty)
    else
        result=$($DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --passwordbox "$text" \
            10 $DIALOG_WIDTH 3>&1 1>&2 2>&3)
    fi
    echo "$result"
}

# Show yes/no dialog
show_yesno() {
    local title="$1"
    local text="$2"

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        $DIALOG_CMD --clear --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --yesno "$text" \
            10 $DIALOG_WIDTH 2>&1 >/dev/tty
    else
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --yesno "$text" \
            10 $DIALOG_WIDTH 3>&1 1>&2 2>&3
    fi
    return $?
}

# Show message box
show_msg() {
    local title="$1"
    local text="$2"

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        $DIALOG_CMD --clear --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --msgbox "$text" \
            14 $DIALOG_WIDTH 2>&1 >/dev/tty
    else
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --msgbox "$text" \
            14 $DIALOG_WIDTH 3>&1 1>&2 2>&3
    fi
}

# Show scrollable message box for long content
show_scrollmsg() {
    local title="$1"
    local text="$2"
    local tmpfile="/tmp/pve-manager-scroll-$$.txt"

    echo "$text" > "$tmpfile"

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        $DIALOG_CMD --clear --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --textbox "$tmpfile" \
            $DIALOG_HEIGHT $DIALOG_WIDTH 2>&1 >/dev/tty
    else
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --textbox "$tmpfile" \
            $DIALOG_HEIGHT $DIALOG_WIDTH 3>&1 1>&2 2>&3
    fi

    rm -f "$tmpfile"
}

# Show info box (no button, auto-dismiss)
show_info() {
    local title="$1"
    local text="$2"

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --infobox "$text" \
            8 $DIALOG_WIDTH 2>&1 >/dev/tty
    else
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --infobox "$text" \
            8 $DIALOG_WIDTH 3>&1 1>&2 2>&3
    fi
}

# Show progress with gauge (percentage based)
show_gauge() {
    local title="$1"
    local text="$2"
    # Reads percentage from stdin

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --gauge "$text" \
            8 $DIALOG_WIDTH 0 2>&1 >/dev/tty
    else
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --gauge "$text" \
            8 $DIALOG_WIDTH 0 3>&1 1>&2 2>&3
    fi
}

# Show progress box with live command output
# This is the key function for showing progress during long operations
# Also logs all output to the operations log
show_progress_box() {
    local title="$1"
    local height="${2:-$DIALOG_HEIGHT}"
    local width="${3:-$DIALOG_WIDTH}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Log start of operation
    echo "[$timestamp] [PROGRESS_START] $title" >> "$OPERATIONS_LOG" 2>/dev/null

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        # Use tee to log output while displaying
        tee -a "$OPERATIONS_LOG" 2>/dev/null | $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --progressbox \
            "$height" "$width" 2>&1 >/dev/tty
    else
        # Whiptail doesn't have progressbox, collect output and show at end
        local output
        output=$(cat)
        local tmpfile="/tmp/pve-manager-wprog-$$.txt"
        echo "$output" > "$tmpfile"
        # Also log to operations log
        echo "$output" >> "$OPERATIONS_LOG" 2>/dev/null
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --textbox "$tmpfile" \
            "$height" "$width" 3>&1 1>&2 2>&3
        rm -f "$tmpfile"
    fi

    # Log end of operation
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [PROGRESS_END] $title" >> "$OPERATIONS_LOG" 2>/dev/null
}

# Run command with progress display
# Usage: run_with_progress "Title" "command to run"
# Returns: exit status of command
run_with_progress() {
    local title="$1"
    local cmd="$2"
    local exit_status

    # Create a temporary file for output
    local output_file="/tmp/pve-manager-output-$$.txt"
    > "$output_file"

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        # Use process substitution to show live output
        (
            echo "=== Starting: $title ==="
            echo ""
            eval "$cmd" 2>&1
            exit_status=$?
            echo ""
            if [[ $exit_status -eq 0 ]]; then
                echo "=== Completed successfully ==="
            else
                echo "=== Failed with exit code: $exit_status ==="
            fi
            echo $exit_status > "$output_file.status"
        ) | $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --programbox \
            $DIALOG_HEIGHT $DIALOG_WIDTH 2>&1 >/dev/tty
    else
        # For whiptail, run command and show output after
        local output
        output=$(eval "$cmd" 2>&1)
        exit_status=$?
        echo $exit_status > "$output_file.status"

        local result_text="$output"
        if [[ $exit_status -eq 0 ]]; then
            result_text+="\n\n=== Completed successfully ==="
        else
            result_text+="\n\n=== Failed with exit code: $exit_status ==="
        fi

        show_scrollmsg "$title" "$result_text"
    fi

    # Read exit status
    if [[ -f "$output_file.status" ]]; then
        exit_status=$(cat "$output_file.status")
        rm -f "$output_file.status"
    fi

    rm -f "$output_file"
    return "${exit_status:-1}"
}

# Run multiple commands with step-by-step progress
# Usage: run_steps "Title" "step1 description" "cmd1" "step2 description" "cmd2" ...
run_steps() {
    local title="$1"
    shift

    local steps=()
    local cmds=()
    while [[ $# -gt 0 ]]; do
        steps+=("$1")
        cmds+=("$2")
        shift 2
    done

    local total=${#steps[@]}
    local output_log="/tmp/pve-manager-steps-$$.log"
    > "$output_log"

    (
        for i in "${!steps[@]}"; do
            local step_num=$((i + 1))
            local percent=$(( (i * 100) / total ))

            echo "XXX"
            echo "$percent"
            echo "Step $step_num/$total: ${steps[$i]}"
            echo "XXX"

            # Run the command and capture output
            echo "" >> "$output_log"
            echo "=== Step $step_num: ${steps[$i]} ===" >> "$output_log"
            if eval "${cmds[$i]}" >> "$output_log" 2>&1; then
                echo "[OK] ${steps[$i]}" >> "$output_log"
            else
                echo "[FAILED] ${steps[$i]}" >> "$output_log"
            fi
        done

        echo "XXX"
        echo "100"
        echo "Complete!"
        echo "XXX"
    ) | show_gauge "$title" "Initializing..."

    # Show the log
    if [[ -s "$output_log" ]]; then
        show_scrollmsg "$title - Results" "$(cat "$output_log")"
    fi

    rm -f "$output_log"
}

# Show text file
show_textbox() {
    local title="$1"
    local file="$2"

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        $DIALOG_CMD --clear --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --textbox "$file" \
            $DIALOG_HEIGHT $DIALOG_WIDTH 2>&1 >/dev/tty
    else
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --textbox "$file" \
            $DIALOG_HEIGHT $DIALOG_WIDTH 3>&1 1>&2 2>&3
    fi
}

# Show tailbox for following log file
show_tailbox() {
    local title="$1"
    local file="$2"

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --tailbox "$file" \
            $DIALOG_HEIGHT $DIALOG_WIDTH 2>&1 >/dev/tty
    else
        # Whiptail fallback
        show_textbox "$title" "$file"
    fi
}

#######################################
# PVE CONNECTION FUNCTIONS
#######################################

# List saved profiles
list_profiles() {
    if [[ ! -s "$PROFILES_FILE" ]]; then
        echo ""
        return
    fi

    local profiles=()
    while IFS='|' read -r name host user port; do
        [[ -z "$name" ]] && continue
        profiles+=("$name" "$host ($user)")
    done < "$PROFILES_FILE"

    echo "${profiles[*]}"
}

# Get profile details
get_profile() {
    local name="$1"
    grep "^${name}|" "$PROFILES_FILE" | head -1
}

# Save profile
save_profile() {
    local name="$1"
    local host="$2"
    local user="$3"
    local port="${4:-22}"

    # Remove existing profile with same name
    sed -i "/^${name}|/d" "$PROFILES_FILE"

    # Add new profile
    echo "${name}|${host}|${user}|${port}" >> "$PROFILES_FILE"
    log_info "Saved profile: $name ($host)"
}

# Delete profile
delete_profile() {
    local name="$1"
    sed -i "/^${name}|/d" "$PROFILES_FILE"
    log_info "Deleted profile: $name"
}

# Test SSH connection
test_ssh_connection() {
    local host="$1"
    local user="$2"
    local port="${3:-22}"

    ssh -o ConnectTimeout=5 -o BatchMode=yes -p "$port" "${user}@${host}" "echo ok" &>/dev/null
    return $?
}

# Execute command on PVE (local or remote)
pve_exec() {
    local cmd="$1"

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        eval "$cmd"
    else
        # Note: < /dev/null prevents consuming stdin (important in while loops)
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" "$cmd" < /dev/null
    fi
}

# Execute command on PVE with live output
pve_exec_live() {
    local cmd="$1"

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        eval "$cmd" 2>&1
    else
        # Note: < /dev/null prevents consuming stdin (important in while loops)
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" "$cmd" < /dev/null 2>&1
    fi
}

# Connect to PVE server
pve_connect() {
    local profile="$1"

    if [[ "$profile" == "local" ]]; then
        if is_pve_host; then
            CURRENT_PVE="local"
            CURRENT_PVE_HOST="localhost"
            CURRENT_PVE_USER="root"
            CURRENT_PVE_PORT="22"
            IS_LOCAL_PVE=true
            log_info "Connected to local PVE"
            return 0
        else
            log_error "Not running on a PVE host"
            return 1
        fi
    fi

    local profile_data
    profile_data=$(get_profile "$profile")

    if [[ -z "$profile_data" ]]; then
        log_error "Profile not found: $profile"
        return 1
    fi

    IFS='|' read -r name host user port <<< "$profile_data"

    show_info "Connecting..." "Testing connection to $host..."

    if test_ssh_connection "$host" "$user" "$port"; then
        CURRENT_PVE="$name"
        CURRENT_PVE_HOST="$host"
        CURRENT_PVE_USER="$user"
        CURRENT_PVE_PORT="$port"
        IS_LOCAL_PVE=false
        log_info "Connected to PVE: $name ($host)"
        return 0
    else
        log_error "Failed to connect to $host"
        return 1
    fi
}

# PVE Connection Menu
pve_connection_menu() {
    while true; do
        local status="Not connected"
        [[ -n "$CURRENT_PVE" ]] && status="Connected: $CURRENT_PVE ($CURRENT_PVE_HOST)"

        local options=(
            "1" "Connect to saved profile"
            "2" "Add new profile"
            "3" "Delete profile"
            "4" "Test connection"
        )

        # Add local option if on PVE host
        if is_pve_host; then
            options+=("5" "Connect to local PVE")
        fi

        options+=("0" "Back to main menu")

        local choice
        choice=$(show_menu "PVE Connection" "Status: $status\n\nSelect an option:" "${options[@]}")

        case "$choice" in
            1)
                local profiles
                profiles=$(list_profiles)
                if [[ -z "$profiles" ]]; then
                    show_msg "No Profiles" "No saved profiles found. Please add a profile first."
                else
                    # Convert to array
                    local profile_array=()
                    while IFS='|' read -r name host user port; do
                        [[ -z "$name" ]] && continue
                        profile_array+=("$name" "$host")
                    done < "$PROFILES_FILE"

                    local selected
                    selected=$(show_menu "Select Profile" "Choose a profile to connect:" "${profile_array[@]}")

                    if [[ -n "$selected" ]]; then
                        if pve_connect "$selected"; then
                            show_msg "Connected" "Successfully connected to $CURRENT_PVE"
                        else
                            show_msg "Error" "Failed to connect to profile: $selected"
                        fi
                    fi
                fi
                ;;
            2)
                local name host user port
                name=$(show_input "New Profile" "Profile name:")
                [[ -z "$name" ]] && continue

                host=$(show_input "New Profile" "PVE host (IP or hostname):")
                [[ -z "$host" ]] && continue

                user=$(show_input "New Profile" "SSH username:" "root")
                [[ -z "$user" ]] && continue

                port=$(show_input "New Profile" "SSH port:" "22")
                [[ -z "$port" ]] && port="22"

                save_profile "$name" "$host" "$user" "$port"
                show_msg "Profile Saved" "Profile '$name' has been saved."
                ;;
            3)
                local profiles
                profiles=$(list_profiles)
                if [[ -z "$profiles" ]]; then
                    show_msg "No Profiles" "No saved profiles to delete."
                else
                    local profile_array=()
                    while IFS='|' read -r name host user port; do
                        [[ -z "$name" ]] && continue
                        profile_array+=("$name" "$host")
                    done < "$PROFILES_FILE"

                    local selected
                    selected=$(show_menu "Delete Profile" "Select profile to delete:" "${profile_array[@]}")

                    if [[ -n "$selected" ]]; then
                        if show_yesno "Confirm Delete" "Delete profile '$selected'?"; then
                            delete_profile "$selected"
                            [[ "$CURRENT_PVE" == "$selected" ]] && CURRENT_PVE=""
                            show_msg "Deleted" "Profile '$selected' has been deleted."
                        fi
                    fi
                fi
                ;;
            4)
                if [[ -z "$CURRENT_PVE" ]]; then
                    show_msg "Not Connected" "Please connect to a PVE server first."
                else
                    show_info "Testing..." "Testing connection to $CURRENT_PVE_HOST..."
                    local version
                    version=$(pve_exec "pveversion 2>/dev/null || echo 'Unknown'")
                    show_msg "Connection Test" "Connection OK!\n\nPVE Version: $version"
                fi
                ;;
            5)
                if pve_connect "local"; then
                    show_msg "Connected" "Connected to local PVE"
                else
                    show_msg "Error" "This system is not a PVE host."
                fi
                ;;
            0|"")
                break
                ;;
        esac
    done
}

#######################################
# LXC MANAGEMENT FUNCTIONS
#######################################

# List available storages for containers (supports rootdir content)
pve_list_container_storages() {
    # Get active storages and check their content types from config
    pve_exec "
        for storage in \$(pvesm status 2>/dev/null | tail -n +2 | awk '\$3 == \"active\" {print \$1}'); do
            content=\$(grep -A10 \"^[a-z]*: \$storage\$\" /etc/pve/storage.cfg 2>/dev/null | grep -m1 'content ' | awk '{print \$2}')
            if [[ \"\$content\" == *rootdir* ]] || [[ \"\$content\" == *images* ]]; then
                echo \"\$storage\"
            fi
        done
    "
}

# List storages that have templates (supports vztmpl content)
pve_list_template_storages() {
    pve_exec "
        for storage in \$(pvesm status 2>/dev/null | tail -n +2 | awk '\$3 == \"active\" {print \$1}'); do
            content=\$(grep -A10 \"^[a-z]*: \$storage\$\" /etc/pve/storage.cfg 2>/dev/null | grep -m1 'content ' | awk '{print \$2}')
            if [[ \"\$content\" == *vztmpl* ]]; then
                echo \"\$storage\"
            fi
        done
    "
}

# List available templates from all storages
pve_list_templates() {
    local storage="${1:-}"
    if [[ -n "$storage" ]]; then
        pve_exec "pveam list $storage 2>/dev/null | tail -n +2 | awk '{print \$1}'"
    else
        # List from all template storages
        local storages
        storages=$(pve_list_template_storages)
        for st in $storages; do
            pve_exec "pveam list $st 2>/dev/null | tail -n +2 | awk '{print \$1}'"
        done
    fi
}

# List available templates for download from online repository
pve_list_available_templates() {
    local section="${1:-}"
    if [[ -n "$section" ]]; then
        pve_exec "pveam available --section $section 2>/dev/null | tail -n +2"
    else
        pve_exec "pveam available 2>/dev/null | tail -n +2"
    fi
}

# Update template index
pve_update_templates() {
    pve_exec_live "pveam update"
}

# Download template to storage
pve_download_template() {
    local storage="$1"
    local template="$2"
    pve_exec_live "pveam download $storage $template"
}

# Quick template download (for use in wizard)
template_download_quick() {
    local default_storage="${1:-local}"

    # Get template storage
    local template_storages
    template_storages=$(pve_list_template_storages)

    local storage="$default_storage"
    # Check if default storage is in the list, if not pick first available
    if ! echo "$template_storages" | grep -q "^${default_storage}$"; then
        storage=$(echo "$template_storages" | head -1)
    fi

    if [[ -z "$storage" ]]; then
        show_msg "No Storage" "No storage available for templates."
        return 1
    fi

    # Update template index first
    show_info "Updating..." "Updating template index..."
    pve_exec "pveam update" &>/dev/null

    # Select section - focus on common system templates
    local section
    section=$(show_menu "Template Section" "Select template category:" \
        "system" "System (Debian, Ubuntu, Alpine, etc.) [Recommended]" \
        "turnkeylinux" "TurnKey Linux appliances" \
        "" "All available templates")

    # Get available templates
    show_info "Loading..." "Fetching available templates..."
    local available
    available=$(pve_list_available_templates "$section")

    if [[ -z "$available" ]]; then
        show_msg "No Templates" "No templates available in this section."
        return 1
    fi

    # Build template menu - show most common first
    local tmpl_array=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local tmpl_section tmpl_name
        tmpl_section=$(echo "$line" | awk '{print $1}')
        tmpl_name=$(echo "$line" | awk '{print $2}')
        [[ -z "$tmpl_name" ]] && continue
        tmpl_array+=("$tmpl_name" "$tmpl_section")
    done <<< "$available"

    if [[ ${#tmpl_array[@]} -eq 0 ]]; then
        show_msg "No Templates" "No templates found."
        return 1
    fi

    local selected_template
    selected_template=$(show_menu "Download Template" "Select template to download to '$storage':" "${tmpl_array[@]}")
    [[ -z "$selected_template" ]] && return 1

    # Download the template
    (
        echo "Downloading: $selected_template"
        echo "To storage: $storage"
        echo ""
        pve_download_template "$storage" "$selected_template"
        echo ""
        echo "=== Download complete ==="
    ) | show_progress_box "Downloading Template" 18 76

    return 0
}

# Template browser and downloader
template_browser() {
    local target_storage="${1:-local}"

    while true; do
        local choice
        choice=$(show_menu "Template Manager" "Manage container templates:" \
            "1" "View downloaded templates" \
            "2" "Browse available templates" \
            "3" "Download template" \
            "4" "Update template index" \
            "0" "Back")

        case "$choice" in
            1)
                show_info "Loading..." "Fetching downloaded templates..."
                local templates
                templates=$(pve_list_templates)

                if [[ -z "$templates" ]]; then
                    show_msg "No Templates" "No templates downloaded yet."
                else
                    local tmpfile="/tmp/pve-templates-$$.txt"
                    echo "Downloaded Templates" > "$tmpfile"
                    echo "====================" >> "$tmpfile"
                    echo "" >> "$tmpfile"
                    echo "$templates" >> "$tmpfile"
                    show_textbox "Downloaded Templates" "$tmpfile"
                    rm -f "$tmpfile"
                fi
                ;;
            2)
                show_info "Loading..." "Fetching available templates from repository..."

                # Select section
                local section
                section=$(show_menu "Template Section" "Select template category:" \
                    "system" "System containers (Debian, Ubuntu, etc.)" \
                    "turnkeylinux" "TurnKey Linux appliances" \
                    "mail" "Mail server templates" \
                    "" "All sections")

                local available
                available=$(pve_list_available_templates "$section")

                if [[ -z "$available" ]]; then
                    show_msg "No Templates" "No templates available. Try updating the template index."
                else
                    local tmpfile="/tmp/pve-available-$$.txt"
                    echo "Available Templates for Download" > "$tmpfile"
                    echo "=================================" >> "$tmpfile"
                    echo "" >> "$tmpfile"
                    echo "$available" >> "$tmpfile"
                    show_textbox "Available Templates" "$tmpfile"
                    rm -f "$tmpfile"
                fi
                ;;
            3)
                # Select storage for download
                show_info "Loading..." "Fetching template storages..."
                local template_storages
                template_storages=$(pve_list_template_storages)

                if [[ -z "$template_storages" ]]; then
                    show_msg "No Storage" "No storage available for templates (vztmpl content type)."
                    continue
                fi

                local storage_array=()
                while IFS= read -r st; do
                    [[ -z "$st" ]] && continue
                    storage_array+=("$st" "Template storage")
                done <<< "$template_storages"

                local storage
                storage=$(show_menu "Select Storage" "Download template to:" "${storage_array[@]}")
                [[ -z "$storage" ]] && continue

                # Select section
                local section
                section=$(show_menu "Template Section" "Select template category:" \
                    "system" "System containers (Debian, Ubuntu, Alpine, etc.)" \
                    "turnkeylinux" "TurnKey Linux appliances" \
                    "" "All sections")

                # Get available templates
                show_info "Loading..." "Fetching available templates..."
                local available
                available=$(pve_list_available_templates "$section")

                if [[ -z "$available" ]]; then
                    show_msg "No Templates" "No templates available. Try updating the template index first."
                    continue
                fi

                # Build template menu
                local tmpl_array=()
                while IFS= read -r line; do
                    [[ -z "$line" ]] && continue
                    # Format: section template
                    local tmpl_section tmpl_name
                    tmpl_section=$(echo "$line" | awk '{print $1}')
                    tmpl_name=$(echo "$line" | awk '{print $2}')
                    [[ -z "$tmpl_name" ]] && continue
                    tmpl_array+=("$tmpl_name" "$tmpl_section")
                done <<< "$available"

                if [[ ${#tmpl_array[@]} -eq 0 ]]; then
                    show_msg "No Templates" "No templates found in this section."
                    continue
                fi

                local selected_template
                selected_template=$(show_menu "Select Template" "Choose template to download:" "${tmpl_array[@]}")
                [[ -z "$selected_template" ]] && continue

                # Download the template
                (
                    echo "Downloading template: $selected_template"
                    echo "To storage: $storage"
                    echo ""
                    pve_download_template "$storage" "$selected_template"
                    echo ""
                    echo "=== Download complete ==="
                ) | show_progress_box "Downloading Template" 18 76

                show_msg "Download Complete" "Template downloaded successfully!\n\nTemplate: $selected_template\nStorage: $storage"
                ;;
            4)
                (
                    echo "Updating template index..."
                    echo ""
                    pve_update_templates
                    echo ""
                    echo "=== Update complete ==="
                ) | show_progress_box "Updating Template Index"
                ;;
            0|"")
                break
                ;;
        esac
    done
}

# List all containers
pve_list_containers() {
    pve_exec "pct list 2>/dev/null | tail -n +2"
}

# Get container info
pve_container_info() {
    local vmid="$1"
    pve_exec "pct config $vmid 2>/dev/null"
}

# Get container status
pve_container_status() {
    local vmid="$1"
    pve_exec "pct status $vmid 2>/dev/null | awk '{print \$2}'"
}

# Create LXC container with progress
lxc_create() {
    local vmid="$1"
    local hostname="$2"
    local template="$3"
    local storage="$4"
    local cpu="$5"
    local ram="$6"
    local disk="$7"
    local bridge="$8"
    local ip="$9"
    local gw="${10}"
    local password="${11}"

    local net_config
    if [[ "$ip" == "dhcp" ]]; then
        net_config="name=eth0,bridge=${bridge},ip=dhcp"
    else
        net_config="name=eth0,bridge=${bridge},ip=${ip}/24,gw=${gw}"
    fi

    # Build the pct create command
    # Note: --rootfs format is storage:size (e.g., local-lvm:8)
    # The template should be in format storage:vztmpl/template.tar.zst
    local cmd="pct create $vmid '$template' \
        --hostname '$hostname' \
        --rootfs '${storage}:${disk}' \
        --cores $cpu \
        --memory $ram \
        --net0 '${net_config}' \
        --password '$password' \
        --unprivileged 1 \
        --features nesting=1 \
        --start 0"

    log_info "Creating container $vmid ($hostname)"
    log_container_op "$vmid" "CREATE" "hostname=$hostname template=$template storage=$storage cores=$cores memory=$memory disk=$disk"

    # Show progress during creation
    (
        echo "Creating LXC container $vmid..."
        echo "  Hostname: $hostname"
        echo "  Template: $template"
        echo "  Storage: $storage"
        echo "  CPU: $cpu cores"
        echo "  Memory: ${ram}MB"
        echo "  Disk: ${disk}GB"
        echo "  Network: $bridge ($ip)"
        echo ""
        echo "Command: pct create $vmid ..."
        echo ""
        echo "Please wait..."
        echo ""
        pve_exec_live "$cmd"
    ) | show_progress_box "Creating Container $vmid"
}

# Start container (with timeout to prevent hanging)
lxc_start() {
    local vmid="$1"
    local timeout_secs="${2:-30}"
    log_info "Starting container $vmid (timeout: ${timeout_secs}s)"
    log_container_op "$vmid" "START" "timeout=${timeout_secs}s"
    pve_exec "timeout $timeout_secs pct start $vmid" 2>&1
}

# Stop container (graceful shutdown with fallback to force stop)
lxc_stop() {
    local vmid="$1"
    local timeout_secs="${2:-15}"
    log_info "Stopping container $vmid (timeout: ${timeout_secs}s)"
    log_container_op "$vmid" "STOP" "timeout=${timeout_secs}s"

    # Try graceful shutdown first
    if pve_exec "pct shutdown $vmid --timeout $timeout_secs" 2>&1; then
        return 0
    fi

    # Graceful shutdown failed, try force stop
    log_warn "Graceful shutdown failed for $vmid, forcing stop..."
    pve_exec "pct stop $vmid" 2>&1 || true
    return 0
}

# Delete container
lxc_delete() {
    local vmid="$1"
    log_info "Deleting container $vmid"
    log_container_op "$vmid" "DELETE" "purge=true"
    pve_exec "pct destroy $vmid --purge" 2>&1
}

# Wait for container to be ready for exec commands
# Returns 0 if ready, 1 if timeout
lxc_wait_ready() {
    local vmid="$1"
    local max_attempts="${2:-15}"
    local attempt=0

    log_info "Waiting for container $vmid to be exec-ready..."

    while [[ $attempt -lt $max_attempts ]]; do
        # Try a simple command - if it works, container is ready
        if lxc_exec_timeout "$vmid" 3 "true" 2>/dev/null; then
            log_info "Container $vmid is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    log_warn "Container $vmid not ready after ${max_attempts}s"
    return 1
}

# Execute command in container (logs command, not output)
lxc_exec() {
    local vmid="$1"
    shift
    local cmd="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Log command being executed (debug level)
    [[ "${LOG_LEVEL:-INFO}" == "DEBUG" ]] && echo "[$timestamp] [EXEC] vmid=$vmid cmd=$cmd" >> "$OPERATIONS_LOG" 2>/dev/null

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        # Local: use bash -c with proper quoting
        # Note: < /dev/null prevents consuming stdin (important in while loops)
        pct exec "$vmid" -- /bin/bash -c "$cmd" < /dev/null
    else
        # Remote: use base64 encoding to avoid escaping issues
        local cmd_b64
        cmd_b64=$(echo -n "$cmd" | base64 -w0)
        # Pass base64 command and decode on remote
        # Note: < /dev/null prevents consuming stdin (important in while loops)
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" \
            "echo $cmd_b64 | base64 -d | pct exec $vmid -- /bin/bash -s" < /dev/null
    fi
}

# Execute command in container with timeout (default 10 seconds)
lxc_exec_timeout() {
    local vmid="$1"
    local timeout_secs="${2:-10}"
    shift 2
    local cmd="$*"

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        # Note: < /dev/null prevents consuming stdin (important in while loops)
        timeout "$timeout_secs" pct exec "$vmid" -- /bin/bash -c "$cmd" < /dev/null
    else
        local cmd_b64
        cmd_b64=$(echo -n "$cmd" | base64 -w0)
        # Note: < /dev/null prevents consuming stdin (important in while loops)
        timeout "$timeout_secs" ssh -o ConnectTimeout=5 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" \
            "echo $cmd_b64 | base64 -d | pct exec $vmid -- /bin/bash -s" < /dev/null
    fi
}

# Execute command in container with live output (also logs to file)
lxc_exec_live() {
    local vmid="$1"
    shift
    local cmd="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Log command being executed
    echo "[$timestamp] [EXEC] vmid=$vmid cmd=$cmd" >> "$OPERATIONS_LOG" 2>/dev/null

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        # Note: < /dev/null prevents consuming stdin (important in while loops)
        pct exec "$vmid" -- /bin/bash -c "$cmd" < /dev/null 2>&1 | tee -a "$OPERATIONS_LOG"
    else
        local cmd_b64
        cmd_b64=$(echo -n "$cmd" | base64 -w0)
        # Note: < /dev/null prevents consuming stdin (important in while loops)
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" \
            "echo $cmd_b64 | base64 -d | pct exec $vmid -- /bin/bash -s" < /dev/null 2>&1 | tee -a "$OPERATIONS_LOG"
    fi
}

# Get next available VMID
get_next_vmid() {
    local next_id
    # Use pvesh to get the next available VMID (most reliable method)
    next_id=$(pve_exec "pvesh get /cluster/nextid 2>/dev/null")

    if [[ -n "$next_id" ]] && [[ "$next_id" =~ ^[0-9]+$ ]]; then
        echo "$next_id"
        return
    fi

    # Fallback: find max VMID from all VMs and containers
    local max_id
    max_id=$(pve_exec "
        {
            pct list 2>/dev/null | tail -n +2 | awk '{print \$1}'
            qm list 2>/dev/null | tail -n +2 | awk '{print \$1}'
        } | sort -n | tail -1
    ")

    if [[ -z "$max_id" ]] || [[ "$max_id" -lt 100 ]]; then
        echo "100"
    else
        echo $((max_id + 1))
    fi
}

# ============================================================================
# VM (QEMU) Helper Functions
# ============================================================================

# List all VMs
pve_list_vms() {
    pve_exec "qm list 2>/dev/null | tail -n +2 | awk '{printf \"%-10s %-12s %-6s %s\\n\", \$1, \$3, \$2, \$4}'"
}

# Get VM status
vm_status() {
    local vmid="$1"
    pve_exec "qm status $vmid 2>/dev/null | awk '{print \$2}'"
}

# Check if QEMU Guest Agent is available
vm_has_guest_agent() {
    local vmid="$1"
    local result
    result=$(pve_exec "qm agent $vmid ping 2>/dev/null && echo 'ok'" 2>/dev/null)
    [[ "$result" == *"ok"* ]]
}

# Execute command in VM via QEMU Guest Agent
vm_exec() {
    local vmid="$1"
    shift
    local cmd="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Log command being executed (debug level)
    [[ "${LOG_LEVEL:-INFO}" == "DEBUG" ]] && echo "[$timestamp] [VM-EXEC] vmid=$vmid cmd=$cmd" >> "$OPERATIONS_LOG" 2>/dev/null

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        # Use qm guest exec - output is JSON, extract out-data
        local result
        result=$(qm guest exec "$vmid" -- /bin/bash -c "$cmd" 2>/dev/null)
        # Extract output from JSON response
        echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('out-data','').rstrip())" 2>/dev/null || echo "$result"
    else
        local cmd_b64
        cmd_b64=$(echo -n "$cmd" | base64 -w0)
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" \
            "result=\$(qm guest exec $vmid -- /bin/bash -c \"\$(echo $cmd_b64 | base64 -d)\" 2>/dev/null); echo \"\$result\" | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('out-data','').rstrip())\" 2>/dev/null || echo \"\$result\"" < /dev/null
    fi
}

# Execute command in VM with live output
vm_exec_live() {
    local vmid="$1"
    shift
    local cmd="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Log command being executed
    echo "[$timestamp] [VM-EXEC] vmid=$vmid cmd=$cmd" >> "$OPERATIONS_LOG" 2>/dev/null

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        local result
        result=$(qm guest exec "$vmid" -- /bin/bash -c "$cmd" 2>&1)
        echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('out-data','').rstrip())" 2>/dev/null | tee -a "$OPERATIONS_LOG" || echo "$result" | tee -a "$OPERATIONS_LOG"
    else
        local cmd_b64
        cmd_b64=$(echo -n "$cmd" | base64 -w0)
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" \
            "result=\$(qm guest exec $vmid -- /bin/bash -c \"\$(echo $cmd_b64 | base64 -d)\" 2>&1); echo \"\$result\" | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('out-data','').rstrip())\" 2>/dev/null || echo \"\$result\"" < /dev/null 2>&1 | tee -a "$OPERATIONS_LOG"
    fi
}

# Write file to VM via QEMU Guest Agent
vm_write_file() {
    local vmid="$1"
    local dest_path="$2"
    local content="$3"

    # Encode content as base64
    local content_b64
    content_b64=$(echo -n "$content" | base64 -w0)

    # Use guest-file-write via qm guest exec
    vm_exec "$vmid" "echo '$content_b64' | base64 -d > '$dest_path'"
}

# Copy file to VM via QEMU Guest Agent
vm_push_file() {
    local vmid="$1"
    local src_path="$2"
    local dest_path="$3"

    if [[ ! -f "$src_path" ]]; then
        log_error "Source file not found: $src_path"
        return 1
    fi

    # Read and encode file
    local content_b64
    content_b64=$(base64 -w0 "$src_path")

    # Write to VM
    vm_exec "$vmid" "echo '$content_b64' | base64 -d > '$dest_path'"
}

# Execute command in VM with timeout (returns exit code, captures output)
vm_exec_timeout() {
    local vmid="$1"
    local timeout_secs="${2:-10}"
    shift 2
    local cmd="$*"

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        local result
        result=$(timeout "$timeout_secs" qm guest exec "$vmid" -- /bin/bash -c "$cmd" 2>/dev/null)
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            return 124
        fi
        echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('out-data','').rstrip())" 2>/dev/null || echo "$result"
        return $rc
    else
        local cmd_b64
        cmd_b64=$(echo -n "$cmd" | base64 -w0)
        timeout "$timeout_secs" ssh -o ConnectTimeout=5 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" \
            "result=\$(qm guest exec $vmid -- /bin/bash -c \"\$(echo $cmd_b64 | base64 -d)\" 2>/dev/null); echo \"\$result\" | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('out-data','').rstrip())\" 2>/dev/null || echo \"\$result\"" < /dev/null
    fi
}

# Get VM hostname
vm_get_hostname() {
    local vmid="$1"
    vm_exec "$vmid" "hostname" 2>/dev/null | tr -d '[:space:]'
}

# Get VM IP address
vm_get_ip() {
    local vmid="$1"
    # Try to get IP from guest agent
    local ip
    ip=$(pve_exec "qm guest cmd $vmid network-get-interfaces 2>/dev/null | python3 -c \"
import sys, json
data = json.load(sys.stdin)
for iface in data:
    if iface.get('name') not in ['lo', 'docker0']:
        for addr in iface.get('ip-addresses', []):
            if addr.get('ip-address-type') == 'ipv4':
                print(addr.get('ip-address'))
                sys.exit(0)
\" 2>/dev/null")
    echo "$ip"
}

# Detect VM OS type
detect_vm_os() {
    local vmid="$1"
    local os_info
    os_info=$(vm_exec "$vmid" "cat /etc/os-release 2>/dev/null | grep ^ID= | cut -d= -f2 | tr -d '\"'")
    echo "$os_info"
}

# Deploy certificate to VM
vm_deploy_cert() {
    local vmid="$1"
    local hostname="$2"
    local cert_dir="$CERTS_DIR/$hostname"

    if [[ ! -d "$cert_dir" ]]; then
        log_error "Certificate directory not found: $cert_dir"
        return 1
    fi

    # Check guest agent
    if ! vm_has_guest_agent "$vmid"; then
        log_error "QEMU Guest Agent not available on VM $vmid"
        return 1
    fi

    log_info "Deploying certificate to VM $vmid"

    # Create directory in VM
    vm_exec "$vmid" "mkdir -p /etc/ssl/pve-manager"

    # Copy files
    local key_file="$cert_dir/${hostname}.key"
    local crt_file="$cert_dir/${hostname}.crt"
    local chain_file="$cert_dir/${hostname}-chain.pem"
    local ca_crt="$CA_DIR/ca.crt"

    # Push files using base64 encoding
    vm_push_file "$vmid" "$key_file" "/etc/ssl/pve-manager/${hostname}.key"
    vm_push_file "$vmid" "$crt_file" "/etc/ssl/pve-manager/${hostname}.crt"
    vm_push_file "$vmid" "$chain_file" "/etc/ssl/pve-manager/${hostname}-chain.pem"
    vm_push_file "$vmid" "$ca_crt" "/etc/ssl/pve-manager/ca.crt"

    # Set permissions
    vm_exec "$vmid" "chmod 600 /etc/ssl/pve-manager/*.key"
    vm_exec "$vmid" "chmod 644 /etc/ssl/pve-manager/*.crt /etc/ssl/pve-manager/*.pem"

    # Install CA cert to system trust store
    local os_type
    os_type=$(detect_vm_os "$vmid")

    case "$os_type" in
        debian|ubuntu)
            vm_exec "$vmid" "cp /etc/ssl/pve-manager/ca.crt /usr/local/share/ca-certificates/pve-manager-ca.crt"
            vm_exec "$vmid" "update-ca-certificates"
            ;;
        centos|rhel|rocky|almalinux|fedora)
            vm_exec "$vmid" "cp /etc/ssl/pve-manager/ca.crt /etc/pki/ca-trust/source/anchors/pve-manager-ca.crt"
            vm_exec "$vmid" "update-ca-trust"
            ;;
        alpine)
            vm_exec "$vmid" "cp /etc/ssl/pve-manager/ca.crt /usr/local/share/ca-certificates/pve-manager-ca.crt"
            vm_exec "$vmid" "update-ca-certificates"
            ;;
    esac

    log_info "Certificate deployed to VM $vmid"
    return 0
}

# Enable HTTPS wizard for VMs (mirrors enable_https_wizard for LXC)
vm_enable_https_wizard() {
    # Check if CA is initialized
    if [[ ! -f "$CA_DIR/ca.key" ]]; then
        show_msg "CA Not Initialized" "Certificate Authority is not initialized.\n\nPlease go to Certificate Management and initialize the CA first."
        return
    fi

    local vms
    vms=$(pve_list_vms)
    if [[ -z "$vms" ]]; then
        show_msg "No VMs" "No virtual machines found."
        return
    fi

    # Filter running VMs only
    local vm_array=()
    while read -r vmid status mem name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        vm_array+=("$vmid" "$name ($status)")
    done <<< "$vms"

    if [[ ${#vm_array[@]} -eq 0 ]]; then
        show_msg "No Running VMs" "No running VMs found. VMs must be running with QEMU Guest Agent."
        return
    fi

    local selected
    selected=$(show_menu "Enable HTTPS" "Select VM (must have QEMU Guest Agent):" "${vm_array[@]}")
    [[ -z "$selected" ]] && return

    # Check guest agent
    show_info "Checking..." "Verifying QEMU Guest Agent..."
    if ! vm_has_guest_agent "$selected"; then
        show_msg "Guest Agent Required" "QEMU Guest Agent is not available on VM $selected.\n\nPlease ensure:\n1. qemu-guest-agent is installed in the VM\n2. Guest Agent is enabled in VM options\n3. VM is running"
        return
    fi

    # Check for nginx or Docker
    local has_nginx is_docker_mode="false"
    has_nginx=$(vm_exec "$selected" "which nginx 2>/dev/null")

    if [[ -z "$has_nginx" ]]; then
        # No native nginx — check if Docker is available as fallback
        local has_docker
        has_docker=$(vm_exec "$selected" "which docker 2>/dev/null")
        if [[ -z "$has_docker" ]]; then
            show_msg "No Nginx or Docker" "Neither nginx nor Docker is installed in VM $selected.\n\nHTTPS enablement requires nginx (native) or Docker to add an nginx container."
            return
        fi
        is_docker_mode="true"
    fi

    # Find services that can be HTTPS-enabled
    show_info "Detecting..." "Scanning for HTTPS-compatible services..."
    local svc_array=()

    if [[ "$is_docker_mode" == "true" ]]; then
        # Docker mode: detect services via /opt/services/<svc>/docker-compose.yml
        if vm_exec "$selected" "test -f /opt/services/jenkins/docker-compose.yml" 2>/dev/null; then
            svc_array+=("docker:jenkins" "Jenkins (Docker)")
        fi
        if vm_exec "$selected" "test -f /opt/services/gitea/docker-compose.yml" 2>/dev/null; then
            svc_array+=("docker:gitea" "Gitea (Docker)")
        fi
        if vm_exec "$selected" "test -f /opt/services/kiwi-tcms/docker-compose.yml" 2>/dev/null; then
            svc_array+=("docker:kiwi-tcms" "Kiwi TCMS (Docker)")
        fi
        if vm_exec "$selected" "test -f /opt/services/testlink/docker-compose.yml" 2>/dev/null; then
            svc_array+=("docker:testlink" "TestLink (Docker)")
        fi
    else
        # Native mode: detect services via nginx site-configs + systemctl
        if vm_exec "$selected" "test -f /etc/nginx/sites-available/jenkins" 2>/dev/null; then
            svc_array+=("jenkins" "Jenkins")
        elif vm_exec "$selected" "systemctl is-active --quiet jenkins" 2>/dev/null; then
            svc_array+=("jenkins" "Jenkins")
        fi

        if vm_exec "$selected" "test -f /etc/nginx/sites-available/kiwi" 2>/dev/null; then
            svc_array+=("kiwi" "Kiwi TCMS")
        fi

        if vm_exec "$selected" "test -f /etc/nginx/sites-available/gitea" 2>/dev/null; then
            svc_array+=("gitea" "Gitea")
        fi

        if vm_exec "$selected" "test -f /etc/nginx/sites-available/testlink" 2>/dev/null; then
            svc_array+=("testlink" "TestLink")
        fi

        if vm_exec "$selected" "test -f /etc/nginx/sites-available/default" 2>/dev/null; then
            svc_array+=("default" "Default Site")
        fi
    fi

    if [[ ${#svc_array[@]} -eq 0 ]]; then
        if [[ "$is_docker_mode" == "true" ]]; then
            show_msg "No Services" "No Docker-deployed services found in VM $selected.\n\nSearched in /opt/services/ for: Jenkins, Gitea, Kiwi TCMS, TestLink"
        else
            show_msg "No Services" "No HTTPS-compatible services found in VM $selected.\n\nSupported services: Jenkins, Kiwi TCMS, Gitea, TestLink"
        fi
        return
    fi

    local selected_svc
    selected_svc=$(show_menu "Select Service" "Choose service to enable HTTPS:" "${svc_array[@]}")
    [[ -z "$selected_svc" ]] && return

    # Get VM hostname and IP
    local hostname ip
    hostname=$(vm_get_hostname "$selected")
    if [[ -z "$hostname" ]]; then
        hostname=$(show_input "VM Hostname" "Enter hostname for certificate:" "vm-$selected")
        [[ -z "$hostname" ]] && return
    fi

    ip=$(vm_get_ip "$selected")
    if [[ -z "$ip" ]]; then
        show_msg "Error" "Could not get IP address for VM $selected."
        return
    fi

    if [[ "$selected_svc" == docker:* ]]; then
        # Docker mode: strip prefix and call Docker handler
        local docker_svc="${selected_svc#docker:}"
        if show_yesno "Enable HTTPS (Docker)" "This will:\n1. Generate SSL certificate for $hostname ($ip)\n2. Deploy certificate to VM\n3. Add nginx container to Docker Compose stack\n4. Restart Docker services with HTTPS\n\nEnable HTTPS for $docker_svc?"; then
            vm_enable_https_for_docker_service "$selected" "$docker_svc" "$hostname" "$ip"
        fi
    else
        # Native mode: existing path
        if show_yesno "Enable HTTPS" "This will:\n1. Generate SSL certificate for $hostname ($ip)\n2. Deploy certificate to VM\n3. Update nginx to use HTTPS (port 443)\n4. Redirect HTTP to HTTPS\n\nEnable HTTPS for $selected_svc?"; then
            vm_enable_https_for_service "$selected" "$selected_svc" "$hostname" "$ip"
        fi
    fi
}

# Enable HTTPS for a specific service in a VM (mirrors enable_https_for_service for LXC)
vm_enable_https_for_service() {
    local vmid="$1"
    local service="$2"
    local hostname="$3"
    local ip="$4"

    (
        echo "=== Enabling HTTPS for $service in VM $vmid ==="
        echo ""

        # Step 1: Generate certificate
        echo "Step 1: Generating SSL certificate..."
        local cert_dir="$CERTS_DIR/$hostname"

        if [[ -f "$cert_dir/${hostname}.crt" ]]; then
            echo "Certificate already exists for $hostname"
        else
            ca_generate_cert "$hostname" "$ip"
            echo "Certificate generated."
        fi
        echo ""

        # Step 2: Deploy certificate to VM
        echo "Step 2: Deploying certificate to VM..."
        vm_deploy_cert "$vmid" "$hostname"
        echo "Certificate deployed to /etc/ssl/pve-manager/"
        echo ""

        # Step 3: Update nginx configuration
        echo "Step 3: Updating nginx configuration..."

        case "$service" in
            jenkins)
                local nginx_conf
                nginx_conf="server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    client_max_body_size 100M;

    proxy_request_buffering off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;
    }
}"
                vm_write_file "$vmid" "/etc/nginx/sites-available/jenkins" "$nginx_conf"
                vm_exec "$vmid" "ln -sf /etc/nginx/sites-available/jenkins /etc/nginx/sites-enabled/jenkins"
                vm_exec "$vmid" "rm -f /etc/nginx/sites-enabled/default"
                ;;

            kiwi)
                local nginx_conf
                nginx_conf="server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    client_max_body_size 100M;

    # Serve static files directly
    location /static/ {
        alias /Kiwi/static/;
        autoindex off;
        expires 30d;
        add_header Cache-Control public;

        # Ensure correct MIME types
        types {
            text/css css;
            application/javascript js;
            application/json json;
            image/svg+xml svg svgz;
            font/woff woff;
            font/woff2 woff2;
            application/vnd.ms-fontobject eot;
            font/ttf ttf;
            font/otf otf;
        }
    }

    # Media/uploads files
    location /uploads/ {
        alias /Kiwi/uploads/;
        autoindex off;
        expires 7d;
    }

    # Favicon
    location = /favicon.ico {
        alias /Kiwi/static/images/favicon.ico;
        expires 30d;
        access_log off;
        log_not_found off;
    }

    # Proxy to gunicorn
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;
    }
}"
                vm_write_file "$vmid" "/etc/nginx/sites-available/kiwi" "$nginx_conf"
                ;;

            gitea)
                local nginx_conf
                nginx_conf="server {
    listen 80;
    listen [::]:80;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;
    }
}"
                vm_write_file "$vmid" "/etc/nginx/sites-available/gitea" "$nginx_conf"
                ;;

            testlink)
                # TestLink uses Nginx + PHP-FPM - find the actual socket path
                local php_sock
                php_sock=$(vm_exec "$vmid" "ls /run/php/php*-fpm.sock 2>/dev/null | head -1")
                [[ -z "$php_sock" ]] && php_sock="/run/php/php8.2-fpm.sock"

                local nginx_conf
                nginx_conf="server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    root /var/www/testlink;
    index index.php index.html;

    client_max_body_size 64M;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \\.php\$ {
        fastcgi_split_path_info ^(.+\\.php)(/.+)\$;
        fastcgi_pass unix:${php_sock};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        include fastcgi_params;
    }

    location ~ /\\. {
        deny all;
    }
}"
                vm_write_file "$vmid" "/etc/nginx/sites-available/testlink" "$nginx_conf"
                ;;

            default)
                local nginx_conf
                nginx_conf="server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }
}"
                vm_write_file "$vmid" "/etc/nginx/sites-available/default" "$nginx_conf"
                ;;
        esac

        # Step 4: Test and reload nginx
        echo "Configuration updated."
        echo ""
        echo "Step 4: Testing nginx configuration..."
        vm_exec_live "$vmid" "nginx -t"

        echo ""
        echo "Reloading nginx..."
        vm_exec_live "$vmid" "systemctl reload nginx"

        echo ""
        echo "=== HTTPS Enabled Successfully ==="
        echo ""
        echo "Access URL: https://${ip}/"
        echo ""
        echo "NOTE: You may need to import the CA certificate into your browser."
        echo "Export CA from: Certificate Management -> Export CA certificate"

    ) 2>&1 | show_progress_box "Enabling HTTPS" 24 80

    show_msg "HTTPS Enabled" "HTTPS has been enabled for $service!\n\nAccess: https://${ip}/\n\nNOTE: Import the CA certificate into your browser to avoid security warnings.\n\nExport CA from:\nCertificate Management -> Export CA certificate"
}

# Enable HTTPS for a Docker-deployed service in a VM by adding an nginx container
vm_enable_https_for_docker_service() {
    local vmid="$1"
    local service="$2"
    local hostname="$3"
    local ip="$4"
    local service_dir="/opt/services/${service}"

    (
        echo "=== Enabling HTTPS for $service (Docker) in VM $vmid ==="
        echo ""

        # Step 1: Generate certificate
        echo "Step 1: Generating SSL certificate..."
        local cert_dir="$CERTS_DIR/$hostname"

        if [[ -f "$cert_dir/${hostname}.crt" ]]; then
            echo "Certificate already exists for $hostname"
        else
            ca_generate_cert "$hostname" "$ip"
            echo "Certificate generated."
        fi
        echo ""

        # Step 2: Deploy certificate to VM
        echo "Step 2: Deploying certificate to VM..."
        vm_deploy_cert "$vmid" "$hostname"
        echo "Certificate deployed to /etc/ssl/pve-manager/"
        echo ""

        # Step 3: Write nginx.conf
        echo "Step 3: Writing nginx reverse-proxy configuration..."

        local upstream_name upstream_port
        case "$service" in
            jenkins)    upstream_name="jenkins";  upstream_port="8080" ;;
            gitea)      upstream_name="gitea";    upstream_port="3000" ;;
            kiwi-tcms)  upstream_name="kiwi";     upstream_port="8080" ;;
            testlink)   upstream_name="testlink";  upstream_port="8080" ;;
            *)
                echo "ERROR: Unknown service: $service"
                return 1
                ;;
        esac

        local nginx_conf="server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    client_max_body_size 100M;
    proxy_request_buffering off;

    location / {
        proxy_pass http://${upstream_name}:${upstream_port};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;
    }
}"
        vm_write_file "$vmid" "${service_dir}/nginx.conf" "$nginx_conf"
        echo "nginx.conf written to ${service_dir}/nginx.conf"
        echo ""

        # Step 4: Write updated docker-compose.yml with nginx service
        echo "Step 4: Updating docker-compose.yml with nginx container..."

        local compose_content=""
        case "$service" in
            jenkins)
                compose_content="services:
  jenkins:
    image: jenkins/jenkins:lts
    container_name: jenkins
    restart: unless-stopped
    expose:
      - \"8080\"
    ports:
      - \"50000:50000\"
    volumes:
      - jenkins_data:/var/jenkins_home
    environment:
      - JAVA_OPTS=-Djava.awt.headless=true

  nginx:
    image: nginx:alpine
    container_name: jenkins-nginx
    restart: unless-stopped
    ports:
      - \"80:80\"
      - \"443:443\"
    volumes:
      - /etc/ssl/pve-manager:/etc/ssl/pve-manager:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - jenkins

volumes:
  jenkins_data:"
                ;;
            gitea)
                compose_content="services:
  gitea:
    image: gitea/gitea:latest
    container_name: gitea
    restart: unless-stopped
    expose:
      - \"3000\"
    ports:
      - \"2222:22\"
    volumes:
      - gitea_data:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      - USER_UID=1000
      - USER_GID=1000
      - GITEA__database__DB_TYPE=sqlite3
      - GITEA__server__ROOT_URL=https://${ip}/
      - GITEA__server__DOMAIN=${ip}

  nginx:
    image: nginx:alpine
    container_name: gitea-nginx
    restart: unless-stopped
    ports:
      - \"80:80\"
      - \"443:443\"
    volumes:
      - /etc/ssl/pve-manager:/etc/ssl/pve-manager:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - gitea

volumes:
  gitea_data:"
                ;;
            kiwi-tcms)
                compose_content="services:
  kiwi:
    image: kiwitcms/kiwi:latest
    container_name: kiwi
    restart: unless-stopped
    expose:
      - \"8080\"
    volumes:
      - kiwi_uploads:/Kiwi/uploads
      - kiwi_db:/Kiwi/db
    environment:
      - KIWI_DB_ENGINE=django.db.backends.sqlite3
      - KIWI_DB_NAME=/Kiwi/db/kiwi.sqlite3

  nginx:
    image: nginx:alpine
    container_name: kiwi-tcms-nginx
    restart: unless-stopped
    ports:
      - \"80:80\"
      - \"443:443\"
    volumes:
      - /etc/ssl/pve-manager:/etc/ssl/pve-manager:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - kiwi

volumes:
  kiwi_uploads:
  kiwi_db:"
                ;;
            testlink)
                compose_content="services:
  mariadb:
    image: mariadb:10.6
    container_name: testlink-db
    restart: unless-stopped
    environment:
      - MARIADB_ROOT_PASSWORD=\${MARIADB_ROOT_PASSWORD:-testlink_root}
      - MARIADB_DATABASE=\${MARIADB_DATABASE:-testlink}
      - MARIADB_USER=\${MARIADB_USER:-testlink}
      - MARIADB_PASSWORD=\${MARIADB_PASSWORD:-testlink_pass}
    volumes:
      - testlink_db:/var/lib/mysql
    healthcheck:
      test: [\"CMD\", \"healthcheck.sh\", \"--connect\", \"--innodb_initialized\"]
      interval: 10s
      timeout: 5s
      retries: 5

  testlink:
    image: bitnami/testlink:latest
    container_name: testlink
    restart: unless-stopped
    expose:
      - \"8080\"
    environment:
      - TESTLINK_DATABASE_HOST=mariadb
      - TESTLINK_DATABASE_PORT_NUMBER=3306
      - TESTLINK_DATABASE_NAME=\${MARIADB_DATABASE:-testlink}
      - TESTLINK_DATABASE_USER=\${MARIADB_USER:-testlink}
      - TESTLINK_DATABASE_PASSWORD=\${MARIADB_PASSWORD:-testlink_pass}
      - TESTLINK_USERNAME=\${TESTLINK_USERNAME:-admin}
      - TESTLINK_PASSWORD=\${TESTLINK_PASSWORD:-admin}
      - TESTLINK_EMAIL=\${TESTLINK_EMAIL:-admin@example.com}
      - PHP_MEMORY_LIMIT=256M
      - PHP_MAX_UPLOAD_SIZE=64M
    volumes:
      - testlink_data:/bitnami/testlink
    depends_on:
      mariadb:
        condition: service_healthy

  nginx:
    image: nginx:alpine
    container_name: testlink-nginx
    restart: unless-stopped
    ports:
      - \"80:80\"
      - \"443:443\"
    volumes:
      - /etc/ssl/pve-manager:/etc/ssl/pve-manager:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - testlink

volumes:
  testlink_db:
  testlink_data:"
                ;;
        esac

        vm_write_file "$vmid" "${service_dir}/docker-compose.yml" "$compose_content"
        echo "docker-compose.yml updated with nginx service."
        echo ""

        # Step 5: Restart Docker stack
        echo "Step 5: Restarting Docker stack..."
        echo ""

        echo "Stopping existing containers..."
        vm_exec_live "$vmid" "cd ${service_dir} && docker compose down 2>&1"
        echo ""

        echo "Pulling nginx image..."
        vm_exec_live "$vmid" "cd ${service_dir} && docker compose pull nginx 2>&1"
        echo ""

        echo "Starting services..."
        vm_exec_live "$vmid" "cd ${service_dir} && docker compose up -d 2>&1"
        echo ""

        # Wait for services to start
        echo "Waiting for services to start..."
        sleep 10

        echo ""
        echo "Running containers:"
        vm_exec_live "$vmid" "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
        echo ""

        echo "=== HTTPS Enabled Successfully ==="
        echo ""
        echo "Access URL: https://${ip}/"
        echo ""
        echo "NOTE: You may need to import the CA certificate into your browser."
        echo "Export CA from: Certificate Management -> Export CA certificate"

    ) 2>&1 | show_progress_box "Enabling HTTPS (Docker)" 24 80

    show_msg "HTTPS Enabled" "HTTPS has been enabled for $service (Docker)!\n\nAccess: https://${ip}/\n\nAn nginx container has been added to the Docker Compose stack for SSL termination.\n\nNOTE: Import the CA certificate into your browser to avoid security warnings.\n\nExport CA from:\nCertificate Management -> Export CA certificate"
}

# Install Docker inside a VM via QEMU Guest Agent
vm_docker_install_with_progress() {
    local vmid="$1"
    local os_type="$2"

    log_info "Installing Docker in VM $vmid (OS: $os_type)"

    (
        echo "=== Docker Installation for VM $vmid ==="
        echo "Detected OS: $os_type"
        echo ""

        case "$os_type" in
            debian|ubuntu)
                echo "[1/5] Updating package lists..."
                vm_exec_live "$vmid" "apt-get update -qq"
                echo ""

                echo "[2/5] Installing minimal dependencies..."
                vm_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl"

                if ! vm_exec "$vmid" "command -v curl" &>/dev/null; then
                    echo "  ERROR: Failed to install curl"
                    echo "  Attempting to fix..."
                    vm_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-broken"
                    vm_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y curl"
                fi
                echo ""

                echo "[3/5] Adding Docker repository GPG key..."
                vm_exec_live "$vmid" "install -m 0755 -d /etc/apt/keyrings"
                vm_exec_live "$vmid" "rm -f /etc/apt/keyrings/docker.asc /etc/apt/keyrings/docker.gpg"

                echo "  Downloading Docker GPG key..."
                vm_exec_live "$vmid" "curl -fsSL https://download.docker.com/linux/${os_type}/gpg -o /etc/apt/keyrings/docker.asc"
                vm_exec_live "$vmid" "chmod a+r /etc/apt/keyrings/docker.asc"

                if ! vm_exec "$vmid" "test -s /etc/apt/keyrings/docker.asc" 2>/dev/null; then
                    echo "  ERROR: Failed to download Docker GPG key"
                    return 1
                fi
                echo "  GPG key installed successfully."
                echo ""

                echo "[4/5] Adding Docker repository..."
                codename=$(vm_exec "$vmid" ". /etc/os-release && echo \$VERSION_CODENAME" 2>/dev/null)
                if [[ -z "$codename" ]]; then
                    version_id=$(vm_exec "$vmid" ". /etc/os-release && echo \$VERSION_ID" 2>/dev/null)
                    case "$os_type-$version_id" in
                        debian-13) codename="trixie" ;;
                        debian-12) codename="bookworm" ;;
                        debian-11) codename="bullseye" ;;
                        ubuntu-24.04) codename="noble" ;;
                        ubuntu-22.04) codename="jammy" ;;
                        ubuntu-20.04) codename="focal" ;;
                        *) codename="stable" ;;
                    esac
                fi
                echo "  Distribution codename: $codename"

                vm_exec "$vmid" "echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${os_type} ${codename} stable\" > /etc/apt/sources.list.d/docker.list"

                echo "  Updating package lists with Docker repository..."
                vm_exec_live "$vmid" "apt-get update"
                echo ""

                echo "[5/5] Installing Docker packages..."
                vm_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"

                if ! vm_exec "$vmid" "command -v docker" &>/dev/null; then
                    echo ""
                    echo "  WARNING: Docker command not found after installation."
                    echo "  Attempting to fix broken packages..."
                    vm_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-broken"
                    vm_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io"
                fi
                echo ""
                ;;
            centos|rhel|rocky|almalinux)
                echo "[1/4] Installing dependencies..."
                vm_exec_live "$vmid" "dnf install -y yum-utils"
                echo ""

                echo "[2/4] Adding Docker repository..."
                vm_exec_live "$vmid" "yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo"
                echo ""

                echo "[3/4] Installing Docker..."
                vm_exec_live "$vmid" "dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
                echo ""

                echo "[4/4] Enabling Docker service..."
                vm_exec_live "$vmid" "systemctl enable docker"
                echo ""
                ;;
            fedora)
                echo "[1/4] Installing dependencies..."
                vm_exec_live "$vmid" "dnf install -y dnf-plugins-core"
                echo ""

                echo "[2/4] Adding Docker repository..."
                vm_exec_live "$vmid" "dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo"
                echo ""

                echo "[3/4] Installing Docker..."
                vm_exec_live "$vmid" "dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
                echo ""

                echo "[4/4] Enabling Docker service..."
                vm_exec_live "$vmid" "systemctl enable docker"
                echo ""
                ;;
            *)
                echo "ERROR: Unsupported OS: $os_type"
                echo ""
                echo "Supported OS types:"
                echo "  - debian, ubuntu (APT-based)"
                echo "  - centos, rhel, rocky, almalinux (DNF/YUM-based)"
                echo "  - fedora (DNF-based)"
                return 1
                ;;
        esac

        echo ""
        echo "Creating Docker daemon configuration..."
        vm_exec_live "$vmid" "mkdir -p /etc/docker"
        vm_exec_live "$vmid" 'cat > /etc/docker/daemon.json << EOF
{
    "storage-driver": "overlay2",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
EOF'

        echo ""
        echo "Starting Docker service..."
        vm_exec_live "$vmid" "systemctl enable docker && systemctl start docker"
        echo ""

        echo "Waiting for Docker to start..."
        sleep 3

        echo ""
        echo "=== Verifying Docker Installation ==="
        vm_exec_live "$vmid" "docker --version"
        vm_exec_live "$vmid" "docker compose version"
        echo ""

        echo "Testing Docker with hello-world..."
        vm_exec_live "$vmid" "docker run --rm hello-world"
        echo ""

        echo "=== Docker Installation Complete ==="

    ) 2>&1 | show_progress_box "Installing Docker in VM $vmid" 24 80
}

# ============================================================================
# VM Management Menu
# ============================================================================

vm_management_menu() {
    while true; do
        if [[ -z "$CURRENT_PVE" ]]; then
            show_msg "Not Connected" "Please connect to a PVE server first."
            return
        fi

        local choice
        choice=$(show_menu "VM Management" "Select an operation:" \
            "1" "List VMs" \
            "2" "VM details" \
            "3" "Enable HTTPS for service" \
            "4" "Deploy service to VM" \
            "5" "Execute command in VM" \
            "6" "Create user" \
            "0" "Back to main menu")

        case "$choice" in
            1)
                show_info "Loading..." "Fetching VM list..."
                local vms
                vms=$(pve_list_vms)

                if [[ -z "$vms" ]]; then
                    show_msg "No VMs" "No virtual machines found on this PVE host."
                else
                    local tmpfile="/tmp/pve-vms-$$.txt"
                    echo "VMID       Status       Mem    Name" > "$tmpfile"
                    echo "----------------------------------------" >> "$tmpfile"
                    echo "$vms" >> "$tmpfile"
                    show_textbox "Virtual Machines" "$tmpfile"
                    rm -f "$tmpfile"
                fi
                ;;
            2)
                local vms
                vms=$(pve_list_vms)
                if [[ -z "$vms" ]]; then
                    show_msg "No VMs" "No virtual machines found."
                    continue
                fi

                local vm_array=()
                while read -r vmid status mem name; do
                    [[ -z "$vmid" ]] && continue
                    vm_array+=("$vmid" "$name ($status)")
                done <<< "$vms"

                local selected
                selected=$(show_menu "VM Details" "Select VM:" "${vm_array[@]}")

                if [[ -n "$selected" ]]; then
                    show_info "Loading..." "Fetching VM details..."
                    local details
                    details=$(pve_exec "qm config $selected 2>/dev/null")

                    # Add guest agent status
                    local ga_status="Not available"
                    if vm_has_guest_agent "$selected"; then
                        ga_status="Available"
                        local vm_ip
                        vm_ip=$(vm_get_ip "$selected")
                        [[ -n "$vm_ip" ]] && ga_status="Available (IP: $vm_ip)"
                    fi

                    local tmpfile="/tmp/pve-vm-details-$$.txt"
                    echo "=== VM $selected Configuration ===" > "$tmpfile"
                    echo "" >> "$tmpfile"
                    echo "Guest Agent: $ga_status" >> "$tmpfile"
                    echo "" >> "$tmpfile"
                    echo "$details" >> "$tmpfile"
                    show_textbox "VM $selected Details" "$tmpfile"
                    rm -f "$tmpfile"
                fi
                ;;
            3)
                vm_enable_https_wizard
                ;;
            4)
                # Deploy service to VM
                local svc_choice
                svc_choice=$(show_menu "Deploy Service to VM" "Select service to deploy:" \
                    "jenkins" "Jenkins (CI/CD automation server)" \
                    "nginx" "Nginx (reverse proxy & web server)" \
                    "0" "Back")

                case "$svc_choice" in
                    jenkins)
                        vm_deploy_service_wizard "jenkins" "Jenkins"
                        ;;
                    nginx)
                        vm_deploy_service_wizard "nginx" "Nginx Reverse Proxy"
                        ;;
                    0|"")
                        continue
                        ;;
                esac
                ;;
            5)
                # Execute command in VM
                local vms
                vms=$(pve_list_vms)
                if [[ -z "$vms" ]]; then
                    show_msg "No VMs" "No virtual machines found."
                    continue
                fi

                # Filter running VMs only
                local vm_array=()
                while read -r vmid status mem name; do
                    [[ -z "$vmid" ]] && continue
                    [[ "$status" != "running" ]] && continue
                    vm_array+=("$vmid" "$name ($status)")
                done <<< "$vms"

                if [[ ${#vm_array[@]} -eq 0 ]]; then
                    show_msg "No Running VMs" "No running VMs found."
                    continue
                fi

                local selected
                selected=$(show_menu "Execute Command" "Select VM:" "${vm_array[@]}")

                if [[ -n "$selected" ]]; then
                    # Check guest agent
                    if ! vm_has_guest_agent "$selected"; then
                        show_msg "Guest Agent Required" "QEMU Guest Agent is not available on VM $selected."
                        continue
                    fi

                    local cmd
                    cmd=$(show_input "Command" "Enter command to execute in VM $selected:" "")
                    if [[ -n "$cmd" ]]; then
                        (
                            echo "=== Executing Command in VM $selected ==="
                            echo "Command: $cmd"
                            echo ""
                            echo "Output:"
                            echo "----------------------------------------"
                            vm_exec_live "$selected" "$cmd"
                            echo "----------------------------------------"
                            echo ""
                            echo "Command completed."
                        ) | show_progress_box "Execute Command"
                    fi
                fi
                ;;
            6)
                vm_create_user_wizard
                ;;
            0|"")
                return
                ;;
        esac
    done
}

# Deploy service to VM with Docker
vm_deploy_service() {
    local vmid="$1"
    local service="$2"
    local service_name="$3"
    local deploy_result_file="/tmp/pve-vm-deploy-result-$$.txt"

    log_info "Deploying $service to VM $vmid (Docker)"
    log_service_op "$service" "VM_DEPLOY_DOCKER" "vmid=$vmid service_name=$service_name"

    # Initialize result file
    echo "0" > "$deploy_result_file"

    (
        echo "=== Deploying $service_name to VM $vmid ==="
        echo ""

        # Check if Docker is installed
        echo "Checking Docker installation..."
        docker_check=$(vm_exec "$vmid" "docker --version 2>/dev/null")
        if [[ -z "$docker_check" ]]; then
            echo "ERROR: Docker not installed in VM $vmid"
            echo "Please install Docker first."
            echo "1" > "$deploy_result_file"
            exit 1
        fi
        echo "Docker found: $docker_check"
        echo ""

        # Get compose content
        compose_content=$(get_service_compose "$service")
        if [[ -z "$compose_content" ]]; then
            echo "ERROR: Unknown service: $service"
            echo "1" > "$deploy_result_file"
            exit 1
        fi

        # Create service directory
        service_dir="/opt/services/${service}"
        echo "Creating service directory: $service_dir"
        vm_exec_live "$vmid" "mkdir -p $service_dir"
        echo ""

        # Write docker-compose.yml
        echo "Writing docker-compose.yml..."
        vm_write_file "$vmid" "${service_dir}/docker-compose.yml" "$compose_content"
        echo "Done."
        echo ""

        # Write additional config files if needed
        case "$service" in
            nginx)
                echo "Writing nginx.conf and reverse proxy site..."
                vm_write_file "$vmid" "${service_dir}/nginx.conf" "$(cat "${PLUGINS[$service]}/nginx.conf")"
                vm_exec_live "$vmid" "mkdir -p ${service_dir}/conf.d ${service_dir}/ssl"
                vm_write_file "$vmid" "${service_dir}/conf.d/default.conf" "$(cat "${PLUGINS[$service]}/conf.d/default.conf")"
                echo "Generating self-signed TLS certificate..."
                vm_ip_cert=$(vm_get_ip "$vmid")
                vm_exec "$vmid" "test -f ${service_dir}/ssl/server.crt || openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${service_dir}/ssl/server.key -out ${service_dir}/ssl/server.crt -subj '/CN=${vm_ip_cert:-pve-nginx}' -addext 'subjectAltName=IP:${vm_ip_cert:-127.0.0.1}' 2>/dev/null"
                echo "Done."
                echo ""
                ;;
        esac

        # Pull Docker images with retry logic
        echo "Pulling Docker images (this may take a few minutes)..."
        echo ""

        local pull_attempts=0
        local max_pull_attempts=3
        local pull_status=1

        while [[ $pull_attempts -lt $max_pull_attempts && $pull_status -ne 0 ]]; do
            pull_attempts=$((pull_attempts + 1))
            echo "Pull attempt $pull_attempts of $max_pull_attempts..."

            # Use timeout to prevent indefinite hangs (5 minutes per attempt)
            pull_output=$(vm_exec_timeout "$vmid" 300 "cd ${service_dir} && docker compose pull --quiet 2>&1")
            pull_status=$?

            if [[ $pull_status -eq 124 ]]; then
                echo "Pull timed out. Retrying..."
                vm_exec "$vmid" "systemctl restart docker 2>/dev/null || true" > /dev/null 2>&1
                sleep 5
            elif [[ $pull_status -ne 0 ]]; then
                echo "Pull failed: $pull_output"
                if [[ $pull_attempts -lt $max_pull_attempts ]]; then
                    echo "Waiting 10 seconds before retry..."
                    sleep 10
                fi
            else
                echo "Images pulled successfully."
            fi
        done

        if [[ $pull_status -ne 0 ]]; then
            echo "ERROR: Failed to pull Docker images after $max_pull_attempts attempts"
            echo "Possible causes: network issues, Docker registry unavailable"
            echo "1" > "$deploy_result_file"
            exit 1
        fi
        echo ""

        echo "Starting $service_name..."
        echo ""
        start_output=$(vm_exec "$vmid" "cd ${service_dir} && docker compose up -d 2>&1")
        start_status=$?
        echo "$start_output"
        echo ""

        if [[ $start_status -ne 0 ]]; then
            echo "ERROR: Failed to start containers"
            echo "1" > "$deploy_result_file"
            exit 1
        fi

        # Wait for services to start
        echo "Waiting for services to start..."
        sleep 5

        # Verify containers are running
        echo ""
        echo "Verifying deployment..."
        running_containers=$(vm_exec "$vmid" "docker ps --format '{{.Names}}' 2>/dev/null" | wc -l)

        if [[ "$running_containers" -eq 0 ]]; then
            echo "WARNING: No containers are running!"
            echo ""
            echo "Checking container logs..."
            vm_exec_live "$vmid" "cd ${service_dir} && docker compose logs --tail=20 2>&1"
            echo "1" > "$deploy_result_file"
            exit 1
        fi

        echo "Running containers ($running_containers):"
        vm_exec_live "$vmid" "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
        echo ""

        echo "=== Deployment Complete ==="
        echo "0" > "$deploy_result_file"

    ) 2>&1 | show_progress_box "Deploying $service_name to VM" 24 80

    # Check deployment result
    local result
    result=$(cat "$deploy_result_file" 2>/dev/null)
    rm -f "$deploy_result_file"

    if [[ "$result" != "0" ]]; then
        return 1
    fi
    return 0
}

# Deploy service to VM natively (reuses plugin install.sh scripts)
vm_deploy_service_native() {
    local vmid="$1"
    local service="$2"
    local service_name="$3"
    local deploy_result_file="/tmp/pve-vm-deploy-native-result-$$.txt"

    log_info "Deploying $service natively to VM $vmid"
    log_service_op "$service" "VM_DEPLOY_NATIVE" "vmid=$vmid service_name=$service_name"

    # Check if plugin supports native installation
    if ! is_plugin_service "$service" || ! plugin_supports_native "$service"; then
        log_error "Native installation not available for $service"
        return 1
    fi

    local install_script="${PLUGINS[$service]}/install.sh"
    if [[ ! -f "$install_script" ]]; then
        log_error "Install script not found for $service"
        return 1
    fi

    # Initialize result file
    echo "0" > "$deploy_result_file"

    (
        echo "=== Installing $service_name Natively in VM $vmid ==="
        echo ""

        # Detect OS
        echo "Detecting OS..."
        os_type=$(vm_exec "$vmid" "cat /etc/os-release 2>/dev/null | grep '^ID=' | cut -d= -f2 | tr -d '\"'")
        echo "OS: $os_type"
        echo ""

        # Run plugin installer - override lxc_exec_live/lxc_exec to use VM equivalents
        # This allows reusing existing plugin install.sh scripts unchanged
        echo "Using plugin installer for $service..."
        export VMID="$vmid"
        export OS_TYPE="$os_type"
        lxc_exec_live() { vm_exec_live "$@"; }
        lxc_exec() { vm_exec "$@"; }
        export -f lxc_exec_live
        export -f lxc_exec
        source "$install_script"
        local result=$?
        # Restore original functions
        unset -f lxc_exec_live
        unset -f lxc_exec
        if [[ $result -ne 0 ]]; then
            echo "1" > "$deploy_result_file"
            exit $result
        fi

        echo ""
        echo "Verifying installation..."
        sleep 3

        # Check service status
        local conf="${PLUGINS[$service]}/plugin.conf"
        local systemd_service
        systemd_service=$(grep "^PLUGIN_SYSTEMD_SERVICE=" "$conf" 2>/dev/null | cut -d= -f2 | tr -d '"' | tr -d "'")
        [[ -z "$systemd_service" ]] && systemd_service="$service"

        service_running=false
        case "$os_type" in
            debian|ubuntu)
                if vm_exec "$vmid" "systemctl is-active --quiet $systemd_service 2>/dev/null"; then
                    service_running=true
                fi
                ;;
            centos|rhel|rocky|almalinux|fedora)
                if vm_exec "$vmid" "systemctl is-active --quiet $systemd_service 2>/dev/null"; then
                    service_running=true
                fi
                ;;
        esac

        if [[ "$service_running" == true ]]; then
            echo "Service is running!"
            echo "0" > "$deploy_result_file"
        else
            echo "WARNING: Service may not be running. Check logs."
            echo "0" > "$deploy_result_file"  # Still return success, user can check
        fi

        echo ""
        echo "=== Native Installation Complete ==="

    ) 2>&1 | show_progress_box "Installing $service_name in VM (Native)" 24 80

    # Check deployment result
    local result
    result=$(cat "$deploy_result_file" 2>/dev/null)
    rm -f "$deploy_result_file"

    if [[ "$result" != "0" ]]; then
        return 1
    fi
    return 0
}

# Interactive wizard for deploying services to VMs
vm_deploy_service_wizard() {
    local service="$1"
    local service_name="$2"

    # Select VM (running only)
    local vms
    vms=$(pve_list_vms)
    if [[ -z "$vms" ]]; then
        show_msg "No VMs" "No virtual machines found."
        return
    fi

    local vm_array=()
    while read -r vmid status mem name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        vm_array+=("$vmid" "$name ($status)")
    done <<< "$vms"

    if [[ ${#vm_array[@]} -eq 0 ]]; then
        show_msg "No Running VMs" "No running VMs found. VMs must be running with QEMU Guest Agent."
        return
    fi

    local selected
    selected=$(show_menu "Deploy $service_name" "Select VM (must have QEMU Guest Agent):" "${vm_array[@]}")
    [[ -z "$selected" ]] && return

    # Verify guest agent
    show_info "Checking..." "Verifying QEMU Guest Agent on VM $selected..."
    if ! vm_has_guest_agent "$selected"; then
        show_msg "Guest Agent Required" "QEMU Guest Agent is not available on VM $selected.\n\nPlease ensure:\n1. qemu-guest-agent is installed in the VM\n2. Guest Agent is enabled in VM options\n3. VM is running"
        return
    fi

    # Choose deployment method
    local method
    local method_options=()

    if is_plugin_service "$service" && plugin_supports_docker "$service"; then
        method_options+=("docker" "Docker (container-based)")
    fi
    if is_plugin_service "$service" && plugin_supports_native "$service"; then
        method_options+=("native" "Native (direct installation)")
    fi

    if [[ ${#method_options[@]} -eq 0 ]]; then
        show_msg "No Methods" "No deployment methods available for $service_name."
        return
    elif [[ ${#method_options[@]} -eq 2 ]]; then
        # Only one method available
        method="${method_options[0]}"
    else
        method=$(show_menu "Deployment Method" "Choose how to deploy $service_name:" "${method_options[@]}")
        [[ -z "$method" ]] && return
    fi

    # For Docker method, check if Docker is installed
    if [[ "$method" == "docker" ]]; then
        show_info "Checking..." "Checking Docker in VM $selected..."
        local docker_check
        docker_check=$(vm_exec "$selected" "docker --version 2>/dev/null")
        if [[ -z "$docker_check" ]]; then
            if show_yesno "Docker Not Found" "Docker is not installed in VM $selected.\n\nWould you like to install Docker now?"; then
                local os_type
                os_type=$(detect_vm_os "$selected")
                if [[ -z "$os_type" ]]; then
                    show_msg "OS Detection Failed" "Could not detect the operating system in VM $selected."
                    return
                fi
                vm_docker_install_with_progress "$selected" "$os_type"

                # Verify Docker was installed
                docker_check=$(vm_exec "$selected" "docker --version 2>/dev/null")
                if [[ -z "$docker_check" ]]; then
                    show_msg "Docker Installation Failed" "Docker installation did not complete successfully.\nPlease install Docker manually and try again."
                    return
                fi
            else
                return
            fi
        fi
    fi

    # Confirm deployment
    local vm_ip
    vm_ip=$(vm_get_ip "$selected")
    local ip_display="${vm_ip:-unknown}"

    if ! show_yesno "Confirm Deployment" "Deploy $service_name to VM $selected?\n\nMethod: $method\nVM IP: $ip_display"; then
        return
    fi

    # Deploy
    local deploy_result=0
    if [[ "$method" == "docker" ]]; then
        vm_deploy_service "$selected" "$service" "$service_name"
        deploy_result=$?
    else
        vm_deploy_service_native "$selected" "$service" "$service_name"
        deploy_result=$?
    fi

    # Show access info
    if [[ $deploy_result -eq 0 ]]; then
        local conf="${PLUGINS[$service]}/plugin.conf"
        local access_url="" credentials=""

        if [[ "$method" == "docker" ]]; then
            access_url=$(grep "^PLUGIN_DOCKER_URL=" "$conf" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'")
            credentials=$(grep "^PLUGIN_DOCKER_CREDENTIALS=" "$conf" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'")
        else
            access_url=$(grep "^PLUGIN_NATIVE_URL=" "$conf" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'")
            credentials=$(grep "^PLUGIN_NATIVE_CREDENTIALS=" "$conf" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'")
        fi

        # Replace {IP} placeholder
        if [[ -n "$vm_ip" && -n "$access_url" ]]; then
            access_url="${access_url//\{IP\}/$vm_ip}"
        fi

        local msg="$service_name deployed successfully to VM $selected!\n\n"
        [[ -n "$access_url" ]] && msg+="Access URL: $access_url\n"
        [[ -n "$credentials" ]] && msg+="Credentials: $credentials\n"
        msg+="\nMethod: $method"

        show_msg "Deployment Complete" "$msg"
    else
        show_msg "Deployment Failed" "$service_name deployment to VM $selected failed.\n\nCheck the logs for details."
    fi
}

# LXC Creation Wizard
lxc_create_wizard() {
    # Check connection
    if [[ -z "$CURRENT_PVE" ]]; then
        show_msg "Not Connected" "Please connect to a PVE server first."
        return
    fi

    # Get available storages for containers
    show_info "Loading..." "Fetching available storages..."
    local container_storages
    container_storages=$(pve_list_container_storages)

    if [[ -z "$container_storages" ]]; then
        show_msg "No Storage" "No storage found that supports containers (rootdir content type)."
        return
    fi

    # Build storage menu
    local storage_array=()
    while IFS= read -r st; do
        [[ -z "$st" ]] && continue
        # Get storage info
        local st_info
        st_info=$(pve_exec "pvesm status 2>/dev/null | grep \"^${st} \" | awk '{printf \"%s (%s)\", \$2, \$3}'")
        storage_array+=("$st" "${st_info:-Storage}")
    done <<< "$container_storages"

    # Select storage for container
    local storage
    storage=$(show_menu "Select Storage" "Choose storage for container disk:" "${storage_array[@]}")
    [[ -z "$storage" ]] && return

    # Get templates
    show_info "Loading..." "Fetching available templates..."
    local templates
    templates=$(pve_list_templates)

    if [[ -z "$templates" ]]; then
        if show_yesno "No Templates" "No templates found.\n\nWould you like to download a template now?"; then
            template_download_quick "$storage"
            # Refresh template list
            templates=$(pve_list_templates)
            if [[ -z "$templates" ]]; then
                show_msg "No Templates" "Still no templates available. Please try again."
                return
            fi
        else
            return
        fi
    fi

    # Build template menu with descriptions, add option to download more
    local template_array=()
    template_array+=("__DOWNLOAD__" "[Download new template...]")
    while IFS= read -r tmpl; do
        [[ -z "$tmpl" ]] && continue
        # Extract just the filename for description
        local tmpl_name
        tmpl_name=$(basename "$tmpl" | sed 's/.tar.*$//')
        template_array+=("$tmpl" "$tmpl_name")
    done <<< "$templates"

    # Select template
    local template
    template=$(show_menu "Select Template" "Choose a container template:" "${template_array[@]}")
    [[ -z "$template" ]] && return

    # Handle download option
    if [[ "$template" == "__DOWNLOAD__" ]]; then
        template_download_quick "$storage"
        # Refresh and re-select
        templates=$(pve_list_templates)
        if [[ -z "$templates" ]]; then
            show_msg "No Templates" "No templates available."
            return
        fi
        template_array=()
        while IFS= read -r tmpl; do
            [[ -z "$tmpl" ]] && continue
            local tmpl_name
            tmpl_name=$(basename "$tmpl" | sed 's/.tar.*$//')
            template_array+=("$tmpl" "$tmpl_name")
        done <<< "$templates"
        template=$(show_menu "Select Template" "Choose a container template:" "${template_array[@]}")
        [[ -z "$template" ]] && return
    fi

    # Get VMID
    local next_vmid
    next_vmid=$(get_next_vmid)

    local vmid
    vmid=$(show_input "Container ID" "Enter VMID for new container:" "$next_vmid")
    [[ -z "$vmid" ]] && return

    # Validate VMID is a number
    if ! [[ "$vmid" =~ ^[0-9]+$ ]]; then
        show_msg "Error" "VMID must be a number."
        return
    fi

    # Get hostname
    local hostname
    hostname=$(show_input "Hostname" "Enter hostname for container:" "ct${vmid}")
    [[ -z "$hostname" ]] && return

    # Get resources
    local cpu
    cpu=$(show_input "CPU Cores" "Number of CPU cores:" "${DEFAULT_CPU:-2}")
    [[ -z "$cpu" ]] && cpu=2

    local ram
    ram=$(show_input "Memory" "Memory in MB:" "${DEFAULT_RAM:-2048}")
    [[ -z "$ram" ]] && ram=2048

    local disk
    disk=$(show_input "Disk Size" "Root disk size in GB:" "${DEFAULT_DISK:-8}")
    [[ -z "$disk" ]] && disk=8

    # Network configuration
    show_info "Loading..." "Fetching network bridges..."
    local bridges
    bridges=$(pve_exec "ip -o link show type bridge 2>/dev/null | awk -F': ' '{print \$2}' | head -10")

    local bridge
    if [[ -n "$bridges" ]]; then
        local bridge_array=()
        while IFS= read -r br; do
            [[ -z "$br" ]] && continue
            bridge_array+=("$br" "Bridge")
        done <<< "$bridges"

        if [[ ${#bridge_array[@]} -gt 0 ]]; then
            bridge=$(show_menu "Select Bridge" "Choose network bridge:" "${bridge_array[@]}")
        fi
    fi
    [[ -z "$bridge" ]] && bridge="${DEFAULT_BRIDGE:-vmbr0}"

    local ip_choice
    ip_choice=$(show_menu "IP Configuration" "Choose IP configuration:" \
        "dhcp" "Use DHCP" \
        "static" "Static IP address")

    local ip="dhcp"
    local gw=""
    if [[ "$ip_choice" == "static" ]]; then
        ip=$(show_input "Static IP" "Enter IP address (e.g., 192.168.1.100):")
        [[ -z "$ip" ]] && return

        gw=$(show_input "Gateway" "Enter gateway address:")
        [[ -z "$gw" ]] && return
    fi

    # Root password
    local password
    password=$(show_password "Root Password" "Enter root password for container:")
    [[ -z "$password" ]] && return

    local password2
    password2=$(show_password "Confirm Password" "Confirm root password:")

    if [[ "$password" != "$password2" ]]; then
        show_msg "Error" "Passwords do not match!"
        return
    fi

    # Confirm creation
    local confirm_text="Create container with these settings?\n\n"
    confirm_text+="VMID: $vmid\n"
    confirm_text+="Hostname: $hostname\n"
    confirm_text+="Template: $template\n"
    confirm_text+="Storage: $storage\n"
    confirm_text+="CPU: $cpu cores\n"
    confirm_text+="Memory: ${ram}MB\n"
    confirm_text+="Disk: ${disk}GB\n"
    confirm_text+="Network: $bridge ($ip)"

    if ! show_yesno "Confirm Creation" "$confirm_text"; then
        return
    fi

    # Create container with progress
    lxc_create "$vmid" "$hostname" "$template" "$storage" "$cpu" "$ram" "$disk" "$bridge" "$ip" "$gw" "$password"

    # Check if creation was successful
    sleep 1
    local status
    status=$(pve_container_status "$vmid" 2>/dev/null)

    if [[ -n "$status" ]]; then
        log_info "Container $vmid created successfully"

        if show_yesno "Start Container?" "Container created successfully!\n\nStart the container now?"; then
            (
                echo "Starting container $vmid..."
                lxc_start "$vmid"
                sleep 2
                echo ""
                echo "Container status: $(pve_container_status "$vmid")"
            ) | show_progress_box "Starting Container"
        fi

        show_msg "Success" "Container $vmid ($hostname) has been created."
    else
        log_error "Failed to create container $vmid"
        show_msg "Error" "Failed to create container. Check the log for details."
    fi
}

# LXC Management Menu
lxc_management_menu() {
    while true; do
        if [[ -z "$CURRENT_PVE" ]]; then
            show_msg "Not Connected" "Please connect to a PVE server first."
            return
        fi

        local choice
        choice=$(show_menu "LXC Management" "Select an operation:" \
            "1" "List containers" \
            "2" "Create new container" \
            "3" "Start container" \
            "4" "Stop container" \
            "5" "Delete container" \
            "6" "Container details" \
            "7" "Bulk operations" \
            "8" "Template manager" \
            "9" "Create user" \
            "0" "Back to main menu")

        case "$choice" in
            1)
                show_info "Loading..." "Fetching container list..."
                local containers
                containers=$(pve_list_containers)

                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found on this PVE host."
                else
                    local tmpfile="/tmp/pve-containers-$$.txt"
                    echo "VMID      Status      Lock     Name" > "$tmpfile"
                    echo "----------------------------------------" >> "$tmpfile"
                    echo "$containers" >> "$tmpfile"
                    show_textbox "Containers" "$tmpfile"
                    rm -f "$tmpfile"
                fi
                ;;
            2)
                lxc_create_wizard
                ;;
            3)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    ct_array+=("$vmid" "$name ($status)")
                done <<< "$containers"

                local selected
                selected=$(show_menu "Start Container" "Select container to start:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    (
                        echo "Starting container $selected..."
                        lxc_start "$selected"
                        sleep 2
                        echo ""
                        echo "Container status: $(pve_container_status "$selected")"
                    ) | show_progress_box "Starting Container"
                fi
                ;;
            4)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    ct_array+=("$vmid" "$name ($status)")
                done <<< "$containers"

                local selected
                selected=$(show_menu "Stop Container" "Select container to stop:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    if show_yesno "Confirm Stop" "Stop container $selected?"; then
                        (
                            echo "Stopping container $selected..."
                            lxc_stop "$selected"
                            sleep 2
                            echo ""
                            echo "Container status: $(pve_container_status "$selected")"
                        ) | show_progress_box "Stopping Container"
                    fi
                fi
                ;;
            5)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    ct_array+=("$vmid" "$name ($status)")
                done <<< "$containers"

                local selected
                selected=$(show_menu "Delete Container" "Select container to DELETE:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    if show_yesno "Confirm DELETE" "WARNING: This will permanently delete container $selected!\n\nAre you sure?"; then
                        (
                            # Stop if running
                            status=$(pve_container_status "$selected")
                            if [[ "$status" == "running" ]]; then
                                echo "Stopping container before deletion..."
                                lxc_stop "$selected"
                                sleep 2
                            fi

                            echo "Deleting container $selected..."
                            lxc_delete "$selected"
                            echo ""
                            echo "Container $selected deleted."
                        ) 2>&1 | show_progress_box "Deleting Container"
                    fi
                fi
                ;;
            6)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    ct_array+=("$vmid" "$name ($status)")
                done <<< "$containers"

                local selected
                selected=$(show_menu "Container Details" "Select container:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    show_info "Loading..." "Fetching container details..."
                    local info
                    info=$(pve_container_info "$selected")

                    local tmpfile="/tmp/pve-ct-info-$$.txt"
                    echo "Container $selected Configuration" > "$tmpfile"
                    echo "=================================" >> "$tmpfile"
                    echo "" >> "$tmpfile"
                    echo "$info" >> "$tmpfile"
                    show_textbox "Container $selected" "$tmpfile"
                    rm -f "$tmpfile"
                fi
                ;;
            7)
                lxc_bulk_menu
                ;;
            8)
                template_browser
                ;;
            9)
                lxc_create_user_wizard
                ;;
            0|"")
                break
                ;;
        esac
    done
}

# Bulk operations menu
lxc_bulk_menu() {
    local containers
    containers=$(pve_list_containers)

    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local choice
    choice=$(show_menu "Bulk Operations" "Select operation:" \
        "1" "Start all containers" \
        "2" "Stop all containers" \
        "3" "Start selected containers" \
        "4" "Stop selected containers" \
        "0" "Back")

    case "$choice" in
        1)
            if show_yesno "Confirm" "Start ALL containers?"; then
                (
                    echo "Starting all containers..."
                    echo ""
                    while read -r vmid status _ name; do
                        [[ -z "$vmid" ]] && continue
                        [[ "$status" == "running" ]] && continue
                        echo "Starting $vmid ($name)..."
                        lxc_start "$vmid" 2>&1
                        sleep 1
                    done <<< "$containers"
                    echo ""
                    echo "=== All containers started ==="
                ) | show_progress_box "Starting All Containers"
            fi
            ;;
        2)
            if show_yesno "Confirm" "Stop ALL containers?"; then
                (
                    echo "Stopping all containers..."
                    echo ""
                    while read -r vmid status _ name; do
                        [[ -z "$vmid" ]] && continue
                        [[ "$status" != "running" ]] && continue
                        echo "Stopping $vmid ($name)..."
                        lxc_stop "$vmid" 2>&1
                        sleep 1
                    done <<< "$containers"
                    echo ""
                    echo "=== All containers stopped ==="
                ) | show_progress_box "Stopping All Containers"
            fi
            ;;
        3|4)
            local ct_array=()
            while read -r vmid status _ name; do
                [[ -z "$vmid" ]] && continue
                ct_array+=("$vmid" "$name ($status)" "off")
            done <<< "$containers"

            local selected
            selected=$(show_checklist "Select Containers" "Choose containers:" "${ct_array[@]}")

            if [[ -n "$selected" ]]; then
                # Remove quotes and convert to array
                selected=${selected//\"/}
                local action="start"
                [[ "$choice" == "4" ]] && action="stop"

                (
                    echo "${action^}ing selected containers..."
                    echo ""
                    for vmid in $selected; do
                        echo "${action^}ing container $vmid..."
                        if [[ "$action" == "start" ]]; then
                            lxc_start "$vmid" 2>&1
                        else
                            lxc_stop "$vmid" 2>&1
                        fi
                        sleep 1
                    done
                    echo ""
                    echo "=== Operation completed ==="
                ) | show_progress_box "${action^}ing Containers"
            fi
            ;;
    esac
}

#######################################
# DOCKER SETUP FUNCTIONS
#######################################

# Detect OS in container (with timeout)
detect_container_os() {
    local vmid="$1"
    local os_id
    os_id=$(lxc_exec_timeout "$vmid" 5 "cat /etc/os-release 2>/dev/null | grep '^ID=' | cut -d= -f2 | tr -d '\"'" 2>/dev/null)
    echo "$os_id"
}

# Check if container has required features for Docker
check_container_docker_features() {
    local vmid="$1"
    local config
    config=$(pve_exec "pct config $vmid 2>/dev/null")

    local has_nesting=false
    local has_keyctl=false

    if echo "$config" | grep -q "nesting=1"; then
        has_nesting=true
    fi

    if echo "$config" | grep -q "keyctl=1"; then
        has_keyctl=true
    fi

    if $has_nesting && $has_keyctl; then
        return 0  # Basic features present
    else
        return 1  # Missing features
    fi
}

# Get missing Docker features for container
get_missing_docker_features() {
    local vmid="$1"
    local config
    config=$(pve_exec "pct config $vmid 2>/dev/null")

    # Also check LXC config file for AppArmor setting
    local lxc_conf
    lxc_conf=$(pve_exec "cat /etc/pve/lxc/${vmid}.conf 2>/dev/null" || echo "")
    local missing=""

    if ! echo "$config" | grep -q "nesting=1"; then
        missing+="nesting "
    fi

    if ! echo "$config" | grep -q "keyctl=1"; then
        missing+="keyctl "
    fi

    # Check for AppArmor unconfined (required for Docker in LXC)
    if ! echo "$lxc_conf" | grep -q "lxc.apparmor.profile:"; then
        missing+="apparmor "
    fi

    # Check for cgroup devices allow
    if ! echo "$lxc_conf" | grep -q "lxc.cgroup2.devices.allow:"; then
        missing+="cgroup "
    fi

    echo "${missing% }"  # Trim trailing space
}

# Wait for container to be fully stopped (no lock held)
wait_container_stopped() {
    local vmid="$1"
    local max_wait="${2:-30}"
    local waited=0

    while [[ $waited -lt $max_wait ]]; do
        local status
        status=$(pve_exec "pct status $vmid 2>/dev/null | awk '{print \$2}'")

        if [[ "$status" == "stopped" ]]; then
            # Check if there's a lock on the container
            local lock_status
            lock_status=$(pve_exec "pct config $vmid 2>/dev/null | grep '^lock:'" || true)

            if [[ -z "$lock_status" ]]; then
                return 0
            fi
        fi

        sleep 1
        waited=$((waited + 1))
    done

    return 1
}

# Enable Docker features on container (requires container to be stopped)
enable_docker_features() {
    local vmid="$1"

    log_info "Enabling Docker features on container $vmid"

    # Wait for container to be fully stopped with no lock
    echo "  Waiting for container to be fully stopped..."
    if ! wait_container_stopped "$vmid" 30; then
        echo "  Container still has lock, attempting to unlock..."
        pve_exec "pct unlock $vmid" 2>/dev/null || true
        sleep 2
    fi

    # Get current features
    local current_features
    current_features=$(pve_exec "pct config $vmid 2>/dev/null | grep '^features:' | cut -d' ' -f2")

    # Build new features string
    local new_features=""
    if [[ -n "$current_features" ]]; then
        new_features="$current_features"
        # Add nesting if not present
        if ! echo "$current_features" | grep -q "nesting=1"; then
            new_features="${new_features},nesting=1"
        fi
        # Add keyctl if not present
        if ! echo "$current_features" | grep -q "keyctl=1"; then
            new_features="${new_features},keyctl=1"
        fi
    else
        new_features="nesting=1,keyctl=1"
    fi

    # Apply features with retry
    local attempt=0
    local max_attempts=3

    while [[ $attempt -lt $max_attempts ]]; do
        echo "  Applying features: $new_features"
        if pve_exec "pct set $vmid --features $new_features" 2>&1; then
            echo "  Features applied successfully."

            # Add LXC configuration for Docker compatibility
            echo "  Adding Docker-compatible LXC configuration..."
            local lxc_conf="/etc/pve/lxc/${vmid}.conf"

            # Remove any existing Docker-related LXC config lines first
            pve_exec "sed -i '/^lxc.apparmor.profile/d' $lxc_conf" 2>&1 || true
            pve_exec "sed -i '/^lxc.cgroup2.devices.allow/d' $lxc_conf" 2>&1 || true
            pve_exec "sed -i '/^lxc.cap.drop/d' $lxc_conf" 2>&1 || true
            pve_exec "sed -i '/^lxc.mount.auto.*proc/d' $lxc_conf" 2>&1 || true

            # Add Docker-compatible LXC configuration
            pve_exec "cat >> $lxc_conf << 'LXCEOF'

# Docker compatibility settings
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: a
lxc.cap.drop:
lxc.mount.auto: proc:rw sys:rw
LXCEOF" 2>&1 || true

            echo "  LXC configuration updated."
            return 0
        fi

        attempt=$((attempt + 1))
        if [[ $attempt -lt $max_attempts ]]; then
            echo "  Retry $attempt/$max_attempts in 3 seconds..."
            sleep 3
            # Try unlocking again
            pve_exec "pct unlock $vmid" 2>/dev/null || true
        fi
    done

    echo "  ERROR: Failed to apply features after $max_attempts attempts"
    return 1
}

# Prepare container for Docker installation
prepare_container_for_docker() {
    local vmid="$1"

    # Check if features are already set
    if check_container_docker_features "$vmid"; then
        return 0  # Already configured
    fi

    local missing
    missing=$(get_missing_docker_features "$vmid")

    # Container needs configuration
    local status
    status=$(pve_container_status "$vmid")

    if [[ "$status" == "running" ]]; then
        # Need to stop container to modify features
        return 1  # Signal that container needs to be stopped
    else
        # Container is stopped, can modify directly
        enable_docker_features "$vmid"
        return $?
    fi
}

# Install Docker in container with progress
docker_install_with_progress() {
    local vmid="$1"
    local os_type="$2"

    log_info "Installing Docker in container $vmid (OS: $os_type)"

    (
        echo "=== Docker Installation for Container $vmid ==="
        echo "Detected OS: $os_type"
        echo ""

        # Check container features first
        echo "[PRE] Checking container configuration..."
        missing_features=$(get_missing_docker_features "$vmid")
        if [[ -n "$missing_features" ]]; then
            echo "  WARNING: Container is missing features: $missing_features"
            echo "  These features are required for Docker to work properly."
            echo "  Please enable them in the container options (nesting=1, keyctl=1)"
            echo ""
        else
            echo "  Container features OK (nesting, keyctl enabled)"
            echo ""
        fi

        case "$os_type" in
            debian|ubuntu)
                echo "[1/5] Updating package lists..."
                lxc_exec_live "$vmid" "apt-get update -qq"
                echo ""

                echo "[2/5] Installing minimal dependencies..."
                # Only install what's absolutely necessary - ca-certificates and curl
                # No need for gnupg - we'll use the .asc key directly
                lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl"

                # Verify curl is installed
                if ! lxc_exec "$vmid" "command -v curl" &>/dev/null; then
                    echo "  ERROR: Failed to install curl"
                    echo "  Attempting to fix..."
                    lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-broken"
                    lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y curl"
                fi
                echo ""

                echo "[3/5] Adding Docker repository GPG key..."
                lxc_exec_live "$vmid" "install -m 0755 -d /etc/apt/keyrings"
                lxc_exec_live "$vmid" "rm -f /etc/apt/keyrings/docker.asc /etc/apt/keyrings/docker.gpg"

                # Download GPG key as .asc file - APT can use this directly without gpg command
                echo "  Downloading Docker GPG key..."
                lxc_exec_live "$vmid" "curl -fsSL https://download.docker.com/linux/${os_type}/gpg -o /etc/apt/keyrings/docker.asc"
                lxc_exec_live "$vmid" "chmod a+r /etc/apt/keyrings/docker.asc"

                # Verify key was downloaded
                if ! lxc_exec "$vmid" "test -s /etc/apt/keyrings/docker.asc" 2>/dev/null; then
                    echo "  ERROR: Failed to download Docker GPG key"
                    return 1
                fi
                echo "  GPG key installed successfully."
                echo ""

                echo "[4/5] Adding Docker repository..."
                # Get version codename
                codename=$(lxc_exec "$vmid" ". /etc/os-release && echo \$VERSION_CODENAME" 2>/dev/null)
                # Fallback for known distros
                if [[ -z "$codename" ]]; then
                    version_id=$(lxc_exec "$vmid" ". /etc/os-release && echo \$VERSION_ID" 2>/dev/null)
                    case "$os_type-$version_id" in
                        debian-13) codename="trixie" ;;
                        debian-12) codename="bookworm" ;;
                        debian-11) codename="bullseye" ;;
                        ubuntu-24.04) codename="noble" ;;
                        ubuntu-22.04) codename="jammy" ;;
                        ubuntu-20.04) codename="focal" ;;
                        *) codename="stable" ;;
                    esac
                fi
                echo "  Distribution codename: $codename"

                # Create the repository file (using .asc key directly)
                lxc_exec "$vmid" "echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${os_type} ${codename} stable\" > /etc/apt/sources.list.d/docker.list"

                echo "  Updating package lists with Docker repository..."
                lxc_exec_live "$vmid" "apt-get update"
                echo ""

                echo "[5/5] Installing Docker packages..."
                lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"

                # Verify installation
                if ! lxc_exec "$vmid" "command -v docker" &>/dev/null; then
                    echo ""
                    echo "  WARNING: Docker command not found after installation."
                    echo "  Attempting to fix broken packages..."
                    lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-broken"
                    lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io"
                fi
                echo ""

                echo "Configuring Docker for LXC..."
                ;;
            alpine)
                echo "[1/3] Updating package lists..."
                lxc_exec_live "$vmid" "apk update"
                echo ""

                echo "[2/3] Installing Docker and dependencies..."
                lxc_exec_live "$vmid" "apk add docker docker-cli-compose openrc"
                lxc_exec_live "$vmid" "rc-update add docker boot 2>/dev/null || true"
                echo ""

                echo "[3/3] Configuring Docker for LXC..."
                ;;
            centos|rhel|rocky|almalinux)
                echo "[1/4] Installing dependencies..."
                lxc_exec_live "$vmid" "dnf install -y yum-utils"
                echo ""

                echo "[2/4] Adding Docker repository..."
                # dnf/yum handles GPG keys automatically from the repo
                lxc_exec_live "$vmid" "yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo"
                echo ""

                echo "[3/4] Installing Docker..."
                lxc_exec_live "$vmid" "dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
                echo ""

                echo "[4/4] Enabling Docker service..."
                lxc_exec_live "$vmid" "systemctl enable docker"
                echo ""

                echo "Configuring Docker for LXC..."
                ;;
            fedora)
                echo "[1/4] Installing dependencies..."
                lxc_exec_live "$vmid" "dnf install -y dnf-plugins-core"
                echo ""

                echo "[2/4] Adding Docker repository..."
                # dnf handles GPG keys automatically from the repo
                lxc_exec_live "$vmid" "dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo"
                echo ""

                echo "[3/4] Installing Docker..."
                lxc_exec_live "$vmid" "dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
                echo ""

                echo "[4/4] Enabling Docker service..."
                lxc_exec_live "$vmid" "systemctl enable docker"
                echo ""

                echo "Configuring Docker for LXC..."
                ;;
            *)
                echo "ERROR: Unsupported OS: $os_type"
                echo ""
                echo "Supported OS types:"
                echo "  - debian, ubuntu (APT-based)"
                echo "  - alpine (APK-based)"
                echo "  - centos, rhel, rocky, almalinux (DNF/YUM-based)"
                echo "  - fedora (DNF-based)"
                return 1
                ;;
        esac

        echo ""
        echo "Configuring system for Docker in LXC..."
        # Set sysctls that Docker needs (ignore errors if not allowed)
        lxc_exec_live "$vmid" "sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true"
        lxc_exec_live "$vmid" "sysctl -w net.ipv4.ip_unprivileged_port_start=0 2>/dev/null || true"
        lxc_exec_live "$vmid" "sysctl -w kernel.unprivileged_userns_clone=1 2>/dev/null || true"
        # Make sysctl settings persistent
        lxc_exec "$vmid" "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf 2>/dev/null || true"
        echo ""

        echo "Creating Docker daemon configuration..."
        lxc_exec_live "$vmid" "mkdir -p /etc/docker"
        lxc_exec_live "$vmid" 'cat > /etc/docker/daemon.json << EOF
{
    "storage-driver": "overlay2",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 65536,
            "Soft": 65536
        }
    },
    "no-new-privileges": false
}
EOF'

        # Fix potential UID/GID ownership issues in LXC containers
        # This can happen if container was converted from unprivileged to privileged
        echo "Fixing file ownership for LXC container..."
        lxc_exec_live "$vmid" "chown -R root:root /etc /usr /var /lib 2>/dev/null || true"
        lxc_exec_live "$vmid" "chmod 4755 /usr/bin/sudo /usr/bin/passwd 2>/dev/null || true"

        # Create Docker systemd override for LXC containers
        # Note: --security-opt is NOT a valid dockerd flag, it's for docker run
        echo "Configuring Docker for LXC environment..."
        lxc_exec "$vmid" "mkdir -p /etc/systemd/system/docker.service.d"
        lxc_exec_live "$vmid" 'cat > /etc/systemd/system/docker.service.d/lxc-override.conf << EOF
[Service]
# Override for Docker in LXC containers
ExecStart=
ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
EOF'
        lxc_exec_live "$vmid" "systemctl daemon-reload"
        echo ""

        echo "Starting Docker service..."
        case "$os_type" in
            debian|ubuntu|centos|rhel|rocky|almalinux|fedora)
                lxc_exec_live "$vmid" "systemctl enable docker && systemctl start docker"
                ;;
            alpine)
                lxc_exec_live "$vmid" "service docker start"
                ;;
        esac
        echo ""

        echo "Waiting for Docker to start..."
        sleep 3

        echo ""
        echo "=== Verifying Docker Installation ==="
        lxc_exec_live "$vmid" "docker --version"
        lxc_exec_live "$vmid" "docker compose version"
        echo ""

        echo "Testing Docker with hello-world..."
        lxc_exec_live "$vmid" "docker run --rm --security-opt apparmor=unconfined hello-world"
        echo ""

        echo "=== Docker Installation Complete ==="

    ) 2>&1 | show_progress_box "Installing Docker in Container $vmid" 24 80
}

# Docker Setup Menu
docker_setup_menu() {
    while true; do
        if [[ -z "$CURRENT_PVE" ]]; then
            show_msg "Not Connected" "Please connect to a PVE server first."
            return
        fi

        local choice
        choice=$(show_menu "Docker Setup" "Select an operation:" \
            "1" "Install Docker in container" \
            "2" "Install Docker in multiple containers" \
            "3" "Check Docker status" \
            "4" "Test Docker installation" \
            "5" "Check/fix container features" \
            "0" "Back to main menu")

        case "$choice" in
            1)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                # Filter running containers
                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    [[ "$status" != "running" ]] && continue
                    ct_array+=("$vmid" "$name")
                done <<< "$containers"

                if [[ ${#ct_array[@]} -eq 0 ]]; then
                    show_msg "No Running Containers" "No running containers found. Please start a container first."
                    continue
                fi

                local selected
                selected=$(show_menu "Select Container" "Choose container for Docker installation:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    # Check container features first
                    show_info "Checking..." "Checking container configuration..."
                    local missing_features
                    missing_features=$(get_missing_docker_features "$selected")

                    if [[ -n "$missing_features" ]]; then
                        if show_yesno "Container Configuration" "Container $selected is missing required features for Docker:\n  - $missing_features\n\nThese features (nesting, keyctl) are required for Docker.\n\nDo you want to enable them now?\n(Container will be restarted)"; then
                            # Apply features with progress display
                            (
                                echo "Configuring container $selected for Docker..."
                                echo ""
                                echo "Stopping container (timeout 15s)..."
                                pve_exec "pct shutdown $selected --timeout 12" 2>&1 || {
                                    echo "Graceful shutdown failed, forcing stop..."
                                    pve_exec "pct stop $selected" 2>&1 || true
                                }

                                echo ""
                                echo "Enabling features (nesting=1, keyctl=1)..."
                                enable_docker_features "$selected" || {
                                    echo "WARNING: Failed to enable features"
                                }

                                echo "Starting container (timeout 30s)..."
                                pve_exec "timeout 30 pct start $selected" 2>&1 || {
                                    echo "Start timed out or failed"
                                }

                                echo "Waiting for container to be ready..."
                                ready_attempts=0
                                while [[ $ready_attempts -lt 15 ]]; do
                                    if lxc_exec_timeout "$selected" 3 "true" 2>/dev/null; then
                                        echo "Container is ready."
                                        break
                                    fi
                                    ready_attempts=$((ready_attempts + 1))
                                    echo "  Waiting... ($ready_attempts/15)"
                                    sleep 1
                                done

                                echo ""
                                echo "=== Container configured ==="
                            ) 2>&1 | show_progress_box "Enabling Docker Features"

                            show_msg "Features Enabled" "Container features have been updated.\n\nEnabled: nesting=1, keyctl=1"
                        else
                            show_msg "Warning" "Docker installation may fail without proper container features.\n\nYou can manually enable them in:\nPVE Web UI → Container → Options → Features"
                        fi
                    fi

                    show_info "Detecting OS..." "Detecting container OS..."
                    local os_type
                    os_type=$(detect_container_os "$selected")

                    if [[ -z "$os_type" ]]; then
                        show_msg "Error" "Could not detect container OS.\n\nMake sure the container is running."
                        continue
                    fi

                    if show_yesno "Install Docker" "Detected OS: $os_type\n\nInstall Docker in container $selected?"; then
                        docker_install_with_progress "$selected" "$os_type"
                    fi
                fi
                ;;
            2)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    [[ "$status" != "running" ]] && continue
                    ct_array+=("$vmid" "$name" "off")
                done <<< "$containers"

                if [[ ${#ct_array[@]} -eq 0 ]]; then
                    show_msg "No Running Containers" "No running containers found."
                    continue
                fi

                local selected
                selected=$(show_checklist "Select Containers" "Choose containers for Docker installation:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    selected=${selected//\"/}

                    for vmid in $selected; do
                        local os_type
                        os_type=$(detect_container_os "$vmid")

                        if [[ -n "$os_type" ]]; then
                            docker_install_with_progress "$vmid" "$os_type"
                        fi
                    done
                    show_msg "Done" "Docker installation completed for selected containers."
                fi
                ;;
            3)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                show_info "Checking..." "Checking Docker status in all containers..."

                local status_report=""
                local installed_count=0
                local total_count=0

                while IFS= read -r line || [[ -n "$line" ]]; do
                    [[ -z "$line" ]] && continue
                    local vmid status name docker_ver
                    vmid=$(echo "$line" | awk '{print $1}')
                    status=$(echo "$line" | awk '{print $2}')
                    name=$(echo "$line" | awk '{print $NF}')

                    [[ -z "$vmid" ]] && continue
                    ((total_count++))

                    if [[ "$status" != "running" ]]; then
                        status_report+="$vmid ($name): NOT RUNNING\n"
                    else
                        # Use timeout to prevent hanging
                        docker_ver=$(lxc_exec_timeout "$vmid" 5 "docker --version 2>/dev/null" 2>/dev/null)
                        if [[ -n "$docker_ver" ]]; then
                            status_report+="$vmid ($name): $docker_ver\n"
                            ((installed_count++))
                        else
                            status_report+="$vmid ($name): NOT INSTALLED\n"
                        fi
                    fi
                done <<< "$containers"

                local summary="Docker installed: $installed_count / $total_count containers\n\n"
                show_msg "Docker Status Report" "${summary}${status_report}"
                ;;
            4)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    [[ "$status" != "running" ]] && continue
                    ct_array+=("$vmid" "$name")
                done <<< "$containers"

                local selected
                selected=$(show_menu "Test Docker" "Select container to test:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    show_info "Testing..." "Running Docker hello-world test..."

                    # Run the test and capture output
                    local test_output
                    local test_result
                    test_output=$(lxc_exec_timeout "$selected" 60 "docker run --rm --security-opt apparmor=unconfined hello-world" 2>&1)
                    test_result=$?

                    # Check if successful
                    if [[ $test_result -eq 0 ]] && echo "$test_output" | grep -q "Hello from Docker"; then
                        show_msg "Docker Test - SUCCESS" "Docker is working correctly in container $selected!\n\n--- Output ---\n$(echo "$test_output" | head -15)"
                    else
                        # Determine the error
                        local error_msg="Docker test failed in container $selected.\n\n"

                        if [[ $test_result -eq 124 ]]; then
                            error_msg+="Error: Command timed out (60s)\n"
                        elif echo "$test_output" | grep -q "command not found"; then
                            error_msg+="Error: Docker is not installed\n"
                        elif echo "$test_output" | grep -q "Cannot connect to the Docker daemon"; then
                            error_msg+="Error: Docker daemon is not running\n\nTry: systemctl start docker"
                        elif echo "$test_output" | grep -q "permission denied"; then
                            error_msg+="Error: Permission denied\n\nTry: Use 'Check/fix container features' option to configure Docker requirements.\nIf already done, reinstall Docker to apply new settings."
                        else
                            error_msg+="Error: Unknown error\n"
                        fi

                        error_msg+="\n--- Output ---\n$(echo "$test_output" | tail -10)"
                        show_msg "Docker Test - FAILED" "$error_msg"
                    fi
                fi
                ;;
            5)
                # Check and fix container features for Docker
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                (
                    echo "Container Docker Feature Check"
                    echo "==============================="
                    echo ""
                    echo "Required for Docker in LXC:"
                    echo "  - nesting=1, keyctl=1 (container features)"
                    echo "  - lxc.apparmor.profile: unconfined"
                    echo "  - lxc.cgroup2.devices.allow: a"
                    echo ""

                    while read -r vmid status _ name; do
                        [[ -z "$vmid" ]] && continue
                        echo -n "Container $vmid ($name): "

                        missing=$(get_missing_docker_features "$vmid")
                        if [[ -z "$missing" ]]; then
                            echo "OK"
                        else
                            echo "NEEDS: $missing"
                        fi
                    done <<< "$containers"
                    echo ""
                    echo "=== Check complete ==="
                ) 2>&1 | show_progress_box "Docker Features Check" 20 76

                # Always offer to fix/apply Docker configuration
                if show_yesno "Apply Docker Config" "Apply Docker-compatible configuration to containers?\n\nThis will:\n- Enable nesting and keyctl features\n- Set AppArmor to unconfined\n- Allow cgroup device access\n\n(Containers will need to be restarted)"; then
                    local ct_array=()
                    while read -r vmid status _ name; do
                        [[ -z "$vmid" ]] && continue
                        missing=$(get_missing_docker_features "$vmid")
                        if [[ -n "$missing" ]]; then
                            ct_array+=("$vmid" "$name (needs: $missing)" "on")
                        else
                            ct_array+=("$vmid" "$name (OK)" "off")
                        fi
                    done <<< "$containers"

                    if [[ ${#ct_array[@]} -eq 0 ]]; then
                        show_msg "No Containers" "No containers found."
                    else
                        local selected
                        selected=$(show_checklist "Select Containers" "Choose containers to configure:" "${ct_array[@]}")

                        if [[ -n "$selected" ]]; then
                            selected=${selected//\"/}

                            (
                                echo "Enabling Docker features..."
                                echo ""

                                for vmid in $selected; do
                                    status=$(pve_container_status "$vmid")

                                    echo "Container $vmid:"
                                    if [[ "$status" == "running" ]]; then
                                        echo "  Stopping container (timeout 15s)..."
                                        pve_exec "pct shutdown $vmid --timeout 12" 2>&1 || {
                                            echo "  Graceful shutdown failed, forcing stop..."
                                            pve_exec "pct stop $vmid" 2>&1 || true
                                        }
                                    fi

                                    echo "  Enabling features (nesting, keyctl)..."
                                    enable_docker_features "$vmid" || {
                                        echo "  WARNING: Failed to enable features for $vmid"
                                    }

                                    if [[ "$status" == "running" ]]; then
                                        echo "  Starting container (timeout 30s)..."
                                        pve_exec "timeout 30 pct start $vmid" 2>&1 || {
                                            echo "  Start timed out or failed"
                                        }
                                        echo "  Waiting for container to be ready..."
                                        ready_attempts=0
                                        while [[ $ready_attempts -lt 15 ]]; do
                                            if lxc_exec_timeout "$vmid" 3 "true" 2>/dev/null; then
                                                break
                                            fi
                                            ready_attempts=$((ready_attempts + 1))
                                            sleep 1
                                        done
                                    fi
                                    echo "  Done."
                                    echo ""
                                done

                                echo "=== Features enabled ==="
                            ) 2>&1 | show_progress_box "Enabling Docker Features"
                        fi
                    fi
                fi
                ;;
            0|"")
                break
                ;;
        esac
    done
}

#######################################
# SSH KEY MANAGEMENT FUNCTIONS
#######################################

# Generate SSH keypair
ssh_generate_key() {
    local key_type="${SSH_KEY_TYPE:-ed25519}"
    local key_file="$SSH_DIR/id_${key_type}"

    if [[ -f "$key_file" ]]; then
        log_info "SSH key already exists: $key_file"
        return 0
    fi

    log_info "Generating SSH keypair (type: $key_type)"
    log_ssh_op "GENERATE_KEYPAIR" "type=$key_type file=$key_file"
    ssh-keygen -t "$key_type" -f "$key_file" -N "" -C "pve-manager@$(hostname)"
    chmod 600 "$key_file"
    chmod 644 "${key_file}.pub"

    return $?
}

# Get public key
ssh_get_pubkey() {
    local key_type="${SSH_KEY_TYPE:-ed25519}"
    local key_file="$SSH_DIR/id_${key_type}.pub"

    if [[ -f "$key_file" ]]; then
        cat "$key_file"
    fi
}

# Copy SSH key to container
ssh_copy_to_container() {
    local vmid="$1"
    local pubkey
    pubkey=$(ssh_get_pubkey)

    if [[ -z "$pubkey" ]]; then
        log_error "No public key available"
        return 1
    fi

    log_info "Copying SSH key to container $vmid"
    log_ssh_op "COPY_KEY" "vmid=$vmid"

    # Create .ssh directory and add key
    lxc_exec "$vmid" "mkdir -p /root/.ssh && chmod 700 /root/.ssh"
    lxc_exec "$vmid" "echo '$pubkey' >> /root/.ssh/authorized_keys"
    lxc_exec "$vmid" "chmod 600 /root/.ssh/authorized_keys"

    return $?
}

# Test SSH to container
ssh_test_container() {
    local vmid="$1"

    # Get container IP (with timeout)
    local ip
    ip=$(get_container_ip "$vmid")

    if [[ -z "$ip" ]]; then
        log_error "Could not get container IP"
        return 1
    fi

    local key_type="${SSH_KEY_TYPE:-ed25519}"
    local key_file="$SSH_DIR/id_${key_type}"

    # Test connection with timeout
    # Note: < /dev/null prevents ssh from consuming stdin (important when called in while loops)
    timeout 5 ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no \
        -i "$key_file" "root@${ip}" "echo ok" < /dev/null &>/dev/null
    return $?
}

# Get container IP (with timeout to prevent hanging)
get_container_ip() {
    local vmid="$1"
    lxc_exec_timeout "$vmid" 5 "hostname -I 2>/dev/null | awk '{print \$1}'" 2>/dev/null
}

# Install/enable an SSH server in a container and permit root login.
# auth_mode: key (default) | password | both
# pwfile: optional path; when password/both generates a password, it is
# written there (0600) instead of stdout, since stdout is routinely teed to
# OPERATIONS_LOG by show_progress_box and must never carry a plaintext secret.
lxc_enable_root_ssh() {
    local vmid="$1"
    local auth_mode="${2:-key}"
    local pwfile="${3:-}"
    case "$auth_mode" in
        key|password|both) ;;
        *) auth_mode="key" ;;
    esac

    log_ssh_op "ENABLE_ROOT_SSH" "vmid=$vmid mode=$auth_mode"

    local os_type
    os_type=$(detect_container_os "$vmid")
    echo "Detected OS: ${os_type:-unknown}"

    echo "Checking for SSH server..."
    if ! lxc_exec "$vmid" "command -v sshd" &>/dev/null; then
        echo "Installing SSH server..."
        case "$os_type" in
            debian|ubuntu)
                lxc_exec_live "$vmid" "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server"
                ;;
            alpine)
                lxc_exec_live "$vmid" "apk update && apk add openssh"
                ;;
            centos|rhel|rocky|almalinux|fedora)
                lxc_exec_live "$vmid" "dnf install -y openssh-server"
                ;;
            *)
                echo "ERROR: Unsupported or undetected OS ('$os_type'); install an SSH server manually."
                return 1
                ;;
        esac
    else
        echo "SSH server already installed."
    fi

    if ! lxc_exec "$vmid" "command -v sshd" &>/dev/null; then
        echo "ERROR: sshd still not found after install attempt."
        return 1
    fi

    echo "Configuring sshd (PermitRootLogin)..."
    local permit_root="prohibit-password"
    [[ "$auth_mode" == "password" || "$auth_mode" == "both" ]] && permit_root="yes"

    # Edit the main config...
    lxc_exec "$vmid" "sed -i -E 's/^[# ]*PermitRootLogin[[:space:]].*/PermitRootLogin $permit_root/' /etc/ssh/sshd_config"
    lxc_exec "$vmid" "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin $permit_root' >> /etc/ssh/sshd_config"
    # ...and also drop a high-precedence snippet, since distros (e.g. Ubuntu
    # cloud images) ship an Include'd sshd_config.d/*.conf that would otherwise
    # win over the edit above.
    lxc_exec "$vmid" "[[ -d /etc/ssh/sshd_config.d ]] && printf 'PermitRootLogin %s\n' '$permit_root' > /etc/ssh/sshd_config.d/00-pve-manager-root-ssh.conf; true"

    if [[ "$auth_mode" == "key" || "$auth_mode" == "both" ]]; then
        echo "Setting up key-based access..."
        local key_file="$SSH_DIR/id_${SSH_KEY_TYPE:-ed25519}"
        [[ -f "$key_file" ]] || ssh_generate_key
        ssh_copy_to_container "$vmid"
    fi

    local generated_password=""
    if [[ "$auth_mode" == "password" || "$auth_mode" == "both" ]]; then
        echo "Setting root password..."
        generated_password=$(openssl rand -base64 16)
        lxc_exec "$vmid" "echo 'root:${generated_password}' | chpasswd"
        if [[ -n "$pwfile" ]]; then
            (umask 077; printf '%s' "$generated_password" > "$pwfile")
        fi
        log_ssh_op "SET_ROOT_PASSWORD" "vmid=$vmid"
    fi

    echo "Enabling and starting SSH service..."
    case "$os_type" in
        alpine)
            lxc_exec "$vmid" "rc-update add sshd default 2>/dev/null; rc-service sshd restart 2>/dev/null || rc-service sshd start 2>/dev/null"
            ;;
        debian|ubuntu)
            lxc_exec "$vmid" "systemctl enable ssh 2>/dev/null; systemctl restart ssh 2>/dev/null || systemctl start ssh 2>/dev/null"
            ;;
        *)
            lxc_exec "$vmid" "systemctl enable sshd 2>/dev/null; systemctl restart sshd 2>/dev/null || systemctl start sshd 2>/dev/null"
            ;;
    esac

    echo "Opening firewall (if active)..."
    lxc_exec "$vmid" "command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q 'Status: active' && ufw allow 22/tcp 2>/dev/null; command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null && firewall-cmd --permanent --add-service=ssh 2>/dev/null && firewall-cmd --reload 2>/dev/null; true"

    local ip
    ip=$(get_container_ip "$vmid")

    echo ""
    echo "=== Root SSH enabled on container $vmid ==="
    echo "IP address: ${ip:-unknown}"
    echo "Auth mode:  $auth_mode"
    if [[ "$auth_mode" == "key" || "$auth_mode" == "both" ]]; then
        echo "Connect with: ssh -i $SSH_DIR/id_${SSH_KEY_TYPE:-ed25519} root@${ip:-<ip>}"
    fi
    if [[ -n "$generated_password" ]]; then
        echo "Root password generated (not shown here; see the dialog that follows)."
    fi

    return 0
}

# SSH Management Menu
ssh_management_menu() {
    while true; do
        if [[ -z "$CURRENT_PVE" ]]; then
            show_msg "Not Connected" "Please connect to a PVE server first."
            return
        fi

        local key_status="Not generated"
        local key_type="${SSH_KEY_TYPE:-ed25519}"
        local key_file="$SSH_DIR/id_${key_type}"
        [[ -f "$key_file" ]] && key_status="Generated ($key_file)"

        local choice
        choice=$(show_menu "SSH Key Management" "Key status: $key_status\n\nSelect an operation:" \
            "1" "Generate SSH keypair" \
            "2" "View public key" \
            "3" "Distribute key to container" \
            "4" "Distribute key to all containers" \
            "5" "Test SSH connectivity" \
            "6" "Setup inter-container SSH" \
            "7" "Enable root SSH on container" \
            "8" "Enable root SSH on all containers" \
            "0" "Back to main menu")

        case "$choice" in
            1)
                if [[ -f "$key_file" ]]; then
                    if ! show_yesno "Key Exists" "SSH key already exists. Generate new key?\n\nWARNING: This will overwrite the existing key!"; then
                        continue
                    fi
                    rm -f "$key_file" "${key_file}.pub"
                fi

                (
                    echo "Generating SSH keypair..."
                    echo "Type: $key_type"
                    echo ""
                    ssh_generate_key
                    echo ""
                    echo "Key generated successfully!"
                    echo ""
                    echo "Public key:"
                    cat "${key_file}.pub"
                ) | show_progress_box "Generate SSH Key"
                ;;
            2)
                local pubkey
                pubkey=$(ssh_get_pubkey)
                if [[ -n "$pubkey" ]]; then
                    show_scrollmsg "Public Key" "$pubkey"
                else
                    show_msg "No Key" "No SSH key found. Please generate one first."
                fi
                ;;
            3)
                if [[ ! -f "$key_file" ]]; then
                    show_msg "No Key" "No SSH key found. Please generate one first."
                    continue
                fi

                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    [[ "$status" != "running" ]] && continue
                    ct_array+=("$vmid" "$name")
                done <<< "$containers"

                if [[ ${#ct_array[@]} -eq 0 ]]; then
                    show_msg "No Running Containers" "No running containers found."
                    continue
                fi

                local selected
                selected=$(show_menu "Select Container" "Choose container:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    (
                        echo "Copying SSH key to container $selected..."
                        ssh_copy_to_container "$selected"
                        echo ""
                        echo "SSH key copied successfully!"
                    ) | show_progress_box "Copy SSH Key"
                fi
                ;;
            4)
                if [[ ! -f "$key_file" ]]; then
                    show_msg "No Key" "No SSH key found. Please generate one first."
                    continue
                fi

                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                if show_yesno "Confirm" "Copy SSH key to all running containers?"; then
                    (
                        echo "Distributing SSH key to all containers..."
                        echo ""
                        count=0
                        while read -r vmid status _ name; do
                            [[ -z "$vmid" ]] && continue
                            [[ "$status" != "running" ]] && continue

                            echo "Copying key to $vmid ($name)..."
                            ssh_copy_to_container "$vmid" && ((count++))
                        done <<< "$containers"
                        echo ""
                        echo "SSH key copied to $count containers."
                    ) 2>&1 | show_progress_box "Distribute SSH Keys"
                fi
                ;;
            5)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                # Show info that test is starting
                show_info "SSH Test" "Testing SSH connectivity to all containers...\nThis may take a moment."

                # Build results directly without subshell pipe
                local results=""
                local container_count=0
                local ok_count=0
                local fail_count=0

                while IFS= read -r line || [[ -n "$line" ]]; do
                    [[ -z "$line" ]] && continue
                    # Parse: VMID STATUS [LOCK] NAME
                    local vmid status name ip
                    vmid=$(echo "$line" | awk '{print $1}')
                    status=$(echo "$line" | awk '{print $2}')
                    name=$(echo "$line" | awk '{print $NF}')

                    [[ -z "$vmid" ]] && continue
                    ((container_count++))

                    if [[ "$status" != "running" ]]; then
                        results+="$vmid ($name): NOT RUNNING\n"
                        ((fail_count++))
                    else
                        ip=$(get_container_ip "$vmid")
                        if [[ -z "$ip" ]]; then
                            results+="$vmid ($name): NO IP\n"
                            ((fail_count++))
                        elif ssh_test_container "$vmid"; then
                            results+="$vmid ($name): OK ($ip)\n"
                            ((ok_count++))
                        else
                            results+="$vmid ($name): FAILED ($ip)\n"
                            ((fail_count++))
                        fi
                    fi
                done <<< "$containers"

                # Show results
                local summary="Tested: $container_count | OK: $ok_count | Failed: $fail_count\n\n"
                show_msg "SSH Connectivity Results" "${summary}${results}"
                ;;
            6)
                if [[ ! -f "$key_file" ]]; then
                    show_msg "No Key" "No SSH key found. Please generate one first."
                    continue
                fi

                if show_yesno "Setup Inter-Container SSH" "This will:\n1. Copy the private key to all containers\n2. Add public key to all containers\n3. Setup known_hosts\n\nProceed?"; then
                    local containers
                    containers=$(pve_list_containers)

                    local privkey
                    privkey=$(cat "$key_file")
                    local pubkey
                    pubkey=$(cat "${key_file}.pub")

                    (
                        echo "Setting up inter-container SSH..."
                        echo ""

                        # Collect IPs first
                        declare -A container_ips
                        echo "Collecting container IPs..."
                        while read -r vmid status _ name; do
                            [[ -z "$vmid" ]] && continue
                            [[ "$status" != "running" ]] && continue
                            container_ips[$vmid]=$(get_container_ip "$vmid")
                            echo "  $vmid: ${container_ips[$vmid]}"
                        done <<< "$containers"
                        echo ""

                        # Setup each container
                        while read -r vmid status _ name; do
                            [[ -z "$vmid" ]] && continue
                            [[ "$status" != "running" ]] && continue

                            echo "Configuring container $vmid ($name)..."

                            # Setup .ssh directory
                            lxc_exec "$vmid" "mkdir -p /root/.ssh && chmod 700 /root/.ssh"

                            # Copy private key
                            lxc_exec "$vmid" "cat > /root/.ssh/id_${key_type} << 'KEYEOF'
$privkey
KEYEOF"
                            lxc_exec "$vmid" "chmod 600 /root/.ssh/id_${key_type}"

                            # Add public key
                            lxc_exec "$vmid" "echo '$pubkey' >> /root/.ssh/authorized_keys"
                            lxc_exec "$vmid" "chmod 600 /root/.ssh/authorized_keys"

                            # Add other containers to known_hosts
                            for other_vmid in "${!container_ips[@]}"; do
                                other_ip="${container_ips[$other_vmid]}"
                                [[ -z "$other_ip" ]] && continue
                                lxc_exec "$vmid" "ssh-keyscan -H $other_ip >> /root/.ssh/known_hosts 2>/dev/null" &>/dev/null
                            done

                            echo "  Done."
                        done <<< "$containers"

                        echo ""
                        echo "=== Inter-container SSH setup complete ==="

                    ) 2>&1 | show_progress_box "Setup Inter-Container SSH" 24 76
                fi
                ;;
            7)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    [[ "$status" != "running" ]] && continue
                    ct_array+=("$vmid" "$name")
                done <<< "$containers"

                if [[ ${#ct_array[@]} -eq 0 ]]; then
                    show_msg "No Running Containers" "No running containers found."
                    continue
                fi

                local selected
                selected=$(show_menu "Select Container" "Choose container to enable root SSH on:" "${ct_array[@]}")
                [[ -z "$selected" ]] && continue

                local mode
                mode=$(show_menu "Root SSH Auth Mode" "How should root authenticate over SSH?" \
                    "key" "SSH key only (recommended)" \
                    "password" "Password only (auto-generated)" \
                    "both" "SSH key + password")
                [[ -z "$mode" ]] && continue

                if [[ "$mode" != "key" ]]; then
                    if ! show_yesno "Confirm Password Auth" "This allows root to log in to container $selected with a password over SSH.\n\nA random password will be generated and shown once. Proceed?"; then
                        continue
                    fi
                fi

                local outfile="/tmp/pve-manager-ssh-enable-$$.log"
                local pwfile; pwfile=$(mktemp); chmod 600 "$pwfile"
                (lxc_enable_root_ssh "$selected" "$mode" "$pwfile") 2>&1 | tee "$outfile" | show_progress_box "Enable Root SSH: $selected" 24 76

                local ip_line password_line
                ip_line=$(grep '^IP address:' "$outfile" | tail -1 | sed 's/^IP address: //')
                password_line=$(cat "$pwfile" 2>/dev/null)
                rm -f "$outfile" "$pwfile"

                local summary="Container: $selected\nAuth mode: $mode\nIP: ${ip_line:-unknown}"
                [[ "$mode" != "password" ]] && summary+="\n\nConnect: ssh -i $SSH_DIR/id_${SSH_KEY_TYPE:-ed25519} root@${ip_line:-<ip>}"
                [[ -n "$password_line" ]] && summary+="\n\nRoot password (shown once, save it now):\n$password_line"
                show_msg "Root SSH Enabled" "$summary"
                ;;
            8)
                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local mode
                mode=$(show_menu "Root SSH Auth Mode" "How should root authenticate over SSH on ALL running containers?" \
                    "key" "SSH key only (recommended)" \
                    "password" "Password only (auto-generated per container)" \
                    "both" "SSH key + password")
                [[ -z "$mode" ]] && continue

                local confirm_text="Enable root SSH (mode: $mode) on all running containers?"
                [[ "$mode" != "key" ]] && confirm_text="This allows root to log in with a password on ALL running containers.\n\nA unique random password will be generated per container and shown once.\n\nProceed?"
                if ! show_yesno "Confirm" "$confirm_text"; then
                    continue
                fi

                local results="" ok_count=0 fail_count=0
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    [[ "$status" != "running" ]] && continue

                    show_info "Enabling Root SSH" "Processing container $vmid ($name)..."

                    local out ip_line password_line pwfile
                    pwfile=$(mktemp); chmod 600 "$pwfile"
                    out=$(lxc_enable_root_ssh "$vmid" "$mode" "$pwfile" 2>&1)
                    if [[ $? -eq 0 ]]; then
                        ip_line=$(echo "$out" | grep '^IP address:' | tail -1 | sed 's/^IP address: //')
                        password_line=$(cat "$pwfile" 2>/dev/null)
                        results+="$vmid ($name): OK, IP ${ip_line:-unknown}"
                        [[ -n "$password_line" ]] && results+=", password: $password_line"
                        results+=$'\n'
                        ((ok_count++))
                    else
                        results+="$vmid ($name): FAILED"$'\n'
                        ((fail_count++))
                    fi
                    rm -f "$pwfile"
                done <<< "$containers"

                show_scrollmsg "Root SSH - All Containers" "Enabled: $ok_count | Failed: $fail_count

$results"
                ;;
            0|"")
                break
                ;;
        esac
    done
}

#######################################
# USER MANAGEMENT FUNCTIONS
#######################################

# Create a user inside a guest (LXC container or VM), optionally granted
# sudo/wheel membership and SSH key access. Dispatches through exec_fn/
# exec_live_fn/os_fn (names of the lxc_*/vm_* primitives) so the same logic
# serves both guest types instead of duplicating it per guest kind.
# enable_sudo/enable_ssh: "1" to enable, anything else to skip.
# pwfile: optional path; the generated password is written there (0600)
# instead of stdout, since stdout is routinely teed to OPERATIONS_LOG by
# show_progress_box and must never carry a plaintext secret.
guest_create_user() {
    local exec_fn="$1" exec_live_fn="$2" os_fn="$3"
    local vmid="$4" username="$5" enable_sudo="$6" enable_ssh="$7" pwfile="${8:-}"

    log_ssh_op "CREATE_USER" "vmid=$vmid user=$username sudo=$enable_sudo ssh=$enable_ssh"

    local os_type
    os_type=$("$os_fn" "$vmid")
    echo "Detected OS: ${os_type:-unknown}"

    if "$exec_fn" "$vmid" "id -u '$username'" &>/dev/null; then
        echo "ERROR: user '$username' already exists on this guest."
        return 1
    fi

    echo "Creating user '$username'..."
    if [[ "$os_type" == "alpine" ]]; then
        "$exec_fn" "$vmid" "adduser -D -s /bin/ash '$username'"
    else
        "$exec_fn" "$vmid" "useradd -m -s /bin/bash '$username'"
    fi

    if ! "$exec_fn" "$vmid" "id -u '$username'" &>/dev/null; then
        echo "ERROR: failed to create user '$username'."
        return 1
    fi

    local generated_password
    generated_password=$(openssl rand -base64 16)
    "$exec_fn" "$vmid" "echo '${username}:${generated_password}' | chpasswd"
    [[ -n "$pwfile" ]] && (umask 077; printf '%s' "$generated_password" > "$pwfile")

    if [[ "$enable_sudo" == "1" ]]; then
        echo "Granting sudo privileges..."
        if ! "$exec_fn" "$vmid" "command -v sudo" &>/dev/null; then
            echo "Installing sudo..."
            case "$os_type" in
                debian|ubuntu)
                    "$exec_live_fn" "$vmid" "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y sudo"
                    ;;
                alpine)
                    "$exec_live_fn" "$vmid" "apk update && apk add sudo"
                    ;;
                centos|rhel|rocky|almalinux|fedora)
                    "$exec_live_fn" "$vmid" "dnf install -y sudo"
                    ;;
                *)
                    echo "WARNING: unknown OS ('$os_type'); skipping sudo install, assuming it is already present."
                    ;;
            esac
        fi

        local sudo_group="wheel"
        "$exec_fn" "$vmid" "getent group sudo" &>/dev/null && sudo_group="sudo"
        "$exec_fn" "$vmid" "usermod -aG $sudo_group '$username'"
    fi

    if [[ "$enable_ssh" == "1" ]]; then
        echo "Enabling SSH access for '$username'..."
        if ! "$exec_fn" "$vmid" "command -v sshd" &>/dev/null; then
            echo "Installing SSH server..."
            case "$os_type" in
                debian|ubuntu)
                    "$exec_live_fn" "$vmid" "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server"
                    ;;
                alpine)
                    "$exec_live_fn" "$vmid" "apk update && apk add openssh"
                    ;;
                centos|rhel|rocky|almalinux|fedora)
                    "$exec_live_fn" "$vmid" "dnf install -y openssh-server"
                    ;;
                *)
                    echo "ERROR: Unsupported or undetected OS ('$os_type'); install an SSH server manually."
                    ;;
            esac
        fi

        local pubkey
        pubkey=$(ssh_get_pubkey)
        if [[ -z "$pubkey" ]]; then
            ssh_generate_key
            pubkey=$(ssh_get_pubkey)
        fi

        local home_dir="/home/${username}"
        "$exec_fn" "$vmid" "mkdir -p '$home_dir/.ssh' && chmod 700 '$home_dir/.ssh'"
        "$exec_fn" "$vmid" "echo '$pubkey' >> '$home_dir/.ssh/authorized_keys'"
        "$exec_fn" "$vmid" "chmod 600 '$home_dir/.ssh/authorized_keys'"
        "$exec_fn" "$vmid" "chown -R '${username}:${username}' '$home_dir/.ssh'"

        case "$os_type" in
            alpine)
                "$exec_fn" "$vmid" "rc-update add sshd default 2>/dev/null; rc-service sshd restart 2>/dev/null || rc-service sshd start 2>/dev/null"
                ;;
            debian|ubuntu)
                "$exec_fn" "$vmid" "systemctl enable ssh 2>/dev/null; systemctl restart ssh 2>/dev/null || systemctl start ssh 2>/dev/null"
                ;;
            *)
                "$exec_fn" "$vmid" "systemctl enable sshd 2>/dev/null; systemctl restart sshd 2>/dev/null || systemctl start sshd 2>/dev/null"
                ;;
        esac
    fi

    echo ""
    echo "=== User '$username' created on guest $vmid ==="
    [[ "$enable_sudo" == "1" ]] && echo "Sudo: yes ($sudo_group)" || echo "Sudo: no"
    [[ "$enable_ssh" == "1" ]] && echo "SSH key access: yes (pve-manager key)" || echo "SSH key access: no"
    echo "Password generated (not shown here; see the dialog that follows)."

    return 0
}

# Wizard: create a user inside an LXC container
lxc_create_user_wizard() {
    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local ct_array=()
    while read -r vmid status _ name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        ct_array+=("$vmid" "$name")
    done <<< "$containers"

    if [[ ${#ct_array[@]} -eq 0 ]]; then
        show_msg "No Running Containers" "No running containers found."
        return
    fi

    local selected
    selected=$(show_menu "Select Container" "Create a user in which container?" "${ct_array[@]}")
    [[ -z "$selected" ]] && return

    guest_create_user_wizard_common "$selected" lxc_exec lxc_exec_live detect_container_os
}

# Wizard: create a user inside a VM (requires QEMU Guest Agent)
vm_create_user_wizard() {
    local vms
    vms=$(pve_list_vms)
    if [[ -z "$vms" ]]; then
        show_msg "No VMs" "No virtual machines found."
        return
    fi

    local vm_array=()
    while read -r vmid status _ name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        vm_array+=("$vmid" "$name")
    done <<< "$vms"

    if [[ ${#vm_array[@]} -eq 0 ]]; then
        show_msg "No Running VMs" "No running VMs found."
        return
    fi

    local selected
    selected=$(show_menu "Select VM" "Create a user in which VM?" "${vm_array[@]}")
    [[ -z "$selected" ]] && return

    if ! vm_has_guest_agent "$selected"; then
        show_msg "Guest Agent Required" "QEMU Guest Agent is not available on VM $selected."
        return
    fi

    guest_create_user_wizard_common "$selected" vm_exec vm_exec_live detect_vm_os
}

# Shared prompt/confirm/run/report flow for the two wizards above.
guest_create_user_wizard_common() {
    local vmid="$1" exec_fn="$2" exec_live_fn="$3" os_fn="$4"

    local username
    username=$(show_input "Create User" "Username to create on guest $vmid:" "")
    [[ -z "$username" ]] && return

    if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        show_msg "Invalid Username" "Use lowercase letters, digits, '-' or '_', starting with a letter or underscore."
        return
    fi

    local enable_sudo=0 enable_ssh=0
    show_yesno "Sudo Access" "Add '$username' to the sudo/wheel group?" && enable_sudo=1
    show_yesno "SSH Access" "Enable SSH key-based access for '$username'?\n(installs/enables sshd if needed, copies the pve-manager key)" && enable_ssh=1

    local outfile="/tmp/pve-manager-create-user-$$.log"
    local pwfile; pwfile=$(mktemp); chmod 600 "$pwfile"
    (guest_create_user "$exec_fn" "$exec_live_fn" "$os_fn" "$vmid" "$username" "$enable_sudo" "$enable_ssh" "$pwfile") \
        2>&1 | tee "$outfile" | show_progress_box "Create User: $username" 24 76

    local password_line
    password_line=$(cat "$pwfile" 2>/dev/null)
    rm -f "$outfile" "$pwfile"

    local summary="User: $username\nGuest: $vmid\nSudo: $([[ "$enable_sudo" == "1" ]] && echo yes || echo no)\nSSH key: $([[ "$enable_ssh" == "1" ]] && echo yes || echo no)"
    [[ -n "$password_line" ]] && summary+="\n\nPassword (shown once, save it now):\n$password_line"
    show_msg "User Created" "$summary"
}

#######################################
# CERTIFICATE AUTHORITY FUNCTIONS
#######################################

# Initialize Certificate Authority
ca_init() {
    local cn="${1:-PVE Manager CA}"
    local org="${2:-PVE Manager}"
    local ca_key="$CA_DIR/ca.key"
    local ca_crt="$CA_DIR/ca.crt"
    local ca_info="$CA_DIR/ca.info"
    local valid_days="${CA_VALID_DAYS:-3650}"

    if [[ -f "$ca_key" ]] && [[ -f "$ca_crt" ]]; then
        log_info "CA already exists"
        return 0
    fi

    log_info "Creating new Certificate Authority"
    log_info "  CN: $cn"
    log_info "  Organization: $org"
    log_cert_op "CREATE_CA" "cn=$cn org=$org valid_days=$valid_days"

    # Generate CA private key
    openssl genrsa -out "$ca_key" 4096 2>/dev/null
    chmod 600 "$ca_key"

    # Generate CA certificate
    openssl req -x509 -new -nodes -key "$ca_key" \
        -sha256 -days "$valid_days" \
        -out "$ca_crt" \
        -subj "/CN=${cn}/O=${org}/OU=Infrastructure"

    chmod 644 "$ca_crt"

    # Save CA info for reference (used by cert generation)
    cat > "$ca_info" << EOF
CA_CN="${cn}"
CA_ORG="${org}"
CA_CREATED="$(date -Iseconds)"
EOF
    chmod 644 "$ca_info"

    log_info "CA created successfully"
    return 0
}

# Generate certificate for container
ca_generate_cert() {
    local hostname="$1"
    local ip="$2"
    local cert_dir="$CERTS_DIR/$hostname"
    local valid_days="${CERT_VALID_DAYS:-365}"

    mkdir -p "$cert_dir"

    local ca_key="$CA_DIR/ca.key"
    local ca_crt="$CA_DIR/ca.crt"
    local ca_info="$CA_DIR/ca.info"
    local key_file="$cert_dir/${hostname}.key"
    local csr_file="$cert_dir/${hostname}.csr"
    local crt_file="$cert_dir/${hostname}.crt"
    local ext_file="$cert_dir/${hostname}.ext"

    # Get CA organization from saved info
    local ca_org="PVE Manager"
    if [[ -f "$ca_info" ]]; then
        source "$ca_info"
        ca_org="${CA_ORG:-PVE Manager}"
    fi

    log_info "Generating certificate for $hostname ($ip)"
    log_cert_op "GENERATE_CERT" "hostname=$hostname ip=$ip valid_days=$valid_days"

    # Generate private key
    openssl genrsa -out "$key_file" 2048 2>/dev/null
    chmod 600 "$key_file"

    # Create CSR
    openssl req -new -key "$key_file" -out "$csr_file" \
        -subj "/CN=${hostname}/O=${ca_org}"

    # Create extension file with SAN
    cat > "$ext_file" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${hostname}
DNS.2 = ${hostname}.local
IP.1 = ${ip}
EOF

    # Sign certificate
    openssl x509 -req -in "$csr_file" \
        -CA "$ca_crt" -CAkey "$ca_key" \
        -CAcreateserial \
        -out "$crt_file" \
        -days "$valid_days" \
        -sha256 \
        -extfile "$ext_file"

    chmod 644 "$crt_file"

    # Create combined PEM file
    cat "$crt_file" "$ca_crt" > "$cert_dir/${hostname}-chain.pem"

    log_info "Certificate generated: $crt_file"
    return 0
}

# Deploy certificate to container
ca_deploy_cert() {
    local vmid="$1"
    local hostname="$2"
    local cert_dir="$CERTS_DIR/$hostname"

    if [[ ! -d "$cert_dir" ]]; then
        log_error "Certificate directory not found: $cert_dir"
        return 1
    fi

    log_info "Deploying certificate to container $vmid"

    # Create directory in container
    lxc_exec "$vmid" "mkdir -p /etc/ssl/pve-manager"

    # Copy files
    local key_file="$cert_dir/${hostname}.key"
    local crt_file="$cert_dir/${hostname}.crt"
    local chain_file="$cert_dir/${hostname}-chain.pem"
    local ca_crt="$CA_DIR/ca.crt"

    # Use pct push if available, otherwise cat through exec
    if [[ "$IS_LOCAL_PVE" == true ]]; then
        pct push "$vmid" "$key_file" "/etc/ssl/pve-manager/${hostname}.key"
        pct push "$vmid" "$crt_file" "/etc/ssl/pve-manager/${hostname}.crt"
        pct push "$vmid" "$chain_file" "/etc/ssl/pve-manager/${hostname}-chain.pem"
        pct push "$vmid" "$ca_crt" "/etc/ssl/pve-manager/ca.crt"
    else
        # Remote: use base64 encoding
        local key_b64 crt_b64 chain_b64 ca_b64
        key_b64=$(base64 -w0 "$key_file")
        crt_b64=$(base64 -w0 "$crt_file")
        chain_b64=$(base64 -w0 "$chain_file")
        ca_b64=$(base64 -w0 "$ca_crt")

        lxc_exec "$vmid" "echo '$key_b64' | base64 -d > /etc/ssl/pve-manager/${hostname}.key"
        lxc_exec "$vmid" "echo '$crt_b64' | base64 -d > /etc/ssl/pve-manager/${hostname}.crt"
        lxc_exec "$vmid" "echo '$chain_b64' | base64 -d > /etc/ssl/pve-manager/${hostname}-chain.pem"
        lxc_exec "$vmid" "echo '$ca_b64' | base64 -d > /etc/ssl/pve-manager/ca.crt"
    fi

    # Set permissions
    lxc_exec "$vmid" "chmod 600 /etc/ssl/pve-manager/*.key"
    lxc_exec "$vmid" "chmod 644 /etc/ssl/pve-manager/*.crt /etc/ssl/pve-manager/*.pem"

    # Install CA cert to system trust store
    local os_type
    os_type=$(detect_container_os "$vmid")

    case "$os_type" in
        debian|ubuntu)
            lxc_exec "$vmid" "cp /etc/ssl/pve-manager/ca.crt /usr/local/share/ca-certificates/pve-manager-ca.crt"
            lxc_exec "$vmid" "update-ca-certificates"
            ;;
        alpine)
            lxc_exec "$vmid" "cp /etc/ssl/pve-manager/ca.crt /usr/local/share/ca-certificates/pve-manager-ca.crt"
            lxc_exec "$vmid" "update-ca-certificates"
            ;;
    esac

    log_info "Certificate deployed to container $vmid"
    return 0
}

# Verify certificate
ca_verify_cert() {
    local hostname="$1"
    local cert_dir="$CERTS_DIR/$hostname"
    local crt_file="$cert_dir/${hostname}.crt"
    local ca_crt="$CA_DIR/ca.crt"

    if [[ ! -f "$crt_file" ]]; then
        return 1
    fi

    openssl verify -CAfile "$ca_crt" "$crt_file" &>/dev/null
    return $?
}

#######################################
# ACME / CLOUDFLARE CERTIFICATES
#
# Issues a publicly-trusted wildcard certificate from an ACME CA (Let's Encrypt)
# using Cloudflare DNS-01 validation, then deploys it to LXC containers and VMs
# to replace self-signed certificates.
#
# Why a wildcard rather than one cert per guest:
#   - guests never need the Cloudflare token; only this host holds it
#   - one issuance covers every guest, so ACME rate limits are a non-issue
#   - renewal is a single operation plus a re-push to recorded targets
#
# Internal names live at <guest>.<ACME_SUBDOMAIN>.<ACME_DOMAIN> and must resolve
# to the guest's LAN IP via split-horizon DNS (e.g. AdGuard rewrites). DNS-01
# validates against the public zone, so nothing is exposed to the internet.
#######################################

# Issue a wildcard certificate via Cloudflare DNS-01.
#
# SAN construction is deliberate. Let's Encrypt REJECTS an order that contains
# both a wildcard and a name that wildcard already covers, with:
#   "Domain name X is redundant with a wildcard domain in the same request"
# So with ACME_SUBDOMAIN=lan and ACME_DOMAIN=example.com we request:
#   example.com, *.example.com, *.lan.example.com
# and must NOT add lan.example.com, which *.example.com already covers.
acme_build_san_args() {
    local domain="$1" sub="$2"
    local -a args=(-d "$domain" -d "*.$domain")
    if [[ -n "$sub" ]]; then
        args+=(-d "*.${sub}.${domain}")
    fi
    printf '%s\n' "${args[@]}"
}

# Fully-qualified internal name for a guest
acme_guest_fqdn() {
    local host="$1"
    local domain="${ACME_DOMAIN:-}" sub="${ACME_SUBDOMAIN:-}"
    [[ -z "$domain" ]] && return 1
    host="${host,,}"
    if [[ -n "$sub" ]]; then
        echo "${host}.${sub}.${domain}"
    else
        echo "${host}.${domain}"
    fi
}

#######################################
# Token storage
#######################################

# Persist the Cloudflare API token. Kept out of CONFIG_FILE so the token never
# lands in a file that might be shared, diffed, or backed up casually.
acme_save_token() {
    local token="$1"

    # Sanitise and validate before writing. The file is source'd, so anything
    # containing whitespace or a quote would break it in a way that fails
    # silently later (CF_Token ends up empty). This also catches a dialog
    # diagnostic being captured as the "password": whiptail writes its result
    # AND its error messages to stderr, so a box that is too small to render
    # returns its own error text as the value.
    token="${token//[$'\t\r\n']/}"
    token="${token#"${token%%[![:space:]]*}"}"   # ltrim
    token="${token%"${token##*[![:space:]]}"}"   # rtrim

    if [[ ! "$token" =~ ^[A-Za-z0-9_-]{20,200}$ ]]; then
        log_error "Refusing to save an implausible Cloudflare token"
        echo "That does not look like a Cloudflare API token."
        echo ""
        echo "Expected 20-200 characters of letters, digits, '-' or '_' only."
        echo "Got ${#token} character(s)."
        [[ "$token" == *"sub-window"* || "$token" == *"Can't"* ]] && \
            echo "" && echo "The terminal appears too small for the dialog: its error text was captured instead of your input. Enlarge the window and retry."
        return 1
    fi

    mkdir -p "$ACME_DIR"
    chmod 700 "$ACME_DIR"
    umask 077
    printf 'CF_Token=%s\n' "$token" > "$ACME_TOKEN_FILE"
    chmod 600 "$ACME_TOKEN_FILE"
    log_cert_op "ACME_TOKEN_SAVED" "file=$ACME_TOKEN_FILE len=${#token}"
    return 0
}

acme_load_token() {
    [[ -f "$ACME_TOKEN_FILE" ]] || return 1
    # shellcheck disable=SC1090
    source "$ACME_TOKEN_FILE"
    [[ -n "${CF_Token:-}" ]]
}

acme_have_token() { [[ -s "$ACME_TOKEN_FILE" ]]; }

# Validate the token against Cloudflare and confirm it can see exactly the zone
# we intend to use. Returns 0 on success and echoes a human-readable summary.
acme_verify_token() {
    local domain="${1:-${ACME_DOMAIN:-}}"
    local out rc

    if ! acme_load_token; then
        echo "No Cloudflare API token configured."
        return 1
    fi

    out=$(curl -s -m 20 -H "Authorization: Bearer $CF_Token" \
            https://api.cloudflare.com/client/v4/user/tokens/verify 2>/dev/null)
    if ! grep -q '"success":true' <<<"$out"; then
        echo "Token verification FAILED."
        echo "$out" | head -c 400
        return 1
    fi
    echo "Token: valid and active"

    [[ -z "$domain" ]] && { echo "No domain configured yet; skipping zone check."; return 0; }

    out=$(curl -s -m 20 -H "Authorization: Bearer $CF_Token" \
            "https://api.cloudflare.com/client/v4/zones?name=${domain}" 2>/dev/null)
    if ! grep -q '"success":true' <<<"$out"; then
        echo "Zone lookup FAILED for ${domain}."
        return 1
    fi

    local zone_id
    zone_id=$(sed -n 's/.*"result":\[{"id":"\([0-9a-f]\{32\}\)".*/\1/p' <<<"$out")
    if [[ -z "$zone_id" ]]; then
        echo "Zone ${domain} NOT visible to this token."
        echo "Check the token's Zone Resources include this zone."
        return 1
    fi
    echo "Zone:  ${domain} visible (id ${zone_id:0:8}...)"
    echo "Scope: DNS edit permission assumed; issuance will confirm it."
    return 0
}
#######################################
# acme.sh client
#######################################

# Path to the acme.sh binary inside our private home, if installed
acme_bin() { echo "$ACME_DIR/acme.sh"; }

acme_client_installed() { [[ -x "$ACME_DIR/acme.sh" ]]; }

# Run acme.sh against OUR private home.
#
# This wrapper is mandatory: acme.sh does NOT infer its working directory from
# the location of the script. `--install --home X` only writes an env file, so
# any later invocation without --home silently falls back to $HOME/.acme.sh and
# operates on a completely different set of accounts and certificates. That
# produced a cert in the wrong place and a bogus "issuance did not produce a
# certificate" error. Never call "$ACME_DIR/acme.sh" directly.
acme_sh() {
    "$ACME_DIR/acme.sh" \
        --home "$ACME_DIR" \
        --config-home "$ACME_DIR" \
        --cert-home "$ACME_DIR/certs" \
        "$@"
}

acme_client_version() {
    acme_client_installed || { echo "not installed"; return 1; }
    acme_sh --version 2>/dev/null | grep -m1 '^v' || echo "unknown"
}

# Directory acme.sh uses for this domain, given the configured key type
acme_domain_dir() {
    local domain="${1:-$ACME_DOMAIN}"
    if [[ "${ACME_KEY_TYPE:-ec-256}" == ec-* ]]; then
        echo "$ACME_DIR/certs/${domain}_ecc"
    else
        echo "$ACME_DIR/certs/${domain}"
    fi
}

# Which ACME directory URL the existing cert for this domain was issued against.
# Used to detect a staging -> production switch, which acme.sh would otherwise
# refuse as "Domains not changed / Skipping", issuing nothing at all.
acme_existing_server() {
    local dir; dir=$(acme_domain_dir "${1:-$ACME_DOMAIN}")
    local conf="$dir/${1:-$ACME_DOMAIN}.conf"
    [[ -f "$conf" ]] || return 1
    sed -n "s/^Le_API='\(.*\)'$/\1/p" "$conf" | head -1
}

# Install acme.sh into ACME_DIR. Deliberately --nocron: renewal is driven by
# acme_renew_all() (menu or systemd timer) so the deploy step always runs too.
acme_install_client() {
    local src="$CONFIG_DIR/src/acme.sh"

    if acme_client_installed; then
        log_info "acme.sh already installed ($(acme_client_version))"
        return 0
    fi

    for tool in git curl openssl; do
        command -v "$tool" >/dev/null 2>&1 || {
            log_error "Missing required tool: $tool"
            echo "ERROR: $tool is required but not installed."
            return 1
        }
    done

    mkdir -p "$CONFIG_DIR/src" "$ACME_DIR"
    chmod 700 "$ACME_DIR"

    if [[ ! -d "$src/.git" ]]; then
        echo "Cloning acme.sh..."
        git clone --depth 1 https://github.com/acmesh-official/acme.sh.git "$src" 2>&1 | tail -3 || {
            log_error "acme.sh clone failed"
            return 1
        }
    else
        echo "Updating acme.sh source..."
        ( cd "$src" && git pull --ff-only 2>&1 | tail -2 )
    fi

    echo "Installing acme.sh to $ACME_DIR ..."
    ( cd "$src" && ./acme.sh --install \
        --home "$ACME_DIR" \
        --config-home "$ACME_DIR" \
        --cert-home "$ACME_DIR/certs" \
        --accountemail "${ACME_EMAIL:-admin@${ACME_DOMAIN:-localhost}}" \
        --nocron 2>&1 | tail -6 )
    mkdir -p "$ACME_DIR/certs"

    if acme_client_installed; then
        log_cert_op "ACME_CLIENT_INSTALLED" "version=$(acme_client_version)"
        echo "acme.sh installed: $(acme_client_version)"
        return 0
    fi
    log_error "acme.sh installation failed"
    return 1
}

# Pre-flight checks that catch the common, silent failure modes before we spend
# an ACME order on them.
acme_preflight() {
    local domain="${ACME_DOMAIN:-}"
    local rc=0

    echo "=== Pre-flight checks ==="

    if [[ -z "$domain" ]]; then
        echo "  [FAIL] No domain configured"
        return 1
    fi
    echo "  domain: $domain"

    # Nameservers must be Cloudflare, or dns_cf cannot create the TXT records
    local ns
    ns=$(dig +short +time=5 NS "$domain" 2>/dev/null | tr '\n' ' ')
    if grep -qi 'cloudflare' <<<"$ns"; then
        echo "  [ OK ] nameservers are Cloudflare: $ns"
    else
        echo "  [FAIL] nameservers are NOT Cloudflare: ${ns:-<none>}"
        echo "         DNS-01 via the Cloudflare API cannot work for this zone."
        rc=1
    fi

    # CAA records can forbid the chosen CA outright
    local caa
    caa=$(dig +short +time=5 CAA "$domain" 2>/dev/null | tr '\n' ' ')
    if [[ -z "$caa" ]]; then
        echo "  [ OK ] no CAA records (no issuance restriction)"
    elif grep -q 'letsencrypt.org' <<<"$caa"; then
        echo "  [ OK ] CAA permits letsencrypt.org"
    else
        echo "  [WARN] CAA present and may block Let's Encrypt: $caa"
        echo "         Needs: 0 issue \"letsencrypt.org\" and 0 issuewild \"letsencrypt.org\""
        rc=1
    fi

    # ACME is JWS-signed and time-sensitive; >5min skew is rejected
    if command -v timedatectl >/dev/null 2>&1; then
        if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes; then
            echo "  [ OK ] clock is NTP-synchronised"
        else
            echo "  [WARN] clock may not be synchronised; ACME may reject signatures"
        fi
    fi

    # Reachability
    if curl -s -o /dev/null -m 15 https://acme-v02.api.letsencrypt.org/directory; then
        echo "  [ OK ] Let's Encrypt reachable"
    else
        echo "  [FAIL] cannot reach Let's Encrypt"
        rc=1
    fi
    if curl -s -o /dev/null -m 15 https://api.cloudflare.com/client/v4/; then
        echo "  [ OK ] Cloudflare API reachable"
    else
        echo "  [FAIL] cannot reach the Cloudflare API"
        rc=1
    fi

    echo ""
    acme_verify_token "$domain" | sed 's/^/  /'
    [[ ${PIPESTATUS[0]} -ne 0 ]] && rc=1

    return $rc
}
#######################################
# CERTIFICATE SOURCE / SINGLE-ISSUER MODEL
#
# Exactly one host in the fleet should hold the Cloudflare token and run the
# ACME client. Every other host DEPLOYS a certificate it did not issue.
#
# Running an issuer per node looks convenient but goes wrong quietly: each one
# consumes Let's Encrypt's 5-duplicate-certificates-per-week budget, each has
# its own renewal schedule (or none -- a second issuer here had no timer at all,
# so its certificate would simply have expired), and the same guest ends up
# recorded as a renewal target on two hosts that then fight over it.
#
# Two settings control where a certificate comes from:
#   ACME_ISSUER_HOST      empty  = this host issues (it is the issuer)
#                         set    = pull the certificate from that host over SSH
#   ACME_CERT_SOURCE_DIR  empty  = use this host's own acme.sh live directory
#                         set    = read the certificate from this local path,
#                                  e.g. when a standalone acme.sh already
#                                  manages it outside the tool
#######################################

acme_is_issuer() { [[ -z "${ACME_ISSUER_HOST:-}" ]]; }

# Directory the deployable certificate is read from.
acme_source_dir() {
    if [[ -n "${ACME_CERT_SOURCE_DIR:-}" ]]; then
        echo "$ACME_CERT_SOURCE_DIR"
    else
        acme_live_dir
    fi
}

# Pull the certificate from the designated issuer into the local live directory.
# Only the three files a deployment needs are copied; the account key and the
# Cloudflare token stay on the issuer.
acme_fetch_from_issuer() {
    local host="${ACME_ISSUER_HOST:-}"
    [[ -z "$host" ]] && return 0          # we are the issuer; nothing to fetch

    local remote="${ACME_ISSUER_DIR:-/etc/ssl/homelab/${ACME_DOMAIN}}"
    local live; live=$(acme_live_dir)
    mkdir -p "$live"; chmod 750 "$live"

    echo "Fetching certificate from issuer $host:$remote"
    local f ok=1
    for f in fullchain.pem privkey.pem chain.pem; do
        if ! scp -q -o BatchMode=yes -o ConnectTimeout=15 \
               "root@${host}:${remote}/${f}" "$live/${f}" 2>/dev/null; then
            [[ "$f" == "chain.pem" ]] && continue      # optional
            echo "  FAILED to fetch $f"
            ok=0
        fi
    done
    chmod 640 "$live/privkey.pem" 2>/dev/null

    if [[ "$ok" != 1 ]]; then
        echo ""
        echo "Could not fetch the certificate from the issuer."
        echo "Check that this host can reach it:"
        echo "  ssh root@${host} ls ${remote}"
        log_error "ACME fetch from issuer $host failed"
        return 1
    fi

    if ! acme_validate_local_cert >/dev/null 2>&1; then
        echo "  fetched certificate is not usable: $(acme_validate_local_cert 2>&1 | head -1)"
        return 1
    fi
    echo "  fetched: $(openssl x509 -in "$live/fullchain.pem" -noout -serial -enddate | tr '\n' ' ')"
    log_cert_op "ACME_FETCH" "issuer=$host serial=$(openssl x509 -in "$live/fullchain.pem" -noout -serial | cut -d= -f2)"
    return 0
}

# Refuse issuance on a host that is not the designated issuer, with an
# explanation rather than a confusing duplicate certificate.
acme_guard_issuance() {
    acme_is_issuer && return 0
    echo "This host is NOT the certificate issuer."
    echo ""
    echo "  issuer: ${ACME_ISSUER_HOST}"
    echo ""
    echo "Issuing here would create a SECOND certificate for the same names:"
    echo "  - it consumes Let's Encrypt's 5-duplicate-certs-per-week budget"
    echo "  - it renews on a separate schedule from the issuer's"
    echo "  - guests end up owned by two hosts that overwrite each other"
    echo ""
    echo "Deploy instead: the certificate is fetched from the issuer."
    echo "To make THIS host the issuer, clear ACME_ISSUER_HOST in the config."
    return 1
}

#######################################
# Issuance
#######################################

# Where the installed (deployable) cert lives on this host
acme_live_dir() { echo "$ACME_DIR/live/${ACME_DOMAIN}"; }

acme_cert_present() {
    local d; d=$(acme_source_dir)
    [[ -s "$d/fullchain.pem" && -s "$d/privkey.pem" ]]
}

# Issue (or re-issue) the wildcard. staging=1 uses Let's Encrypt's staging CA,
# which has far higher rate limits and its own account namespace.
#
# Rate limits worth respecting: 50 certs/week per registered domain, and only
# 5 duplicate certificates (identical SAN set) per week. Debug deployment with
# acme_deploy_* against the already-issued files instead of re-issuing.
acme_issue() {
    local staging="${1:-0}"
    local domain="${ACME_DOMAIN:-}"
    local sub="${ACME_SUBDOMAIN:-}"
    local keytype="${ACME_KEY_TYPE:-ec-256}"
    local server="letsencrypt"
    [[ "$staging" == "1" ]] && server="letsencrypt_test"

    [[ -z "$domain" ]] && { echo "ERROR: no domain configured"; return 1; }
    acme_guard_issuance || return 1
    acme_client_installed || { echo "ERROR: acme.sh not installed"; return 1; }
    acme_load_token || { echo "ERROR: no Cloudflare token configured"; return 1; }

    local -a san_args force_flag=()
    mapfile -t san_args < <(acme_build_san_args "$domain" "$sub")

    local want_url="https://acme-v02.api.letsencrypt.org/directory"
    [[ "$staging" == "1" ]] && want_url="https://acme-staging-v02.api.letsencrypt.org/directory"

    echo "CA:       $server"
    echo "Key type: $keytype"
    echo "SANs:     ${san_args[*]//-d /}"
    echo ""
    log_cert_op "ACME_ISSUE" "domain=$domain sub=$sub server=$server keytype=$keytype"

    # A certificate may already exist for this exact SAN set from an earlier run.
    # acme.sh then treats the request as a renewal and refuses with
    #   "Domains not changed. Skipping. Next renewal time is ..."
    # issuing nothing. That is correct for a repeat of the same CA, but wrong
    # when switching staging -> production: the existing staging cert would
    # silently block the production order. Clear the state in that case.
    local had_url
    if had_url=$(acme_existing_server "$domain"); then
        if [[ "$had_url" != "$want_url" ]]; then
            echo "An existing certificate was issued against a different CA:"
            echo "  had:  $had_url"
            echo "  want: $want_url"
            echo "Clearing that state so a fresh order is placed..."
            acme_sh --remove -d "$domain" $([[ "$keytype" == ec-* ]] && echo --ecc) >/dev/null 2>&1
            rm -rf "$(acme_domain_dir "$domain")"
            echo ""
        else
            echo "A certificate for this SAN set already exists from the same CA."
            echo "Re-issuing with --force (this consumes duplicate-certificate quota)."
            force_flag=(--force)
            echo ""
        fi
    fi

    # Register the account for this CA (idempotent)
    acme_sh --register-account --server "$server" \
        -m "${ACME_EMAIL:-admin@$domain}" 2>&1 | tail -2

    echo ""
    echo "Requesting certificate (DNS-01 via Cloudflare)..."
    # acme.sh polls Cloudflare's own nameservers for the TXT records, which is
    # faster and more reliable than a fixed sleep.
    acme_sh --issue \
            --server "$server" --dns dns_cf \
            "${san_args[@]}" \
            --keylength "$keytype" \
            "${force_flag[@]}" \
            --log "$LOG_DIR/acme.sh.log" --log-level 2 2>&1 \
            | grep -vE '^[A-Za-z0-9+/=]{60,}$|^-----(BEGIN|END)' | tail -25

    # acme.sh exits non-zero in some skip cases, so judge by the artifact
    local certdir; certdir=$(acme_domain_dir "$domain")
    if [[ ! -s "$certdir/fullchain.cer" ]]; then
        echo ""
        echo "ERROR: no certificate was produced."
        echo ""
        echo "Expected it at:"
        echo "  $certdir/fullchain.cer"
        echo ""
        echo "Common causes, in order of likelihood:"
        echo "  - the Cloudflare token lacks Zone:DNS:Edit on this zone"
        echo "    (run 'Pre-flight checks' from the menu)"
        echo "  - the zone is not served by Cloudflare nameservers"
        echo "  - a CAA record forbids this CA"
        echo "  - Let's Encrypt rate limit: only 5 identical certificates per week"
        echo ""
        echo "Last lines of $LOG_DIR/acme.sh.log:"
        grep -viE '^[A-Za-z0-9+/=]{60,}$' "$LOG_DIR/acme.sh.log" 2>/dev/null | tail -12 | sed 's/^/    /'
        log_error "ACME issuance failed for $domain (server=$server)"
        return 1
    fi

    # Install to a stable path so deploys and renewals read the same files
    local live; live=$(acme_live_dir)
    mkdir -p "$live"; chmod 750 "$live"
    local -a ecc_flag=()
    [[ "$keytype" == ec-* ]] && ecc_flag=(--ecc)

    acme_sh --install-cert -d "$domain" "${ecc_flag[@]}" \
        --cert-file      "$live/cert.pem" \
        --key-file       "$live/privkey.pem" \
        --fullchain-file "$live/fullchain.pem" \
        --ca-file        "$live/chain.pem" 2>&1 | tail -5
    chmod 640 "$live/privkey.pem" 2>/dev/null

    echo ""
    if [[ "$staging" == "1" ]]; then
        echo "STAGING certificate issued. It is NOT publicly trusted -- expected."
        echo "Re-run issuance against production when you are satisfied."
    else
        echo "Production certificate issued and installed:"
        acme_cert_summary | sed 's/^/  /'
    fi
    log_cert_op "ACME_ISSUE_OK" "domain=$domain server=$server"
    return 0
}

# Human-readable summary of the installed cert
acme_cert_summary() {
    local live; live=$(acme_source_dir)
    if ! acme_cert_present; then
        echo "No certificate installed."
        return 1
    fi
    local fc="$live/fullchain.pem"
    echo "Subject : $(openssl x509 -in "$fc" -noout -subject 2>/dev/null | sed 's/^subject=//')"
    echo "Issuer  : $(openssl x509 -in "$fc" -noout -issuer  2>/dev/null | sed 's/^issuer=//')"
    echo "Expires : $(openssl x509 -in "$fc" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
    echo "SANs    : $(openssl x509 -in "$fc" -noout -ext subjectAltName 2>/dev/null | tail -1 | sed 's/^ *//')"
    echo "Chain   : $(grep -c 'BEGIN CERTIFICATE' "$fc") certificates"
    if openssl verify -purpose sslserver -CAfile /etc/ssl/certs/ca-certificates.crt \
         -untrusted "$fc" "$fc" >/dev/null 2>&1; then
        echo "Trust   : PUBLICLY TRUSTED (verifies against the system trust store)"
    else
        echo "Trust   : NOT publicly trusted (staging cert, or incomplete chain)"
    fi
    local days
    days=$(( ( $(date -d "$(openssl x509 -in "$fc" -noout -enddate | sed 's/notAfter=//')" +%s) - $(date +%s) ) / 86400 ))
    echo "Days left: $days"
}

# Guard used before deploying: never push a cert that isn't a usable pair, and
# never silently push a staging cert to production services.
acme_validate_local_cert() {
    local live; live=$(acme_source_dir)
    local fc="$live/fullchain.pem" key="$live/privkey.pem"

    [[ -s "$fc"  ]] || { echo "Missing $fc"; return 1; }
    [[ -s "$key" ]] || { echo "Missing $key"; return 1; }
    openssl x509 -in "$fc" -noout >/dev/null 2>&1 || { echo "Certificate does not parse"; return 1; }
    openssl pkey -in "$key" -noout >/dev/null 2>&1 || { echo "Private key does not parse"; return 1; }

    local a b
    a=$(openssl x509 -in "$fc" -noout -pubkey | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
    b=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
    [[ "$a" == "$b" ]] || { echo "Certificate and key are not a matching pair"; return 1; }

    openssl x509 -in "$fc" -noout -checkend 86400 >/dev/null 2>&1 \
        || { echo "Certificate expires within 24h"; return 1; }
    return 0
}
#######################################
# Deployment to guests
#######################################

#######################################
# CLUSTER-WIDE (CROSS-NODE) EXECUTION
#
# Proxmox pct/qm only work for guests the local node owns. Rather than making
# the user reconnect, resolve the owning node and run the command there over the
# cluster's existing root SSH trust.
#
# Node addresses come from /etc/pve/.members, which pmxcfs replicates, so any
# node can resolve any other. SSH uses the IP rather than the node name: the
# name may not be in known_hosts (it frequently is not) while the IP is how the
# cluster already talks to itself.
#######################################

# IP of a cluster node, from the replicated members file.
acme_node_ip() {
    local node="$1"
    pve_exec "sed -n 's/.*\"$node\"[^{]*{[^}]*\"ip\": *\"\([0-9.]*\)\".*/\1/p' /etc/pve/.members 2>/dev/null | head -1" \
        | tr -d '\r'
}

# All node names in the cluster.
acme_nodes() {
    pve_exec "grep -oE '\"[A-Za-z0-9._-]+\": *\{ *\"id\"' /etc/pve/.members 2>/dev/null | sed 's/\": *{.*//; s/^\"//'" \
        | tr -d '\r'
}

# Run a command on a specific cluster node.
#
# The command is base64-encoded before transport. It may pass through two layers
# of shell (pve_exec's ssh, then the node-to-node ssh) and quoting survives none
# of that reliably; base64 does.
acme_node_exec() {
    local node="$1" cmd="$2"
    local here b64 ip
    here=$(acme_connected_node)
    b64=$(printf '%s' "$cmd" | base64 -w0)

    # < /dev/null on every path: ssh (and anything else that reads stdin) will
    # otherwise swallow the caller's input, which silently truncates a
    # `while read ... done < <(...)` loop after the first remote iteration.
    if [[ -z "$node" || "$node" == "$here" ]]; then
        # NOTE: no redirect on `bash` itself -- it reads the decoded script from
        # the pipe, so `bash < /dev/null` would execute nothing at all.
        pve_exec "echo $b64 | base64 -d | bash" < /dev/null
        return $?
    fi
    ip=$(acme_node_ip "$node")
    if [[ -z "$ip" ]]; then
        echo "acme_node_exec: cannot resolve an address for node '$node'" >&2
        return 1
    fi
    # ssh -n is what stops ssh reading the caller's stdin; the remote bash still
    # needs the pipe to receive its script, so it must NOT be redirected.
    pve_exec "ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new root@$ip 'echo $b64 | base64 -d | bash'" < /dev/null
}

# Cache of vmid -> "<kind> <node>" so a deploy loop does not re-glob pmxcfs.
declare -gA ACME_GUEST_OWNER=()

acme_guest_owner() {
    local vmid="$1"
    if [[ -n "${ACME_GUEST_OWNER[$vmid]:-}" ]]; then
        echo "${ACME_GUEST_OWNER[$vmid]}"
        return 0
    fi
    local loc
    loc=$(acme_locate_guest "$vmid") || return 1
    ACME_GUEST_OWNER[$vmid]="$loc"
    echo "$loc"
}

# Every guest in the cluster, with its owning node: "<kind>|<vmid>|<name>|<status>|<node>"
#
# Asks each node for its own pct/qm list rather than parsing the 35-column
# /cluster/resources table, so it reuses the parsing that is already proven and
# needs no JSON tooling on the host.
acme_cluster_guests() {
    local node listing
    # Read the whole node list first rather than streaming it: the loop body
    # runs remote commands, and anything that touches stdin would eat the rest.
    local -a nodes=()
    mapfile -t nodes < <(acme_nodes)
    for node in "${nodes[@]}"; do
        [[ -z "$node" ]] && continue
        listing=$(acme_node_exec "$node" "pct list 2>/dev/null | tail -n +2" 2>/dev/null)
        if [[ -n "$listing" ]]; then
            awk -v n="$node" 'NF>=3 && $1 ~ /^[0-9]+$/ {print "lxc|" $1 "|" $NF "|" $2 "|" n}' <<< "$listing"
        fi
        listing=$(acme_node_exec "$node" "qm list 2>/dev/null | tail -n +2" 2>/dev/null)
        if [[ -n "$listing" ]]; then
            awk -v n="$node" 'NF>=3 && $1 ~ /^[0-9]+$/ {print "vm|" $1 "|" $2 "|" $3 "|" n}' <<< "$listing"
        fi
    done
}
# Execute a command inside a guest, wherever in the cluster it lives.
#
# The local case delegates to the existing lxc_exec/vm_exec, which are already
# proven; only a guest on another node takes the cross-node path. Commands are
# quoted with printf %q for the inner shell and base64-encoded by
# acme_node_exec for transport, so arbitrary quoting survives.
acme_guest_exec() {
    local kind="$1" vmid="$2" cmd="$3"
    local loc owner here q

    here=$(acme_connected_node)
    if loc=$(acme_guest_owner "$vmid"); then
        owner=${loc##* }
    else
        owner="$here"
    fi

    if [[ -z "$owner" || "$owner" == "$here" ]]; then
        case "$kind" in
            lxc) lxc_exec "$vmid" "$cmd" ;;
            vm)  vm_exec  "$vmid" "$cmd" ;;
            *)   log_error "acme_guest_exec: unknown kind '$kind'"; return 1 ;;
        esac
        return $?
    fi

    printf -v q '%q' "$cmd" 2>/dev/null || q="'${cmd//\'/\'\\\'\'}'"
    case "$kind" in
        lxc)
            acme_node_exec "$owner" "pct exec $vmid -- /bin/bash -c $q < /dev/null"
            ;;
        vm)
            # qm returns JSON; pull out-data on the owning node
            acme_node_exec "$owner" \
                "qm guest exec $vmid -- /bin/bash -c $q 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('out-data','').rstrip())\" 2>/dev/null"
            ;;
        *) log_error "acme_guest_exec: unknown kind '$kind'"; return 1 ;;
    esac
}

# Copy a local file into a guest, wherever it lives.
#
# Content is base64'd and decoded inside the guest, which works identically for
# LXC and VM and on any node -- unlike `pct push`, which requires both the file
# and the command to be on the owning node. Certificates are a few KB, well
# inside any argument-length limit.
acme_guest_push() {
    local kind="$1" vmid="$2" src="$3" dst="$4"
    [[ -s "$src" ]] || { log_error "acme_guest_push: missing source $src"; return 1; }

    local loc owner here
    here=$(acme_connected_node)
    if loc=$(acme_guest_owner "$vmid"); then owner=${loc##* }; else owner="$here"; fi

    # Fast path: local node, LXC, pct push handles it directly
    if [[ "$kind" == "lxc" && "$IS_LOCAL_PVE" == true && ( -z "$owner" || "$owner" == "$here" ) ]]; then
        pct push "$vmid" "$src" "$dst" && return 0
        # fall through to the base64 path if pct push refused
    fi

    local b64
    b64=$(base64 -w0 "$src") || return 1
    acme_guest_exec "$kind" "$vmid" \
        "mkdir -p \"\$(dirname '$dst')\" && printf '%s' '$b64' | base64 -d > '$dst'"
}

# Write content to a file inside a guest WITHOUT changing its inode.
#
# Essential for a path that is a Docker single-file bind mount: replacing the
# file (install/mv/sed -i all do) creates a new inode, the mount keeps pointing
# at the old one, and the container silently keeps reading stale content -- or
# sees the file vanish. Truncate-and-write preserves the inode.
acme_guest_write_inplace() {
    local kind="$1" vmid="$2" path="$3" content="$4"
    local b64
    b64=$(printf '%s' "$content" | base64 -w0)
    acme_guest_exec "$kind" "$vmid" \
        "printf '%s' '$b64' | base64 -d | cat > '$path'"
}
# Guest-side path of a service's config file.
#
# For a containerised proxy the config path found in the container is a CONTAINER
# path; it has to be translated through the container's mounts before it can be
# edited from the guest. Echoes nothing when the config is not bind-mounted out,
# which means it cannot be rewritten from here.
acme_guest_config_path() {
    local kind="$1" vmid="$2" spec="$3" cfg="$4"
    case "$spec" in
        docker:*)
            local cname mounts
            cname=${spec#docker:}; cname=${cname%%:*}
            mounts=$(acme_guest_exec "$kind" "$vmid" \
                "docker inspect -f '{{range .Mounts}}{{.Source}}|{{.Destination}}{{\"\\n\"}}{{end}}' '$cname' 2>/dev/null" 2>/dev/null)
            acme_map_container_path "$cfg" "$mounts"
            ;;
        caddy)   echo "${cfg:-/etc/caddy/Caddyfile}" ;;
        nginx)   echo "${cfg:-}" ;;      # set when a single file holds server_name
        apache2) echo "" ;;              # multi-file layout; not rewritten
        *) echo "" ;;
    esac
}

# Validate a service's config, in place, before reloading it.
acme_service_validate() {
    local kind="$1" vmid="$2" spec="$3" cfg="$4"
    case "$spec" in
        docker:*:caddy)
            local c=${spec#docker:}; c=${c%%:*}
            acme_guest_exec "$kind" "$vmid" "docker exec '$c' caddy validate --config '$cfg' --adapter caddyfile >/dev/null 2>&1 && echo OK" 2>/dev/null | grep -q OK
            ;;
        docker:*:nginx)
            local c=${spec#docker:}; c=${c%%:*}
            acme_guest_exec "$kind" "$vmid" "docker exec '$c' nginx -t >/dev/null 2>&1 && echo OK" 2>/dev/null | grep -q OK
            ;;
        caddy)   acme_guest_exec "$kind" "$vmid" "caddy validate --config '${cfg:-/etc/caddy/Caddyfile}' >/dev/null 2>&1 && echo OK" 2>/dev/null | grep -q OK ;;
        nginx)   acme_guest_exec "$kind" "$vmid" "nginx -t >/dev/null 2>&1 && echo OK" 2>/dev/null | grep -q OK ;;
        apache2) acme_guest_exec "$kind" "$vmid" "(apache2ctl configtest || httpd -t) >/dev/null 2>&1 && echo OK" 2>/dev/null | grep -q OK ;;
        *) return 0 ;;
    esac
}

# Point a service's virtual host at a name our certificate actually covers.
#
# Replacing the certificate alone leaves a vhost named <app>.myhome.lan, which
# no public certificate can match -- the service loads the new cert but every
# client still sees a name mismatch. This rewrites the configured name to
# <guest>.<subdomain>.<domain>, in place so a single-file bind mount survives,
# then validates, reloads and confirms adoption. Rolls the config back if the
# validation fails.
acme_rewrite_vhost() {
    local kind="$1" vmid="$2" spec="$3" cfg="$4" newname="$5"
    local gcfg content names n changed=0 stamp

    gcfg=$(acme_guest_config_path "$kind" "$vmid" "$spec" "$cfg")
    if [[ -z "$gcfg" ]]; then
        echo "  vhost rename SKIPPED: this service's config is not reachable from"
        echo "    the guest (multi-file layout, or inside the image/a named volume)."
        echo "    Point its server name at $newname by hand."
        return 1
    fi

    names=$(acme_service_names "$kind" "$vmid" "$spec" "$cfg")
    [[ -z "$names" ]] && { echo "  vhost rename SKIPPED: no server name found in $gcfg"; return 1; }

    content=$(acme_guest_exec "$kind" "$vmid" "cat '$gcfg' 2>/dev/null")
    [[ -z "$content" ]] && { echo "  vhost rename SKIPPED: could not read $gcfg"; return 1; }

    local newcontent="$content"
    while read -r n; do
        [[ -z "$n" || "$n" == "$newname" ]] && continue
        # already covered? leave it alone
        if [[ "$n" == "$ACME_DOMAIN" || "$n" == *".$ACME_DOMAIN" ]]; then continue; fi
        newcontent="${newcontent//$n/$newname}"
        changed=1
        echo "  vhost rename: $n -> $newname"
    done <<< "$names"

    if [[ "$changed" -eq 0 ]]; then
        echo "  vhost already uses a covered name"
        return 0
    fi

    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    acme_guest_exec "$kind" "$vmid" "cp -a '$gcfg' '$gcfg.pvebak.$stamp'" >/dev/null 2>&1

    # inode-preserving write: $gcfg may be a single-file Docker bind mount
    if ! acme_guest_write_inplace "$kind" "$vmid" "$gcfg" "$newcontent"; then
        echo "  vhost rename FAILED: could not write $gcfg"
        return 1
    fi

    if ! acme_service_validate "$kind" "$vmid" "$spec" "$cfg"; then
        echo "  vhost rename FAILED validation -- restoring $gcfg"
        acme_guest_write_inplace "$kind" "$vmid" "$gcfg" "$content"
        return 1
    fi
    echo "  config validated"
    return 0
}

# Discover which TLS-terminating service a guest runs, and where it currently
# reads its certificate from. Overwriting those exact paths replaces the cert
# without editing any service config, which is both safer and more certain to
# take effect than rewriting directives.
#
# Echoes one line per finding: service|cert_path|key_path
acme_detect_tls_service() {
    local kind="$1" vmid="$2"
    local out

    # nginx
    if acme_guest_exec "$kind" "$vmid" "command -v nginx >/dev/null 2>&1 && echo yes" 2>/dev/null | grep -q yes \
       && acme_service_active "$kind" "$vmid" nginx; then
        # Must be a single clean token: this becomes a field in a pipe-delimited
        # record, so an embedded newline would corrupt every downstream parse.
        local NGINX_CONF
        NGINX_CONF=$(acme_guest_exec "$kind" "$vmid" \
            "grep -rlE '^[[:space:]]*server_name' /etc/nginx 2>/dev/null | head -1" 2>/dev/null \
            | tr -d '\r' | head -1 | tr -d '\n' | tr -d '|')
        out=$(acme_guest_exec "$kind" "$vmid" \
            "grep -rhE '^[[:space:]]*ssl_certificate(_key)?[[:space:]]' /etc/nginx 2>/dev/null | head -20" 2>/dev/null)
        local c k
        c=$(grep -E 'ssl_certificate[[:space:]]'     <<<"$out" | head -1 | sed -E 's/.*ssl_certificate[[:space:]]+//;s/;.*//'      | tr -d '"'"'"' ')
        k=$(grep -E 'ssl_certificate_key[[:space:]]' <<<"$out" | head -1 | sed -E 's/.*ssl_certificate_key[[:space:]]+//;s/;.*//'  | tr -d '"'"'"' ')
        [[ -n "$c" && -n "$k" ]] && echo "nginx|$c|$k|${NGINX_CONF:-}"
    fi

    # apache2 / httpd
    if acme_guest_exec "$kind" "$vmid" "command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1 && echo yes" 2>/dev/null | grep -q yes \
       && { acme_service_active "$kind" "$vmid" apache2 || acme_service_active "$kind" "$vmid" httpd; }; then
        out=$(acme_guest_exec "$kind" "$vmid" \
            "grep -rhiE '^[[:space:]]*SSLCertificate(File|KeyFile)[[:space:]]' /etc/apache2 /etc/httpd 2>/dev/null | head -20" 2>/dev/null)
        local c k
        c=$(grep -iE 'SSLCertificateFile[[:space:]]'    <<<"$out" | head -1 | sed -E 's/.*[Ff]ile[[:space:]]+//'    | tr -d '"'"'"' ')
        k=$(grep -iE 'SSLCertificateKeyFile[[:space:]]' <<<"$out" | head -1 | sed -E 's/.*[Kk]eyFile[[:space:]]+//' | tr -d '"'"'"' ')
        [[ -n "$c" && -n "$k" ]] && echo "apache2|$c|$k"
    fi

    # caddy (explicit `tls <cert> <key>` only; auto_https-managed certs are not ours to touch)
    if acme_guest_exec "$kind" "$vmid" "command -v caddy >/dev/null 2>&1 && echo yes" 2>/dev/null | grep -q yes \
       && acme_service_active "$kind" "$vmid" caddy; then
        out=$(acme_guest_exec "$kind" "$vmid" \
            "grep -rhE '^[[:space:]]*tls[[:space:]]+/' /etc/caddy 2>/dev/null | head -5" 2>/dev/null)
        local c k
        c=$(head -1 <<<"$out" | awk '{print $2}')
        k=$(head -1 <<<"$out" | awk '{print $3}')
        [[ -n "$c" && -n "$k" ]] && echo "caddy|$c|$k"
    fi
}

# Is a host-installed service actually running?
#
# Presence of the binary and a config file is not enough. Nextcloud's container
# image ships apache2 installed but dormant, with Caddy holding :80/:443 — a
# stopped service has nothing to reload, so treating it as a TLS terminator
# overwrites its certificate for no reason and reports a spurious failure.
acme_service_active() {
    local kind="$1" vmid="$2" svc="$3"
    local out
    # systemd only -- deliberately NO pgrep fallback. Inside an LXC running
    # Docker, the containers' processes are visible in the LXC's own PID
    # namespace, so `pgrep -x apache2` matches an apache inside the application
    # container and wrongly declares the host service live. That made the tool
    # overwrite the guest's snakeoil certificate and fail a deployment that had
    # actually succeeded. If systemd does not manage it, it is not a host
    # service we should be touching.
    out=$(acme_guest_exec "$kind" "$vmid" "systemctl is-active $svc 2>/dev/null" 2>/dev/null | tr -d '\r')
    [[ "$out" == "active" ]]
}

# Reload command per service, preferring a graceful reload over a restart.
acme_service_reload_cmd() {
    case "$1" in
        nginx)   echo "nginx -t && (systemctl reload nginx || nginx -s reload)" ;;
        apache2) echo "(apache2ctl configtest || httpd -t) && (systemctl reload apache2 || systemctl reload httpd || apache2ctl graceful)" ;;
        # --force matters: `caddy reload` with an identical config logs
        # "config is unchanged", exits 0, and never re-reads the certificate
        # files from disk. Without it the cert is replaced but not adopted.
        caddy)   echo "caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 && (caddy reload --config /etc/caddy/Caddyfile --force || systemctl reload caddy || systemctl restart caddy)" ;;
        *)       echo "" ;;
    esac
}

# Find which cluster node owns a guest, and its kind.
#
# /etc/pve is pmxcfs and is replicated cluster-wide, so the config file's path
# identifies the owning node from ANY node -- no API call or extra tooling.
# Echoes "<kind> <node>"; returns 1 if the guest does not exist at all.
acme_locate_guest() {
    local vmid="$1" p
    p=$(pve_exec "ls /etc/pve/nodes/*/lxc/${vmid}.conf 2>/dev/null | head -1" | tr -d '\r')
    if [[ -n "$p" ]]; then
        echo "lxc $(sed 's|.*/nodes/\([^/]*\)/.*|\1|' <<<"$p")"
        return 0
    fi
    p=$(pve_exec "ls /etc/pve/nodes/*/qemu-server/${vmid}.conf 2>/dev/null | head -1" | tr -d '\r')
    if [[ -n "$p" ]]; then
        echo "vm $(sed 's|.*/nodes/\([^/]*\)/.*|\1|' <<<"$p")"
        return 0
    fi
    return 1
}

# Node we are currently driving
acme_connected_node() {
    pve_exec "hostname -s" 2>/dev/null | tr -d '\r'
}

# Verify a guest can actually be operated on before attempting anything.
# Prints a human-readable explanation of any blocker. Returns 0 if usable.
#
# This exists because the underlying failures are cryptic: operating on a guest
# owned by another node produces "Configuration file 'nodes/PDxxx/lxc/N.conf'
# does not exist", and pushing to a stopped container produces "can only push
# files to a running CT" -- neither of which names the real problem.
acme_guest_preflight() {
    local kind="$1" vmid="$2"
    local here loc real_kind owner status

    here=$(acme_connected_node)

    if ! loc=$(acme_locate_guest "$vmid"); then
        echo "Guest $vmid does not exist anywhere in this cluster."
        echo ""
        echo "Connected node: ${here:-<unknown>}"
        echo "Check the ID, or refresh the guest list."
        return 1
    fi
    real_kind=${loc%% *}
    owner=${loc##* }

    if [[ "$real_kind" != "$kind" ]]; then
        echo "Guest $vmid is a $real_kind, not a $kind."
        echo ""
        echo "Use the '$real_kind' deployment menu entry instead."
        return 1
    fi

    # A guest on another node is fine: commands are routed to its owner over
    # the cluster's root SSH trust. Only report it, and fail if unreachable.
    if [[ -n "$here" && "$owner" != "$here" ]]; then
        local ip
        ip=$(acme_node_ip "$owner")
        if [[ -z "$ip" ]]; then
            echo "Guest $vmid lives on node '$owner', but that node has no address"
            echo "in /etc/pve/.members -- it may be offline."
            return 1
        fi
        if ! acme_node_exec "$owner" "true" >/dev/null 2>&1; then
            echo "Guest $vmid lives on node '$owner' ($ip), which cannot be reached"
            echo "over SSH from '$here'."
            echo ""
            echo "The cluster's node-to-node root SSH trust is what makes cross-node"
            echo "deployment work. Verify with:"
            echo "  ssh root@$ip hostname"
            echo "If that prompts or fails, fix the host key / authorized_keys first."
            return 1
        fi
        echo "NOTE: guest is on node '$owner'; commands will be routed there."
    fi

    case "$kind" in
        lxc) status=$(acme_node_exec "$owner" "pct status $vmid 2>/dev/null | awk '{print \$2}'" | tr -d '\r') ;;
        vm)  status=$(acme_node_exec "$owner" "qm status $vmid 2>/dev/null | awk '{print \$2}'"  | tr -d '\r') ;;
    esac
    if [[ "$status" != "running" ]]; then
        echo "Guest $vmid ($kind) is '${status:-unknown}', not running."
        echo ""
        echo "Certificates can only be installed into a running guest."
        echo "Start it first, then retry."
        return 1
    fi

    if [[ "$kind" == "vm" ]] \
       && ! acme_node_exec "$owner" "qm agent $vmid ping >/dev/null 2>&1 && echo ok" 2>/dev/null | grep -q ok; then
        echo "VM $vmid is running but the QEMU Guest Agent is not responding."
        echo ""
        echo "The agent is required to copy files into a VM. Install it in the"
        echo "guest (qemu-guest-agent) and enable the agent option on the VM."
        return 1
    fi

    return 0
}
# Detect a TLS terminator running as a DOCKER CONTAINER inside a guest.
#
# This is a common homelab shape -- immich, for instance, ships a caddy:2-alpine
# container that terminates :443 and reads its certificate from a bind-mounted
# host directory. Nothing is installed on the guest itself, so the plain
# nginx/apache/caddy probe finds nothing and "replace" would silently do nothing.
#
# The certificate path in the container config is a CONTAINER path; it must be
# translated to the guest-side path through the container's own mount table
# before it can be written.
#
# Echoes one line per finding:
#   docker:<container>:<flavour>|<guest_cert_path>|<guest_key_path>|<config_path>
acme_detect_docker_tls_service() {
    local kind="$1" vmid="$2"

    acme_guest_exec "$kind" "$vmid" "command -v docker >/dev/null 2>&1 && echo yes" 2>/dev/null \
        | grep -q yes || return 0

    local names
    names=$(acme_guest_exec "$kind" "$vmid" "docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null" 2>/dev/null)
    [[ -z "$names" ]] && return 0

    local cname image flavour cfg ctr_cert ctr_key mounts host_cert host_key
    while read -r cname image; do
        [[ -z "$cname" ]] && continue
        flavour=""
        case "${image,,}" in
            *caddy*)   flavour=caddy ;;
            *nginx*)   flavour=nginx ;;
            *traefik*) flavour=traefik ;;
        esac
        [[ -z "$flavour" ]] && continue

        # Only interested in something actually terminating TLS
        acme_guest_exec "$kind" "$vmid" "docker port '$cname' 2>/dev/null | grep -q 443 && echo yes" 2>/dev/null \
            | grep -q yes || continue

        ctr_cert=""; ctr_key=""; cfg=""
        case "$flavour" in
            caddy)
                cfg=/etc/caddy/Caddyfile
                local line
                line=$(acme_guest_exec "$kind" "$vmid" \
                    "docker exec '$cname' sh -c 'grep -hE \"^[[:space:]]*tls[[:space:]]+/\" $cfg 2>/dev/null | head -1' 2>/dev/null" 2>/dev/null)
                ctr_cert=$(awk '{print $2}' <<<"$line")
                ctr_key=$(awk  '{print $3}' <<<"$line")
                if [[ -z "$ctr_cert" ]]; then
                    # No `tls <cert> <key>` line. Caddy may be managing its own
                    # certificates -- either its internal PKI (`issuer internal`)
                    # or automatic ACME. Replacing a file cannot change that, so
                    # say so instead of reporting "no TLS service found", which
                    # is what this looked like before and is simply wrong.
                    local mode
                    mode=$(acme_guest_exec "$kind" "$vmid" \
                        "docker exec '$cname' sh -c \"grep -hoE 'issuer[[:space:]]+internal|tls[[:space:]]+internal|auto_https' $cfg 2>/dev/null | head -1\" 2>/dev/null" 2>/dev/null | tr -d '\r')
                    echo "docker:${cname}:caddy|SELFMANAGED:${mode:-automatic}|SELFMANAGED|$cfg"
                    continue
                fi
                ;;
            nginx)
                # Point cfg at the specific file holding server_name. Using the
                # /etc/nginx directory instead makes the vhost rename impossible,
                # because a directory cannot be mapped to a single bind mount.
                cfg=$(acme_guest_exec "$kind" "$vmid" \
                    "docker exec '$cname' sh -c \"grep -rlE '^[[:space:]]*server_name' /etc/nginx 2>/dev/null | head -1\" 2>/dev/null" 2>/dev/null \
                    | tr -d '\r' | head -1 | tr -d '\n' | tr -d '|')
                [[ -z "$cfg" ]] && cfg=/etc/nginx
                local out
                out=$(acme_guest_exec "$kind" "$vmid" \
                    "docker exec '$cname' sh -c 'grep -rhE \"^[[:space:]]*ssl_certificate(_key)?[[:space:]]\" /etc/nginx 2>/dev/null | head -20' 2>/dev/null" 2>/dev/null)
                ctr_cert=$(grep -E 'ssl_certificate[[:space:]]'     <<<"$out" | head -1 | sed -E 's/.*ssl_certificate[[:space:]]+//;s/;.*//'     | tr -d '"'"'"' ')
                ctr_key=$( grep -E 'ssl_certificate_key[[:space:]]' <<<"$out" | head -1 | sed -E 's/.*ssl_certificate_key[[:space:]]+//;s/;.*//' | tr -d '"'"'"' ')
                ;;
            traefik)
                # Traefik's cert paths live in a dynamic config whose location varies;
                # report the container so the user knows, but do not guess paths.
                echo "docker:${cname}:traefik|UNSUPPORTED|UNSUPPORTED|"
                continue
                ;;
        esac

        [[ -z "$ctr_cert" || -z "$ctr_key" ]] && continue

        # Translate container paths to guest paths using the bind mounts
        mounts=$(acme_guest_exec "$kind" "$vmid" \
            "docker inspect -f '{{range .Mounts}}{{.Source}}|{{.Destination}}{{\"\\n\"}}{{end}}' '$cname' 2>/dev/null" 2>/dev/null)
        host_cert=$(acme_map_container_path "$ctr_cert" "$mounts")
        host_key=$( acme_map_container_path "$ctr_key"  "$mounts")

        if [[ -z "$host_cert" || -z "$host_key" ]]; then
            # Paths live inside the image or a named volume, not a bind mount --
            # writing them from the guest is not possible.
            echo "docker:${cname}:${flavour}|NOTBOUND:${ctr_cert}|NOTBOUND:${ctr_key}|$cfg"
        else
            echo "docker:${cname}:${flavour}|${host_cert}|${host_key}|$cfg"
        fi
    done <<< "$names"
}

# Map a path inside a container to its path on the guest, using the container's
# mount table ("<source>|<destination>" lines). Longest destination wins, so a
# nested mount is preferred over its parent. Echoes nothing if unmapped.
acme_map_container_path() {
    local cpath="$1" mounts="$2"
    local best_src="" best_dst="" src dst
    while IFS='|' read -r src dst; do
        [[ -z "$dst" ]] && continue
        if [[ "$cpath" == "$dst" || "$cpath" == "$dst"/* ]]; then
            if (( ${#dst} > ${#best_dst} )); then best_dst="$dst"; best_src="$src"; fi
        fi
    done <<< "$mounts"
    [[ -z "$best_dst" ]] && return 0
    if [[ "$cpath" == "$best_dst" ]]; then
        echo "$best_src"
    else
        echo "${best_src}${cpath#"$best_dst"}"
    fi
}

# After a reload, confirm the service is really serving OUR certificate.
#
# This is the check that matters: writing the file and getting exit 0 from a
# reload does not mean the service adopted it. Caddy in particular answers
# "config is unchanged" and keeps the certificate it already had in memory.
# Compares serial numbers over a real TLS handshake from inside the guest.
acme_verify_service_cert() {
    local kind="$1" vmid="$2" sni="$3" port="${4:-443}"
    local want got
    want=$(openssl x509 -in "$(acme_source_dir)/fullchain.pem" -noout -serial 2>/dev/null | cut -d= -f2)
    [[ -z "$want" ]] && return 0
    if [[ -z "$sni" ]]; then
        echo "  NOT VERIFIED: no server name available to probe with, so adoption"
        echo "    could not be confirmed. Check manually with:"
        echo "    openssl s_client -connect <guest>:${port} | openssl x509 -noout -serial"
        return 1
    fi

    local i
    for i in 1 2 3 4 5; do
        got=$(acme_guest_exec "$kind" "$vmid" \
            "echo | openssl s_client -connect 127.0.0.1:${port} -servername '${sni}' 2>/dev/null | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2" \
            2>/dev/null | tr -d '\r')
        [[ "$got" == "$want" ]] && { echo "  verified: :$port is serving the new certificate (SNI $sni)"; return 0; }
        sleep 2
    done

    echo "  NOT ADOPTED: :$port is still serving a different certificate."
    echo "    expected serial: ${want:0:20}"
    echo "    serving serial : ${got:-<no certificate returned>}"
    if [[ -z "$got" ]]; then
        echo "    No certificate came back for SNI '$sni'. The proxy probably has"
        echo "    no virtual host for that name, so it aborts the handshake."
    else
        echo "    The file was replaced but the service did not re-read it."
        echo "    Try restarting the service rather than reloading it."
    fi
    return 1
}

# Reload a containerised proxy, preferring a graceful reload.
acme_docker_reload_cmd() {
    local cname="$1" flavour="$2" cfg="$3"
    case "$flavour" in
        # --force: see acme_service_reload_cmd. Without it caddy answers
        # "config is unchanged" and keeps serving the certificate already in
        # memory, so the deployment silently has no effect.
        caddy) echo "docker exec '$cname' caddy reload --config '$cfg' --adapter caddyfile --force || docker restart '$cname'" ;;
        nginx) echo "docker exec '$cname' nginx -t && docker exec '$cname' nginx -s reload || docker restart '$cname'" ;;
        *)     echo "docker restart '$cname'" ;;
    esac
}
# All TLS terminators in a guest: host-installed services AND containerised ones.
# Normalised to four fields: <spec>|<cert>|<key>|<config>
#   spec = nginx | apache2 | caddy | docker:<container>:<flavour>
acme_detect_all_tls() {
    local kind="$1" vmid="$2" line n
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # normalise to exactly 4 fields (host detectors may emit 3 or 4)
        n=$(awk -F'|' '{print NF}' <<<"$line")
        if [[ "$n" -lt 4 ]]; then echo "${line}|"; else echo "$line"; fi
    done < <(acme_detect_tls_service "$kind" "$vmid")
    acme_detect_docker_tls_service "$kind" "$vmid"
}

# Does the service's configured server name fall under our certificate?
# A cert replacement that leaves the vhost named <host>.myhome.lan still shows a
# name mismatch in browsers, so say so rather than reporting success.
# Server names a service is configured for (first line is the primary).
acme_service_names() {
    local kind="$1" vmid="$2" spec="$3" cfg="$4"
    local names=""
    case "$spec" in
        docker:*:caddy)
            local cname=${spec#docker:}; cname=${cname%%:*}
            names=$(acme_guest_exec "$kind" "$vmid" \
                "docker exec '$cname' sh -c 'grep -hoE \"^[A-Za-z0-9_.*-]+\\.[A-Za-z0-9_.*-]+\" ${cfg:-/etc/caddy/Caddyfile} 2>/dev/null' 2>/dev/null" 2>/dev/null | head -5)
            ;;
        caddy)
            names=$(acme_guest_exec "$kind" "$vmid" \
                "grep -hoE '^[A-Za-z0-9_.*-]+\\.[A-Za-z0-9_.*-]+' /etc/caddy/Caddyfile 2>/dev/null" 2>/dev/null | head -5)
            ;;
        docker:*:nginx)
            # must look INSIDE the container: /etc/nginx on the guest is a
            # different filesystem (often absent entirely)
            local cn=${spec#docker:}; cn=${cn%%:*}
            names=$(acme_guest_exec "$kind" "$vmid" \
                "docker exec '$cn' sh -c \"grep -rhE '^[[:space:]]*server_name[[:space:]]' /etc/nginx 2>/dev/null\" 2>/dev/null | sed -E 's/.*server_name[[:space:]]+//;s/;.*//'" 2>/dev/null \
                | tr ' ' '\n' | sed '/^$/d;/^_$/d' | head -5)
            ;;
        nginx)
            names=$(acme_guest_exec "$kind" "$vmid" \
                "grep -rhE '^[[:space:]]*server_name[[:space:]]' /etc/nginx 2>/dev/null | sed -E 's/.*server_name[[:space:]]+//;s/;.*//'" 2>/dev/null | tr ' ' '\n' | sed '/^$/d;/^_$/d' | head -5)
            ;;
        docker:*:apache2)
            local ca=${spec#docker:}; ca=${ca%%:*}
            names=$(acme_guest_exec "$kind" "$vmid" \
                "docker exec '$ca' sh -c \"grep -rhiE '^[[:space:]]*ServerName[[:space:]]' /etc/apache2 /etc/httpd 2>/dev/null\" 2>/dev/null | sed -E 's/.*[Nn]ame[[:space:]]+//'" 2>/dev/null | head -5)
            ;;
        apache2)
            names=$(acme_guest_exec "$kind" "$vmid" \
                "grep -rhiE '^[[:space:]]*ServerName[[:space:]]' /etc/apache2 /etc/httpd 2>/dev/null | sed -E 's/.*[Nn]ame[[:space:]]+//'" 2>/dev/null | head -5)
            ;;
    esac
    printf '%s\n' "$names" | sed '/^$/d'
}

# Warn when a configured name is not covered by our certificate.
acme_check_servername() {
    local kind="$1" vmid="$2" spec="$3" cfg="$4"
    local names
    names=$(acme_service_names "$kind" "$vmid" "$spec" "$cfg")
    [[ -z "$names" ]] && return 0

    local n bad=()
    while read -r n; do
        [[ -z "$n" ]] && continue
        # covered by <domain>, *.<domain> or *.<sub>.<domain>?
        if [[ "$n" == "$ACME_DOMAIN" ]] \
           || [[ "$n" == *".$ACME_DOMAIN" ]] \
           || [[ -n "${ACME_SUBDOMAIN:-}" && "$n" == *".${ACME_SUBDOMAIN}.${ACME_DOMAIN}" ]]; then
            continue
        fi
        bad+=("$n")
    done <<< "$names"

    if (( ${#bad[@]} )); then
        echo "  WARNING: this service is configured for ${bad[*]}"
        echo "           which the certificate does NOT cover. TLS will load, but"
        echo "           clients using that name still see a name mismatch."
        echo "           Update the vhost to a *.${ACME_SUBDOMAIN:-lan}.${ACME_DOMAIN} name."
        return 1
    fi
    return 0
}

# Deploy the wildcard cert into one guest.
#   kind      lxc|vm
#   vmid      guest id
#   mode      "inplace"  overwrite the paths the detected service already uses
#             "standard" install to /etc/ssl/pve-manager/<domain>/ only
acme_deploy_to_guest() {
    local kind="$1" vmid="$2" mode="${3:-inplace}" rename="${4:-0}"
    local domain="${ACME_DOMAIN:-}"
    local live; live=$(acme_source_dir)
    local std="/etc/ssl/pve-manager/${domain}"

    # Reachability first: the underlying pct/qm errors are cryptic, so diagnose
    # the guest before touching a certificate.
    local pf
    if ! pf=$(acme_guest_preflight "$kind" "$vmid"); then
        echo "CANNOT DEPLOY to $kind/$vmid"
        echo ""
        printf '%s\n' "$pf"
        return 1
    fi

    local problem
    if ! problem=$(acme_validate_local_cert); then
        echo "CANNOT DEPLOY: $problem"
        return 1
    fi

    # Refuse to push a staging certificate to a real service
    if ! openssl verify -purpose sslserver -CAfile /etc/ssl/certs/ca-certificates.crt \
           -untrusted "$live/fullchain.pem" "$live/fullchain.pem" >/dev/null 2>&1; then
        echo "CANNOT DEPLOY: the local certificate is NOT publicly trusted"
        echo "(this is a staging certificate, or the chain is incomplete)"
        echo "Issue a PRODUCTION certificate first."
        return 1
    fi

    local hostname fqdn
    case "$kind" in
        lxc) hostname=$(acme_guest_exec lxc "$vmid" "hostname" 2>/dev/null | tr -d '\r') ;;
        vm)  hostname=$(vm_get_hostname "$vmid" 2>/dev/null | tr -d '\r') ;;
    esac
    hostname="${hostname:-guest$vmid}"
    fqdn=$(acme_guest_fqdn "$hostname")

    echo "Guest    : $kind/$vmid ($hostname)"
    echo "Covered  : $fqdn  (by the *.${ACME_SUBDOMAIN:+${ACME_SUBDOMAIN}.}${domain} wildcard)"
    log_cert_op "ACME_DEPLOY" "kind=$kind vmid=$vmid host=$hostname mode=$mode"

    # Always install to the canonical path as well, so services configured later
    # have a stable location to point at.
    acme_guest_exec "$kind" "$vmid" "mkdir -p '$std'" >/dev/null 2>&1
    acme_guest_push "$kind" "$vmid" "$live/fullchain.pem" "$std/fullchain.pem" || return 1
    acme_guest_push "$kind" "$vmid" "$live/privkey.pem"   "$std/privkey.pem"   || return 1
    acme_guest_push "$kind" "$vmid" "$live/chain.pem"     "$std/chain.pem"     >/dev/null 2>&1
    acme_guest_exec "$kind" "$vmid" "chmod 644 '$std/fullchain.pem' '$std/chain.pem' 2>/dev/null; chmod 640 '$std/privkey.pem'" >/dev/null 2>&1
    echo "Installed: $std/{fullchain,privkey,chain}.pem"

    # Record BEFORE the mode branch: a standard-mode target still needs the new
    # cert pushed on renewal, and an early return here would silently exclude it.
    # Recorded before the service loop runs, so `rename` here is the REQUEST.
    # A guest where nothing was renamed is corrected at the end of the loop.
    acme_record_target "$kind" "$vmid" "$hostname" "$mode" "$rename"

    [[ "$mode" == "standard" ]] && { echo "Mode     : standard (no service reconfigured)"; return 0; }

    # In-place: overwrite whatever the running service already reads.
    # Covers services installed in the guest AND proxies running as Docker
    # containers (immich, for example, terminates TLS in a caddy container).
    local found=0 actionable=0 fails=0 spec cpath kpath cfg reload label
    while IFS='|' read -r spec cpath kpath cfg; do
        [[ -z "$spec" ]] && continue
        found=$((found+1))
        label="$spec"
        echo ""
        echo "Service  : $label"

        if [[ "$cpath" == UNSUPPORTED ]]; then
            echo "  SKIPPED: certificate paths for this proxy are not discoverable"
            echo "           automatically. Point it at:"
            echo "             $std/fullchain.pem"
            echo "             $std/privkey.pem"
            fails=$((fails+1))
            continue
        fi
        if [[ "$cpath" == SELFMANAGED:* ]]; then
            echo "  SKIPPED: this proxy issues its OWN certificates (${cpath#SELFMANAGED:})."
            echo "           Nothing on disk to replace -- Caddy generates the cert"
            echo "           itself, so it would overwrite anything we wrote."
            echo ""
            echo "           To use this certificate instead, change its site block"
            echo "           from the internal/automatic issuer to explicit files:"
            echo "               tls $std/fullchain.pem $std/privkey.pem"
            echo "           and rename the site to a *.${ACME_SUBDOMAIN:-lan}.${domain} name,"
            echo "           then reload. Both files are already installed above."
            fails=$((fails+1))
            continue
        fi
        if [[ "$cpath" == NOTBOUND:* ]]; then
            echo "  SKIPPED: the container reads ${cpath#NOTBOUND:}"
            echo "           which is inside the image or a named volume, not a"
            echo "           bind mount, so it cannot be written from the guest."
            echo "           Bind-mount a host directory for its certificates,"
            echo "           or point it at $std/."
            fails=$((fails+1))
            continue
        fi

        actionable=$((actionable+1))
        echo "  cert   : $cpath"
        echo "  key    : $kpath"

        # back up inside the guest before overwriting
        acme_guest_exec "$kind" "$vmid" \
            "for f in '$cpath' '$kpath'; do [ -f \"\$f\" ] && cp -a \"\$f\" \"\$f.pvebak.$(date -u +%Y%m%dT%H%M%SZ)\"; done" >/dev/null 2>&1

        if ! acme_guest_push "$kind" "$vmid" "$live/fullchain.pem" "$cpath"; then
            echo "  FAILED writing $cpath"
            fails=$((fails+1)); continue
        fi
        if ! acme_guest_push "$kind" "$vmid" "$live/privkey.pem" "$kpath"; then
            echo "  FAILED writing $kpath"
            fails=$((fails+1)); continue
        fi
        acme_guest_exec "$kind" "$vmid" "chmod 644 '$cpath'; chmod 640 '$kpath'" >/dev/null 2>&1

        # confirm the bytes really landed
        local remote_sha local_sha
        remote_sha=$(acme_guest_exec "$kind" "$vmid" "sha256sum '$cpath' 2>/dev/null | cut -d' ' -f1" 2>/dev/null | tr -d '\r')
        local_sha=$(sha256sum "$live/fullchain.pem" | cut -d' ' -f1)
        if [[ "$remote_sha" != "$local_sha" ]]; then
            echo "  FAILED verification: certificate on disk does not match what was sent"
            echo "    sent   : ${local_sha:0:16}"
            echo "    on disk: ${remote_sha:0:16}"
            fails=$((fails+1)); continue
        fi
        echo "  written and verified"

        # Optionally repoint the virtual host at a name the certificate covers.
        # Done BEFORE the reload so the cert and the name change take effect in
        # one restart rather than leaving a window with a mismatched vhost.
        local renamed=0
        if [[ "$rename" == "1" ]]; then
            if acme_rewrite_vhost "$kind" "$vmid" "$spec" "$cfg" "$fqdn"; then
                renamed=1
            else
                fails=$((fails+1))
            fi
        fi

        case "$spec" in
            docker:*)
                local dname dflav
                dname=${spec#docker:}; dflav=${dname##*:}; dname=${dname%%:*}
                reload=$(acme_docker_reload_cmd "$dname" "$dflav" "$cfg")
                ;;
            *) reload=$(acme_service_reload_cmd "$spec") ;;
        esac

        local reloaded=0
        if [[ -n "$reload" ]]; then
            local rout
            if rout=$(acme_guest_exec "$kind" "$vmid" "$reload" 2>&1); then
                echo "  reload command succeeded"
                reloaded=1
            else
                echo "  RELOAD FAILED -- the service is still serving the old cert."
                echo "  Its config test probably rejected something. Output:"
                printf '%s\n' "$rout" | head -12 | sed 's/^/    | /'
                echo "  Backups are beside the originals as *.pvebak.*"
                fails=$((fails+1))
            fi
        fi

        # A successful reload is NOT proof of adoption, so check the live socket.
        if [[ "$reloaded" == 1 ]]; then
            local primary
            if [[ "$renamed" == 1 ]]; then
                primary="$fqdn"
            else
                primary=$(acme_service_names "$kind" "$vmid" "$spec" "$cfg" | head -1)
            fi
            # Some proxies declare no server name at all (Harbor's nginx uses
            # `server_name _`), and an empty SNI would skip verification
            # entirely. Fall back to the guest's own covered name: such a proxy
            # answers every SNI, so the handshake still proves adoption.
            [[ -z "$primary" ]] && primary="$fqdn"
            if ! acme_verify_service_cert "$kind" "$vmid" "$primary" 443; then
                fails=$((fails+1))
            fi
        fi

        # Only warn about coverage if we did not just fix it
        if [[ "$renamed" != 1 ]]; then
            acme_check_servername "$kind" "$vmid" "$spec" "$cfg" || true
        else
            echo "  reminder: add a DNS record  $fqdn -> this guest's LAN IP"
        fi
    done < <(acme_detect_all_tls "$kind" "$vmid")

    if [[ "$found" -eq 0 ]]; then
        echo ""
        echo "No TLS service found to replace."
        echo ""
        echo "Looked for: nginx, apache2 and caddy installed in the guest, and"
        echo "caddy/nginx/traefik running as a Docker container publishing :443."
        echo ""
        echo "The certificate IS installed at $std/ for manual wiring."
        echo "If this guest terminates TLS some other way, point that service at:"
        echo "  cert: $std/fullchain.pem"
        echo "  key : $std/privkey.pem"
        # Re-record as 'standard': the certificate is in place and should keep
        # being refreshed, but there is nothing to replace in-place. Leaving it
        # recorded as 'inplace' would make every future renewal report a failure
        # for a guest that simply has no web server.
        acme_record_target "$kind" "$vmid" "$hostname" standard 0
        echo ""
        echo "Recorded as 'standard' so renewals keep it fresh without reporting"
        echo "a failure each time."
        return 0
    fi

    # Every detected service was self-managed / unwritable, so there is nothing
    # in-place to do here -- ever. Record it as 'standard' (the certificate IS
    # installed at the canonical path) so renewals keep it fresh instead of
    # reporting the same unfixable failure every 60 days.
    if [[ "$actionable" -eq 0 && "$found" -gt 0 ]]; then
        acme_record_target "$kind" "$vmid" "$hostname" standard 0
        echo ""
        echo "RESULT: nothing here can be replaced in place (see above)."
        echo "Re-recorded as 'standard' so renewals refresh the certificate at"
        echo "$std/ without reporting this as a failure each time."
        return 0
    fi

    if [[ "$fails" -gt 0 ]]; then
        echo ""
        echo "RESULT: $fails of $found service(s) did not complete -- see above."
        return 1
    fi
    echo ""
    echo "RESULT: $found service(s) updated successfully."
    return 0
}

# Remember deploy targets so renewal can re-push without re-discovering them
acme_record_target() {
    local kind="$1" vmid="$2" hostname="$3" mode="$4" rename="${5:-0}"
    mkdir -p "$ACME_DIR"
    touch "$ACME_TARGETS_FILE"
    grep -vE "^${kind}:${vmid}:" "$ACME_TARGETS_FILE" > "$ACME_TARGETS_FILE.tmp" 2>/dev/null || true
    printf '%s:%s:%s:%s:%s\n' "$kind" "$vmid" "$hostname" "$mode" "$rename" >> "$ACME_TARGETS_FILE.tmp"
    mv -f "$ACME_TARGETS_FILE.tmp" "$ACME_TARGETS_FILE"
}

acme_list_targets() {
    [[ -s "$ACME_TARGETS_FILE" ]] || { echo "(no deploy targets recorded yet)"; return 0; }
    printf '%-5s %-6s %-24s %-9s %s\n' TYPE VMID HOSTNAME MODE RENAMED
    while IFS=':' read -r kind vmid hostname mode rename; do
        [[ -z "$kind" ]] && continue
        printf '%-5s %-6s %-24s %-9s %s\n' "$kind" "$vmid" "$hostname" "$mode" "${rename:-0}"
    done < "$ACME_TARGETS_FILE"
}
#######################################
# Renewal
#######################################

# Renew if due, then re-push to every recorded target. Safe to run from cron or
# a systemd timer; acme.sh exits cleanly when nothing is due.
acme_renew_all() {
    local force="${1:-0}"
    [[ -n "${ACME_DOMAIN:-}" ]] || { echo "no domain configured"; return 1; }

    # On a non-issuer host there is nothing to renew: fetch the issuer's current
    # certificate and re-push it to the recorded targets.
    if ! acme_is_issuer; then
        echo "=== Not the issuer (${ACME_ISSUER_HOST}); fetching instead of renewing ==="
        acme_fetch_from_issuer || return 1
        acme_redeploy_targets
        return $?
    fi

    acme_client_installed || { echo "acme.sh not installed"; return 1; }
    acme_load_token       || { echo "no Cloudflare token configured"; return 1; }

    local -a ecc_flag=()
    [[ "${ACME_KEY_TYPE:-ec-256}" == ec-* ]] && ecc_flag=(--ecc)
    local -a force_flag=()
    [[ "$force" == "1" ]] && force_flag=(--force)

    echo "=== Renewal ==="
    if [[ "$force" == "1" ]]; then
        echo "NOTE: a forced renewal consumes one of Let's Encrypt's 5"
        echo "      duplicate-certificates-per-week for this SAN set."
        echo ""
        acme_sh --renew -d "$ACME_DOMAIN" \
            "${ecc_flag[@]}" "${force_flag[@]}" 2>&1 \
            | grep -vE '^[A-Za-z0-9+/=]{60,}$|^-----(BEGIN|END)' | tail -15
    else
        acme_sh --cron 2>&1 | tail -10
    fi

    echo ""
    if ! acme_validate_local_cert >/dev/null 2>&1; then
        echo "Local certificate is not usable after renewal; not deploying."
        return 1
    fi
    acme_cert_summary | sed 's/^/  /'

    acme_redeploy_targets
    return $?
}

# Re-push the current certificate to every recorded target.
acme_redeploy_targets() {
    echo ""
    echo "=== Re-deploying to recorded targets ==="
    if [[ ! -s "$ACME_TARGETS_FILE" ]]; then
        echo "(none recorded)"
        return 0
    fi

    local rc=0 kind vmid hostname mode rename
    while IFS=':' read -r kind vmid hostname mode rename; do
        [[ -z "$kind" ]] && continue
        echo ""
        echo "--- $kind/$vmid ($hostname) ---"
        # Renewal never renames a vhost: that is a one-off migration decision,
        # not something to redo unattended every 60 days.
        if [[ "$kind" == "papi" ]]; then
            if ! acme_deploy_proxmox_api "$vmid" "$hostname"; then
                echo "  deploy FAILED"
                rc=1
            fi
        elif ! acme_deploy_to_guest "$kind" "$vmid" "${mode:-inplace}" 0; then
            echo "  deploy FAILED"
            rc=1
        fi
    done < "$ACME_TARGETS_FILE"
    return $rc
}

# Hint text: a publicly-trusted cert is useless until the names resolve to the
# guests' LAN addresses. This is the step people forget.
acme_dns_hint() {
    local domain="${ACME_DOMAIN:-example.com}" sub="${ACME_SUBDOMAIN:-lan}"
    cat << EOF
The certificate is valid for *.${sub}.${domain}, but browsers still need those
names to resolve to your guests' LAN addresses. DNS-01 validated against the
public zone; it created no address records.

Add split-horizon records on your internal resolver, one per guest, e.g.:

    gitea.${sub}.${domain}       ->  10.x.x.x
    nextcloud.${sub}.${domain}   ->  10.x.x.x

On AdGuard Home: Filters -> DNS rewrites. Note that AdGuard's rewrite entries
need "enabled: true"; an entry without it is stored but silently inert.

Do NOT create a wildcard rewrite for *.${domain} itself -- it would shadow every
public record in that zone (www, mail, MX targets) for every client on the LAN.
Keep internal names under the .${sub}. namespace.

Avoid publishing RFC1918 addresses in the public zone instead: public resolvers
strip private answers as DNS-rebinding protection, so it breaks unpredictably.

If a name still fails to resolve after you add it, flush the caches on any
forwarding resolver in front of AdGuard -- a cached NXDOMAIN will persist.
EOF
}

#######################################
# Menus
#######################################

acme_config_menu() {
    while true; do
        local tok_state="NOT SET"
        acme_have_token && tok_state="set (hidden)"

        local choice
        choice=$(show_menu "ACME / Cloudflare Configuration" \
            "Configure publicly-trusted certificate issuance.\n\nSelect a setting:" \
            "1" "Cloudflare API token [$tok_state]" \
            "2" "Public domain (${ACME_DOMAIN:-<unset>})" \
            "3" "Internal subdomain (${ACME_SUBDOMAIN:-<unset>})" \
            "4" "Account email (${ACME_EMAIL:-<unset>})" \
            "5" "Key type (${ACME_KEY_TYPE:-ec-256})" \
            "6" "Test token against Cloudflare" \
            "7" "Issuer host (${ACME_ISSUER_HOST:-<this host issues>})" \
            "8" "Local cert source dir (${ACME_CERT_SOURCE_DIR:-<acme.sh live dir>})" \
            "0" "Back")

        case "$choice" in
            1)
                # Instructions go in their own message box. The password box
                # itself must stay short: show_password renders a fixed 10-row
                # dialog, and a prompt too tall for it makes whiptail emit an
                # error that would be captured as the entered value.
                show_scrollmsg "Cloudflare API Token" \
"Create the token in the Cloudflare dashboard:

  My Profile -> API Tokens -> Create Token -> Create Custom Token

  Permissions    : Zone -> DNS   -> Edit
                   Zone -> Zone  -> Read
  Zone Resources : Include -> Specific zone -> your domain
  TTL            : leave blank (an expiring token silently breaks
                   unattended renewal)

Do NOT use a Global API Key, and do not grant Account-level scopes.

The token is stored at
  $ACME_TOKEN_FILE
with mode 0600, on this host only. It is never copied to guests.

Press OK, then paste the token on the next screen."
                local token
                token=$(show_password "Cloudflare API Token" "Paste the API token:")
                if [[ -n "$token" ]]; then
                    local saveout
                    if saveout=$(acme_save_token "$token" 2>&1); then
                        local res
                        res=$(acme_verify_token "${ACME_DOMAIN:-}")
                        show_msg "Token Saved" "Stored at:\n$ACME_TOKEN_FILE (mode 0600)\n\n$res"
                    else
                        show_msg "Token Rejected" "$saveout"
                    fi
                fi
                ;;
            2)
                local v
                v=$(show_input "Public Domain" \
"Enter the public domain you own and host on Cloudflare.

This must be a real, registrable domain. A reserved pseudo-TLD such as
.lan, .local or .home can NEVER be certified by a public CA, because
there is no way to prove ownership of it." "${ACME_DOMAIN:-}")
                if [[ -n "$v" ]]; then
                    if [[ "$v" =~ \.(lan|local|home|internal|corp|localdomain)$ ]]; then
                        show_msg "Not Usable" \
"'$v' ends in a reserved pseudo-TLD.\n\nNo public CA can issue for it. Use a domain you have registered and delegated to Cloudflare."
                    else
                        save_config "ACME_DOMAIN" "$v" && ACME_DOMAIN="$v"
                    fi
                fi
                ;;
            3)
                local v
                v=$(show_input "Internal Subdomain" \
"Label for internal hosts, giving <guest>.<label>.<domain>.

Keeping internal names under one label means a single wildcard covers
them all, and your internal records can never shadow public ones.
Leave empty to place guests directly on the domain." "${ACME_SUBDOMAIN:-lan}")
                save_config "ACME_SUBDOMAIN" "$v" && ACME_SUBDOMAIN="$v"
                ;;
            4)
                local v
                v=$(show_input "Account Email" "Email for the ACME account (expiry notices, account recovery):" "${ACME_EMAIL:-}")
                [[ -n "$v" ]] && save_config "ACME_EMAIL" "$v" && ACME_EMAIL="$v"
                ;;
            5)
                local v
                v=$(show_menu "Key Type" "Select certificate key type:" \
                    "ec-256" "ECDSA P-256 (recommended: faster handshakes)" \
                    "ec-384" "ECDSA P-384" \
                    "2048"   "RSA 2048 (for legacy clients only)" \
                    "4096"   "RSA 4096")
                [[ -n "$v" ]] && save_config "ACME_KEY_TYPE" "$v" && ACME_KEY_TYPE="$v"
                ;;
            6)
                local res
                res=$(acme_verify_token "${ACME_DOMAIN:-}" 2>&1)
                show_scrollmsg "Token Test" "$res"
                ;;
            7)
                local v
                v=$(show_input "Issuer Host" \
"Which host issues the certificate for the whole fleet?

Leave EMPTY if THIS host is the issuer (it holds the Cloudflare
token and runs the ACME client).

Set it to the issuer's hostname or IP on every other host. Those
hosts then only deploy: they fetch the certificate over SSH and
never issue their own. Running an issuer per node consumes the
5-duplicate-certificates-per-week budget, creates competing
renewal schedules, and lets two hosts fight over one guest." "${ACME_ISSUER_HOST:-}")
                save_config "ACME_ISSUER_HOST" "$v" && ACME_ISSUER_HOST="$v"
                if [[ -n "$v" ]]; then
                    local d
                    d=$(show_input "Issuer Certificate Directory" \
"Path on ${v} holding fullchain.pem / privkey.pem / chain.pem:" \
"${ACME_ISSUER_DIR:-/etc/ssl/homelab/${ACME_DOMAIN}}")
                    save_config "ACME_ISSUER_DIR" "$d" && ACME_ISSUER_DIR="$d"
                fi
                ;;
            8)
                local v
                v=$(show_input "Local Certificate Source" \
"Read the deployable certificate from this local directory instead
of the tool's own acme.sh live directory.

Use this when a standalone acme.sh already manages the certificate
outside the tool, e.g. /etc/ssl/homelab/${ACME_DOMAIN:-<domain>}.

Leave empty to use the tool's own live directory." "${ACME_CERT_SOURCE_DIR:-}")
                save_config "ACME_CERT_SOURCE_DIR" "$v" && ACME_CERT_SOURCE_DIR="$v"
                ;;
            0|"") return ;;
        esac
    done
}
# Build a list of running guests of one kind. Echoes "vmid|name" lines.
#
# Column layouts differ and are not fixed-width safe:
#   pct list  -> "VMID Status Lock Name", but Lock is usually EMPTY, so the row
#                collapses to 3 fields and the name is the LAST field.
#   pve_list_vms -> "VMID Status Name MEM" (it already reorders qm list).
# Taking $1/$2 plus the name by position-from-the-correct-end handles both,
# including a container that happens to be locked mid-backup.
acme_running_guests() {
    local kind="$1" listing
    case "$kind" in
        lxc) listing=$(pve_list_containers) ;;
        vm)  listing=$(pve_list_vms) ;;
        *)   return 1 ;;
    esac
    [[ -z "$listing" ]] && return 1

    if [[ "$kind" == "lxc" ]]; then
        # name is the last field whether or not Lock is populated
        awk 'NF>=3 && $1 ~ /^[0-9]+$/ && $2=="running" { print $1 "|" $NF }' <<< "$listing"
    else
        awk 'NF>=3 && $1 ~ /^[0-9]+$/ && $2=="running" { print $1 "|" $3 }' <<< "$listing"
    fi
}

# Let the user pick one or more running guests, then deploy to each.
#
# Output is written to a log file and ALWAYS shown afterwards, pass or fail.
# Piping straight into show_progress_box lost the exit status and, when a guest
# failed early, closed the box before anything could be read.
acme_deploy_menu() {
    local kind="$1"
    local label="LXC containers"; [[ "$kind" == "vm" ]] && label="VMs"

    if [[ -z "$CURRENT_PVE" ]]; then
        show_msg "Not Connected" "Connect to a PVE server first."
        return
    fi
    # A deployer host may not have the certificate yet, or may be holding a
    # stale copy; refresh from the issuer before every deployment.
    if ! acme_is_issuer; then
        local fout
        fout=$(acme_fetch_from_issuer 2>&1)
        if [[ $? -ne 0 ]]; then
            show_scrollmsg "Cannot Fetch Certificate" "$fout"
            return
        fi
    fi

    if ! acme_cert_present; then
        show_msg "No Certificate" \
"No certificate is available at:
  $(acme_source_dir)

$(acme_is_issuer && echo "This host is the issuer -- use 'Issue certificate' first." || echo "Fetch it from the issuer (${ACME_ISSUER_HOST}) with menu option F.")"
        return
    fi
    if ! acme_validate_local_cert >/dev/null 2>&1; then
        show_msg "Certificate Unusable" "The local certificate cannot be deployed:\n\n$(acme_validate_local_cert 2>&1)"
        return
    fi

    local node; node=$(acme_connected_node)

    # Cluster-wide: guests on other nodes are reachable, so list them all and
    # label each with its owning node.
    local -a items=()
    local g gkind gvmid gname gstatus gnode
    local -a rows=(); local row
    mapfile -t rows < <(acme_cluster_guests)
    for row in "${rows[@]}"; do
        IFS='|' read -r gkind gvmid gname gstatus gnode <<< "$row"
        [[ -z "$gvmid" ]] && continue
        [[ "$gkind" != "$kind" ]] && continue
        [[ "$gstatus" != "running" ]] && continue
        items+=("$gvmid" "$(printf '%-22s [%s]' "$gname" "$gnode")" "off")
    done

    if [[ ${#items[@]} -eq 0 ]]; then
        show_msg "None Found" \
"No running $label anywhere in the cluster.

Checked every node listed in /etc/pve/.members. Start the guest first,
or check that the other nodes are online and reachable."
        return
    fi

    local selected
    selected=$(show_checklist "Deploy Certificate" \
"Certificate: ${ACME_DOMAIN}   (connected via ${node:-?})

All running $label in the cluster are listed, with their owning node.
Guests on other nodes are reached over the cluster SSH trust.

Select targets:" "${items[@]}")
    [[ -z "$selected" ]] && return

    local mode
    mode=$(show_menu "Deployment Mode" \
"How should the certificate be applied?" \
        "inplace"  "Replace the cert the service already uses (recommended)" \
        "standard" "Install to /etc/ssl/pve-manager only, change nothing")
    [[ -z "$mode" ]] && return

    # Replacing the certificate is only half the job when the vhost is still
    # named <app>.myhome.lan: no public cert can cover that, so clients keep
    # seeing a name mismatch. Offer to repoint it.
    local rename=0
    if [[ "$mode" == "inplace" ]]; then
        if show_yesno "Rewrite Virtual Host Name?" \
"Also repoint each service's virtual host at a name this certificate covers,
i.e. <guest>.${ACME_SUBDOMAIN:-lan}.${ACME_DOMAIN} ?

  YES  the new name works with a green padlock straight away.
       The OLD name stops working, so update bookmarks and any
       mobile apps that use it. A backup of each config is kept
       in the guest as *.pvebak.<timestamp>.

  NO   only the certificate is replaced. The service will load it,
       but clients using the old name still see a mismatch.

Either way you must add DNS for the new name on your internal resolver."; then
            rename=1
        fi
    fi

    local stamp logf
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    logf="$LOG_DIR/acme-deploy-${stamp}.log"
    : > "$logf" 2>/dev/null || logf="/tmp/acme-deploy-${stamp}.log"

    show_info "Deploying" "Deploying ${ACME_DOMAIN} certificate...\n\nLog: $logf"

    local id ok=0 fail=0 failed_ids=""
    {
        echo "ACME certificate deployment"
        echo "  when      : $(date -Iseconds)"
        echo "  node      : ${node:-?}"
        echo "  kind      : $kind"
        echo "  mode      : $mode"
        echo "  rename    : $([[ "$rename" == 1 ]] && echo 'yes - vhost repointed at the new domain' || echo 'no')"
        echo "  domain    : ${ACME_DOMAIN}"
        echo "  targets   : $(tr -d '\"' <<<"$selected")"
        echo "=================================================================="
    } >> "$logf"

    for id in $selected; do
        id="${id//\"/}"
        {
            echo ""
            echo "################ $kind/$id ################"
        } >> "$logf"
        if acme_deploy_to_guest "$kind" "$id" "$mode" "$rename" >> "$logf" 2>&1; then
            ok=$((ok+1))
            echo "[OK] $kind/$id" >> "$logf"
        else
            fail=$((fail+1)); failed_ids="$failed_ids $id"
            echo "[FAILED] $kind/$id" >> "$logf"
        fi
    done

    {
        echo ""
        echo "=================================================================="
        echo "Succeeded: $ok    Failed: $fail"
        if [[ "$fail" -gt 0 ]]; then
            echo "Failed targets:$failed_ids"
            echo ""
            echo "Scroll up for the reason against each guest."
        fi
        if [[ "$ok" -gt 0 ]]; then
            echo ""
            acme_dns_hint
        fi
    } >> "$logf"

    # Always show the full transcript, pass or fail.
    show_textbox "Deployment Log ($ok ok, $fail failed)" "$logf"

    # And make a failure impossible to miss.
    if [[ "$fail" -gt 0 ]]; then
        local reasons
        reasons=$(grep -E '^(CANNOT DEPLOY|  SKIPPED|  FAILED|  RELOAD FAILED|No TLS service found)' "$logf" \
                  | sed 's/^ *//' | sort -u | head -8)
        show_scrollmsg "Deployment FAILED for$failed_ids" \
"$fail of $((ok+fail)) target(s) failed.

Reasons seen:
$reasons

Full log:
  $logf

Review it with:
  less $logf"
    else
        show_msg "Deployment Complete" \
"$ok target(s) updated successfully.

Remember the names must resolve to each guest's LAN IP on your internal
resolver, or browsers cannot reach them. See 'Show DNS setup requirements'.

Log: $logf"
    fi
}

#######################################
# PROXMOX-PRODUCT TARGETS (certificate API)
#
# Proxmox Datacenter Manager and Proxmox Backup Server run as VMs whose TLS is
# owned by their own proxy, and they expose a certificate API for replacing it:
#   POST /api2/json/nodes/localhost/certificates/custom
#        certificates=<PEM chain>  key=<PEM key>  force=1  restart=1
# That is the supported path. It needs no guest agent and no SSH into the VM,
# and the product keeps managing the certificate files itself.
#
# Recorded as kind "papi". Connection details live in an env file per target,
# $ACME_DIR/api/<vmid>.env (mode 0600), which may be a symlink to wherever the
# secret is kept. Keys:
#   PX_URL           https://<host>:<port>          (PDM 8443, PBS 8007)
#   PX_SCHEME        PDMAPIToken | PBSAPIToken      (default by product)
#   PX_TOKEN_ID      user@realm!tokenid
#   PX_TOKEN_SECRET  <uuid>
# PDM_URL / PDM_TOKEN_ID / PDM_TOKEN_SECRET are accepted as aliases.
#
# The token needs System.Modify on / . With Privilege Separation enabled that
# must be granted to the TOKEN (an "API Token Permission"); a grant on the user
# does not flow through, and the token then authenticates with every privilege
# false -- /access/permissions reports it plainly.
#######################################

acme_papi_envfile() { echo "$ACME_DIR/api/$1.env"; }

# Load a target's connection details into PX_* variables.
acme_papi_load() {
    local vmid="$1" f
    f=$(acme_papi_envfile "$vmid")
    PX_URL=""; PX_SCHEME=""; PX_TOKEN_ID=""; PX_TOKEN_SECRET=""
    PDM_URL=""; PDM_TOKEN_ID=""; PDM_TOKEN_SECRET=""
    PBS_URL=""; PBS_TOKEN_ID=""; PBS_TOKEN_SECRET=""
    if [[ ! -r "$f" ]]; then
        echo "no API credentials for target $vmid (expected $f)"
        return 1
    fi
    # shellcheck disable=SC1090
    source "$f"
    if [[ -n "$PDM_TOKEN_ID" ]]; then
        : "${PX_URL:=$PDM_URL}" "${PX_TOKEN_ID:=$PDM_TOKEN_ID}" "${PX_TOKEN_SECRET:=$PDM_TOKEN_SECRET}" "${PX_SCHEME:=PDMAPIToken}"
    elif [[ -n "$PBS_TOKEN_ID" ]]; then
        : "${PX_URL:=$PBS_URL}" "${PX_TOKEN_ID:=$PBS_TOKEN_ID}" "${PX_TOKEN_SECRET:=$PBS_TOKEN_SECRET}" "${PX_SCHEME:=PBSAPIToken}"
    fi
    : "${PX_SCHEME:=PDMAPIToken}"
    local missing=""
    [[ -z "$PX_URL" ]]          && missing+=" PX_URL"
    [[ -z "$PX_TOKEN_ID" ]]     && missing+=" PX_TOKEN_ID"
    [[ -z "$PX_TOKEN_SECRET" ]] && missing+=" PX_TOKEN_SECRET"
    if [[ -n "$missing" ]]; then
        echo "incomplete API credentials in $f:$missing"
        return 1
    fi
    PX_URL="${PX_URL%/}"
    return 0
}

# Call the product API. Echoes the body; the HTTP status goes to PX_HTTP.
acme_papi_call() {
    local method="$1" path="$2"; shift 2
    local out
    out=$(curl -sk -m 60 -X "$method" \
            -H "Authorization: ${PX_SCHEME}=${PX_TOKEN_ID}:${PX_TOKEN_SECRET}" \
            -w $'\n%{http_code}' "$@" "${PX_URL}/api2/json${path}" < /dev/null 2>/dev/null)
    PX_HTTP="${out##*$'\n'}"
    printf '%s' "${out%$'\n'*}"
}

# Serial currently served on the product's TLS port, probed with a real handshake.
acme_papi_live_serial() {
    local sni="$1" hostport="${PX_URL#https://}"
    hostport="${hostport%%/*}"
    echo | timeout 10 openssl s_client -connect "$hostport" -servername "$sni" 2>/dev/null \
        | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}

acme_deploy_proxmox_api() {
    local vmid="$1" name="${2:-guest$1}"
    local live; live=$(acme_source_dir)
    local fqdn; fqdn=$(acme_guest_fqdn "$name")

    local problem
    if ! problem=$(acme_validate_local_cert); then
        echo "CANNOT DEPLOY: $problem"; return 1
    fi
    # Load credentials in THIS shell. Wrapping this in $(...) runs it in a
    # subshell and discards the PX_* variables it sets, so the calls below
    # silently use whatever an earlier target left behind -- one product's
    # token for another's key, or none at all during unattended renewal.
    local msgf; msgf=$(mktemp)
    if ! acme_papi_load "$vmid" >"$msgf" 2>&1; then
        echo "CANNOT DEPLOY to papi/$vmid: $(cat "$msgf")"
        echo ""
        echo "Create $(acme_papi_envfile "$vmid") (mode 0600) with PX_URL,"
        echo "PX_TOKEN_ID and PX_TOKEN_SECRET, or register the target again."
        rm -f "$msgf"
        return 1
    fi
    rm -f "$msgf"

    echo "Target   : papi/$vmid ($name) via ${PX_URL}"
    echo "Covered  : $fqdn"

    # Authenticate and check rights before sending a private key anywhere.
    acme_papi_call GET /version >/dev/null
    if [[ "$PX_HTTP" != 200 ]]; then
        echo "CANNOT DEPLOY: API rejected the token (http $PX_HTTP)."
        echo "Check the token ID/secret and the ${PX_SCHEME} scheme."
        return 1
    fi
    local perms
    perms=$(acme_papi_call GET /access/permissions)
    if ! grep -q '"System.Modify":true' <<<"$perms"; then
        echo "CANNOT DEPLOY: the token authenticates but lacks System.Modify on /."
        echo ""
        echo "With Privilege Separation enabled, the grant must be an"
        echo "'API Token Permission' for ${PX_TOKEN_ID} (role Administrator,"
        echo "path /). A permission on the user does not reach the token."
        echo "Or edit the token and untick Privilege Separation."
        return 1
    fi

    local want
    want=$(openssl x509 -in "$live/fullchain.pem" -noout -serial | cut -d= -f2)

    # Idempotent: uploading restarts the product's proxy, so skip when current.
    if [[ "$(acme_papi_live_serial "$fqdn")" == "$want" ]]; then
        echo "  already serving this certificate -- nothing to do"
        acme_record_target papi "$vmid" "$name" api 0
        return 0
    fi

    local body
    body=$(acme_papi_call POST /nodes/localhost/certificates/custom \
            --data-urlencode "certificates@$live/fullchain.pem" \
            --data-urlencode "key@$live/privkey.pem" \
            --data-urlencode "force=1" \
            --data-urlencode "restart=1")
    if [[ "$PX_HTTP" != 200 ]]; then
        echo "  UPLOAD FAILED (http $PX_HTTP):"
        printf '%s\n' "$body" | head -8 | sed 's/^/    | /'
        return 1
    fi
    echo "  uploaded; the product's proxy is restarting"

    local i got=""
    for i in $(seq 1 15); do
        got=$(acme_papi_live_serial "$fqdn")
        [[ "$got" == "$want" ]] && break
        sleep 2
    done
    if [[ "$got" != "$want" ]]; then
        echo "  NOT ADOPTED: still serving ${got:-<no certificate>}"
        echo "    expected serial: ${want:0:20}"
        echo "    Rollback: DELETE ${PX_URL}/api2/json/nodes/localhost/certificates/custom"
        echo "    makes the product regenerate its own self-signed certificate."
        return 1
    fi
    echo "  verified: ${PX_URL#https://} is serving the new certificate (SNI $fqdn)"
    acme_record_target papi "$vmid" "$name" api 0
    echo ""
    echo "RESULT: 1 service(s) updated successfully."
    return 0
}

# Record a Proxmox-product target and link its credentials into place.
acme_register_proxmox_api() {
    local vmid="$1" name="$2" envsrc="$3"
    [[ -r "$envsrc" ]] || { echo "credentials file not readable: $envsrc"; return 1; }
    local perm; perm=$(stat -c %a "$envsrc" 2>/dev/null)
    if [[ "$perm" != 600 && "$perm" != 400 ]]; then
        echo "refusing: $envsrc is mode $perm; a token secret must be 0600"
        return 1
    fi
    mkdir -p "$ACME_DIR/api"; chmod 700 "$ACME_DIR/api"
    ln -sfn "$envsrc" "$(acme_papi_envfile "$vmid")"
    acme_papi_load "$vmid" || return 1
    echo "registered papi/$vmid ($name) -> $envsrc"
    acme_deploy_proxmox_api "$vmid" "$name"
}

# Survey every running guest in the cluster and report what TLS terminator it
# has, so it is obvious up front which apps "replace" can handle and which need
# manual wiring. Read-only.
acme_cluster_scan() {
    local gkind gvmid gname gstatus gnode det line spec cpath kpath cfg
    echo "Cluster TLS survey"
    echo "  certificate: ${ACME_DOMAIN:-<unset>}  (*.${ACME_SUBDOMAIN:-lan}.${ACME_DOMAIN:-?})"
    echo "  scanning every running guest on every node; this takes a moment."
    echo "======================================================================"
    local -a rows=()
    mapfile -t rows < <(acme_cluster_guests)
    local row
    for row in "${rows[@]}"; do
        IFS='|' read -r gkind gvmid gname gstatus gnode <<< "$row"
        [[ -z "$gvmid" ]] && continue
        [[ "$gstatus" != "running" ]] && continue
        printf '\n%-4s %-6s %-20s [%s]\n' "$gkind" "$gvmid" "$gname" "$gnode"

        det=$(acme_detect_all_tls "$gkind" "$gvmid" 2>/dev/null)
        if [[ -z "$det" ]]; then
            echo "      no nginx/apache2/caddy, and no caddy/nginx/traefik container on :443"
            echo "      -> 'standard' mode only (cert installed, wire it up yourself)"
            continue
        fi
        while IFS='|' read -r spec cpath kpath cfg; do
            [[ -z "$spec" ]] && continue
            case "$cpath" in
                UNSUPPORTED) echo "      $spec -> cert paths not discoverable; manual" ;;
                SELFMANAGED:*) echo "      $spec -> issues its own certs (${cpath#SELFMANAGED:}); needs a Caddyfile change" ;;
                NOTBOUND:*)  echo "      $spec -> reads ${cpath#NOTBOUND:} (not bind-mounted); manual" ;;
                *)
                    echo "      $spec"
                    echo "        cert: $cpath"
                    local nm
                    nm=$(acme_service_names "$gkind" "$gvmid" "$spec" "$cfg" 2>/dev/null | head -3 | tr '\n' ' ')
                    echo "        names: ${nm:-<none found>}"
                    if [[ -n "$nm" ]] && ! grep -q "$ACME_DOMAIN" <<<"$nm"; then
                        echo "        NOTE: not covered by the certificate -- use the vhost rename option"
                    fi
                    ;;
            esac
        done <<< "$det"
    done
    echo ""
    echo "======================================================================"
    echo "Done."
}

# Main ACME menu
acme_menu() {
    while true; do
        local cert_line="not issued"
        if acme_cert_present; then
            local exp
            exp=$(openssl x509 -in "$(acme_live_dir)/fullchain.pem" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
            cert_line="issued, expires $exp"
        fi
        local client_line="not installed"
        acme_client_installed && client_line="$(acme_client_version)"
        local tok_line="NOT SET"
        acme_have_token && tok_line="set"

        local role_line="ISSUER (this host issues and renews)"
        acme_is_issuer || role_line="DEPLOYER (issuer: ${ACME_ISSUER_HOST})"
        local src_line="$(acme_source_dir)"

        local status="Domain:   ${ACME_DOMAIN:-<unset>}
Internal: *.${ACME_SUBDOMAIN:-lan}.${ACME_DOMAIN:-<unset>}
Role:     $role_line
Source:   $src_line
Token:    $tok_line
Client:   $client_line
Cert:     $cert_line"

        local choice
        choice=$(show_menu "Cloudflare / Let's Encrypt Certificates" \
            "$status\n\nSelect an operation:" \
            "1" "Configure (token, domain, email)" \
            "2" "Install / update acme.sh client" \
            "3" "Run pre-flight checks" \
            "4" "Issue certificate - STAGING (dry run, no rate-limit cost)" \
            "5" "Issue certificate - PRODUCTION" \
            "6" "Show certificate details" \
            "7" "Deploy to LXC containers (any node)" \
            "8" "Deploy to VMs (any node)" \
            "9" "Renew now and re-deploy to all recorded targets" \
            "F" "Fetch certificate from the issuer host" \
            "S" "Scan cluster: what TLS service each guest has" \
            "T" "List recorded deploy targets" \
            "P" "Register a Proxmox product (PDM/PBS) via its API" \
            "D" "Show DNS setup requirements" \
            "0" "Back")

        case "$choice" in
            1) acme_config_menu ;;
            2) ( acme_install_client ) | show_progress_box "Install acme.sh" ;;
            3)
                if [[ -z "${ACME_DOMAIN:-}" ]]; then
                    show_msg "Not Configured" "Set the domain and token first (option 1)."
                    continue
                fi
                ( acme_preflight ) | show_progress_box "Pre-flight Checks"
                ;;
            4|5)
                local staging=1 what="STAGING"
                [[ "$choice" == "5" ]] && { staging=0; what="PRODUCTION"; }

                if [[ -z "${ACME_DOMAIN:-}" ]] || ! acme_have_token; then
                    show_msg "Not Configured" "Set the domain and Cloudflare token first (option 1)."
                    continue
                fi
                if ! acme_client_installed; then
                    show_msg "No Client" "acme.sh is not installed. Run option 2 first."
                    continue
                fi
                if [[ "$staging" == "0" ]]; then
                    if ! show_yesno "Production Issuance" \
"Issue a PRODUCTION certificate for:

  ${ACME_DOMAIN}
  *.${ACME_DOMAIN}${ACME_SUBDOMAIN:+
  *.${ACME_SUBDOMAIN}.${ACME_DOMAIN}}

Let's Encrypt allows only 5 identical certificates per week, so
avoid repeated production issuance. Run STAGING first if unsure.

Continue?"; then
                        continue
                    fi
                fi
                ( acme_issue "$staging" ) | show_progress_box "Issue Certificate ($what)"
                ;;
            6)
                local info
                info=$(acme_cert_summary 2>&1)
                show_scrollmsg "Certificate Details" "$info"
                ;;
            7) acme_deploy_menu lxc ;;
            8) acme_deploy_menu vm ;;
            9)
                if ! show_yesno "Renew" "Renew if due, then re-deploy to all recorded targets?"; then
                    continue
                fi
                ( acme_renew_all 0 ) | show_progress_box "Renew and Re-deploy"
                ;;
            F|f)
                if acme_is_issuer; then
                    show_msg "This Host Is The Issuer" \
"No issuer host is configured, so this host issues its own certificate
and there is nothing to fetch.

If another host should be the issuer, set it in Configure -> option 7."
                    continue
                fi
                ( acme_fetch_from_issuer ) | show_progress_box "Fetch From Issuer"
                ;;
            S|s)
                if [[ -z "${ACME_DOMAIN:-}" ]]; then
                    show_msg "Not Configured" "Set the domain first (option 1)."
                    continue
                fi
                local scanlog="$LOG_DIR/acme-scan-$(date -u +%Y%m%dT%H%M%SZ).log"
                : > "$scanlog" 2>/dev/null || scanlog="/tmp/acme-scan-$$.log"
                show_info "Scanning" "Surveying every running guest in the cluster..."
                acme_cluster_scan > "$scanlog" 2>&1
                show_textbox "Cluster TLS Survey" "$scanlog"
                ;;
            T|t)
                local t
                t=$(acme_list_targets 2>&1)
                show_scrollmsg "Deploy Targets" "$t"
                ;;
            P|p)
                if ! acme_cert_present; then
                    show_msg "No Certificate" "No certificate available at $(acme_source_dir)."
                    continue
                fi
                show_scrollmsg "Proxmox Product via API" \
"Proxmox Datacenter Manager and Proxmox Backup Server replace their own
certificate through their API, so no guest agent or SSH is needed.

1. In the product's UI create an API token (e.g. root@pam!certdeploy).
2. Give the TOKEN System.Modify on / : either untick Privilege
   Separation, or add an 'API Token Permission' (not a user
   permission) with role Administrator on path /.
3. Save a 0600 env file on this host, e.g. /etc/homelab/pdm-token.env:

     PX_URL='https://<host>:8443'          (PBS: port 8007)
     PX_SCHEME='PDMAPIToken'               (PBS: PBSAPIToken)
     PX_TOKEN_ID='root@pam!certdeploy'
     PX_TOKEN_SECRET='<secret>'

   Quote the values: the token ID contains '!'."
                local pv pn pe
                pv=$(show_input "VM ID" "VM ID of the product (used as the target key):" "")
                [[ -z "$pv" ]] && continue
                pn=$(show_input "Name" "Short name; the certificate name will be <name>.${ACME_SUBDOMAIN:-lan}.${ACME_DOMAIN}:" "")
                [[ -z "$pn" ]] && continue
                pe=$(show_input "Credentials File" "Path to the 0600 env file:" "/etc/homelab/${pn}-token.env")
                [[ -z "$pe" ]] && continue
                local plog="$LOG_DIR/acme-papi-$(date -u +%Y%m%dT%H%M%SZ).log"
                acme_register_proxmox_api "$pv" "$pn" "$pe" > "$plog" 2>&1
                show_textbox "Proxmox Product Deployment" "$plog"
                ;;
            D|d) show_scrollmsg "DNS Requirements" "$(acme_dns_hint)" ;;
            0|"") return ;;
        esac
    done
}

# Certificate Management Menu
certificate_menu() {
    while true; do
        local ca_status="Not initialized"
        [[ -f "$CA_DIR/ca.key" ]] && ca_status="Initialized"

        local choice
        choice=$(show_menu "Certificate Management" "CA Status: $ca_status\n\nSelect an operation:" \
            "1" "Initialize Certificate Authority" \
            "2" "View CA certificate" \
            "3" "Generate certificate for container" \
            "4" "Generate certificates for all containers" \
            "5" "Deploy certificate to container" \
            "6" "Deploy certificates to all containers" \
            "7" "List generated certificates" \
            "8" "Export CA certificate" \
            "9" "Renew certificate" \
            "C" "Cloudflare / Let's Encrypt (publicly-trusted certs)" \
            "0" "Back to main menu")

        case "$choice" in
            1)
                if [[ -f "$CA_DIR/ca.key" ]]; then
                    if ! show_yesno "CA Exists" "Certificate Authority already exists.\n\nRe-initialize? WARNING: This will invalidate all existing certificates!"; then
                        continue
                    fi
                    rm -rf "$CA_DIR"/*
                    mkdir -p "$CERTS_DIR"
                fi

                # Prompt for CA Common Name
                local ca_cn
                ca_cn=$(show_input "CA Common Name" "Enter the Common Name (CN) for the CA certificate:" "PVE Manager CA")
                [[ -z "$ca_cn" ]] && continue

                # Prompt for CA Organization
                local ca_org
                ca_org=$(show_input "CA Organization" "Enter the Organization (O) for the CA certificate:" "PVE Manager")
                [[ -z "$ca_org" ]] && continue

                (
                    echo "Initializing Certificate Authority..."
                    echo "  Common Name: $ca_cn"
                    echo "  Organization: $ca_org"
                    echo ""
                    ca_init "$ca_cn" "$ca_org"
                    echo ""
                    echo "CA initialized successfully!"
                    echo ""
                    echo "CA Certificate:"
                    openssl x509 -in "$CA_DIR/ca.crt" -noout -subject -dates
                ) | show_progress_box "Initialize CA"
                ;;
            2)
                if [[ ! -f "$CA_DIR/ca.crt" ]]; then
                    show_msg "No CA" "CA not initialized. Please initialize first."
                    continue
                fi

                local ca_info
                ca_info=$(openssl x509 -in "$CA_DIR/ca.crt" -text -noout)
                show_scrollmsg "CA Certificate" "$ca_info"
                ;;
            3)
                if [[ ! -f "$CA_DIR/ca.key" ]]; then
                    show_msg "No CA" "CA not initialized. Please initialize first."
                    continue
                fi

                if [[ -z "$CURRENT_PVE" ]]; then
                    show_msg "Not Connected" "Please connect to a PVE server first."
                    continue
                fi

                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    [[ "$status" != "running" ]] && continue
                    ct_array+=("$vmid" "$name")
                done <<< "$containers"

                if [[ ${#ct_array[@]} -eq 0 ]]; then
                    show_msg "No Running Containers" "No running containers found."
                    continue
                fi

                local selected
                selected=$(show_menu "Select Container" "Choose container:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    show_info "Getting info..." "Getting container information..."
                    local hostname ip
                    hostname=$(lxc_exec "$selected" "hostname")
                    ip=$(get_container_ip "$selected")

                    if [[ -z "$hostname" ]] || [[ -z "$ip" ]]; then
                        show_msg "Error" "Could not get container hostname or IP."
                        continue
                    fi

                    (
                        echo "Generating certificate for $hostname..."
                        echo "  IP: $ip"
                        echo ""
                        ca_generate_cert "$hostname" "$ip"
                        echo ""
                        echo "Certificate generated!"
                        echo ""
                        echo "Certificate info:"
                        openssl x509 -in "$CERTS_DIR/$hostname/${hostname}.crt" -noout -subject -dates
                    ) | show_progress_box "Generate Certificate"
                fi
                ;;
            4)
                if [[ ! -f "$CA_DIR/ca.key" ]]; then
                    show_msg "No CA" "CA not initialized. Please initialize first."
                    continue
                fi

                if [[ -z "$CURRENT_PVE" ]]; then
                    show_msg "Not Connected" "Please connect to a PVE server first."
                    continue
                fi

                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                if show_yesno "Confirm" "Generate certificates for all running containers?"; then
                    (
                        echo "Generating certificates for all containers..."
                        echo ""
                        count=0
                        while read -r vmid status _ name; do
                            [[ -z "$vmid" ]] && continue
                            [[ "$status" != "running" ]] && continue

                            echo "Container $vmid..."
                            hostname=$(lxc_exec "$vmid" "hostname")
                            ip=$(get_container_ip "$vmid")

                            if [[ -n "$hostname" ]] && [[ -n "$ip" ]]; then
                                ca_generate_cert "$hostname" "$ip" && ((count++))
                                echo "  Generated: $hostname ($ip)"
                            else
                                echo "  Skipped: could not get hostname/IP"
                            fi
                        done <<< "$containers"
                        echo ""
                        echo "Generated certificates for $count containers."
                    ) 2>&1 | show_progress_box "Generate All Certificates"
                fi
                ;;
            5)
                if [[ -z "$CURRENT_PVE" ]]; then
                    show_msg "Not Connected" "Please connect to a PVE server first."
                    continue
                fi

                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                local ct_array=()
                while read -r vmid status _ name; do
                    [[ -z "$vmid" ]] && continue
                    [[ "$status" != "running" ]] && continue
                    ct_array+=("$vmid" "$name")
                done <<< "$containers"

                if [[ ${#ct_array[@]} -eq 0 ]]; then
                    show_msg "No Running Containers" "No running containers found."
                    continue
                fi

                local selected
                selected=$(show_menu "Select Container" "Choose container:" "${ct_array[@]}")

                if [[ -n "$selected" ]]; then
                    local hostname
                    hostname=$(lxc_exec "$selected" "hostname")

                    if [[ ! -d "$CERTS_DIR/$hostname" ]]; then
                        show_msg "No Certificate" "No certificate found for $hostname.\nPlease generate one first."
                        continue
                    fi

                    (
                        echo "Deploying certificate to container $selected..."
                        echo "  Hostname: $hostname"
                        echo ""
                        ca_deploy_cert "$selected" "$hostname"
                        echo ""
                        echo "Certificate deployed successfully!"
                    ) | show_progress_box "Deploy Certificate"
                fi
                ;;
            6)
                if [[ -z "$CURRENT_PVE" ]]; then
                    show_msg "Not Connected" "Please connect to a PVE server first."
                    continue
                fi

                local containers
                containers=$(pve_list_containers)
                if [[ -z "$containers" ]]; then
                    show_msg "No Containers" "No containers found."
                    continue
                fi

                if show_yesno "Confirm" "Deploy certificates to all running containers?"; then
                    (
                        echo "Deploying certificates to all containers..."
                        echo ""
                        count=0
                        while read -r vmid status _ name; do
                            [[ -z "$vmid" ]] && continue
                            [[ "$status" != "running" ]] && continue

                            hostname=$(lxc_exec "$vmid" "hostname")

                            if [[ -d "$CERTS_DIR/$hostname" ]]; then
                                echo "Deploying to $vmid ($hostname)..."
                                ca_deploy_cert "$vmid" "$hostname" && ((count++))
                            else
                                echo "Skipping $vmid ($hostname): no certificate"
                            fi
                        done <<< "$containers"
                        echo ""
                        echo "Deployed certificates to $count containers."
                    ) 2>&1 | show_progress_box "Deploy All Certificates"
                fi
                ;;
            7)
                if [[ ! -d "$CERTS_DIR" ]]; then
                    show_msg "No Certificates" "No certificates generated yet.\n\nCertificates directory: $CERTS_DIR"
                    continue
                fi

                local cert_list=""
                local cert_count=0

                for cert_dir in "$CERTS_DIR"/*/; do
                    [[ ! -d "$cert_dir" ]] && continue
                    local hostname crt_file expiry cert_status
                    hostname=$(basename "$cert_dir")
                    crt_file="$cert_dir/${hostname}.crt"

                    if [[ -f "$crt_file" ]]; then
                        ((cert_count++))
                        expiry=$(openssl x509 -in "$crt_file" -enddate -noout 2>/dev/null | cut -d= -f2)

                        if ca_verify_cert "$hostname" 2>/dev/null; then
                            cert_status="VALID"
                        else
                            cert_status="INVALID"
                        fi

                        cert_list+="$hostname\n"
                        cert_list+="  Expires: $expiry\n"
                        cert_list+="  Status: $cert_status\n\n"
                    fi
                done

                if [[ $cert_count -eq 0 ]]; then
                    show_msg "No Certificates" "No certificates generated yet.\n\nCertificates directory: $CERTS_DIR"
                else
                    show_msg "Generated Certificates ($cert_count)" "$cert_list"
                fi
                ;;
            8)
                if [[ ! -f "$CA_DIR/ca.crt" ]]; then
                    show_msg "No CA" "CA not initialized."
                    continue
                fi

                local export_path
                export_path=$(show_input "Export CA" "Enter export path:" "/tmp/pve-manager-ca.crt")

                if [[ -n "$export_path" ]]; then
                    cp "$CA_DIR/ca.crt" "$export_path"
                    show_msg "Exported" "CA certificate exported to:\n$export_path\n\nImport this certificate into your browser/system to trust HTTPS connections."
                fi
                ;;
            9)
                # Renew certificate
                if [[ ! -f "$CA_DIR/ca.key" ]]; then
                    show_msg "No CA" "CA not initialized. Please initialize first."
                    continue
                fi

                if [[ ! -d "$CERTS_DIR" ]] || [[ -z "$(ls -A "$CERTS_DIR" 2>/dev/null)" ]]; then
                    show_msg "No Certificates" "No certificates to renew. Generate certificates first."
                    continue
                fi

                # Build list of existing certificates
                local cert_array=()
                for cert_dir in "$CERTS_DIR"/*/; do
                    [[ ! -d "$cert_dir" ]] && continue
                    local hostname crt_file expiry
                    hostname=$(basename "$cert_dir")
                    crt_file="$cert_dir/${hostname}.crt"

                    if [[ -f "$crt_file" ]]; then
                        expiry=$(openssl x509 -in "$crt_file" -enddate -noout 2>/dev/null | cut -d= -f2)
                        cert_array+=("$hostname" "Expires: $expiry")
                    fi
                done

                if [[ ${#cert_array[@]} -eq 0 ]]; then
                    show_msg "No Certificates" "No certificates found to renew."
                    continue
                fi

                # Add "All certificates" option
                cert_array=("ALL" "Renew all certificates" "${cert_array[@]}")

                local selected
                selected=$(show_menu "Renew Certificate" "Select certificate to renew:" "${cert_array[@]}")

                if [[ -z "$selected" ]]; then
                    continue
                fi

                if [[ "$selected" == "ALL" ]]; then
                    # Renew all certificates
                    if [[ -z "$CURRENT_PVE" ]]; then
                        show_msg "Not Connected" "Please connect to a PVE server first to renew and redeploy certificates."
                        continue
                    fi

                    if show_yesno "Confirm Renewal" "Renew all certificates?\n\nThis will:\n- Regenerate certificates with new expiry dates\n- Redeploy to running containers\n- Services may need restart to use new certificates"; then
                        (
                            echo "Renewing all certificates..."
                            echo ""
                            local renewed=0 deployed=0

                            for cert_dir in "$CERTS_DIR"/*/; do
                                [[ ! -d "$cert_dir" ]] && continue
                                local hostname crt_file
                                hostname=$(basename "$cert_dir")
                                crt_file="$cert_dir/${hostname}.crt"

                                [[ ! -f "$crt_file" ]] && continue

                                # Get IP from existing certificate SAN
                                local ip
                                ip=$(openssl x509 -in "$crt_file" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -1 | grep -oP 'IP Address:\K[0-9.]+' | head -1)

                                if [[ -z "$ip" ]]; then
                                    echo "[$hostname] Skipped: cannot determine IP from certificate"
                                    continue
                                fi

                                echo "[$hostname] Renewing certificate..."

                                # Backup old certificate
                                cp "$crt_file" "${crt_file}.bak" 2>/dev/null

                                # Regenerate certificate
                                if ca_generate_cert "$hostname" "$ip"; then
                                    echo "[$hostname] Certificate renewed (IP: $ip)"
                                    ((renewed++))

                                    # Try to find running container with this hostname and redeploy
                                    local containers vmid container_hostname
                                    containers=$(pve_list_containers 2>/dev/null)

                                    while read -r vmid status _ name; do
                                        [[ -z "$vmid" ]] && continue
                                        [[ "$status" != "running" ]] && continue

                                        container_hostname=$(lxc_exec "$vmid" "hostname" 2>/dev/null)
                                        if [[ "$container_hostname" == "$hostname" ]]; then
                                            echo "[$hostname] Deploying to container $vmid..."
                                            if ca_deploy_cert "$vmid" "$hostname"; then
                                                echo "[$hostname] Deployed successfully"
                                                ((deployed++))
                                            else
                                                echo "[$hostname] Deploy failed"
                                            fi
                                            break
                                        fi
                                    done <<< "$containers"
                                else
                                    echo "[$hostname] Renewal failed"
                                    # Restore backup
                                    [[ -f "${crt_file}.bak" ]] && mv "${crt_file}.bak" "$crt_file"
                                fi
                                echo ""
                            done

                            echo "================================"
                            echo "Renewed: $renewed certificates"
                            echo "Deployed: $deployed certificates"
                            echo ""
                            echo "Note: Restart services to use new certificates"
                        ) 2>&1 | show_progress_box "Renew All Certificates"
                    fi
                else
                    # Renew single certificate
                    local hostname="$selected"
                    local crt_file="$CERTS_DIR/$hostname/${hostname}.crt"

                    if [[ ! -f "$crt_file" ]]; then
                        show_msg "Error" "Certificate file not found: $crt_file"
                        continue
                    fi

                    # Get IP from existing certificate
                    local ip
                    ip=$(openssl x509 -in "$crt_file" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -1 | grep -oP 'IP Address:\K[0-9.]+' | head -1)

                    if [[ -z "$ip" ]]; then
                        # Try to get from running container
                        if [[ -n "$CURRENT_PVE" ]]; then
                            local containers vmid container_hostname
                            containers=$(pve_list_containers 2>/dev/null)

                            while read -r vmid status _ name; do
                                [[ -z "$vmid" ]] && continue
                                [[ "$status" != "running" ]] && continue

                                container_hostname=$(lxc_exec "$vmid" "hostname" 2>/dev/null)
                                if [[ "$container_hostname" == "$hostname" ]]; then
                                    ip=$(get_container_ip "$vmid" 2>/dev/null)
                                    break
                                fi
                            done <<< "$containers"
                        fi
                    fi

                    if [[ -z "$ip" ]]; then
                        ip=$(show_input "Container IP" "Could not determine IP for $hostname.\n\nEnter IP address:" "")
                        [[ -z "$ip" ]] && continue
                    fi

                    local redeploy=false
                    local target_vmid=""

                    if [[ -n "$CURRENT_PVE" ]]; then
                        local containers vmid container_hostname
                        containers=$(pve_list_containers 2>/dev/null)

                        while read -r vmid status _ name; do
                            [[ -z "$vmid" ]] && continue
                            [[ "$status" != "running" ]] && continue

                            container_hostname=$(lxc_exec "$vmid" "hostname" 2>/dev/null)
                            if [[ "$container_hostname" == "$hostname" ]]; then
                                target_vmid="$vmid"
                                break
                            fi
                        done <<< "$containers"

                        if [[ -n "$target_vmid" ]]; then
                            if show_yesno "Redeploy?" "Found running container $target_vmid with hostname $hostname.\n\nDeploy renewed certificate to container?"; then
                                redeploy=true
                            fi
                        fi
                    fi

                    (
                        echo "Renewing certificate for $hostname..."
                        echo "  IP: $ip"
                        echo ""

                        # Backup old certificate
                        cp "$crt_file" "${crt_file}.bak" 2>/dev/null

                        if ca_generate_cert "$hostname" "$ip"; then
                            echo "Certificate renewed successfully!"
                            echo ""
                            echo "New certificate info:"
                            openssl x509 -in "$crt_file" -noout -subject -dates

                            if [[ "$redeploy" == true ]] && [[ -n "$target_vmid" ]]; then
                                echo ""
                                echo "Deploying to container $target_vmid..."
                                if ca_deploy_cert "$target_vmid" "$hostname"; then
                                    echo "Certificate deployed successfully!"
                                    echo ""
                                    echo "Note: Restart services to use new certificate"
                                else
                                    echo "Certificate deployment failed!"
                                fi
                            fi
                        else
                            echo "Certificate renewal failed!"
                            # Restore backup
                            [[ -f "${crt_file}.bak" ]] && mv "${crt_file}.bak" "$crt_file"
                        fi
                    ) 2>&1 | show_progress_box "Renew Certificate"
                fi
                ;;
            C|c) acme_menu ;;
            0|"")
                break
                ;;
        esac
    done
}

#######################################
# SERVICE DEPLOYMENT FUNCTIONS
#######################################

# Get docker-compose template for service
get_service_compose() {
    local service="$1"

    # Use plugin system
    if is_plugin_service "$service" && plugin_supports_docker "$service"; then
        get_plugin_compose "$service"
        return
    fi

    # Service not found
    log_error "Unknown service: $service"
    return 1
}

# Get prometheus config for monitoring
get_prometheus_config() {
    cat << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
EOF
}

# Get alloy config
get_alloy_config() {
    cat << 'EOF'
logging {
  level = "info"
}

prometheus.scrape "default" {
  targets = [
    {"__address__" = "localhost:9100"},
  ]
  forward_to = [prometheus.remote_write.default.receiver]
}

prometheus.remote_write "default" {
  endpoint {
    url = "http://prometheus:9090/api/v1/write"
  }
}

loki.source.journal "read" {
  forward_to = [loki.write.default.receiver]
}

loki.write "default" {
  endpoint {
    url = "http://loki:3100/loki/api/v1/push"
  }
}
EOF
}

# Write nginx config for monitoring stack HTTPS proxy
# Uses base64 encoding to avoid variable substitution issues with heredocs
write_nginx_monitoring_config() {
    local vmid="$1"
    local service_dir="$2"

    # Base64-encoded nginx config (Grafana at root, Prometheus at /prometheus)
    # Prometheus uses --web.external-url=/prometheus/ so nginx passes path as-is
    local nginx_config_b64="d29ya2VyX3Byb2Nlc3NlcyBhdXRvOwplcnJvcl9sb2cgL3Zhci9sb2cvbmdpbngvZXJyb3IubG9nIHdhcm47CnBpZCAvdmFyL3J1bi9uZ2lueC5waWQ7CgpldmVudHMgewogICAgd29ya2VyX2Nvbm5lY3Rpb25zIDEwMjQ7Cn0KCmh0dHAgewogICAgaW5jbHVkZSAvZXRjL25naW54L21pbWUudHlwZXM7CiAgICBkZWZhdWx0X3R5cGUgYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtOwogICAgc2VuZGZpbGUgb247CiAgICBrZWVwYWxpdmVfdGltZW91dCA2NTsKCiAgICBzZXJ2ZXIgewogICAgICAgIGxpc3RlbiA4MDsKICAgICAgICBzZXJ2ZXJfbmFtZSBfOwogICAgICAgIHJldHVybiAzMDEgaHR0cHM6Ly8kaG9zdCRyZXF1ZXN0X3VyaTsKICAgIH0KCiAgICBzZXJ2ZXIgewogICAgICAgIGxpc3RlbiA0NDMgc3NsOwogICAgICAgIHNlcnZlcl9uYW1lIF87CgogICAgICAgIHNzbF9jZXJ0aWZpY2F0ZSAvZXRjL25naW54L3NzbC9zZXJ2ZXIuY3J0OwogICAgICAgIHNzbF9jZXJ0aWZpY2F0ZV9rZXkgL2V0Yy9uZ2lueC9zc2wvc2VydmVyLmtleTsKICAgICAgICBzc2xfcHJvdG9jb2xzIFRMU3YxLjIgVExTdjEuMzsKICAgICAgICBzc2xfY2lwaGVycyBISUdIOiFhTlVMTDohTUQ1OwoKICAgICAgICBsb2NhdGlvbiAvIHsKICAgICAgICAgICAgcHJveHlfcGFzcyBodHRwOi8vZ3JhZmFuYTozMDAwOwogICAgICAgICAgICBwcm94eV9odHRwX3ZlcnNpb24gMS4xOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFVwZ3JhZGUgJGh0dHBfdXBncmFkZTsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBDb25uZWN0aW9uICJ1cGdyYWRlIjsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBIb3N0ICRob3N0OwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtUmVhbC1JUCAkcmVtb3RlX2FkZHI7CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgWC1Gb3J3YXJkZWQtRm9yICRwcm94eV9hZGRfeF9mb3J3YXJkZWRfZm9yOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtRm9yd2FyZGVkLVByb3RvIGh0dHBzOwogICAgICAgIH0KCiAgICAgICAgbG9jYXRpb24gL3Byb21ldGhldXMgewogICAgICAgICAgICBwcm94eV9wYXNzIGh0dHA6Ly9wcm9tZXRoZXVzOjkwOTA7CiAgICAgICAgICAgIHByb3h5X2h0dHBfdmVyc2lvbiAxLjE7CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgSG9zdCAkaG9zdDsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBYLVJlYWwtSVAgJHJlbW90ZV9hZGRyOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtRm9yd2FyZGVkLUZvciAkcHJveHlfYWRkX3hfZm9yd2FyZGVkX2ZvcjsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBYLUZvcndhcmRlZC1Qcm90byBodHRwczsKICAgICAgICB9CgogICAgICAgIGxvY2F0aW9uIC9sb2tpLyB7CiAgICAgICAgICAgIHByb3h5X3Bhc3MgaHR0cDovL2xva2k6MzEwMC87CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgSG9zdCAkaG9zdDsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBYLVJlYWwtSVAgJHJlbW90ZV9hZGRyOwogICAgICAgIH0KCiAgICAgICAgbG9jYXRpb24gL25vZGUtbWV0cmljcy8gewogICAgICAgICAgICBwcm94eV9wYXNzIGh0dHA6Ly9ub2RlLWV4cG9ydGVyOjkxMDAvOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIEhvc3QgJGhvc3Q7CiAgICAgICAgfQogICAgfQp9Cg=="

    lxc_exec "$vmid" "echo '$nginx_config_b64' | base64 -d > ${service_dir}/nginx.conf"
}

# Write nginx config for Harbor HTTPS proxy
# Uses base64 encoding to avoid variable substitution issues with heredocs
write_nginx_harbor_config() {
    local vmid="$1"
    local service_dir="$2"

    # Base64-encoded nginx config for Harbor (Portal at root, Registry at /v2/)
    local nginx_config_b64="d29ya2VyX3Byb2Nlc3NlcyBhdXRvOwplcnJvcl9sb2cgL3Zhci9sb2cvbmdpbngvZXJyb3IubG9nIHdhcm47CnBpZCAvdmFyL3J1bi9uZ2lueC5waWQ7CgpldmVudHMgewogICAgd29ya2VyX2Nvbm5lY3Rpb25zIDEwMjQ7Cn0KCmh0dHAgewogICAgaW5jbHVkZSAvZXRjL25naW54L21pbWUudHlwZXM7CiAgICBkZWZhdWx0X3R5cGUgYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtOwogICAgc2VuZGZpbGUgb247CiAgICBrZWVwYWxpdmVfdGltZW91dCA2NTsKICAgIGNsaWVudF9tYXhfYm9keV9zaXplIDA7CgogICAgdXBzdHJlYW0gaGFyYm9yLXBvcnRhbCB7CiAgICAgICAgc2VydmVyIGhhcmJvci1wb3J0YWw6ODA4MDsKICAgIH0KCiAgICB1cHN0cmVhbSBoYXJib3ItY29yZSB7CiAgICAgICAgc2VydmVyIGhhcmJvci1jb3JlOjgwODA7CiAgICB9CgogICAgdXBzdHJlYW0gaGFyYm9yLXJlZ2lzdHJ5IHsKICAgICAgICBzZXJ2ZXIgaGFyYm9yLXJlZ2lzdHJ5OjUwMDA7CiAgICB9CgogICAgc2VydmVyIHsKICAgICAgICBsaXN0ZW4gODA7CiAgICAgICAgc2VydmVyX25hbWUgXzsKICAgICAgICByZXR1cm4gMzAxIGh0dHBzOi8vJGhvc3QkcmVxdWVzdF91cmk7CiAgICB9CgogICAgc2VydmVyIHsKICAgICAgICBsaXN0ZW4gNDQzIHNzbDsKICAgICAgICBzZXJ2ZXJfbmFtZSBfOwoKICAgICAgICBzc2xfY2VydGlmaWNhdGUgL2V0Yy9uZ2lueC9zc2wvc2VydmVyLmNydDsKICAgICAgICBzc2xfY2VydGlmaWNhdGVfa2V5IC9ldGMvbmdpbngvc3NsL3NlcnZlci5rZXk7CiAgICAgICAgc3NsX3Byb3RvY29scyBUTFN2MS4yIFRMU3YxLjM7CiAgICAgICAgc3NsX2NpcGhlcnMgSElHSDohYU5VTEw6IU1ENTsKCiAgICAgICAgY2xpZW50X21heF9ib2R5X3NpemUgMDsKICAgICAgICBjaHVua2VkX3RyYW5zZmVyX2VuY29kaW5nIG9uOwoKICAgICAgICBsb2NhdGlvbiAvIHsKICAgICAgICAgICAgcHJveHlfcGFzcyBodHRwOi8vaGFyYm9yLXBvcnRhbDsKICAgICAgICAgICAgcHJveHlfaHR0cF92ZXJzaW9uIDEuMTsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBIb3N0ICRob3N0OwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtUmVhbC1JUCAkcmVtb3RlX2FkZHI7CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgWC1Gb3J3YXJkZWQtRm9yICRwcm94eV9hZGRfeF9mb3J3YXJkZWRfZm9yOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtRm9yd2FyZGVkLVByb3RvIGh0dHBzOwogICAgICAgIH0KCiAgICAgICAgbG9jYXRpb24gL2FwaS8gewogICAgICAgICAgICBwcm94eV9wYXNzIGh0dHA6Ly9oYXJib3ItY29yZS9hcGkvOwogICAgICAgICAgICBwcm94eV9odHRwX3ZlcnNpb24gMS4xOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIEhvc3QgJGhvc3Q7CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgWC1SZWFsLUlQICRyZW1vdGVfYWRkcjsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBYLUZvcndhcmRlZC1Gb3IgJHByb3h5X2FkZF94X2ZvcndhcmRlZF9mb3I7CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgWC1Gb3J3YXJkZWQtUHJvdG8gaHR0cHM7CiAgICAgICAgfQoKICAgICAgICBsb2NhdGlvbiAvc2VydmljZS8gewogICAgICAgICAgICBwcm94eV9wYXNzIGh0dHA6Ly9oYXJib3ItY29yZS9zZXJ2aWNlLzsKICAgICAgICAgICAgcHJveHlfaHR0cF92ZXJzaW9uIDEuMTsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBIb3N0ICRob3N0OwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtUmVhbC1JUCAkcmVtb3RlX2FkZHI7CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgWC1Gb3J3YXJkZWQtRm9yICRwcm94eV9hZGRfeF9mb3J3YXJkZWRfZm9yOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtRm9yd2FyZGVkLVByb3RvIGh0dHBzOwogICAgICAgIH0KCiAgICAgICAgbG9jYXRpb24gL3YyLyB7CiAgICAgICAgICAgIHByb3h5X3Bhc3MgaHR0cDovL2hhcmJvci1yZWdpc3RyeS92Mi87CiAgICAgICAgICAgIHByb3h5X2h0dHBfdmVyc2lvbiAxLjE7CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgSG9zdCAkaG9zdDsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBYLVJlYWwtSVAgJHJlbW90ZV9hZGRyOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtRm9yd2FyZGVkLUZvciAkcHJveHlfYWRkX3hfZm9yd2FyZGVkX2ZvcjsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBYLUZvcndhcmRlZC1Qcm90byBodHRwczsKICAgICAgICAgICAgcHJveHlfYnVmZmVyaW5nIG9mZjsKICAgICAgICAgICAgcHJveHlfcmVxdWVzdF9idWZmZXJpbmcgb2ZmOwogICAgICAgIH0KCiAgICAgICAgbG9jYXRpb24gL2MvIHsKICAgICAgICAgICAgcHJveHlfcGFzcyBodHRwOi8vaGFyYm9yLWNvcmUvYy87CiAgICAgICAgICAgIHByb3h5X2h0dHBfdmVyc2lvbiAxLjE7CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgSG9zdCAkaG9zdDsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBYLVJlYWwtSVAgJHJlbW90ZV9hZGRyOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtRm9yd2FyZGVkLUZvciAkcHJveHlfYWRkX3hfZm9yd2FyZGVkX2ZvcjsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBYLUZvcndhcmRlZC1Qcm90byBodHRwczsKICAgICAgICB9CgogICAgICAgIGxvY2F0aW9uIC9jaGFydHJlcG8vIHsKICAgICAgICAgICAgcHJveHlfcGFzcyBodHRwOi8vaGFyYm9yLWNvcmUvY2hhcnRyZXBvLzsKICAgICAgICAgICAgcHJveHlfaHR0cF92ZXJzaW9uIDEuMTsKICAgICAgICAgICAgcHJveHlfc2V0X2hlYWRlciBIb3N0ICRob3N0OwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtUmVhbC1JUCAkcmVtb3RlX2FkZHI7CiAgICAgICAgICAgIHByb3h5X3NldF9oZWFkZXIgWC1Gb3J3YXJkZWQtRm9yICRwcm94eV9hZGRfeF9mb3J3YXJkZWRfZm9yOwogICAgICAgICAgICBwcm94eV9zZXRfaGVhZGVyIFgtRm9yd2FyZGVkLVByb3RvIGh0dHBzOwogICAgICAgIH0KICAgIH0KfQo="

    lxc_exec "$vmid" "echo '$nginx_config_b64' | base64 -d > ${service_dir}/nginx.conf"
}

# Provision Grafana datasources and dashboards for monitoring stack
provision_grafana_dashboards() {
    local vmid="$1"
    local service_dir="$2"

    # Create provisioning directories
    lxc_exec "$vmid" "mkdir -p ${service_dir}/provisioning/datasources ${service_dir}/provisioning/dashboards ${service_dir}/dashboards"

    # Datasources config (Prometheus and Loki)
    lxc_exec "$vmid" "cat > ${service_dir}/provisioning/datasources/datasources.yml << 'DSEOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    editable: false
DSEOF"

    # Dashboard provider config
    lxc_exec "$vmid" "cat > ${service_dir}/provisioning/dashboards/dashboards.yml << 'DBPEOF'
apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: 'Provisioned'
    folderUid: 'provisioned'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
DBPEOF"

    # Node Exporter Dashboard (CPU, Memory, Disk, Network)
    local node_dashboard_b64="ewogICJhbm5vdGF0aW9ucyI6IHsibGlzdCI6IFtdfSwKICAiZWRpdGFibGUiOiB0cnVlLAogICJmaXNjYWxZZWFyU3RhcnRNb250aCI6IDAsCiAgImdyYXBoVG9vbHRpcCI6IDAsCiAgImlkIjogbnVsbCwKICAibGlua3MiOiBbXSwKICAicGFuZWxzIjogWwogICAgewogICAgICAiZGF0YXNvdXJjZSI6IHsidHlwZSI6ICJwcm9tZXRoZXVzIiwgInVpZCI6ICJwcm9tZXRoZXVzIn0sCiAgICAgICJmaWVsZENvbmZpZyI6IHsKICAgICAgICAiZGVmYXVsdHMiOiB7ImNvbG9yIjogeyJtb2RlIjogInBhbGV0dGUtY2xhc3NpYyJ9LCAiY3VzdG9tIjogeyJheGlzQ2VudGVyZWRaZXJvIjogZmFsc2UsICJheGlzQ29sb3JNb2RlIjogInRleHQiLCAiYXhpc0xhYmVsIjogIiIsICJheGlzUGxhY2VtZW50IjogImF1dG8iLCAiYmFyQWxpZ25tZW50IjogMCwgImRyYXdTdHlsZSI6ICJsaW5lIiwgImZpbGxPcGFjaXR5IjogMTAsICJncmFkaWVudE1vZGUiOiAibm9uZSIsICJoaWRlRnJvbSI6IHsibGVnZW5kIjogZmFsc2UsICJ0b29sdGlwIjogZmFsc2UsICJ2aXoiOiBmYWxzZX0sICJsaW5lSW50ZXJwb2xhdGlvbiI6ICJsaW5lYXIiLCAibGluZVdpZHRoIjogMSwgInBvaW50U2l6ZSI6IDUsICJzY2FsZURpc3RyaWJ1dGlvbiI6IHsidHlwZSI6ICJsaW5lYXIifSwgInNob3dQb2ludHMiOiAibmV2ZXIiLCAic3Bhbk51bGxzIjogZmFsc2UsICJzdGFja2luZyI6IHsiZ3JvdXAiOiAiQSIsICJtb2RlIjogIm5vbmUifSwgInRocmVzaG9sZHNTdHlsZSI6IHsibW9kZSI6ICJvZmYifX0sICJtYXBwaW5ncyI6IFtdLCAidGhyZXNob2xkcyI6IHsibW9kZSI6ICJhYnNvbHV0ZSIsICJzdGVwcyI6IFt7ImNvbG9yIjogImdyZWVuIiwgInZhbHVlIjogbnVsbH0sIHsiY29sb3IiOiAicmVkIiwgInZhbHVlIjogODB9XX0sICJ1bml0IjogInBlcmNlbnQifSwKICAgICAgICAib3ZlcnJpZGVzIjogW10KICAgICAgfSwKICAgICAgImdyaWRQb3MiOiB7ImgiOiA4LCAidyI6IDEyLCAieCI6IDAsICJ5IjogMH0sCiAgICAgICJpZCI6IDEsCiAgICAgICJvcHRpb25zIjogeyJsZWdlbmQiOiB7ImNhbGNzIjogWyJtZWFuIiwgIm1heCJdLCAiZGlzcGxheU1vZGUiOiAidGFibGUiLCAicGxhY2VtZW50IjogImJvdHRvbSIsICJzaG93TGVnZW5kIjogdHJ1ZX0sICJ0b29sdGlwIjogeyJtb2RlIjogInNpbmdsZSIsICJzb3J0IjogIm5vbmUifX0sCiAgICAgICJ0YXJnZXRzIjogW3siZGF0YXNvdXJjZSI6IHsidHlwZSI6ICJwcm9tZXRoZXVzIiwgInVpZCI6ICJwcm9tZXRoZXVzIn0sICJlZGl0b3JNb2RlIjogImNvZGUiLCAiZXhwciI6ICIxMDAgLSAoYXZnIGJ5KGluc3RhbmNlKSAoaXJhdGUobm9kZV9jcHVfc2Vjb25kc190b3RhbHttb2RlPVwiaWRsZVwifVs1bV0pKSAqIDEwMCkiLCAibGVnZW5kRm9ybWF0IjogInt7aW5zdGFuY2V9fSIsICJyYW5nZSI6IHRydWUsICJyZWZJZCI6ICJBIn1dLAogICAgICAidGl0bGUiOiAiQ1BVIFVzYWdlIiwKICAgICAgInR5cGUiOiAidGltZXNlcmllcyIKICAgIH0sCiAgICB7CiAgICAgICJkYXRhc291cmNlIjogeyJ0eXBlIjogInByb21ldGhldXMiLCAidWlkIjogInByb21ldGhldXMifSwKICAgICAgImZpZWxkQ29uZmlnIjogewogICAgICAgICJkZWZhdWx0cyI6IHsiY29sb3IiOiB7Im1vZGUiOiAicGFsZXR0ZS1jbGFzc2ljIn0sICJjdXN0b20iOiB7ImF4aXNDZW50ZXJlZFplcm8iOiBmYWxzZSwgImF4aXNDb2xvck1vZGUiOiAidGV4dCIsICJheGlzTGFiZWwiOiAiIiwgImF4aXNQbGFjZW1lbnQiOiAiYXV0byIsICJiYXJBbGlnbm1lbnQiOiAwLCAiZHJhd1N0eWxlIjogImxpbmUiLCAiZmlsbE9wYWNpdHkiOiAxMCwgImdyYWRpZW50TW9kZSI6ICJub25lIiwgImhpZGVGcm9tIjogeyJsZWdlbmQiOiBmYWxzZSwgInRvb2x0aXAiOiBmYWxzZSwgInZpeiI6IGZhbHNlfSwgImxpbmVJbnRlcnBvbGF0aW9uIjogImxpbmVhciIsICJsaW5lV2lkdGgiOiAxLCAicG9pbnRTaXplIjogNSwgInNjYWxlRGlzdHJpYnV0aW9uIjogeyJ0eXBlIjogImxpbmVhciJ9LCAic2hvd1BvaW50cyI6ICJuZXZlciIsICJzcGFuTnVsbHMiOiBmYWxzZSwgInN0YWNraW5nIjogeyJncm91cCI6ICJBIiwgIm1vZGUiOiAibm9uZSJ9LCAidGhyZXNob2xkc1N0eWxlIjogeyJtb2RlIjogIm9mZiJ9fSwgIm1hcHBpbmdzIjogW10sICJ0aHJlc2hvbGRzIjogeyJtb2RlIjogImFic29sdXRlIiwgInN0ZXBzIjogW3siY29sb3IiOiAiZ3JlZW4iLCAidmFsdWUiOiBudWxsfSwgeyJjb2xvciI6ICJyZWQiLCAidmFsdWUiOiA4MH1dfSwgInVuaXQiOiAicGVyY2VudCJ9LAogICAgICAgICJvdmVycmlkZXMiOiBbXQogICAgICB9LAogICAgICAiZ3JpZFBvcyI6IHsiaCI6IDgsICJ3IjogMTIsICJ4IjogMTIsICJ5IjogMH0sCiAgICAgICJpZCI6IDIsCiAgICAgICJvcHRpb25zIjogeyJsZWdlbmQiOiB7ImNhbGNzIjogWyJtZWFuIiwgIm1heCJdLCAiZGlzcGxheU1vZGUiOiAidGFibGUiLCAicGxhY2VtZW50IjogImJvdHRvbSIsICJzaG93TGVnZW5kIjogdHJ1ZX0sICJ0b29sdGlwIjogeyJtb2RlIjogInNpbmdsZSIsICJzb3J0IjogIm5vbmUifX0sCiAgICAgICJ0YXJnZXRzIjogW3siZGF0YXNvdXJjZSI6IHsidHlwZSI6ICJwcm9tZXRoZXVzIiwgInVpZCI6ICJwcm9tZXRoZXVzIn0sICJlZGl0b3JNb2RlIjogImNvZGUiLCAiZXhwciI6ICIxMDAgLSAoKG5vZGVfbWVtb3J5X01lbUF2YWlsYWJsZV9ieXRlcyAvIG5vZGVfbWVtb3J5X01lbVRvdGFsX2J5dGVzKSAqIDEwMCkiLCAibGVnZW5kRm9ybWF0IjogInt7aW5zdGFuY2V9fSIsICJyYW5nZSI6IHRydWUsICJyZWZJZCI6ICJBIn1dLAogICAgICAidGl0bGUiOiAiTWVtb3J5IFVzYWdlIiwKICAgICAgInR5cGUiOiAidGltZXNlcmllcyIKICAgIH0sCiAgICB7CiAgICAgICJkYXRhc291cmNlIjogeyJ0eXBlIjogInByb21ldGhldXMiLCAidWlkIjogInByb21ldGhldXMifSwKICAgICAgImZpZWxkQ29uZmlnIjogewogICAgICAgICJkZWZhdWx0cyI6IHsiY29sb3IiOiB7Im1vZGUiOiAicGFsZXR0ZS1jbGFzc2ljIn0sICJjdXN0b20iOiB7ImF4aXNDZW50ZXJlZFplcm8iOiBmYWxzZSwgImF4aXNDb2xvck1vZGUiOiAidGV4dCIsICJheGlzTGFiZWwiOiAiIiwgImF4aXNQbGFjZW1lbnQiOiAiYXV0byIsICJiYXJBbGlnbm1lbnQiOiAwLCAiZHJhd1N0eWxlIjogImxpbmUiLCAiZmlsbE9wYWNpdHkiOiAxMCwgImdyYWRpZW50TW9kZSI6ICJub25lIiwgImhpZGVGcm9tIjogeyJsZWdlbmQiOiBmYWxzZSwgInRvb2x0aXAiOiBmYWxzZSwgInZpeiI6IGZhbHNlfSwgImxpbmVJbnRlcnBvbGF0aW9uIjogImxpbmVhciIsICJsaW5lV2lkdGgiOiAxLCAicG9pbnRTaXplIjogNSwgInNjYWxlRGlzdHJpYnV0aW9uIjogeyJ0eXBlIjogImxpbmVhciJ9LCAic2hvd1BvaW50cyI6ICJuZXZlciIsICJzcGFuTnVsbHMiOiBmYWxzZSwgInN0YWNraW5nIjogeyJncm91cCI6ICJBIiwgIm1vZGUiOiAibm9uZSJ9LCAidGhyZXNob2xkc1N0eWxlIjogeyJtb2RlIjogIm9mZiJ9fSwgIm1hcHBpbmdzIjogW10sICJ0aHJlc2hvbGRzIjogeyJtb2RlIjogImFic29sdXRlIiwgInN0ZXBzIjogW3siY29sb3IiOiAiZ3JlZW4iLCAidmFsdWUiOiBudWxsfSwgeyJjb2xvciI6ICJyZWQiLCAidmFsdWUiOiA4MH1dfSwgInVuaXQiOiAicGVyY2VudCJ9LAogICAgICAgICJvdmVycmlkZXMiOiBbXQogICAgICB9LAogICAgICAiZ3JpZFBvcyI6IHsiaCI6IDgsICJ3IjogMTIsICJ4IjogMCwgInkiOiA4fSwKICAgICAgImlkIjogMywKICAgICAgIm9wdGlvbnMiOiB7ImxlZ2VuZCI6IHsiY2FsY3MiOiBbIm1lYW4iLCAibWF4Il0sICJkaXNwbGF5TW9kZSI6ICJ0YWJsZSIsICJwbGFjZW1lbnQiOiAiYm90dG9tIiwgInNob3dMZWdlbmQiOiB0cnVlfSwgInRvb2x0aXAiOiB7Im1vZGUiOiAic2luZ2xlIiwgInNvcnQiOiAibm9uZSJ9fSwKICAgICAgInRhcmdldHMiOiBbeyJkYXRhc291cmNlIjogeyJ0eXBlIjogInByb21ldGhldXMiLCAidWlkIjogInByb21ldGhldXMifSwgImVkaXRvck1vZGUiOiAiY29kZSIsICJleHByIjogIjEwMCAtICgobm9kZV9maWxlc3lzdGVtX2F2YWlsX2J5dGVze21vdW50cG9pbnQ9XCIvXCIsZnN0eXBlIX5cInRtcGZzfHJvb3Rmc1wifSAvIG5vZGVfZmlsZXN5c3RlbV9zaXplX2J5dGVze21vdW50cG9pbnQ9XCIvXCIsZnN0eXBlIX5cInRtcGZzfHJvb3Rmc1wifSkgKiAxMDApIiwgImxlZ2VuZEZvcm1hdCI6ICJ7e2luc3RhbmNlfX0iLCAicmFuZ2UiOiB0cnVlLCAicmVmSWQiOiAiQSJ9XSwKICAgICAgInRpdGxlIjogIkRpc2sgVXNhZ2UiLAogICAgICAidHlwZSI6ICJ0aW1lc2VyaWVzIgogICAgfSwKICAgIHsKICAgICAgImRhdGFzb3VyY2UiOiB7InR5cGUiOiAicHJvbWV0aGV1cyIsICJ1aWQiOiAicHJvbWV0aGV1cyJ9LAogICAgICAiZmllbGRDb25maWciOiB7CiAgICAgICAgImRlZmF1bHRzIjogeyJjb2xvciI6IHsibW9kZSI6ICJwYWxldHRlLWNsYXNzaWMifSwgImN1c3RvbSI6IHsiYXhpc0NlbnRlcmVkWmVybyI6IGZhbHNlLCAiYXhpc0NvbG9yTW9kZSI6ICJ0ZXh0IiwgImF4aXNMYWJlbCI6ICIiLCAiYXhpc1BsYWNlbWVudCI6ICJhdXRvIiwgImJhckFsaWdubWVudCI6IDAsICJkcmF3U3R5bGUiOiAibGluZSIsICJmaWxsT3BhY2l0eSI6IDEwLCAiZ3JhZGllbnRNb2RlIjogIm5vbmUiLCAiaGlkZUZyb20iOiB7ImxlZ2VuZCI6IGZhbHNlLCAidG9vbHRpcCI6IGZhbHNlLCAidml6IjogZmFsc2V9LCAibGluZUludGVycG9sYXRpb24iOiAibGluZWFyIiwgImxpbmVXaWR0aCI6IDEsICJwb2ludFNpemUiOiA1LCAic2NhbGVEaXN0cmlidXRpb24iOiB7InR5cGUiOiAibGluZWFyIn0sICJzaG93UG9pbnRzIjogIm5ldmVyIiwgInNwYW5OdWxscyI6IGZhbHNlLCAic3RhY2tpbmciOiB7Imdyb3VwIjogIkEiLCAibW9kZSI6ICJub25lIn0sICJ0aHJlc2hvbGRzU3R5bGUiOiB7Im1vZGUiOiAib2ZmIn19LCAibWFwcGluZ3MiOiBbXSwgInRocmVzaG9sZHMiOiB7Im1vZGUiOiAiYWJzb2x1dGUiLCAic3RlcHMiOiBbeyJjb2xvciI6ICJncmVlbiIsICJ2YWx1ZSI6IG51bGx9XX0sICJ1bml0IjogIkJwcyJ9LAogICAgICAgICJvdmVycmlkZXMiOiBbXQogICAgICB9LAogICAgICAiZ3JpZFBvcyI6IHsiaCI6IDgsICJ3IjogMTIsICJ4IjogMTIsICJ5IjogOH0sCiAgICAgICJpZCI6IDQsCiAgICAgICJvcHRpb25zIjogeyJsZWdlbmQiOiB7ImNhbGNzIjogWyJtZWFuIiwgIm1heCJdLCAiZGlzcGxheU1vZGUiOiAidGFibGUiLCAicGxhY2VtZW50IjogImJvdHRvbSIsICJzaG93TGVnZW5kIjogdHJ1ZX0sICJ0b29sdGlwIjogeyJtb2RlIjogInNpbmdsZSIsICJzb3J0IjogIm5vbmUifX0sCiAgICAgICJ0YXJnZXRzIjogW3siZGF0YXNvdXJjZSI6IHsidHlwZSI6ICJwcm9tZXRoZXVzIiwgInVpZCI6ICJwcm9tZXRoZXVzIn0sICJlZGl0b3JNb2RlIjogImNvZGUiLCAiZXhwciI6ICJpcmF0ZShub2RlX25ldHdvcmtfcmVjZWl2ZV9ieXRlc190b3RhbHtkZXZpY2UhflwibG9cIn1bNW1dKSIsICJsZWdlbmRGb3JtYXQiOiAie3tpbnN0YW5jZX19IC0ge3tkZXZpY2V9fSByeCIsICJyYW5nZSI6IHRydWUsICJyZWZJZCI6ICJBIn0sIHsiZGF0YXNvdXJjZSI6IHsidHlwZSI6ICJwcm9tZXRoZXVzIiwgInVpZCI6ICJwcm9tZXRoZXVzIn0sICJlZGl0b3JNb2RlIjogImNvZGUiLCAiZXhwciI6ICJpcmF0ZShub2RlX25ldHdvcmtfdHJhbnNtaXRfYnl0ZXNfdG90YWx7ZGV2aWNlIX5cImxvXCJ9WzVtXSkiLCAibGVnZW5kRm9ybWF0IjogInt7aW5zdGFuY2V9fSAtIHt7ZGV2aWNlfX0gdHgiLCAicmFuZ2UiOiB0cnVlLCAicmVmSWQiOiAiQiJ9XSwKICAgICAgInRpdGxlIjogIk5ldHdvcmsgSS9PIiwKICAgICAgInR5cGUiOiAidGltZXNlcmllcyIKICAgIH0KICBdLAogICJyZWZyZXNoIjogIjEwcyIsCiAgInNjaGVtYVZlcnNpb24iOiAzOCwKICAic3R5bGUiOiAiZGFyayIsCiAgInRhZ3MiOiBbIm5vZGUtZXhwb3J0ZXIiLCAicHJvbWV0aGV1cyJdLAogICJ0ZW1wbGF0aW5nIjogeyJsaXN0IjogW119LAogICJ0aW1lIjogeyJmcm9tIjogIm5vdy0xaCIsICJ0byI6ICJub3cifSwKICAidGltZXpvbmUiOiAiYnJvd3NlciIsCiAgInRpdGxlIjogIk5vZGUgRXhwb3J0ZXIiLAogICJ1aWQiOiAibm9kZS1leHBvcnRlciIsCiAgInZlcnNpb24iOiAxCn0K"
    lxc_exec "$vmid" "echo '$node_dashboard_b64' | base64 -d > ${service_dir}/dashboards/node-exporter.json"

    # Loki Logs Dashboard (Log Stream, Volume, Error Logs)
    local loki_dashboard_b64="ewogICJhbm5vdGF0aW9ucyI6IHsibGlzdCI6IFtdfSwKICAiZWRpdGFibGUiOiB0cnVlLAogICJmaXNjYWxZZWFyU3RhcnRNb250aCI6IDAsCiAgImdyYXBoVG9vbHRpcCI6IDAsCiAgImlkIjogbnVsbCwKICAibGlua3MiOiBbXSwKICAicGFuZWxzIjogWwogICAgewogICAgICAiZGF0YXNvdXJjZSI6IHsidHlwZSI6ICJsb2tpIiwgInVpZCI6ICJsb2tpIn0sCiAgICAgICJncmlkUG9zIjogeyJoIjogNiwgInciOiAyNCwgIngiOiAwLCAieSI6IDB9LAogICAgICAiaWQiOiAxLAogICAgICAib3B0aW9ucyI6IHsKICAgICAgICAiZGVkdXBTdHJhdGVneSI6ICJub25lIiwKICAgICAgICAiZW5hYmxlTG9nRGV0YWlscyI6IHRydWUsCiAgICAgICAgInByZXR0aWZ5TG9nTWVzc2FnZSI6IGZhbHNlLAogICAgICAgICJzaG93Q29tbW9uTGFiZWxzIjogZmFsc2UsCiAgICAgICAgInNob3dMYWJlbHMiOiB0cnVlLAogICAgICAgICJzaG93VGltZSI6IHRydWUsCiAgICAgICAgInNvcnRPcmRlciI6ICJEZXNjZW5kaW5nIiwKICAgICAgICAid3JhcExvZ01lc3NhZ2UiOiBmYWxzZQogICAgICB9LAogICAgICAidGFyZ2V0cyI6IFsKICAgICAgICB7CiAgICAgICAgICAiZGF0YXNvdXJjZSI6IHsidHlwZSI6ICJsb2tpIiwgInVpZCI6ICJsb2tpIn0sCiAgICAgICAgICAiZWRpdG9yTW9kZSI6ICJjb2RlIiwKICAgICAgICAgICJleHByIjogIntqb2I9flwiLitcIn0gfD0gYCRmaWx0ZXJgIiwKICAgICAgICAgICJxdWVyeVR5cGUiOiAicmFuZ2UiLAogICAgICAgICAgInJlZklkIjogIkEiCiAgICAgICAgfQogICAgICBdLAogICAgICAidGl0bGUiOiAiTG9nIFN0cmVhbSIsCiAgICAgICJ0eXBlIjogImxvZ3MiCiAgICB9LAogICAgewogICAgICAiZGF0YXNvdXJjZSI6IHsidHlwZSI6ICJsb2tpIiwgInVpZCI6ICJsb2tpIn0sCiAgICAgICJmaWVsZENvbmZpZyI6IHsKICAgICAgICAiZGVmYXVsdHMiOiB7ImNvbG9yIjogeyJtb2RlIjogInBhbGV0dGUtY2xhc3NpYyJ9LCAiY3VzdG9tIjogeyJheGlzQ2VudGVyZWRaZXJvIjogZmFsc2UsICJheGlzQ29sb3JNb2RlIjogInRleHQiLCAiYXhpc0xhYmVsIjogIiIsICJheGlzUGxhY2VtZW50IjogImF1dG8iLCAiYmFyQWxpZ25tZW50IjogMCwgImRyYXdTdHlsZSI6ICJiYXJzIiwgImZpbGxPcGFjaXR5IjogMTAwLCAiZ3JhZGllbnRNb2RlIjogIm5vbmUiLCAiaGlkZUZyb20iOiB7ImxlZ2VuZCI6IGZhbHNlLCAidG9vbHRpcCI6IGZhbHNlLCAidml6IjogZmFsc2V9LCAibGluZUludGVycG9sYXRpb24iOiAibGluZWFyIiwgImxpbmVXaWR0aCI6IDEsICJwb2ludFNpemUiOiA1LCAic2NhbGVEaXN0cmlidXRpb24iOiB7InR5cGUiOiAibGluZWFyIn0sICJzaG93UG9pbnRzIjogIm5ldmVyIiwgInNwYW5OdWxscyI6IGZhbHNlLCAic3RhY2tpbmciOiB7Imdyb3VwIjogIkEiLCAibW9kZSI6ICJub3JtYWwifSwgInRocmVzaG9sZHNTdHlsZSI6IHsibW9kZSI6ICJvZmYifX0sICJtYXBwaW5ncyI6IFtdLCAidGhyZXNob2xkcyI6IHsibW9kZSI6ICJhYnNvbHV0ZSIsICJzdGVwcyI6IFt7ImNvbG9yIjogImdyZWVuIiwgInZhbHVlIjogbnVsbH1dfX0sCiAgICAgICAgIm92ZXJyaWRlcyI6IFtdCiAgICAgIH0sCiAgICAgICJncmlkUG9zIjogeyJoIjogOCwgInciOiAyNCwgIngiOiAwLCAieSI6IDZ9LAogICAgICAiaWQiOiAyLAogICAgICAib3B0aW9ucyI6IHsibGVnZW5kIjogeyJjYWxjcyI6IFtdLCAiZGlzcGxheU1vZGUiOiAibGlzdCIsICJwbGFjZW1lbnQiOiAiYm90dG9tIiwgInNob3dMZWdlbmQiOiB0cnVlfSwgInRvb2x0aXAiOiB7Im1vZGUiOiAic2luZ2xlIiwgInNvcnQiOiAibm9uZSJ9fSwKICAgICAgInRhcmdldHMiOiBbCiAgICAgICAgewogICAgICAgICAgImRhdGFzb3VyY2UiOiB7InR5cGUiOiAibG9raSIsICJ1aWQiOiAibG9raSJ9LAogICAgICAgICAgImVkaXRvck1vZGUiOiAiY29kZSIsCiAgICAgICAgICAiZXhwciI6ICJzdW0gYnkgKGpvYikgKGNvdW50X292ZXJfdGltZSh7am9iPX5cIi4rXCJ9WzFtXSkpIiwKICAgICAgICAgICJxdWVyeVR5cGUiOiAicmFuZ2UiLAogICAgICAgICAgInJlZklkIjogIkEiCiAgICAgICAgfQogICAgICBdLAogICAgICAidGl0bGUiOiAiTG9nIFZvbHVtZSBieSBKb2IiLAogICAgICAidHlwZSI6ICJ0aW1lc2VyaWVzIgogICAgfSwKICAgIHsKICAgICAgImRhdGFzb3VyY2UiOiB7InR5cGUiOiAibG9raSIsICJ1aWQiOiAibG9raSJ9LAogICAgICAiZ3JpZFBvcyI6IHsiaCI6IDEwLCAidyI6IDI0LCAieCI6IDAsICJ5IjogMTR9LAogICAgICAiaWQiOiAzLAogICAgICAib3B0aW9ucyI6IHsKICAgICAgICAiZGVkdXBTdHJhdGVneSI6ICJub25lIiwKICAgICAgICAiZW5hYmxlTG9nRGV0YWlscyI6IHRydWUsCiAgICAgICAgInByZXR0aWZ5TG9nTWVzc2FnZSI6IGZhbHNlLAogICAgICAgICJzaG93Q29tbW9uTGFiZWxzIjogZmFsc2UsCiAgICAgICAgInNob3dMYWJlbHMiOiB0cnVlLAogICAgICAgICJzaG93VGltZSI6IHRydWUsCiAgICAgICAgInNvcnRPcmRlciI6ICJEZXNjZW5kaW5nIiwKICAgICAgICAid3JhcExvZ01lc3NhZ2UiOiBmYWxzZQogICAgICB9LAogICAgICAidGFyZ2V0cyI6IFsKICAgICAgICB7CiAgICAgICAgICAiZGF0YXNvdXJjZSI6IHsidHlwZSI6ICJsb2tpIiwgInVpZCI6ICJsb2tpIn0sCiAgICAgICAgICAiZWRpdG9yTW9kZSI6ICJjb2RlIiwKICAgICAgICAgICJleHByIjogIntqb2I9flwiLitcIn0gfH4gYCg/aSkoZXJyb3J8d2FybnxmYXRhbHxjcml0aWNhbClgIiwKICAgICAgICAgICJxdWVyeVR5cGUiOiAicmFuZ2UiLAogICAgICAgICAgInJlZklkIjogIkEiCiAgICAgICAgfQogICAgICBdLAogICAgICAidGl0bGUiOiAiRXJyb3IgTG9ncyIsCiAgICAgICJ0eXBlIjogImxvZ3MiCiAgICB9CiAgXSwKICAicmVmcmVzaCI6ICIxMHMiLAogICJzY2hlbWFWZXJzaW9uIjogMzgsCiAgInN0eWxlIjogImRhcmsiLAogICJ0YWdzIjogWyJsb2tpIiwgImxvZ3MiXSwKICAidGVtcGxhdGluZyI6IHsKICAgICJsaXN0IjogWwogICAgICB7CiAgICAgICAgImN1cnJlbnQiOiB7InNlbGVjdGVkIjogZmFsc2UsICJ0ZXh0IjogIiIsICJ2YWx1ZSI6ICIifSwKICAgICAgICAiaGlkZSI6IDAsCiAgICAgICAgImxhYmVsIjogIkZpbHRlciIsCiAgICAgICAgIm5hbWUiOiAiZmlsdGVyIiwKICAgICAgICAib3B0aW9ucyI6IFt7InNlbGVjdGVkIjogdHJ1ZSwgInRleHQiOiAiIiwgInZhbHVlIjogIiJ9XSwKICAgICAgICAicXVlcnkiOiAiIiwKICAgICAgICAic2tpcFVybFN5bmMiOiBmYWxzZSwKICAgICAgICAidHlwZSI6ICJ0ZXh0Ym94IgogICAgICB9CiAgICBdCiAgfSwKICAidGltZSI6IHsiZnJvbSI6ICJub3ctMWgiLCAidG8iOiAibm93In0sCiAgInRpbWV6b25lIjogImJyb3dzZXIiLAogICJ0aXRsZSI6ICJMb2tpIExvZ3MiLAogICJ1aWQiOiAibG9raS1sb2dzIiwKICAidmVyc2lvbiI6IDEKfQo="
    lxc_exec "$vmid" "echo '$loki_dashboard_b64' | base64 -d > ${service_dir}/dashboards/loki-logs.json"

    echo "Grafana dashboards provisioned."
}

# Deploy service natively (without Docker)
deploy_service_native() {
    local vmid="$1"
    local service="$2"
    local service_name="$3"
    local deploy_result_file="/tmp/pve-deploy-native-result-$$.txt"

    log_info "Deploying $service natively to container $vmid"
    log_service_op "$service" "DEPLOY_NATIVE" "vmid=$vmid service_name=$service_name"

    # Check if plugin supports native installation
    if ! is_plugin_service "$service" || ! plugin_supports_native "$service"; then
        log_error "Native installation not available for $service"
        return 1
    fi

    local install_script="${PLUGINS[$service]}/install.sh"
    if [[ ! -f "$install_script" ]]; then
        log_error "Install script not found for $service"
        return 1
    fi

    # Initialize result file
    echo "0" > "$deploy_result_file"

    (
        echo "=== Installing $service_name Natively in Container $vmid ==="
        echo ""

        # Detect OS
        echo "Detecting OS..."
        os_type=$(lxc_exec "$vmid" "cat /etc/os-release 2>/dev/null | grep '^ID=' | cut -d= -f2 | tr -d '\"'")
        echo "OS: $os_type"
        echo ""

        # Run plugin installer
        echo "Using plugin installer for $service..."
        export VMID="$vmid"
        export OS_TYPE="$os_type"
        source "$install_script"
        local result=$?
        if [[ $result -ne 0 ]]; then
            echo "1" > "$deploy_result_file"
            exit $result
        fi

        echo ""
        echo "Verifying installation..."
        sleep 3

        # Check service status
        local conf="${PLUGINS[$service]}/plugin.conf"
        local systemd_service
        systemd_service=$(grep "^PLUGIN_SYSTEMD_SERVICE=" "$conf" 2>/dev/null | cut -d= -f2 | tr -d '"' | tr -d "'")
        [[ -z "$systemd_service" ]] && systemd_service="$service"

        service_running=false
        case "$os_type" in
            debian|ubuntu)
                if lxc_exec "$vmid" "systemctl is-active --quiet $systemd_service 2>/dev/null"; then
                    service_running=true
                fi
                ;;
            alpine)
                if lxc_exec "$vmid" "rc-service $systemd_service status 2>/dev/null | grep -q started"; then
                    service_running=true
                fi
                ;;
        esac

        if [[ "$service_running" == true ]]; then
            echo "Service is running!"
            echo "0" > "$deploy_result_file"
        else
            echo "WARNING: Service may not be running. Check logs."
            echo "0" > "$deploy_result_file"  # Still return success, user can check
        fi

        echo ""
        echo "=== Native Installation Complete ==="

    ) 2>&1 | show_progress_box "Installing $service_name (Native)" 24 80

    # Check deployment result
    local result
    result=$(cat "$deploy_result_file" 2>/dev/null)
    rm -f "$deploy_result_file"

    if [[ "$result" != "0" ]]; then
        return 1
    fi
    return 0
}
# Deploy service to container with progress (Docker-based)
deploy_service_with_progress() {
    local vmid="$1"
    local service="$2"
    local service_name="$3"
    local deploy_result_file="/tmp/pve-deploy-result-$$.txt"

    log_info "Deploying $service to container $vmid"
    log_service_op "$service" "DEPLOY_DOCKER" "vmid=$vmid service_name=$service_name"

    # Initialize result file
    echo "0" > "$deploy_result_file"

    (
        echo "=== Deploying $service_name to Container $vmid ==="
        echo ""

        # Check if Docker is installed
        echo "Checking Docker installation..."
        docker_check=$(lxc_exec "$vmid" "docker --version 2>/dev/null")
        if [[ -z "$docker_check" ]]; then
            echo "ERROR: Docker not installed in container $vmid"
            echo "Please install Docker first."
            echo "1" > "$deploy_result_file"
            exit 1
        fi
        echo "Docker found: $docker_check"
        echo ""

        # Get compose content
        compose_content=$(get_service_compose "$service")
        if [[ -z "$compose_content" ]]; then
            echo "ERROR: Unknown service: $service"
            echo "1" > "$deploy_result_file"
            exit 1
        fi

        # Create service directory
        service_dir="/opt/services/${service}"
        echo "Creating service directory: $service_dir"
        lxc_exec_live "$vmid" "mkdir -p $service_dir"
        echo ""

        # Write docker-compose.yml
        echo "Writing docker-compose.yml..."
        lxc_exec "$vmid" "cat > ${service_dir}/docker-compose.yml << 'COMPOSEEOF'
${compose_content}
COMPOSEEOF"
        echo "Done."
        echo ""

        # Write additional config files if needed
        case "$service" in
            monitoring-stack)
                echo "Writing prometheus.yml..."
                prom_config=$(get_prometheus_config)
                lxc_exec "$vmid" "cat > ${service_dir}/prometheus.yml << 'PROMEOF'
${prom_config}
PROMEOF"
                echo "Done."

                echo "Setting up SSL certificates..."
                # Get container IP for certificate
                container_ip=$(lxc_exec "$vmid" "hostname -I | awk '{print \$1}'" 2>/dev/null | tr -d '[:space:]')
                lxc_exec_live "$vmid" "mkdir -p ${service_dir}/ssl"
                # Generate self-signed SSL certificate
                lxc_exec "$vmid" "openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                    -keyout ${service_dir}/ssl/server.key \
                    -out ${service_dir}/ssl/server.crt \
                    -subj '/C=US/ST=State/L=City/O=Monitoring/CN=${container_ip:-localhost}' \
                    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${container_ip:-127.0.0.1}' 2>/dev/null"
                lxc_exec_live "$vmid" "chmod 600 ${service_dir}/ssl/server.key"
                echo "SSL certificates generated."

                echo "Writing nginx.conf..."
                # Use base64-encoded config to avoid variable substitution issues
                write_nginx_monitoring_config "$vmid" "$service_dir"
                echo "Done."

                echo "Provisioning Grafana dashboards..."
                provision_grafana_dashboards "$vmid" "$service_dir"
                echo ""
                ;;
            prometheus)
                echo "Writing prometheus.yml..."
                prom_config=$(get_prometheus_config)
                lxc_exec "$vmid" "cat > ${service_dir}/prometheus.yml << 'PROMEOF'
${prom_config}
PROMEOF"
                echo "Done."
                echo ""
                ;;
            alloy)
                echo "Writing config.alloy..."
                alloy_config=$(get_alloy_config)
                lxc_exec "$vmid" "cat > ${service_dir}/config.alloy << 'ALLOYEOF'
${alloy_config}
ALLOYEOF"
                echo "Done."
                echo ""
                ;;
            sonarqube)
                echo "Configuring system settings for SonarQube..."
                lxc_exec_live "$vmid" "sysctl -w vm.max_map_count=524288 2>/dev/null || true"
                lxc_exec_live "$vmid" "sysctl -w fs.file-max=131072 2>/dev/null || true"
                echo ""
                ;;
            dependency-track)
                echo "Configuring system settings for Dependency-Track..."
                # Dependency-Track API server needs more memory for processing large SBOMs
                lxc_exec_live "$vmid" "sysctl -w vm.max_map_count=262144 2>/dev/null || true"
                echo ""
                ;;
            freeipa)
                # FreeIPA needs custom deployment with hostname resolution
                local fqdn="${FREEIPA_FQDN:-ipa.srv.local}"
                local domain="${fqdn#*.}"
                local realm="${domain^^}"

                echo "FreeIPA custom deployment..."
                echo "  FQDN:   $fqdn"
                echo "  Domain: $domain"
                echo "  Realm:  $realm"
                echo ""

                # Get the container IP
                container_ip=$(lxc_exec "$vmid" "hostname -I | awk '{print \$1}'" 2>/dev/null | tr -d '[:space:]')
                echo "Container IP: $container_ip"

                # Set hostname in the LXC container
                echo "Setting up hostname in LXC container..."
                lxc_exec_live "$vmid" "hostnamectl set-hostname $fqdn 2>/dev/null || echo $fqdn > /etc/hostname"

                # Add FQDN to /etc/hosts in the LXC container
                echo "Updating /etc/hosts..."
                lxc_exec "$vmid" "sed -i '/$fqdn/d' /etc/hosts 2>/dev/null || true"
                lxc_exec "$vmid" "echo '${container_ip} ${fqdn} ${fqdn%%.*}' >> /etc/hosts"
                echo "Done."
                echo ""

                # Clean up any previous FreeIPA deployment
                echo "Cleaning up any previous FreeIPA deployment..."
                lxc_exec "$vmid" "docker rm -f freeipa 2>/dev/null || true"
                lxc_exec "$vmid" "docker volume rm freeipa_data 2>/dev/null || true"
                # Prune stale networks and containers to avoid containerd networking errors
                echo "Pruning stale Docker networks..."
                lxc_exec "$vmid" "docker network prune -f 2>/dev/null || true"
                lxc_exec "$vmid" "docker container prune -f 2>/dev/null || true"

                # Resolve Docker daemon issues
                echo "Preparing Docker daemon..."

                # Disable systemd start rate limiting for docker to prevent
                # "Start request repeated too quickly" errors from previous failures
                lxc_exec "$vmid" "mkdir -p /etc/systemd/system/docker.service.d"
                lxc_exec "$vmid" "cat > /etc/systemd/system/docker.service.d/no-rate-limit.conf << 'SVCEOF'
[Unit]
StartLimitIntervalSec=0
StartLimitBurst=0
[Service]
RestartSec=3
SVCEOF"
                lxc_exec "$vmid" "systemctl daemon-reload"
                lxc_exec "$vmid" "systemctl reset-failed docker.service containerd.service 2>/dev/null || true"

                # Full stop of Docker stack
                lxc_exec "$vmid" "systemctl stop docker.socket docker containerd 2>/dev/null || true"
                # Clean stale runtime state
                lxc_exec "$vmid" "rm -rf /var/run/docker /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null || true"

                # Start containerd first, then Docker
                echo "Starting Docker daemon..."
                lxc_exec_live "$vmid" "systemctl start containerd"
                sleep 2
                lxc_exec_live "$vmid" "systemctl start docker"
                sleep 3

                # Verify Docker is running
                if ! lxc_exec "$vmid" "docker info >/dev/null 2>&1"; then
                    echo "Docker failed to start. Retrying..."
                    lxc_exec "$vmid" "systemctl stop docker.socket docker containerd 2>/dev/null || true"
                    lxc_exec "$vmid" "rm -rf /var/run/docker /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null || true"
                    lxc_exec "$vmid" "systemctl reset-failed docker.service containerd.service 2>/dev/null || true"
                    sleep 5
                    lxc_exec_live "$vmid" "systemctl start containerd"
                    sleep 2
                    lxc_exec_live "$vmid" "systemctl start docker"
                    sleep 5
                    if ! lxc_exec "$vmid" "docker info >/dev/null 2>&1"; then
                        echo "ERROR: Docker daemon failed to start."
                        echo ""
                        echo "Docker logs:"
                        lxc_exec_live "$vmid" "journalctl -u docker.service -n 20 --no-pager 2>&1"
                        echo "1" > "$deploy_result_file"
                        exit 1
                    fi
                fi
                echo "Docker daemon is healthy."
                echo ""

                # Pull the image first
                echo "Pulling FreeIPA image (this may take several minutes)..."
                local pull_attempts=0
                local pull_status=1
                while [[ $pull_attempts -lt 3 && $pull_status -ne 0 ]]; do
                    pull_attempts=$((pull_attempts + 1))
                    echo "Pull attempt $pull_attempts of 3..."
                    lxc_exec_timeout "$vmid" 300 "docker pull freeipa/freeipa-server:fedora-43-4.13.0 2>&1"
                    pull_status=$?
                    if [[ $pull_status -ne 0 && $pull_attempts -lt 3 ]]; then
                        echo "Retrying in 10 seconds..."
                        sleep 10
                    fi
                done
                if [[ $pull_status -ne 0 ]]; then
                    echo "ERROR: Failed to pull FreeIPA image"
                    echo "1" > "$deploy_result_file"
                    exit 1
                fi
                echo "Image pulled successfully."
                echo ""

                # Run FreeIPA using docker run with --add-host for hostname resolution
                echo "Starting FreeIPA container..."
                lxc_exec_live "$vmid" "docker run -d \
                    --name freeipa \
                    --hostname ${fqdn} \
                    --privileged \
                    --security-opt seccomp=unconfined \
                    --security-opt apparmor=unconfined \
                    --cgroupns=host \
                    --add-host ${fqdn}:${container_ip} \
                    -e PASSWORD=Admin123 \
                    -p 80:80 -p 443:443 \
                    -p 389:389 -p 636:636 \
                    -p 88:88 -p 88:88/udp \
                    -p 464:464 -p 464:464/udp \
                    -p 53:53 -p 53:53/udp \
                    -v freeipa_data:/data \
                    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
                    --tmpfs /run --tmpfs /tmp \
                    freeipa/freeipa-server:fedora-43-4.13.0 \
                    -U --realm=${realm} --domain=${domain} \
                    --ds-password=Admin123 --admin-password=Admin123 \
                    --no-ntp --no-host-dns \
                    --setup-dns --no-forwarders --allow-zone-overlap"

                echo ""
                echo "FreeIPA container started."
                echo "Initial setup takes 5-10 minutes. Checking startup..."
                echo ""

                # Wait and check if container is still running
                sleep 10
                local freeipa_status
                freeipa_status=$(lxc_exec "$vmid" "docker inspect -f '{{.State.Status}}' freeipa 2>/dev/null")

                if [[ "$freeipa_status" == "running" ]]; then
                    echo "FreeIPA container is running."
                    echo ""
                    echo "Recent logs:"
                    lxc_exec_live "$vmid" "docker logs --tail=10 freeipa 2>&1"
                    echo ""
                    echo "=== FreeIPA Deployment Started ==="
                    echo "Setup is running in the background (5-10 minutes)."
                    echo "Monitor with: docker logs -f freeipa"
                    echo ""
                    echo "Access:"
                    echo "  Web UI: https://${container_ip}/"
                    echo "  LDAP:   ldap://${container_ip}:389"
                    echo "  Admin:  admin / Admin123"
                    echo "0" > "$deploy_result_file"
                else
                    echo "ERROR: FreeIPA container stopped unexpectedly."
                    echo ""
                    echo "Container logs:"
                    lxc_exec_live "$vmid" "docker logs --tail=30 freeipa 2>&1"
                    echo "1" > "$deploy_result_file"
                fi
                exit 0
                ;;
            harbor)
                # Harbor uses official installer - handle specially
                echo "Harbor requires the official installer..."

                # Install docker-compose standalone (required by Harbor installer)
                echo "Checking docker-compose..."
                if ! lxc_exec "$vmid" "command -v docker-compose" > /dev/null 2>&1; then
                    echo "Installing docker-compose..."
                    lxc_exec_live "$vmid" "ARCH=\$(uname -m) && curl -L https://github.com/docker/compose/releases/latest/download/docker-compose-linux-\${ARCH} -o /usr/local/bin/docker-compose"
                    lxc_exec_live "$vmid" "chmod +x /usr/local/bin/docker-compose"
                fi
                echo "Done."

                echo "Downloading Harbor v2.14.2 offline installer..."
                lxc_exec_live "$vmid" "cd /opt && wget -q https://github.com/goharbor/harbor/releases/download/v2.14.2/harbor-offline-installer-v2.14.2.tgz"
                lxc_exec_live "$vmid" "cd /opt && tar xzf harbor-offline-installer-v2.14.2.tgz"
                lxc_exec_live "$vmid" "rm -f /opt/harbor-offline-installer-v2.14.2.tgz"
                echo "Done."

                # Get container IP for configuration
                container_ip=$(lxc_exec "$vmid" "hostname -I | awk '{print \$1}'" 2>/dev/null | tr -d '[:space:]')

                echo "Generating SSL certificates..."
                lxc_exec_live "$vmid" "mkdir -p /opt/harbor/ssl"
                lxc_exec "$vmid" "openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                    -keyout /opt/harbor/ssl/server.key \
                    -out /opt/harbor/ssl/server.crt \
                    -subj '/C=US/ST=State/L=City/O=Harbor/CN=${container_ip:-localhost}' \
                    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${container_ip:-127.0.0.1}' 2>/dev/null"
                echo "SSL certificates generated."

                echo "Configuring Harbor..."
                lxc_exec "$vmid" "cat > /opt/harbor/harbor.yml << HARBOREOF
hostname: ${container_ip:-localhost}
http:
  port: 80
https:
  port: 443
  certificate: /opt/harbor/ssl/server.crt
  private_key: /opt/harbor/ssl/server.key
harbor_admin_password: Harbor12345
database:
  password: Harbor12345
  max_idle_conns: 50
  max_open_conns: 100
  conn_max_lifetime: 5m
  conn_max_idle_time: 0
data_volume: /data/harbor
trivy:
  ignore_unfixed: false
  skip_update: false
  offline_scan: false
  security_check: vuln
  insecure: false
jobservice:
  max_job_workers: 10
  job_loggers:
    - STD_OUTPUT
    - FILE
  logger_sweeper_duration: 1
notification:
  webhook_job_max_retry: 3
  webhook_job_http_client_timeout: 3
log:
  level: info
  local:
    rotate_count: 50
    rotate_size: 200M
    location: /var/log/harbor
_version: 2.14.0
proxy:
  http_proxy:
  https_proxy:
  no_proxy:
  components:
    - core
    - jobservice
    - trivy
upload_purging:
  enabled: true
  age: 168h
  interval: 24h
  dryrun: false
cache:
  enabled: false
  expire_hours: 24
HARBOREOF"
                echo "Done."

                # Prepare data directory
                lxc_exec_live "$vmid" "mkdir -p /data/harbor"

                # Configure Docker to skip AppArmor (required for LXC containers)
                echo "Configuring Docker for LXC environment..."
                lxc_exec "$vmid" 'mkdir -p /etc/docker && cat > /etc/docker/daemon.json << DAEMONJSON
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "no-new-privileges": false
}
DAEMONJSON'
                # Restart Docker to apply settings
                lxc_exec_live "$vmid" "systemctl restart docker"
                sleep 2

                # Run Harbor installer (this pulls images and starts containers)
                echo ""
                echo "Running Harbor installer (this may take several minutes)..."
                lxc_exec_live "$vmid" "cd /opt/harbor && ./install.sh --with-trivy"

                # Fix AppArmor issues for LXC by adding security_opt to all services
                echo "Applying LXC compatibility fixes..."
                # Install PyYAML if not present, then add security_opt to disable AppArmor
                lxc_exec "$vmid" "apt-get install -y python3-yaml >/dev/null 2>&1 || pip3 install pyyaml >/dev/null 2>&1 || true"
                lxc_exec "$vmid" "cd /opt/harbor && python3 -c \"
import yaml
with open('docker-compose.yml', 'r') as f:
    data = yaml.safe_load(f)
for svc in data.get('services', {}).values():
    svc['security_opt'] = ['apparmor:unconfined']
with open('docker-compose.yml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
\""
                # Restart with fixed config
                lxc_exec_live "$vmid" "cd /opt/harbor && docker-compose down && docker-compose up -d"

                # Create symlink for service directory compatibility
                lxc_exec_live "$vmid" "ln -sf /opt/harbor ${service_dir} 2>/dev/null || true"

                echo ""
                echo "=== Harbor Deployment Complete ==="
                echo "Portal: https://${container_ip}/"
                echo "Credentials: admin / Harbor12345"
                echo "0" > "$deploy_result_file"
                exit 0
                ;;
            nginx)
                echo "Writing nginx.conf..."
                nginx_main=$(cat "${PLUGINS[$service]}/nginx.conf")
                lxc_exec "$vmid" "cat > ${service_dir}/nginx.conf << 'NGINXMAINEOF'
${nginx_main}
NGINXMAINEOF"
                echo "Writing reverse proxy site (conf.d/default.conf)..."
                lxc_exec_live "$vmid" "mkdir -p ${service_dir}/conf.d ${service_dir}/ssl"
                nginx_site=$(cat "${PLUGINS[$service]}/conf.d/default.conf")
                lxc_exec "$vmid" "cat > ${service_dir}/conf.d/default.conf << 'NGINXSITEEOF'
${nginx_site}
NGINXSITEEOF"
                echo "Generating self-signed TLS certificate..."
                container_ip=$(lxc_exec "$vmid" "hostname -I | awk '{print \$1}'" 2>/dev/null | tr -d '[:space:]')
                lxc_exec "$vmid" "test -f ${service_dir}/ssl/server.crt || openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${service_dir}/ssl/server.key -out ${service_dir}/ssl/server.crt -subj '/CN=${container_ip:-pve-nginx}' -addext 'subjectAltName=IP:${container_ip:-127.0.0.1}' 2>/dev/null"
                echo "Done."
                echo ""
                ;;
        esac

        # Start the service (skip for Harbor which uses its own installer)
        echo "Pulling Docker images (this may take a few minutes)..."
        echo ""

        # Pull with timeout and retry logic for reliability
        local pull_attempts=0
        local max_pull_attempts=3
        local pull_status=1

        while [[ $pull_attempts -lt $max_pull_attempts && $pull_status -ne 0 ]]; do
            pull_attempts=$((pull_attempts + 1))
            echo "Pull attempt $pull_attempts of $max_pull_attempts..."

            # Use timeout to prevent indefinite hangs (5 minutes per attempt)
            pull_output=$(lxc_exec_timeout "$vmid" 300 "cd ${service_dir} && docker compose pull --quiet 2>&1")
            pull_status=$?

            if [[ $pull_status -eq 124 ]]; then
                echo "Pull timed out. Retrying..."
                # Reset Docker network on timeout
                lxc_exec "$vmid" "systemctl restart docker 2>/dev/null || true" > /dev/null 2>&1
                sleep 5
            elif [[ $pull_status -ne 0 ]]; then
                echo "Pull failed: $pull_output"
                if [[ $pull_attempts -lt $max_pull_attempts ]]; then
                    echo "Waiting 10 seconds before retry..."
                    sleep 10
                fi
            else
                echo "Images pulled successfully."
            fi
        done

        if [[ $pull_status -ne 0 ]]; then
            echo "ERROR: Failed to pull Docker images after $max_pull_attempts attempts"
            echo "Possible causes: network issues, Docker registry unavailable"
            echo "1" > "$deploy_result_file"
            exit 1
        fi
        echo ""

        echo "Starting $service_name..."
        echo ""
        start_output=$(lxc_exec "$vmid" "cd ${service_dir} && docker compose up -d 2>&1")
        start_status=$?
        echo "$start_output"
        echo ""

        if [[ $start_status -ne 0 ]]; then
            echo "ERROR: Failed to start containers"
            echo "Check if container has Docker features enabled (nesting, keyctl, AppArmor)"
            echo "1" > "$deploy_result_file"
            exit 1
        fi

        # Wait for services to start
        echo "Waiting for services to start..."
        sleep 5

        # Verify containers are running
        echo ""
        echo "Verifying deployment..."
        running_containers=$(lxc_exec "$vmid" "docker ps --format '{{.Names}}' 2>/dev/null" | wc -l)

        if [[ "$running_containers" -eq 0 ]]; then
            echo "WARNING: No containers are running!"
            echo ""
            echo "Checking container logs..."
            lxc_exec_live "$vmid" "cd ${service_dir} && docker compose logs --tail=20 2>&1"
            echo "1" > "$deploy_result_file"
            exit 1
        fi

        echo "Running containers ($running_containers):"
        lxc_exec_live "$vmid" "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
        echo ""

        echo "=== Deployment Complete ==="
        echo "0" > "$deploy_result_file"

    ) 2>&1 | show_progress_box "Deploying $service_name" 24 80

    # Check deployment result
    local result
    result=$(cat "$deploy_result_file" 2>/dev/null)
    rm -f "$deploy_result_file"

    if [[ "$result" != "0" ]]; then
        return 1
    fi
    return 0
}

# Service Deployment Menu
# Show supported services list
show_supported_services() {
    local services_info="
═══════════════════════════════════════════════════════════════
                    PVE MANAGER - SUPPORTED SERVICES
═══════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────┐
│  MONITORING STACK                                           │
├─────────────────────────────────────────────────────────────┤
│  • Prometheus        - Metrics collection & alerting        │
│  • Grafana           - Visualization & dashboards           │
│  • Loki              - Log aggregation system               │
│  • Alloy             - Telemetry collector (metrics/logs)   │
│  • Node Exporter     - Hardware/OS metrics exporter         │
│  • Full Stack        - All monitoring tools combined        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  DEVELOPMENT TOOLS                                          │
├─────────────────────────────────────────────────────────────┤
│  • SonarQube         - Code quality & security analysis     │
│  • Nexus             - Artifact repository manager          │
│  • Gitea             - Lightweight Git server               │
│  • Jenkins           - CI/CD automation server              │
│  • Harbor            - Container image registry             │
│  • Dependency-Track  - SCA & SBOM vulnerability mgmt        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  TESTING TOOLS                                              │
├─────────────────────────────────────────────────────────────┤
│  • Kiwi TCMS         - Test case management system          │
│  • Selenium Grid     - Browser automation testing           │
│  • TestLink          - Test management & execution          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  INFRASTRUCTURE TOOLS                                       │
├─────────────────────────────────────────────────────────────┤
│  • Pi-hole           - Network-wide DNS ad blocker          │
│  • Keycloak          - Identity & access management (IAM)   │
│  • FreeIPA           - Identity mgmt (LDAP/Kerberos/DNS)    │
│  • Postfix Relay     - SMTP mail relay server               │
│  • Traefik           - Reverse proxy & load balancer        │
│  • Nginx             - Reverse proxy & web server           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  DATABASES                                                 │
├─────────────────────────────────────────────────────────────┤
│  • MySQL             - Relational database server           │
│  • PostgreSQL        - Relational database server           │
│  • MongoDB           - NoSQL document database              │
└─────────────────────────────────────────────────────────────┘

───────────────────────────────────────────────────────────────
  DEPLOYMENT OPTIONS:
  ─────────────────────────────────────────────────────────────
  [Docker]  All services support Docker-based deployment
  [Native]  Some services support native OS installation:
            Prometheus, Grafana, Gitea, Jenkins, Kiwi TCMS,
            TestLink, SonarQube, Pi-hole, Nginx
  [.env]    Databases prompt for credentials at deploy time
            (stored in /opt/services/<db>/.env)

───────────────────────────────────────────────────────────────
  Total Services: 25
═══════════════════════════════════════════════════════════════
"

    local tmpfile="/tmp/pve-services-list-$$.txt"
    echo "$services_info" > "$tmpfile"
    show_textbox "Supported Services" "$tmpfile" 30 70
    rm -f "$tmpfile"
}

# Reverse Proxy Menu
reverse_proxy_menu() {
    while true; do
        local choice
        choice=$(show_menu "Reverse Proxy" "Select reverse proxy to deploy:" \
            "1" "Nginx (reverse proxy & web server)" \
            "2" "Traefik (reverse proxy & load balancer)" \
            "0" "Back")

        case "$choice" in
            1) deploy_service_wizard "nginx" "Nginx Reverse Proxy" ;;
            2) deploy_service_wizard "traefik" "Traefik Reverse Proxy" ;;
            0|"") break ;;
        esac
    done
}

# Service Deployment Menu
service_deployment_menu() {
    while true; do
        if [[ -z "$CURRENT_PVE" ]]; then
            show_msg "Not Connected" "Please connect to a PVE server first."
            return
        fi

        local choice
        choice=$(show_menu "Service Deployment" "Select a category:" \
            "1" "Monitoring Stack" \
            "2" "Development Tools" \
            "3" "Testing Tools" \
            "4" "Infrastructure Tools" \
            "5" "Reverse Proxy (Nginx / Traefik)" \
            "6" "Databases (MySQL / PostgreSQL / MongoDB)" \
            "7" "View deployed services" \
            "8" "Update/Redeploy service" \
            "9" "Stop service" \
            "10" "Remove service" \
            "11" "Enable HTTPS for service (manual)" \
            "12" "Auto-HTTPS via Nginx (reverse proxy)" \
            "13" "View supported services list" \
            "0" "Back to main menu")

        case "$choice" in
            1)
                monitoring_menu
                ;;
            2)
                devtools_menu
                ;;
            3)
                testing_menu
                ;;
            4)
                infrastructure_menu
                ;;
            5)
                reverse_proxy_menu
                ;;
            6)
                database_menu
                ;;
            7)
                view_deployed_services
                ;;
            8)
                update_service_wizard
                ;;
            9)
                stop_service_wizard
                ;;
            10)
                remove_service_wizard
                ;;
            11)
                enable_https_wizard
                ;;
            12)
                nginx_auto_https_wizard
                ;;
            13)
                show_supported_services
                ;;
            0|"")
                break
                ;;
        esac
    done
}

# Update/Redeploy service wizard
update_service_wizard() {
    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local ct_array=()
    while read -r vmid status rest; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        local name="${rest##* }"
        ct_array+=("$vmid" "$name")
    done <<< "$containers"

    if [[ ${#ct_array[@]} -eq 0 ]]; then
        show_msg "No Running Containers" "No running containers found."
        return
    fi

    local selected
    selected=$(show_menu "Select Container" "Choose container with service to update:" "${ct_array[@]}")
    [[ -z "$selected" ]] && return

    # Find deployed services in container
    local services_dir="/opt/services"
    local service_list
    service_list=$(lxc_exec "$selected" "ls -1 $services_dir 2>/dev/null" | tr '\n' ' ')

    if [[ -z "$service_list" ]]; then
        show_msg "No Services" "No services found in container $selected.\n\nServices directory: $services_dir"
        return
    fi

    # Build menu from found services
    local svc_array=()
    for svc in $service_list; do
        [[ -z "$svc" ]] && continue
        svc_array+=("$svc" "$svc")
    done

    if [[ ${#svc_array[@]} -eq 0 ]]; then
        show_msg "No Services" "No services found in container $selected."
        return
    fi

    local selected_svc
    selected_svc=$(show_menu "Select Service" "Choose service to update/redeploy:" "${svc_array[@]}")
    [[ -z "$selected_svc" ]] && return

    if show_yesno "Confirm Update" "This will:\n1. Stop the current service\n2. Update docker-compose.yml with latest config\n3. Pull latest images\n4. Restart the service\n\nUpdate $selected_svc in container $selected?"; then
        redeploy_service_with_progress "$selected" "$selected_svc"
    fi
}

# Redeploy service with progress
redeploy_service_with_progress() {
    local vmid="$1"
    local service="$2"
    local result_file="/tmp/pve-redeploy-result-$$.txt"

    echo "0" > "$result_file"

    (
        echo "=== Updating $service in Container $vmid ==="
        echo ""

        service_dir="/opt/services/${service}"

        # Check if service exists
        if ! lxc_exec "$vmid" "test -d $service_dir" 2>/dev/null; then
            echo "ERROR: Service directory not found: $service_dir"
            echo "1" > "$result_file"
            exit 1
        fi

        # Stop existing service
        echo "Stopping current service..."
        lxc_exec_live "$vmid" "cd $service_dir && docker compose down 2>&1"
        echo ""

        # Update docker-compose.yml with latest config
        echo "Updating configuration..."
        compose_content=$(get_service_compose "$service")
        if [[ -n "$compose_content" ]]; then
            lxc_exec "$vmid" "cat > ${service_dir}/docker-compose.yml << 'COMPOSEEOF'
${compose_content}
COMPOSEEOF"
            echo "Configuration updated."
        else
            echo "No template found for $service, keeping existing config."
        fi
        echo ""

        # Pull latest images with timeout and retry
        echo "Pulling latest images..."
        local pull_ok=false
        for attempt in 1 2 3; do
            echo "Pull attempt $attempt..."
            if lxc_exec_timeout "$vmid" 300 "cd $service_dir && docker compose pull --quiet 2>&1"; then
                pull_ok=true
                echo "Images pulled successfully."
                break
            fi
            echo "Pull attempt $attempt failed, retrying..."
            sleep 5
        done
        if [[ "$pull_ok" != "true" ]]; then
            echo "WARNING: Failed to pull latest images, continuing with existing..."
        fi
        echo ""

        # Start service
        echo "Starting service..."
        lxc_exec_live "$vmid" "cd $service_dir && docker compose up -d 2>&1"
        echo ""

        # Wait and verify
        echo "Waiting for service to start..."
        sleep 5

        echo ""
        echo "Service status:"
        lxc_exec_live "$vmid" "cd $service_dir && docker compose ps 2>&1"
        echo ""

        echo "=== Update Complete ==="
        echo "0" > "$result_file"

    ) 2>&1 | show_progress_box "Updating $service" 24 80

    local result
    result=$(cat "$result_file" 2>/dev/null)
    rm -f "$result_file"

    if [[ "$result" == "0" ]]; then
        show_msg "Update Complete" "$service has been updated in container $vmid."
    else
        show_msg "Update Failed" "Failed to update $service. Check logs for details."
    fi
}

# Stop service wizard
stop_service_wizard() {
    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local ct_array=()
    while read -r vmid status rest; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        local name="${rest##* }"
        ct_array+=("$vmid" "$name")
    done <<< "$containers"

    if [[ ${#ct_array[@]} -eq 0 ]]; then
        show_msg "No Running Containers" "No running containers found."
        return
    fi

    local selected
    selected=$(show_menu "Select Container" "Choose container:" "${ct_array[@]}")
    [[ -z "$selected" ]] && return

    # Find deployed services
    local services_dir="/opt/services"
    local service_list
    service_list=$(lxc_exec "$selected" "ls -1 $services_dir 2>/dev/null" | tr '\n' ' ')

    if [[ -z "$service_list" ]]; then
        show_msg "No Services" "No services found in container $selected."
        return
    fi

    local svc_array=()
    for svc in $service_list; do
        [[ -z "$svc" ]] && continue
        svc_array+=("$svc" "$svc")
    done

    local selected_svc
    selected_svc=$(show_menu "Select Service" "Choose service to stop:" "${svc_array[@]}")
    [[ -z "$selected_svc" ]] && return

    if show_yesno "Confirm Stop" "Stop $selected_svc in container $selected?"; then
        (
            echo "Stopping $selected_svc..."
            lxc_exec_live "$selected" "cd /opt/services/$selected_svc && docker compose down 2>&1"
            echo ""
            echo "Service stopped."
        ) 2>&1 | show_progress_box "Stopping Service" 12 60

        show_msg "Service Stopped" "$selected_svc has been stopped in container $selected."
    fi
}

# Remove service wizard
remove_service_wizard() {
    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local ct_array=()
    while read -r vmid status rest; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        local name="${rest##* }"
        ct_array+=("$vmid" "$name")
    done <<< "$containers"

    if [[ ${#ct_array[@]} -eq 0 ]]; then
        show_msg "No Running Containers" "No running containers found."
        return
    fi

    local selected
    selected=$(show_menu "Select Container" "Choose container:" "${ct_array[@]}")
    [[ -z "$selected" ]] && return

    # Find both Docker-based and native services
    local docker_services native_services
    docker_services=$(lxc_exec "$selected" "ls -1 /opt/services 2>/dev/null" | tr '\n' ' ')
    native_services=$(lxc_exec "$selected" "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -E '^(kiwi|gitea|jenkins|grafana|prometheus|nginx|mariadb|sonarqube|pihole-FTL)\.service' | awk '{print \$1}' | sed 's/.service//; s/pihole-FTL/pihole/' " | tr '\n' ' ')

    local svc_array=()

    # Add Docker services
    for svc in $docker_services; do
        [[ -z "$svc" ]] && continue
        svc_array+=("docker:$svc" "$svc (Docker)")
    done

    # Add Native services
    for svc in $native_services; do
        [[ -z "$svc" ]] && continue
        svc_array+=("native:$svc" "$svc (Native)")
    done

    if [[ ${#svc_array[@]} -eq 0 ]]; then
        show_msg "No Services" "No services found in container $selected."
        return
    fi

    local selected_svc
    selected_svc=$(show_menu "Select Service" "Choose service to remove:" "${svc_array[@]}")
    [[ -z "$selected_svc" ]] && return

    # Parse service type and name
    local svc_type svc_name
    svc_type="${selected_svc%%:*}"
    svc_name="${selected_svc#*:}"

    if [[ "$svc_type" == "docker" ]]; then
        # Docker service removal
        if show_yesno "Confirm Remove" "WARNING: This will:\n1. Stop the Docker service\n2. Remove all containers\n3. Delete volumes (data will be lost!)\n4. Remove service directory\n\nRemove $svc_name from container $selected?"; then
            (
                echo "Removing Docker service: $svc_name..."
                echo ""
                echo "Stopping containers..."
                lxc_exec_live "$selected" "cd /opt/services/$svc_name && docker compose down -v 2>&1"
                echo ""
                echo "Removing service directory..."
                lxc_exec_live "$selected" "rm -rf /opt/services/$svc_name"
                echo ""
                echo "Service removed."
            ) 2>&1 | show_progress_box "Removing Docker Service" 15 60

            show_msg "Service Removed" "$svc_name (Docker) has been removed from container $selected."
        fi
    else
        # Native service removal
        if show_yesno "Confirm Remove" "WARNING: This will:\n1. Stop and disable the systemd service\n2. Remove application files\n3. Remove database (if applicable)\n4. Remove user account\n\nRemove $svc_name (Native) from container $selected?"; then
            remove_native_service "$selected" "$svc_name"
        fi
    fi
}

# Remove native service
remove_native_service() {
    local vmid="$1"
    local service="$2"

    # Verify plugin exists and supports native
    if ! is_plugin_service "$service" || ! plugin_supports_native "$service"; then
        show_msg "Error" "Native removal not available for $service"
        return 1
    fi

    local remove_script="${PLUGINS[$service]}/remove.sh"
    if [[ ! -f "$remove_script" ]]; then
        show_msg "Error" "Remove script not found for $service"
        return 1
    fi

    (
        echo "=== Removing Native Service: $service ==="
        echo ""
        echo "Using plugin remover for $service..."

        # Detect OS for plugin script
        local os_type
        os_type=$(lxc_exec "$vmid" "cat /etc/os-release 2>/dev/null | grep '^ID=' | cut -d= -f2 | tr -d '\"'")
        export VMID="$vmid"
        export OS_TYPE="$os_type"

        # Source the remove script
        source "$remove_script"

        # Reload systemd after removal
        echo ""
        echo "Reloading systemd..."
        lxc_exec_live "$vmid" "systemctl daemon-reload"

        echo ""
        echo "=== Native Service Removed ==="

    ) 2>&1 | show_progress_box "Removing Native Service" 20 70

    show_msg "Service Removed" "$service (Native) has been removed from container $vmid."
}

# Auto-HTTPS via Nginx wizard
# Detects running services in a container and automatically fronts them with
# an Nginx reverse proxy terminating TLS with a PVE Manager CA certificate.
nginx_auto_https_wizard() {
    # Check if CA is initialized
    if [[ ! -f "$CA_DIR/ca.key" ]]; then
        show_msg "CA Not Initialized" "Certificate Authority is not initialized.\n\nPlease go to Certificate Management and initialize the CA first."
        return
    fi

    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local ct_array=()
    while read -r vmid status _ name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        ct_array+=("$vmid" "$name")
    done <<< "$containers"

    if [[ ${#ct_array[@]} -eq 0 ]]; then
        show_msg "No Running Containers" "No running containers found."
        return
    fi

    local selected
    selected=$(show_menu "Auto-HTTPS via Nginx" "Choose container to scan for services:" "${ct_array[@]}")
    [[ -z "$selected" ]] && return

    # Build container-name -> "port|label" map from plugin metadata
    local -A SVC_PORT SVC_LABEL
    local pid conf cname cport pname pcat
    for pid in "${!PLUGINS[@]}"; do
        # Skip the reverse proxies themselves
        [[ "$pid" == "nginx" || "$pid" == "traefik" ]] && continue
        conf="${PLUGINS[$pid]}/plugin.conf"
        # Skip databases - they are not HTTP services and must not be proxied
        pcat=$(get_plugin_value "$conf" "PLUGIN_CATEGORY")
        [[ "$pcat" == "database" ]] && continue
        cname=$(get_plugin_value "$conf" "PLUGIN_DOCKER_CONTAINER")
        cport=$(get_plugin_value "$conf" "PLUGIN_DOCKER_PORT")
        pname=$(get_plugin_value "$conf" "PLUGIN_NAME")
        [[ -z "$cname" ]] && continue
        # Take the first port token only (e.g. "80, 5000" -> "80")
        cport="${cport%%[!0-9]*}"
        [[ -z "$cport" ]] && continue
        SVC_PORT["$cname"]="$cport"
        SVC_LABEL["$cname"]="${pname:-$cname}"
    done

    # Detect running Docker containers and match them to known web services
    show_info "Detecting..." "Scanning running services in container $selected..."
    local running
    running=$(lxc_exec "$selected" "docker ps --format '{{.Names}}' 2>/dev/null")

    local checklist=()
    local detected_count=0
    if [[ -n "$running" ]]; then
        while read -r cn; do
            [[ -z "$cn" ]] && continue
            # Skip proxy containers
            case "$cn" in
                nginx|traefik|nginx-proxy) continue ;;
            esac
            local port="${SVC_PORT[$cn]}"
            [[ -z "$port" ]] && continue
            # Skip services that already serve TLS or are not HTTP
            case "$port" in
                443|8443|25) continue ;;
            esac
            checklist+=("$cn" "${SVC_LABEL[$cn]} (http://127.0.0.1:$port)" "on")
            ((detected_count++)) || true
        done <<< "$running"
    fi

    if [[ $detected_count -eq 0 ]]; then
        show_msg "No Services Detected" "No plain-HTTP web services were detected in container $selected.\n\nThe wizard looks for running Docker services with a known HTTP port (e.g. Grafana, Gitea, Jenkins, SonarQube, Nexus, Prometheus, Keycloak).\n\nServices already serving HTTPS (Harbor, Kiwi TCMS, FreeIPA) are skipped."
        return
    fi

    local picked
    picked=$(show_checklist "Select Services" "Select services to expose over HTTPS via Nginx:" "${checklist[@]}")
    [[ -z "$picked" ]] && return

    # Get hostname and IP for the certificate
    local hostname ip
    hostname=$(lxc_exec "$selected" "hostname" 2>/dev/null | tr -d '[:space:]')
    ip=$(get_container_ip "$selected")
    if [[ -z "$hostname" || -z "$ip" ]]; then
        show_msg "Error" "Could not determine hostname or IP for container $selected."
        return
    fi

    # Fixed Docker reverse-proxy identity (used when method="docker")
    local docker_proxy_container="pve-auto-https-nginx"
    local docker_proxy_conf_dir="/opt/pve-manager/auto-https/conf.d"

    # Determine OS-specific paths/commands
    local os_type conf_dir reload_cmd install_cmd
    os_type=$(detect_container_os "$selected")
    case "$os_type" in
        alpine)
            conf_dir="/etc/nginx/http.d"
            reload_cmd="rc-service nginx reload 2>/dev/null || rc-service nginx restart"
            install_cmd="apk add --no-cache nginx openssl && rc-update add nginx default"
            ;;
        debian|ubuntu|*)
            conf_dir="/etc/nginx/conf.d"
            reload_cmd="systemctl reload nginx 2>/dev/null || systemctl restart nginx"
            install_cmd="apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nginx openssl && systemctl enable nginx"
            ;;
    esac

    # Detect existing reverse-proxy setup and Docker availability, then pick a method
    local has_nginx docker_available existing_docker existing_native method
    has_nginx=$(lxc_exec "$selected" "command -v nginx 2>/dev/null")
    docker_available=$(lxc_exec "$selected" "command -v docker 2>/dev/null")
    existing_docker=$(lxc_exec "$selected" "docker inspect -f '{{.Name}}' $docker_proxy_container 2>/dev/null")
    existing_native=$(lxc_exec "$selected" "test -f $conf_dir/pve-https-upgrade-map.conf && echo yes")

    if [[ -n "$existing_docker" && -z "$existing_native" ]]; then
        method="docker"
    elif [[ -z "$existing_docker" && -n "$existing_native" ]]; then
        method="native"
    elif [[ -z "$docker_available" ]]; then
        method="native"
    else
        method=$(show_menu "Reverse Proxy Method" "Choose how to run the Nginx reverse proxy in container $selected:" \
            "native" "Native nginx (installed as a system service)" \
            "docker" "Dockerized nginx (container: $docker_proxy_container)")
        [[ -z "$method" ]] && return
    fi

    if [[ "$method" == "docker" ]]; then
        conf_dir="$docker_proxy_conf_dir"
    elif [[ -z "$has_nginx" ]]; then
        if ! show_yesno "Install Nginx" "Nginx is not installed in container $selected.\n\nInstall nginx now (native) to use as the HTTPS reverse proxy?"; then
            return
        fi
    fi

    # Resolve the picked checklist tags to valid (tag, port) pairs first, so we
    # know up front whether exactly one service is being integrated.
    local svc_tags=() svc_ports=()
    local tag
    for tag in $picked; do
        tag="${tag//\"/}"
        [[ -z "$tag" ]] && continue
        local sport="${SVC_PORT[$tag]}"
        [[ -z "$sport" ]] && continue
        svc_tags+=("$tag")
        svc_ports+=("$sport")
    done

    if [[ ${#svc_tags[@]} -eq 0 ]]; then
        show_msg "Nothing Selected" "No valid services were selected."
        return
    fi

    # Assign a dedicated HTTPS port to each selected service and build summary.
    # A single integrated service defaults to the standard HTTPS port (443);
    # with multiple services each gets its own port (service port + 10000).
    local -A USED_PORTS
    # Mark ports actually published by Docker in THIS container as used, so we
    # only collide-avoid against real conflicts (e.g. an existing "nginx" or
    # "traefik" proxy already on 443) instead of every plugin's declared port
    # across the whole catalog (several unrelated plugins also declare 443).
    local used_port
    for used_port in $(lxc_exec "$selected" "docker ps --format '{{.Ports}}' 2>/dev/null" | grep -oE '[0-9]+->' | cut -d'-' -f1); do
        USED_PORTS["$used_port"]=1
    done

    local single_service=false
    [[ ${#svc_tags[@]} -eq 1 ]] && single_service=true

    local svc_https=()
    local summary=""
    local i
    for i in "${!svc_tags[@]}"; do
        local sport="${svc_ports[$i]}"
        local hport
        if $single_service; then
            hport=443
        else
            # Default HTTPS port = service port + 10000, fall back to 9443+ on collision/overflow
            hport=$((sport + 10000))
            if [[ $hport -gt 65000 ]]; then hport=9443; fi
        fi
        local wanted_443=false
        $single_service && [[ "$hport" == "443" ]] && wanted_443=true
        while [[ -n "${USED_PORTS[$hport]}" ]]; do hport=$((hport + 1)); done
        USED_PORTS["$hport"]=1
        svc_https+=("$hport")
        local url="https://${ip}:${hport}"
        [[ "$hport" == "443" ]] && url="https://${ip}"
        summary+="  • ${SVC_LABEL[${svc_tags[$i]}]}: ${url}  ->  127.0.0.1:${sport}\n"
        if $wanted_443 && [[ "$hport" != "443" ]]; then
            summary+="    (port 443 is already in use by another service in this container; using ${hport} instead)\n"
        fi
    done

    local method_desc="native nginx (system service)"
    [[ "$method" == "docker" ]] && method_desc="Dockerized nginx (container: $docker_proxy_container)"
    if ! show_yesno "Confirm Auto-HTTPS" "This will configure Nginx HTTPS reverse proxies in container $selected using ${method_desc}:\n\n${summary}\nCertificate: $hostname ($ip), issued by PVE Manager CA.\n\nProceed?"; then
        return
    fi

    # Build the connection-upgrade map (written once, http context)
    local map_conf
    map_conf=$(cat << 'MAPEOF'
# PVE Manager - websocket/upgrade support for reverse proxy
map $http_upgrade $pve_connection_upgrade {
    default upgrade;
    ''      close;
}
MAPEOF
)
    local map_b64
    map_b64=$(printf '%s' "$map_conf" | base64 -w0)

    # Apply everything with a progress box
    (
        echo "=== Auto-HTTPS via Nginx - Container $selected (method: $method) ==="
        echo ""

        if [[ "$method" == "native" && -z "$has_nginx" ]]; then
            echo "Installing nginx ($os_type)..."
            lxc_exec_live "$selected" "$install_cmd"
            echo ""
        fi
        lxc_exec_live "$selected" "mkdir -p $conf_dir"

        echo "Generating certificate for $hostname ($ip)..."
        if [[ -f "$CERTS_DIR/$hostname/${hostname}.crt" ]]; then
            echo "Certificate already exists, reusing."
        else
            ca_generate_cert "$hostname" "$ip"
        fi
        echo "Deploying certificate to container..."
        ca_deploy_cert "$selected" "$hostname" >/dev/null 2>&1
        echo "Certificate installed to /etc/ssl/pve-manager/"
        echo ""

        echo "Writing upgrade map..."
        lxc_exec "$selected" "echo '$map_b64' | base64 -d > $conf_dir/pve-https-upgrade-map.conf"

        # Write one reverse-proxy server block per service
        local i
        for i in "${!svc_tags[@]}"; do
            local t="${svc_tags[$i]}"
            local sp="${svc_ports[$i]}"
            local hp="${svc_https[$i]}"
            local hp_url="https://${ip}:${hp}"
            [[ "$hp" == "443" ]] && hp_url="https://${ip}"
            echo "Configuring ${SVC_LABEL[$t]}: ${hp_url} -> 127.0.0.1:${sp}"

            local site
            site=$(cat << EOF
# PVE Manager - auto HTTPS reverse proxy for ${t}
server {
    listen ${hp} ssl;
    listen [::]:${hp} ssl;
    server_name ${hostname} ${ip};

    ssl_certificate     /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:SSL:10m;

    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:${sp};
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host  \$host;
        proxy_set_header X-Forwarded-Port  ${hp};
        proxy_http_version 1.1;
        proxy_set_header Upgrade           \$http_upgrade;
        proxy_set_header Connection        \$pve_connection_upgrade;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
EOF
)
            local site_b64
            site_b64=$(printf '%s' "$site" | base64 -w0)
            lxc_exec "$selected" "echo '$site_b64' | base64 -d > $conf_dir/pve-https-${t}.conf"
        done
        echo ""

        if [[ "$method" == "native" ]]; then
            echo "Validating nginx configuration..."
            if lxc_exec "$selected" "nginx -t 2>&1"; then
                echo "Configuration valid. Reloading nginx..."
                lxc_exec_live "$selected" "$reload_cmd"
                echo ""
                echo "=== Auto-HTTPS configuration complete ==="
            else
                echo ""
                echo "ERROR: nginx configuration test failed. No changes were reloaded."
                echo "Review the generated files in $conf_dir/pve-https-*.conf"
            fi
        else
            echo "Validating nginx configuration (Docker)..."
            if lxc_exec "$selected" "docker run --rm -v $conf_dir:/etc/nginx/conf.d:ro -v /etc/ssl/pve-manager:/etc/ssl/pve-manager:ro nginx:stable nginx -t 2>&1"; then
                echo "Configuration valid."
                if [[ -n "$existing_docker" ]]; then
                    echo "Restarting existing $docker_proxy_container container..."
                    lxc_exec_live "$selected" "docker restart $docker_proxy_container"
                else
                    echo "Starting $docker_proxy_container container (network: host)..."
                    lxc_exec_live "$selected" "docker run -d --name $docker_proxy_container --network host --restart unless-stopped -v $conf_dir:/etc/nginx/conf.d:ro -v /etc/ssl/pve-manager:/etc/ssl/pve-manager:ro nginx:stable"
                fi
                echo ""
                echo "=== Auto-HTTPS configuration complete ==="
            else
                echo ""
                echo "ERROR: nginx configuration test failed. No changes were applied."
                echo "Review the generated files in $conf_dir/pve-https-*.conf"
            fi
        fi
    ) 2>&1 | show_progress_box "Configuring Auto-HTTPS" 24 84

    # Build access summary
    local access=""
    local i
    for i in "${!svc_tags[@]}"; do
        local access_url="https://${ip}:${svc_https[$i]}"
        [[ "${svc_https[$i]}" == "443" ]] && access_url="https://${ip}"
        access+="${SVC_LABEL[${svc_tags[$i]}]}: ${access_url}\n"
    done
    show_msg "Auto-HTTPS Complete" "Nginx HTTPS reverse proxies configured in container $selected using ${method_desc}:\n\n${access}\nThe PVE Manager CA certificate is trusted inside the container. To trust these URLs from your workstation, import the CA cert (Certificate Management > Export CA certificate)."
}

# Enable HTTPS wizard
enable_https_wizard() {
    # Check if CA is initialized
    if [[ ! -f "$CA_DIR/ca.key" ]]; then
        show_msg "CA Not Initialized" "Certificate Authority is not initialized.\n\nPlease go to Certificate Management and initialize the CA first."
        return
    fi

    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local ct_array=()
    while read -r vmid status rest; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        local name="${rest##* }"
        ct_array+=("$vmid" "$name")
    done <<< "$containers"

    if [[ ${#ct_array[@]} -eq 0 ]]; then
        show_msg "No Running Containers" "No running containers found."
        return
    fi

    local selected
    selected=$(show_menu "Select Container" "Choose container to enable HTTPS:" "${ct_array[@]}")
    [[ -z "$selected" ]] && return

    # Check for native services with nginx
    local has_nginx
    has_nginx=$(lxc_exec "$selected" "which nginx 2>/dev/null")

    if [[ -z "$has_nginx" ]]; then
        show_msg "No Nginx" "Nginx is not installed in container $selected.\n\nHTTPS enablement requires nginx as reverse proxy."
        return
    fi

    # Find services that can be HTTPS-enabled
    local svc_array=()

    # Check for Kiwi TCMS
    if lxc_exec "$selected" "test -f /etc/nginx/sites-available/kiwi" 2>/dev/null; then
        svc_array+=("kiwi" "Kiwi TCMS")
    fi

    # Check for Gitea (if using nginx)
    if lxc_exec "$selected" "test -f /etc/nginx/sites-available/gitea" 2>/dev/null; then
        svc_array+=("gitea" "Gitea")
    fi

    # Check for TestLink (Nginx-based)
    if lxc_exec "$selected" "test -f /etc/nginx/sites-available/testlink" 2>/dev/null; then
        svc_array+=("testlink" "TestLink")
    fi

    # Check for generic nginx default
    if lxc_exec "$selected" "test -f /etc/nginx/sites-available/default" 2>/dev/null; then
        svc_array+=("default" "Default Site")
    fi

    if [[ ${#svc_array[@]} -eq 0 ]]; then
        show_msg "No Services" "No HTTPS-compatible services found in container $selected.\n\nSupported services: Kiwi TCMS, Gitea, TestLink"
        return
    fi

    local selected_svc
    selected_svc=$(show_menu "Select Service" "Choose service to enable HTTPS:" "${svc_array[@]}")
    [[ -z "$selected_svc" ]] && return

    # Get container hostname and IP
    local hostname ip
    hostname=$(lxc_exec "$selected" "hostname")
    ip=$(get_container_ip "$selected")

    if [[ -z "$hostname" ]] || [[ -z "$ip" ]]; then
        show_msg "Error" "Could not get hostname or IP for container $selected."
        return
    fi

    if show_yesno "Enable HTTPS" "This will:\n1. Generate SSL certificate for $hostname ($ip)\n2. Deploy certificate to container\n3. Update nginx to use HTTPS (port 443)\n4. Redirect HTTP to HTTPS\n\nEnable HTTPS for $selected_svc?"; then
        enable_https_for_service "$selected" "$selected_svc" "$hostname" "$ip"
    fi
}

# Enable HTTPS for a specific service
enable_https_for_service() {
    local vmid="$1"
    local service="$2"
    local hostname="$3"
    local ip="$4"

    (
        echo "=== Enabling HTTPS for $service in Container $vmid ==="
        echo ""

        # Step 1: Generate certificate
        echo "Step 1: Generating SSL certificate..."
        local cert_dir="$CERTS_DIR/$hostname"

        if [[ -f "$cert_dir/${hostname}.crt" ]]; then
            echo "Certificate already exists for $hostname"
        else
            ca_generate_cert "$hostname" "$ip"
            echo "Certificate generated."
        fi
        echo ""

        # Step 2: Deploy certificate to container
        echo "Step 2: Deploying certificate to container..."
        ca_deploy_cert "$vmid" "$hostname"
        echo "Certificate deployed to /etc/ssl/pve-manager/"
        echo ""

        # Step 3: Update nginx configuration
        echo "Step 3: Updating nginx configuration..."

        case "$service" in
            kiwi)
                lxc_exec "$vmid" "cat > /etc/nginx/sites-available/kiwi << 'NGINXEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    client_max_body_size 100M;

    # Serve static files directly
    location /static/ {
        alias /Kiwi/static/;
        autoindex off;
        expires 30d;
        add_header Cache-Control public;

        # Ensure correct MIME types
        types {
            text/css css;
            application/javascript js;
            application/json json;
            image/svg+xml svg svgz;
            font/woff woff;
            font/woff2 woff2;
            application/vnd.ms-fontobject eot;
            font/ttf ttf;
            font/otf otf;
        }
    }

    # Media/uploads files
    location /uploads/ {
        alias /Kiwi/uploads/;
        autoindex off;
        expires 7d;
    }

    # Favicon
    location = /favicon.ico {
        alias /Kiwi/static/images/favicon.ico;
        expires 30d;
        access_log off;
        log_not_found off;
    }

    # Proxy to gunicorn
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;
    }
}
NGINXEOF"
                ;;

            gitea)
                lxc_exec "$vmid" "cat > /etc/nginx/sites-available/gitea << 'NGINXEOF'
server {
    listen 80;
    listen [::]:80;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;
    }
}
NGINXEOF"
                ;;

            testlink)
                # TestLink uses Nginx + PHP-FPM - find the actual socket path
                local php_sock
                php_sock=$(lxc_exec "$vmid" "ls /run/php/php*-fpm.sock 2>/dev/null | head -1")
                [[ -z "$php_sock" ]] && php_sock="/run/php/php8.2-fpm.sock"

                lxc_exec "$vmid" "cat > /etc/nginx/sites-available/testlink << NGINXEOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://\\\$host\\\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    root /var/www/testlink;
    index index.php index.html;

    client_max_body_size 64M;

    location / {
        try_files \\\$uri \\\$uri/ =404;
    }

    location ~ \\\\.php\\\$ {
        fastcgi_split_path_info ^(.+\\\\.php)(/.+)\\\$;
        fastcgi_pass unix:${php_sock};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \\\$document_root\\\$fastcgi_script_name;
        fastcgi_param PATH_INFO \\\$fastcgi_path_info;
        include fastcgi_params;
    }

    location ~ /\\\\. {
        deny all;
    }
}
NGINXEOF"
                ;;

            default)
                lxc_exec "$vmid" "cat > /etc/nginx/sites-available/default << 'NGINXEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/pve-manager/${hostname}-chain.pem;
    ssl_certificate_key /etc/ssl/pve-manager/${hostname}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
NGINXEOF"
                ;;
        esac

        # Step 4: Test and reload nginx
        echo "Configuration updated."
        echo ""
        echo "Step 4: Testing nginx configuration..."
        lxc_exec_live "$vmid" "nginx -t"

        echo ""
        echo "Reloading nginx..."
        lxc_exec_live "$vmid" "systemctl reload nginx"

        echo ""
        echo "=== HTTPS Enabled Successfully ==="
        echo ""
        echo "Access URL: https://${ip}/"
        echo ""
        echo "NOTE: You may need to import the CA certificate into your browser."
        echo "Export CA from: Certificate Management -> Export CA certificate"

    ) 2>&1 | show_progress_box "Enabling HTTPS" 24 80

    show_msg "HTTPS Enabled" "HTTPS has been enabled for $service!\n\nAccess: https://${ip}/\n\nNOTE: Import the CA certificate into your browser to avoid security warnings.\n\nExport CA from:\nCertificate Management -> Export CA certificate"
}

# Monitoring deployment menu
monitoring_menu() {
    while true; do
        local choice
        choice=$(show_menu "Monitoring Tools" "Select service to deploy:" \
            "1" "Full Monitoring Stack (Prometheus, Grafana, Loki, Node Exporter)" \
            "2" "Prometheus only" \
            "3" "Grafana only" \
            "4" "Loki only" \
            "5" "Alloy (metrics/logs agent)" \
            "6" "Node Exporter only" \
            "0" "Back")

        case "$choice" in
            1) deploy_service_wizard "monitoring-stack" "Full Monitoring Stack" ;;
            2) deploy_service_wizard "prometheus" "Prometheus" ;;
            3) deploy_service_wizard "grafana" "Grafana" ;;
            4) deploy_service_wizard "loki" "Loki" ;;
            5) deploy_service_wizard "alloy" "Alloy" ;;
            6) deploy_service_wizard "node-exporter" "Node Exporter" ;;
            0|"") break ;;
        esac
    done
}

# Dev tools deployment menu
devtools_menu() {
    while true; do
        local choice
        choice=$(show_menu "Development Tools" "Select service to deploy:" \
            "1" "SonarQube (Code Quality)" \
            "2" "Nexus (Artifact Repository)" \
            "3" "Gitea (Git Server)" \
            "4" "Jenkins (CI/CD)" \
            "5" "Jenkins Inbound Agent (Docker)" \
            "6" "Harbor (Container Registry)" \
            "7" "Dependency-Track (SCA/SBOM)" \
            "0" "Back")

        case "$choice" in
            1) deploy_service_wizard "sonarqube" "SonarQube" ;;
            2) deploy_service_wizard "nexus" "Nexus Repository" ;;
            3) deploy_service_wizard "gitea" "Gitea" ;;
            4) deploy_service_wizard "jenkins" "Jenkins" ;;
            5) jenkins_agent_wizard ;;
            6) deploy_service_wizard "harbor" "Harbor" ;;
            7) deploy_service_wizard "dependency-track" "Dependency-Track" ;;
            0|"") break ;;
        esac
    done
}

# Testing tools deployment menu
testing_menu() {
    while true; do
        local choice
        choice=$(show_menu "Testing Tools" "Select service to deploy:" \
            "1" "Kiwi TCMS (Test Case Management)" \
            "2" "Selenium Grid (Browser Automation)" \
            "3" "TestLink (Test Management)" \
            "0" "Back")

        case "$choice" in
            1) deploy_service_wizard "kiwi-tcms" "Kiwi TCMS" ;;
            2) deploy_service_wizard "selenium-grid" "Selenium Grid" ;;
            3) deploy_service_wizard "testlink" "TestLink" ;;
            0|"") break ;;
        esac
    done
}

# Infrastructure tools deployment menu
infrastructure_menu() {
    while true; do
        local choice
        choice=$(show_menu "Infrastructure Tools" "Select option:" \
            "1" "Pi-hole (DNS Ad Blocker)" \
            "2" "Keycloak (Identity & Access Mgmt)" \
            "3" "FreeIPA (Identity Management)" \
            "4" "Postfix Mail Relay (SMTP)" \
            "5" "FreeIPA Setup Wizard (LDAP Structure)" \
            "6" "Update DNS settings for containers" \
            "0" "Back")

        case "$choice" in
            1) deploy_service_wizard "pihole" "Pi-hole" ;;
            2) deploy_service_wizard "keycloak" "Keycloak" ;;
            3) deploy_service_wizard "freeipa" "FreeIPA" ;;
            4) deploy_service_wizard "postfix-relay" "Postfix Mail Relay" ;;
            5) freeipa_setup_wizard ;;
            6) update_dns_settings_wizard ;;
            0|"") break ;;
        esac
    done
}

# FreeIPA Setup Wizard - Configure LDAP structure
freeipa_setup_wizard() {
    if [[ -z "$CURRENT_PVE" ]]; then
        show_msg "Not Connected" "Please connect to a PVE server first."
        return
    fi

    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    # Find containers with FreeIPA
    local freeipa_containers=()
    while read -r vmid status _ name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        # Check for FreeIPA docker container or native installation
        if lxc_exec "$vmid" "docker ps --format '{{.Names}}' 2>/dev/null | grep -q freeipa" 2>/dev/null || \
           lxc_exec "$vmid" "test -f /etc/ipa/default.conf" 2>/dev/null; then
            freeipa_containers+=("$vmid" "$name")
        fi
    done <<< "$containers"

    if [[ ${#freeipa_containers[@]} -eq 0 ]]; then
        show_msg "No FreeIPA Found" "No containers with FreeIPA found.\n\nPlease deploy FreeIPA first."
        return
    fi

    local selected
    selected=$(show_menu "Select FreeIPA Container" "Choose container with FreeIPA:" "${freeipa_containers[@]}")
    [[ -z "$selected" ]] && return

    # FreeIPA Setup Menu
    while true; do
        local choice
        choice=$(show_menu "FreeIPA Setup - CT $selected" "Select operation:" \
            "1" "Check FreeIPA Status" \
            "2" "Create Organizational Units (OUs)" \
            "3" "Create User Groups" \
            "4" "Create Users" \
            "5" "Create Host Groups" \
            "6" "Configure Password Policy" \
            "7" "Configure Sudo Rules" \
            "8" "View LDAP Structure" \
            "9" "Export LDAP Configuration" \
            "0" "Back")

        case "$choice" in
            1) freeipa_check_status "$selected" ;;
            2) freeipa_create_ous "$selected" ;;
            3) freeipa_create_groups "$selected" ;;
            4) freeipa_create_users "$selected" ;;
            5) freeipa_create_hostgroups "$selected" ;;
            6) freeipa_password_policy "$selected" ;;
            7) freeipa_sudo_rules "$selected" ;;
            8) freeipa_view_structure "$selected" ;;
            9) freeipa_export_config "$selected" ;;
            0|"") break ;;
        esac
    done
}

# Helper to execute IPA commands in container
freeipa_exec() {
    local vmid="$1"
    local cmd="$2"
    # Check if FreeIPA is running in Docker or natively
    if lxc_exec "$vmid" "docker ps --format '{{.Names}}' 2>/dev/null | grep -q freeipa" 2>/dev/null; then
        lxc_exec "$vmid" "docker exec freeipa $cmd"
    else
        lxc_exec "$vmid" "$cmd"
    fi
}

freeipa_exec_live() {
    local vmid="$1"
    local cmd="$2"
    if lxc_exec "$vmid" "docker ps --format '{{.Names}}' 2>/dev/null | grep -q freeipa" 2>/dev/null; then
        lxc_exec_live "$vmid" "docker exec freeipa $cmd"
    else
        lxc_exec_live "$vmid" "$cmd"
    fi
}

# Check FreeIPA status
freeipa_check_status() {
    local vmid="$1"
    (
        echo "=== FreeIPA Status Check ==="
        echo ""
        echo "Checking IPA services..."
        freeipa_exec_live "$vmid" "ipactl status 2>&1 || echo 'IPA not fully initialized'"
        echo ""
        echo "Checking Kerberos..."
        freeipa_exec_live "$vmid" "klist -k /etc/krb5.keytab 2>&1 | head -10 || echo 'Kerberos not configured'"
        echo ""
        echo "Domain info:"
        freeipa_exec_live "$vmid" "cat /etc/ipa/default.conf 2>&1 | grep -E '^(realm|domain|server)' || echo 'Config not found'"
        echo ""
        echo "=== Status Check Complete ==="
    ) 2>&1 | show_progress_box "FreeIPA Status" 20 70
}

# Create Organizational Units
freeipa_create_ous() {
    local vmid="$1"

    # Get admin password
    local admin_pass
    admin_pass=$(show_password "Admin Password" "Enter FreeIPA admin password:")
    [[ -z "$admin_pass" ]] && return

    # Predefined OU templates
    local ou_choice
    ou_choice=$(show_menu "Create OUs" "Select OU template or custom:" \
        "1" "Standard Corporate (Users, Groups, Computers, Services)" \
        "2" "Departmental (IT, HR, Finance, Sales, Engineering)" \
        "3" "Custom OUs")

    [[ -z "$ou_choice" ]] && return

    local ous=()
    case "$ou_choice" in
        1)
            ous=("users" "groups" "computers" "services" "policies")
            ;;
        2)
            ous=("it" "hr" "finance" "sales" "engineering" "management" "contractors")
            ;;
        3)
            local custom_ous
            custom_ous=$(show_input "Custom OUs" "Enter OU names (comma-separated):" "department1,department2,department3")
            [[ -z "$custom_ous" ]] && return
            IFS=',' read -ra ous <<< "$custom_ous"
            ;;
    esac

    (
        echo "=== Creating Organizational Units ==="
        echo ""
        echo "Authenticating as admin..."
        freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true
        echo ""

        for ou in "${ous[@]}"; do
            ou=$(echo "$ou" | xargs)  # trim whitespace
            [[ -z "$ou" ]] && continue
            echo "Creating OU: $ou..."
            # FreeIPA uses automember groups and user/host groups instead of traditional OUs
            # Create as groups with description
            freeipa_exec_live "$vmid" "ipa group-add '${ou}' --desc='Organizational Unit: ${ou}' 2>&1 || echo 'Group may already exist'"
        done

        echo ""
        echo "=== OUs Created ==="
        echo ""
        echo "Listing groups:"
        freeipa_exec_live "$vmid" "ipa group-find --all 2>&1 | head -50"
    ) 2>&1 | show_progress_box "Creating OUs" 25 70
}

# Create User Groups
freeipa_create_groups() {
    local vmid="$1"

    local admin_pass
    admin_pass=$(show_password "Admin Password" "Enter FreeIPA admin password:")
    [[ -z "$admin_pass" ]] && return

    local group_choice
    group_choice=$(show_menu "Create Groups" "Select group template:" \
        "1" "Role-based (admins, developers, operators, viewers)" \
        "2" "Access-based (vpn-users, ssh-users, sudo-users)" \
        "3" "Custom Groups")

    [[ -z "$group_choice" ]] && return

    local groups=()
    local descriptions=()
    case "$group_choice" in
        1)
            groups=("admins" "developers" "operators" "viewers" "auditors")
            descriptions=("System Administrators" "Software Developers" "Operations Team" "Read-only Users" "Security Auditors")
            ;;
        2)
            groups=("vpn-users" "ssh-users" "sudo-users" "db-users" "web-users")
            descriptions=("VPN Access Group" "SSH Access Group" "Sudo Privileges Group" "Database Access Group" "Web Services Group")
            ;;
        3)
            local custom_groups
            custom_groups=$(show_input "Custom Groups" "Enter group names (comma-separated):" "group1,group2")
            [[ -z "$custom_groups" ]] && return
            IFS=',' read -ra groups <<< "$custom_groups"
            for g in "${groups[@]}"; do
                descriptions+=("Custom group: $g")
            done
            ;;
    esac

    (
        echo "=== Creating User Groups ==="
        echo ""
        echo "Authenticating as admin..."
        freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true
        echo ""

        local i=0
        for group in "${groups[@]}"; do
            group=$(echo "$group" | xargs)
            [[ -z "$group" ]] && continue
            local desc="${descriptions[$i]:-Custom group}"
            echo "Creating group: $group..."
            freeipa_exec_live "$vmid" "ipa group-add '$group' --desc='$desc' 2>&1 || echo 'Group may already exist'"
            ((i++))
        done

        echo ""
        echo "=== Groups Created ==="
    ) 2>&1 | show_progress_box "Creating Groups" 20 70
}

# Create Users
freeipa_create_users() {
    local vmid="$1"

    local admin_pass
    admin_pass=$(show_password "Admin Password" "Enter FreeIPA admin password:")
    [[ -z "$admin_pass" ]] && return

    local user_choice
    user_choice=$(show_menu "Create Users" "Select option:" \
        "1" "Create Single User" \
        "2" "Create Multiple Users (Batch)" \
        "3" "Create Service Account")

    [[ -z "$user_choice" ]] && return

    case "$user_choice" in
        1)
            # Single user creation
            local username firstname lastname email user_pass groups
            username=$(show_input "Username" "Enter username:" "")
            [[ -z "$username" ]] && return
            firstname=$(show_input "First Name" "Enter first name:" "")
            [[ -z "$firstname" ]] && return
            lastname=$(show_input "Last Name" "Enter last name:" "")
            [[ -z "$lastname" ]] && return
            email=$(show_input "Email" "Enter email address:" "${username}@example.com")
            user_pass=$(show_password "User Password" "Enter initial password for user:")
            [[ -z "$user_pass" ]] && return
            groups=$(show_input "Groups" "Enter groups to add user to (comma-separated, or leave empty):" "")

            (
                echo "=== Creating User: $username ==="
                echo ""
                freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true
                echo "Creating user..."
                freeipa_exec_live "$vmid" "ipa user-add '$username' --first='$firstname' --last='$lastname' --email='$email' --password <<< '$user_pass' 2>&1"

                if [[ -n "$groups" ]]; then
                    echo ""
                    echo "Adding to groups..."
                    IFS=',' read -ra group_arr <<< "$groups"
                    for g in "${group_arr[@]}"; do
                        g=$(echo "$g" | xargs)
                        [[ -z "$g" ]] && continue
                        freeipa_exec_live "$vmid" "ipa group-add-member '$g' --users='$username' 2>&1 || true"
                    done
                fi
                echo ""
                echo "=== User Created ==="
            ) 2>&1 | show_progress_box "Creating User" 18 70
            ;;
        2)
            # Batch user creation
            local user_list
            user_list=$(show_input "Batch Users" "Enter users (format: user1:First1:Last1,user2:First2:Last2):" "jdoe:John:Doe,jsmith:Jane:Smith")
            [[ -z "$user_list" ]] && return
            local default_pass
            default_pass=$(show_password "Default Password" "Enter default password for all users:")
            [[ -z "$default_pass" ]] && return

            (
                echo "=== Batch User Creation ==="
                echo ""
                freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true

                IFS=',' read -ra users <<< "$user_list"
                for user_entry in "${users[@]}"; do
                    IFS=':' read -r uname fname lname <<< "$user_entry"
                    uname=$(echo "$uname" | xargs)
                    fname=$(echo "$fname" | xargs)
                    lname=$(echo "$lname" | xargs)
                    [[ -z "$uname" ]] && continue
                    echo "Creating user: $uname ($fname $lname)..."
                    freeipa_exec_live "$vmid" "ipa user-add '$uname' --first='${fname:-User}' --last='${lname:-$uname}' --password <<< '$default_pass' 2>&1 || echo 'User may exist'"
                done
                echo ""
                echo "=== Batch Creation Complete ==="
            ) 2>&1 | show_progress_box "Creating Users" 20 70
            ;;
        3)
            # Service account
            local svc_name svc_desc
            svc_name=$(show_input "Service Account" "Enter service account name:" "svc-app")
            [[ -z "$svc_name" ]] && return
            svc_desc=$(show_input "Description" "Enter description:" "Service account for application")

            (
                echo "=== Creating Service Account ==="
                echo ""
                freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true
                echo "Creating service account..."
                freeipa_exec_live "$vmid" "ipa service-add '$svc_name' 2>&1 || ipa user-add '$svc_name' --first='Service' --last='Account' --shell=/sbin/nologin 2>&1"
                echo ""
                echo "=== Service Account Created ==="
            ) 2>&1 | show_progress_box "Creating Service Account" 15 70
            ;;
    esac
}

# Create Host Groups
freeipa_create_hostgroups() {
    local vmid="$1"

    local admin_pass
    admin_pass=$(show_password "Admin Password" "Enter FreeIPA admin password:")
    [[ -z "$admin_pass" ]] && return

    local hg_choice
    hg_choice=$(show_menu "Create Host Groups" "Select template:" \
        "1" "Environment-based (production, staging, development)" \
        "2" "Function-based (webservers, databases, appservers)" \
        "3" "Custom Host Groups")

    [[ -z "$hg_choice" ]] && return

    local hostgroups=()
    case "$hg_choice" in
        1)
            hostgroups=("production-servers" "staging-servers" "development-servers" "testing-servers")
            ;;
        2)
            hostgroups=("webservers" "databases" "appservers" "loadbalancers" "monitoring")
            ;;
        3)
            local custom_hg
            custom_hg=$(show_input "Custom Host Groups" "Enter host group names (comma-separated):" "group1,group2")
            [[ -z "$custom_hg" ]] && return
            IFS=',' read -ra hostgroups <<< "$custom_hg"
            ;;
    esac

    (
        echo "=== Creating Host Groups ==="
        echo ""
        freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true

        for hg in "${hostgroups[@]}"; do
            hg=$(echo "$hg" | xargs)
            [[ -z "$hg" ]] && continue
            echo "Creating host group: $hg..."
            freeipa_exec_live "$vmid" "ipa hostgroup-add '$hg' --desc='Host group: $hg' 2>&1 || echo 'May already exist'"
        done

        echo ""
        echo "=== Host Groups Created ==="
    ) 2>&1 | show_progress_box "Creating Host Groups" 18 70
}

# Configure Password Policy
freeipa_password_policy() {
    local vmid="$1"

    local admin_pass
    admin_pass=$(show_password "Admin Password" "Enter FreeIPA admin password:")
    [[ -z "$admin_pass" ]] && return

    local policy_choice
    policy_choice=$(show_menu "Password Policy" "Select policy template:" \
        "1" "Standard (8 chars, 90 days, history 5)" \
        "2" "Strong (12 chars, 60 days, complexity)" \
        "3" "Relaxed (6 chars, 180 days)" \
        "4" "Custom Policy")

    [[ -z "$policy_choice" ]] && return

    local min_length max_life history min_classes
    case "$policy_choice" in
        1) min_length=8; max_life=90; history=5; min_classes=2 ;;
        2) min_length=12; max_life=60; history=10; min_classes=3 ;;
        3) min_length=6; max_life=180; history=3; min_classes=1 ;;
        4)
            min_length=$(show_input "Min Length" "Minimum password length:" "8")
            max_life=$(show_input "Max Life" "Password max lifetime (days):" "90")
            history=$(show_input "History" "Password history count:" "5")
            min_classes=$(show_input "Min Classes" "Min character classes (1-4):" "2")
            ;;
    esac

    (
        echo "=== Configuring Password Policy ==="
        echo ""
        echo "Settings:"
        echo "  Min Length: $min_length"
        echo "  Max Lifetime: $max_life days"
        echo "  History: $history passwords"
        echo "  Min Classes: $min_classes"
        echo ""
        freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true
        echo "Applying policy..."
        freeipa_exec_live "$vmid" "ipa pwpolicy-mod --minlength=$min_length --maxlife=$max_life --history=$history --minclasses=$min_classes 2>&1"
        echo ""
        echo "Current policy:"
        freeipa_exec_live "$vmid" "ipa pwpolicy-show 2>&1"
        echo ""
        echo "=== Password Policy Updated ==="
    ) 2>&1 | show_progress_box "Password Policy" 22 70
}

# Configure Sudo Rules
freeipa_sudo_rules() {
    local vmid="$1"

    local admin_pass
    admin_pass=$(show_password "Admin Password" "Enter FreeIPA admin password:")
    [[ -z "$admin_pass" ]] && return

    local sudo_choice
    sudo_choice=$(show_menu "Sudo Rules" "Select option:" \
        "1" "Create Admin Sudo Rule (full sudo)" \
        "2" "Create Limited Sudo Rule (specific commands)" \
        "3" "View Existing Rules")

    [[ -z "$sudo_choice" ]] && return

    case "$sudo_choice" in
        1)
            local rule_name groups
            rule_name=$(show_input "Rule Name" "Enter sudo rule name:" "admin-sudo")
            [[ -z "$rule_name" ]] && return
            groups=$(show_input "Groups" "Enter groups to grant sudo (comma-separated):" "admins")
            [[ -z "$groups" ]] && return

            (
                echo "=== Creating Admin Sudo Rule ==="
                echo ""
                freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true
                echo "Creating sudo rule: $rule_name..."
                freeipa_exec_live "$vmid" "ipa sudorule-add '$rule_name' --desc='Full sudo access' 2>&1 || true"
                freeipa_exec_live "$vmid" "ipa sudorule-add-option '$rule_name' --sudooption='!authenticate' 2>&1 || true"
                freeipa_exec_live "$vmid" "ipa sudorule-mod '$rule_name' --cmdcat=all --hostcat=all 2>&1 || true"

                IFS=',' read -ra group_arr <<< "$groups"
                for g in "${group_arr[@]}"; do
                    g=$(echo "$g" | xargs)
                    [[ -z "$g" ]] && continue
                    echo "Adding group $g to rule..."
                    freeipa_exec_live "$vmid" "ipa sudorule-add-user '$rule_name' --groups='$g' 2>&1 || true"
                done
                echo ""
                echo "=== Sudo Rule Created ==="
            ) 2>&1 | show_progress_box "Creating Sudo Rule" 20 70
            ;;
        2)
            local rule_name groups commands
            rule_name=$(show_input "Rule Name" "Enter sudo rule name:" "limited-sudo")
            [[ -z "$rule_name" ]] && return
            groups=$(show_input "Groups" "Enter groups:" "operators")
            [[ -z "$groups" ]] && return
            commands=$(show_input "Commands" "Enter allowed commands (comma-separated):" "/bin/systemctl,/bin/journalctl")
            [[ -z "$commands" ]] && return

            (
                echo "=== Creating Limited Sudo Rule ==="
                echo ""
                freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true

                # Create sudo commands
                IFS=',' read -ra cmd_arr <<< "$commands"
                for cmd in "${cmd_arr[@]}"; do
                    cmd=$(echo "$cmd" | xargs)
                    [[ -z "$cmd" ]] && continue
                    echo "Adding sudo command: $cmd..."
                    freeipa_exec_live "$vmid" "ipa sudocmd-add '$cmd' 2>&1 || true"
                done

                echo "Creating sudo rule..."
                freeipa_exec_live "$vmid" "ipa sudorule-add '$rule_name' --desc='Limited sudo access' --hostcat=all 2>&1 || true"

                for cmd in "${cmd_arr[@]}"; do
                    cmd=$(echo "$cmd" | xargs)
                    [[ -z "$cmd" ]] && continue
                    freeipa_exec_live "$vmid" "ipa sudorule-add-allow-command '$rule_name' --sudocmds='$cmd' 2>&1 || true"
                done

                IFS=',' read -ra group_arr <<< "$groups"
                for g in "${group_arr[@]}"; do
                    g=$(echo "$g" | xargs)
                    [[ -z "$g" ]] && continue
                    freeipa_exec_live "$vmid" "ipa sudorule-add-user '$rule_name' --groups='$g' 2>&1 || true"
                done
                echo ""
                echo "=== Limited Sudo Rule Created ==="
            ) 2>&1 | show_progress_box "Creating Sudo Rule" 22 70
            ;;
        3)
            (
                echo "=== Existing Sudo Rules ==="
                echo ""
                freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true
                freeipa_exec_live "$vmid" "ipa sudorule-find --all 2>&1"
            ) 2>&1 | show_progress_box "Sudo Rules" 25 70
            ;;
    esac
}

# View LDAP Structure
freeipa_view_structure() {
    local vmid="$1"

    local admin_pass
    admin_pass=$(show_password "Admin Password" "Enter FreeIPA admin password:")
    [[ -z "$admin_pass" ]] && return

    (
        echo "═══════════════════════════════════════════════════════════"
        echo "                  FreeIPA LDAP STRUCTURE"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true

        echo "┌─────────────────────────────────────────────────────────┐"
        echo "│  USERS                                                  │"
        echo "└─────────────────────────────────────────────────────────┘"
        freeipa_exec_live "$vmid" "ipa user-find --all 2>&1 | grep -E '(User login|First name|Last name|Email)' | head -40"
        echo ""

        echo "┌─────────────────────────────────────────────────────────┐"
        echo "│  GROUPS                                                 │"
        echo "└─────────────────────────────────────────────────────────┘"
        freeipa_exec_live "$vmid" "ipa group-find 2>&1 | grep -E '(Group name|Description|GID)' | head -40"
        echo ""

        echo "┌─────────────────────────────────────────────────────────┐"
        echo "│  HOST GROUPS                                            │"
        echo "└─────────────────────────────────────────────────────────┘"
        freeipa_exec_live "$vmid" "ipa hostgroup-find 2>&1 | grep -E '(Host-group|Description)' | head -20"
        echo ""

        echo "┌─────────────────────────────────────────────────────────┐"
        echo "│  SUDO RULES                                             │"
        echo "└─────────────────────────────────────────────────────────┘"
        freeipa_exec_live "$vmid" "ipa sudorule-find 2>&1 | grep -E '(Rule name|Description|Enabled)' | head -20"
        echo ""
        echo "═══════════════════════════════════════════════════════════"
    ) 2>&1 | show_progress_box "LDAP Structure" 35 70
}

# Export LDAP Configuration
freeipa_export_config() {
    local vmid="$1"

    local admin_pass
    admin_pass=$(show_password "Admin Password" "Enter FreeIPA admin password:")
    [[ -z "$admin_pass" ]] && return

    local export_path
    export_path=$(show_input "Export Path" "Enter local path for export:" "/tmp/freeipa-export-$(date +%Y%m%d)")

    mkdir -p "$export_path"

    (
        echo "=== Exporting FreeIPA Configuration ==="
        echo "Export path: $export_path"
        echo ""
        freeipa_exec "$vmid" "echo '$admin_pass' | kinit admin 2>&1" || true

        echo "Exporting users..."
        freeipa_exec "$vmid" "ipa user-find --all --raw 2>&1" > "$export_path/users.txt"

        echo "Exporting groups..."
        freeipa_exec "$vmid" "ipa group-find --all --raw 2>&1" > "$export_path/groups.txt"

        echo "Exporting host groups..."
        freeipa_exec "$vmid" "ipa hostgroup-find --all --raw 2>&1" > "$export_path/hostgroups.txt"

        echo "Exporting sudo rules..."
        freeipa_exec "$vmid" "ipa sudorule-find --all --raw 2>&1" > "$export_path/sudorules.txt"

        echo "Exporting password policy..."
        freeipa_exec "$vmid" "ipa pwpolicy-show --all --raw 2>&1" > "$export_path/pwpolicy.txt"

        echo ""
        echo "=== Export Complete ==="
        echo "Files saved to: $export_path"
        ls -la "$export_path"
    ) 2>&1 | show_progress_box "Exporting Config" 20 70

    show_msg "Export Complete" "FreeIPA configuration exported to:\n$export_path\n\nFiles:\n- users.txt\n- groups.txt\n- hostgroups.txt\n- sudorules.txt\n- pwpolicy.txt"
}

# Update DNS settings wizard
update_dns_settings_wizard() {
    if [[ -z "$CURRENT_PVE" ]]; then
        show_msg "Not Connected" "Please connect to a PVE server first."
        return
    fi

    # First, find containers with Pi-hole installed
    local containers pihole_containers=""
    containers=$(pve_list_containers)

    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    # Find Pi-hole containers
    while read -r vmid status _ name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue

        # Check if Pi-hole is installed (check for pihole command or pihole-FTL service)
        if lxc_exec "$vmid" "command -v pihole" &>/dev/null || \
           lxc_exec "$vmid" "systemctl is-active pihole-FTL" &>/dev/null 2>&1 || \
           lxc_exec "$vmid" "docker ps --format '{{.Names}}' 2>/dev/null | grep -q pihole" 2>/dev/null; then
            local ip
            ip=$(get_container_ip "$vmid")
            if [[ -n "$ip" ]]; then
                pihole_containers+="$vmid|$name|$ip\n"
            fi
        fi
    done <<< "$containers"

    if [[ -z "$pihole_containers" ]]; then
        # No Pi-hole found, ask for manual DNS entry
        local dns_server
        dns_server=$(show_input "DNS Server" "No Pi-hole containers found.\n\nEnter DNS server IP address manually:" "8.8.8.8")
        [[ -z "$dns_server" ]] && return
    else
        # Show Pi-hole containers to select from
        local pihole_array=()
        while IFS='|' read -r vmid name ip; do
            [[ -z "$vmid" ]] && continue
            pihole_array+=("$ip" "Pi-hole on $name (CT $vmid)")
        done < <(echo -e "$pihole_containers")

        # Add manual option
        pihole_array+=("manual" "Enter DNS server manually")

        local dns_server
        dns_server=$(show_menu "Select DNS Server" "Choose Pi-hole instance or enter manually:" "${pihole_array[@]}")
        [[ -z "$dns_server" ]] && return

        if [[ "$dns_server" == "manual" ]]; then
            dns_server=$(show_input "DNS Server" "Enter DNS server IP address:" "8.8.8.8")
            [[ -z "$dns_server" ]] && return
        fi
    fi

    # Now select which containers to update
    local update_choice
    update_choice=$(show_menu "Update Scope" "Update DNS settings for:" \
        "all" "All running containers" \
        "select" "Select specific containers")

    [[ -z "$update_choice" ]] && return

    local target_containers=()

    if [[ "$update_choice" == "all" ]]; then
        while read -r vmid status _ name; do
            [[ -z "$vmid" ]] && continue
            [[ "$status" != "running" ]] && continue
            target_containers+=("$vmid")
        done <<< "$containers"
    else
        # Let user select containers
        local ct_array=()
        while read -r vmid status _ name; do
            [[ -z "$vmid" ]] && continue
            [[ "$status" != "running" ]] && continue
            ct_array+=("$vmid" "$name" "off")
        done <<< "$containers"

        if [[ ${#ct_array[@]} -eq 0 ]]; then
            show_msg "No Containers" "No running containers found."
            return
        fi

        local selected
        selected=$(show_checklist "Select Containers" "Choose containers to update DNS:" "${ct_array[@]}")
        [[ -z "$selected" ]] && return

        # Parse selected containers
        for vmid in $selected; do
            vmid="${vmid//\"/}"  # Remove quotes
            target_containers+=("$vmid")
        done
    fi

    if [[ ${#target_containers[@]} -eq 0 ]]; then
        show_msg "No Selection" "No containers selected."
        return
    fi

    # Confirm
    if ! show_yesno "Confirm DNS Update" "Update DNS settings for ${#target_containers[@]} container(s)?\n\nDNS Server: $dns_server\n\nThis will modify /etc/resolv.conf in each container."; then
        return
    fi

    # Update DNS in selected containers
    (
        echo "=== Updating DNS Settings ==="
        echo "DNS Server: $dns_server"
        echo ""

        local success=0 failed=0

        for vmid in "${target_containers[@]}"; do
            local name
            name=$(pve_exec "pct config $vmid 2>/dev/null | grep '^hostname:' | cut -d' ' -f2")
            [[ -z "$name" ]] && name="CT-$vmid"

            echo "Updating $name (CT $vmid)..."

            # Disable systemd-resolved if present
            lxc_exec "$vmid" "systemctl disable systemd-resolved 2>/dev/null || true" < /dev/null
            lxc_exec "$vmid" "systemctl stop systemd-resolved 2>/dev/null || true" < /dev/null

            # Update resolv.conf
            if lxc_exec "$vmid" "rm -f /etc/resolv.conf && echo 'nameserver $dns_server' > /etc/resolv.conf && echo 'nameserver 8.8.8.8' >> /etc/resolv.conf" < /dev/null 2>&1; then
                echo "  OK"
                ((success++))
            else
                echo "  FAILED"
                ((failed++))
            fi
        done

        echo ""
        echo "=== DNS Update Complete ==="
        echo "Success: $success"
        echo "Failed: $failed"

    ) 2>&1 | show_progress_box "Updating DNS Settings" 20 70

    show_msg "DNS Updated" "DNS settings have been updated.\n\nDNS Server: $dns_server\nContainers updated: ${#target_containers[@]}"
}

# Deploy a Jenkins inbound (JNLP) agent into a container via Docker.
# Based on https://hub.docker.com/r/jenkins/inbound-agent/
# When the Jenkins controller URL is HTTPS, the wizard can fetch the controller's
# certificate (or reuse the PVE Manager CA) and inject it into the agent's JVM
# trust store so the agent trusts a self-signed / private-CA controller.
jenkins_agent_wizard() {
    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local ct_array=()
    while read -r vmid status _ name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        ct_array+=("$vmid" "$name")
    done <<< "$containers"

    if [[ ${#ct_array[@]} -eq 0 ]]; then
        show_msg "No Running Containers" "No running containers found."
        return
    fi

    local selected
    selected=$(show_menu "Jenkins Inbound Agent" "Choose container to run the Jenkins agent:" "${ct_array[@]}")
    [[ -z "$selected" ]] && return

    # Ensure Docker is available (offer to install)
    show_info "Checking..." "Checking Docker installation..."
    local docker_check
    docker_check=$(lxc_exec "$selected" "docker --version 2>/dev/null")
    if [[ -z "$docker_check" ]]; then
        if show_yesno "Docker Required" "Docker is not installed in container $selected.\n\nInstall Docker now?"; then
            local os_type
            os_type=$(detect_container_os "$selected")
            docker_install_with_progress "$selected" "$os_type"
            docker_check=$(lxc_exec "$selected" "docker --version 2>/dev/null")
            if [[ -z "$docker_check" ]]; then
                show_msg "Docker Failed" "Docker installation failed. Cannot proceed."
                return
            fi
        else
            return
        fi
    fi

    # Collect connection details from the Jenkins node configuration
    local jurl aname asecret awork
    jurl=$(show_input "Jenkins Controller URL" "Enter the Jenkins controller URL the agent connects to.\nUse the same scheme the controller is served on (http/https):" "https://jenkins.local:8080")
    [[ -z "$jurl" ]] && return

    aname=$(show_input "Agent Name" "Enter the agent (node) name exactly as configured in Jenkins\n(Manage Jenkins > Nodes > <node>):" "agent-${selected}")
    [[ -z "$aname" ]] && return

    asecret=$(show_input "Agent Secret" "Enter the agent secret shown on the Jenkins node's connection page\n(the long hex string next to '-secret'):" "")
    if [[ -z "$asecret" ]]; then
        show_msg "Secret Required" "The agent secret is required to connect an inbound agent."
        return
    fi

    awork=$(show_input "Agent Work Directory" "Remoting work directory inside the agent container:" "/home/jenkins/agent")
    [[ -z "$awork" ]] && awork="/home/jenkins/agent"

    # WebSocket transport (recommended when the controller is behind an HTTPS proxy)
    local ws="false"
    if show_yesno "WebSocket Transport" "Use WebSocket transport (-webSocket)?\n\nRecommended when the controller is behind an HTTPS reverse proxy\n(e.g. the Auto-HTTPS via Nginx wizard), as it needs only the HTTPS port."; then
        ws="true"
    fi

    # HTTPS handling: obtain a certificate the agent should trust
    local cert_mode="none" cert_pem="" cert_source=""
    if [[ "$jurl" == https://* ]]; then
        # Parse host and port from the URL
        local hostport host port
        hostport="${jurl#*://}"; hostport="${hostport%%/*}"
        host="${hostport%%:*}"
        port="${hostport##*:}"
        [[ "$port" == "$host" || -z "$port" ]] && port=443

        local ca_avail="no"
        [[ -f "$CA_DIR/ca.crt" ]] && ca_avail="yes"

        local method
        method=$(show_menu "HTTPS Certificate" "Controller URL is HTTPS. How should the agent trust the controller's certificate?" \
            "fetch" "Fetch certificate from controller ($host:$port)" \
            "pveca" "Reuse PVE Manager CA certificate ($ca_avail)" \
            "skip"  "Skip (controller uses a publicly-trusted cert)")
        [[ -z "$method" ]] && return

        case "$method" in
            fetch)
                show_info "Fetching..." "Retrieving certificate chain from $host:$port ..."
                cert_pem=$(echo | openssl s_client -connect "${host}:${port}" -servername "$host" -showcerts 2>/dev/null \
                    | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/')
                if [[ -z "$cert_pem" ]]; then
                    show_msg "Fetch Failed" "Could not retrieve a certificate from $host:$port.\n\nThe PVE host may be unable to reach the controller, or the port is wrong.\n\nYou can retry, reuse the PVE Manager CA, or skip."
                    return
                fi
                cert_mode="custom"
                cert_source="fetched from ${host}:${port}"

                # Warn on hostname mismatch: the remoting agent still performs TLS
                # hostname verification (trust via -cert does not disable it). If the
                # controller's leaf cert does not cover the host in the URL, the agent
                # will fail with "No name matching <host> found" even though the cert
                # is trusted. Surface this now so the user can fix the URL or cert.
                local leaf_names
                leaf_names=$(printf '%s\n' "$cert_pem" \
                    | openssl x509 -noout -ext subjectAltName 2>/dev/null \
                    | grep -oE '(DNS|IP Address):[^,]+' | sed 's/^\(DNS\|IP Address\)://; s/ //g' | paste -sd, -)
                if [[ -z "$leaf_names" ]]; then
                    leaf_names=$(printf '%s\n' "$cert_pem" | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN *= *//; s/,.*//')
                fi
                if [[ -n "$leaf_names" ]] && ! printf '%s' ",${leaf_names}," | grep -qiF ",${host},"; then
                    show_msg "Certificate Name Mismatch" "The controller's certificate is issued for:\n  ${leaf_names}\n\nbut the agent connects to host:\n  ${host}\n\nThe agent verifies the hostname against the certificate, so it will\nfail with 'No name matching ${host} found' unless you either:\n\n  - set the Controller URL to a name the cert covers\n    (e.g. https://${leaf_names%%,*}:${port}), or\n  - reissue the controller cert with '${host}' in its SAN.\n\nDeployment will continue; fix the URL/cert if the agent does not connect." 20 78
                fi
                ;;
            pveca)
                if [[ "$ca_avail" != "yes" ]]; then
                    show_msg "CA Not Available" "The PVE Manager CA is not initialized.\n\nInitialize it under Certificate Management, or choose 'Fetch'."
                    return
                fi
                cert_pem=$(cat "$CA_DIR/ca.crt")
                cert_mode="custom"
                cert_source="PVE Manager CA"
                ;;
            skip)
                cert_mode="none"
                ;;
        esac
    fi

    # Sanitize agent name for docker container/dir naming
    local safe
    safe=$(echo "$aname" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_.-' '-' | sed 's/^-*//; s/-*$//')
    [[ -z "$safe" ]] && safe="agent"
    local cname="jenkins-agent-${safe}"
    local service_dir="/opt/services/${cname}"

    # Warn if this agent already exists
    if lxc_exec "$selected" "test -d ${service_dir}" 2>/dev/null; then
        if ! show_yesno "Agent Exists" "An agent deployment already exists at:\n  ${service_dir}\n\nRedeploy / overwrite it?"; then
            return
        fi
    fi

    # Confirmation summary
    local tls_line="Plain HTTP (no certificate handling)"
    [[ "$jurl" == https://* ]] && tls_line="HTTPS"
    [[ "$cert_mode" == "custom" ]] && tls_line="HTTPS (trust cert: ${cert_source})"
    if ! show_yesno "Confirm Agent Deployment" "Deploy Jenkins inbound agent to container $selected?\n\nController : $jurl\nAgent name : $aname\nWork dir   : $awork\nWebSocket  : $ws\nTransport  : $tls_line\nContainer  : $cname" 20 78; then
        return
    fi

    # Build docker-compose.yml. We pass each trust anchor INLINE to the remoting
    # agent's repeatable `-cert` option (one PEM per value) rather than editing the
    # JVM trust store, so a self-signed / private-CA controller is trusted reliably.
    #
    # We deliberately avoid the `-cert @file` at-syntax: args4j (the option parser
    # in hudson.remoting.Launcher) expands ANY argv token beginning with `@` as a
    # command file, splicing that file's lines in as arguments *before* option
    # parsing. That turned each PEM body line into a bogus option, producing
    # "'-----END CERTIFICATE-----' is not a valid option". An inline PEM value is a
    # single argv token (not `@`-prefixed) and is parsed directly as a certificate.
    #
    # The default `jenkins-agent` entrypoint appends these command args to agent.jar.
    # agent.jar reads only the FIRST certificate from each -cert value, so we split
    # the chain into one PEM per cert and emit one -cert per certificate.
    local cert_count=0 cert_cmd="" cert_dir=""
    if [[ "$cert_mode" == "custom" ]]; then
        cert_dir=$(mktemp -d)
        printf '%s\n' "$cert_pem" > "$cert_dir/chain.pem"
        ( cd "$cert_dir" && csplit -z -s -f cert- -b '%d.pem' chain.pem '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null ) || true
        local cf esc
        for cf in "$cert_dir"/cert-*.pem; do
            [ -f "$cf" ] || continue
            # Flatten the PEM into a single YAML double-quoted scalar: real newlines
            # become literal \n, which YAML re-expands to newlines in the argv token.
            # PEM is base64 + dashes only, so no " or \ to escape.
            esc=$(awk 'BEGIN{ORS=""} {printf "%s\\n", $0}' "$cf")
            cert_cmd+="
      - \"-cert\"
      - \"${esc}\""
            ((cert_count++)) || true
        done
        [[ "$cert_count" -lt 1 ]] && cert_count=1
    fi

    local compose
    compose="version: '3.8'
services:
  jenkins-agent:
    image: jenkins/inbound-agent:latest
    container_name: ${cname}
    restart: unless-stopped
    environment:
      - \"JENKINS_URL=${jurl}\"
      - \"JENKINS_AGENT_NAME=${aname}\"
      - \"JENKINS_SECRET=${asecret}\"
      - \"JENKINS_AGENT_WORKDIR=${awork}\"
      - \"JENKINS_WEB_SOCKET=${ws}\""

    if [[ "$cert_mode" == "custom" ]]; then
        compose+="
    volumes:
      - agent_work:${awork}
    command:${cert_cmd}"
    else
        compose+="
    volumes:
      - agent_work:${awork}"
    fi

    compose+="
volumes:
  agent_work:"

    # Deploy with a progress box. The trust anchors are embedded inline in the
    # compose file's command:, so nothing cert-related needs to be written into
    # the container separately.
    local compose_b64
    compose_b64=$(printf '%s' "$compose" | base64 -w0)

    (
        echo "=== Deploying Jenkins Inbound Agent to Container $selected ==="
        echo ""
        echo "Agent name : $aname"
        echo "Controller : $jurl"
        echo "Transport  : $tls_line"
        echo ""

        echo "Creating service directory: $service_dir"
        lxc_exec_live "$selected" "mkdir -p $service_dir"

        if [[ "$cert_mode" == "custom" ]]; then
            echo "Embedding controller certificate(s) inline ($cert_source, $cert_count cert(s))..."
            # Remove any stale certs/ dir from a previous @file-based deployment.
            lxc_exec "$selected" "rm -rf ${service_dir}/certs 2>/dev/null || true"
        fi

        echo "Writing docker-compose.yml..."
        lxc_exec "$selected" "echo '$compose_b64' | base64 -d > ${service_dir}/docker-compose.yml"
        echo ""

        echo "Pulling image and starting agent..."
        lxc_exec_live "$selected" "cd ${service_dir} && docker compose up -d 2>&1"
        echo ""

        echo "Current status:"
        lxc_exec "$selected" "docker ps --filter name=${cname} --format '  {{.Names}}: {{.Status}}' 2>/dev/null"
        echo ""
        echo "=== Deployment finished ==="
    ) 2>&1 | show_progress_box "Deploying Jenkins Agent" 24 84

    # Clean up the host-side temporary cert directory
    [[ -n "$cert_dir" && -d "$cert_dir" ]] && rm -rf "$cert_dir"

    local cert_note=""
    [[ "$cert_mode" == "custom" ]] && cert_note="\nTrusted cert: ${cert_source} (${cert_count} cert(s) via -cert)"
    show_msg "Jenkins Agent Deployed" "Inbound agent '$aname' deployed to container $selected.\n\nController : $jurl\nContainer  : $cname\nDirectory  : $service_dir${cert_note}\n\nVerify the agent shows as connected in Jenkins\n(Manage Jenkins > Nodes).\n\nView logs:\n  docker logs -f $cname\n\nIf it still reports 'unable to find valid certification path',\nre-run this wizard and choose 'Fetch certificate from controller'\nso the exact presented chain is trusted."
}

# Deploy a database service (MySQL / PostgreSQL / MongoDB) via Docker.
# Prompts for credentials and writes them to a .env file that docker compose reads.
db_deploy_wizard() {
    local service="$1"
    local service_name="$2"

    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local ct_array=()
    while read -r vmid status _ name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        ct_array+=("$vmid" "$name")
    done <<< "$containers"

    if [[ ${#ct_array[@]} -eq 0 ]]; then
        show_msg "No Running Containers" "No running containers found."
        return
    fi

    local selected
    selected=$(show_menu "Select Container" "Choose container to deploy $service_name:" "${ct_array[@]}")
    [[ -z "$selected" ]] && return

    # Ensure Docker is available (offer to install)
    show_info "Checking..." "Checking Docker installation..."
    local docker_check
    docker_check=$(lxc_exec "$selected" "docker --version 2>/dev/null")
    if [[ -z "$docker_check" ]]; then
        if show_yesno "Docker Required" "Docker is not installed in container $selected.\n\nInstall Docker now?"; then
            local os_type
            os_type=$(detect_container_os "$selected")
            docker_install_with_progress "$selected" "$os_type"
            docker_check=$(lxc_exec "$selected" "docker --version 2>/dev/null")
            if [[ -z "$docker_check" ]]; then
                show_msg "Docker Failed" "Docker installation failed. Cannot proceed."
                return
            fi
        else
            return
        fi
    fi

    # Default listening port per engine
    local def_port
    case "$service" in
        mysql)      def_port="3306" ;;
        postgresql) def_port="5432" ;;
        mongodb)    def_port="27017" ;;
    esac

    local db_port
    db_port=$(show_input "Database Port" "Host port to publish $service_name on:" "$def_port")
    [[ -z "$db_port" ]] && db_port="$def_port"

    # Collect engine-specific credentials. Empty password => auto-generated.
    local env_content="" summary="" access_line="" conn_example=""
    local dbname dbuser dbpass rootpass

    case "$service" in
        mysql)
            rootpass=$(show_input "MySQL root Password" "Password for the MySQL 'root' user (blank = auto-generate):" "")
            [[ -z "$rootpass" ]] && rootpass=$(openssl rand -hex 16)
            dbname=$(show_input "Database Name" "Name of the initial database to create:" "appdb")
            [[ -z "$dbname" ]] && dbname="appdb"
            dbuser=$(show_input "Application User" "Non-root application username to create:" "appuser")
            [[ -z "$dbuser" ]] && dbuser="appuser"
            dbpass=$(show_input "Application Password" "Password for '$dbuser' (blank = auto-generate):" "")
            [[ -z "$dbpass" ]] && dbpass=$(openssl rand -hex 16)
            env_content="DB_PORT=${db_port}
MYSQL_ROOT_PASSWORD=${rootpass}
MYSQL_DATABASE=${dbname}
MYSQL_USER=${dbuser}
MYSQL_PASSWORD=${dbpass}"
            summary="Port         : ${db_port}\nroot password: ${rootpass}\nDatabase     : ${dbname}\nApp user     : ${dbuser}\nApp password : ${dbpass}"
            conn_example="mysql -h {IP} -P ${db_port} -u ${dbuser} -p'${dbpass}' ${dbname}"
            ;;
        postgresql)
            dbuser=$(show_input "Superuser Name" "PostgreSQL superuser/role to create:" "appuser")
            [[ -z "$dbuser" ]] && dbuser="appuser"
            dbpass=$(show_input "Superuser Password" "Password for '$dbuser' (blank = auto-generate):" "")
            [[ -z "$dbpass" ]] && dbpass=$(openssl rand -hex 16)
            dbname=$(show_input "Database Name" "Name of the initial database to create:" "appdb")
            [[ -z "$dbname" ]] && dbname="appdb"
            env_content="DB_PORT=${db_port}
POSTGRES_USER=${dbuser}
POSTGRES_PASSWORD=${dbpass}
POSTGRES_DB=${dbname}"
            summary="Port     : ${db_port}\nUser     : ${dbuser}\nPassword : ${dbpass}\nDatabase : ${dbname}"
            conn_example="psql \"postgresql://${dbuser}:${dbpass}@{IP}:${db_port}/${dbname}\""
            ;;
        mongodb)
            dbuser=$(show_input "Root Username" "MongoDB root username to create:" "admin")
            [[ -z "$dbuser" ]] && dbuser="admin"
            dbpass=$(show_input "Root Password" "Password for '$dbuser' (blank = auto-generate):" "")
            [[ -z "$dbpass" ]] && dbpass=$(openssl rand -hex 16)
            dbname=$(show_input "Initial Database" "Name of the initial database:" "appdb")
            [[ -z "$dbname" ]] && dbname="appdb"
            env_content="DB_PORT=${db_port}
MONGO_ROOT_USER=${dbuser}
MONGO_ROOT_PASSWORD=${dbpass}
MONGO_DB=${dbname}"
            summary="Port     : ${db_port}\nRoot user: ${dbuser}\nPassword : ${dbpass}\nDatabase : ${dbname}"
            conn_example="mongosh \"mongodb://${dbuser}:${dbpass}@{IP}:${db_port}/${dbname}?authSource=admin\""
            ;;
        *)
            show_msg "Unknown Database" "Unsupported database service: $service"
            return
            ;;
    esac

    local service_dir="/opt/services/${service}"

    # Warn if already deployed
    if lxc_exec "$selected" "test -f ${service_dir}/docker-compose.yml" 2>/dev/null; then
        if ! show_yesno "Already Deployed" "$service_name already appears deployed at:\n  ${service_dir}\n\nRedeploy / overwrite it? (existing data volume is preserved)"; then
            return
        fi
    fi

    if ! show_yesno "Confirm Deployment" "Deploy $service_name to container $selected via Docker?\n\n${summary}\n\nCredentials are written to ${service_dir}/.env"; then
        return
    fi

    # Fetch compose from the plugin and prepare payloads
    local compose_content
    compose_content=$(get_service_compose "$service")
    if [[ -z "$compose_content" ]]; then
        show_msg "Error" "Could not load compose definition for $service."
        return
    fi
    local compose_b64 env_b64
    compose_b64=$(printf '%s' "$compose_content" | base64 -w0)
    env_b64=$(printf '%s' "$env_content" | base64 -w0)

    (
        echo "=== Deploying $service_name to Container $selected ==="
        echo ""
        echo "Checking Docker..."
        lxc_exec "$selected" "docker --version 2>/dev/null"
        echo ""

        echo "Creating service directory: $service_dir"
        lxc_exec_live "$selected" "mkdir -p $service_dir"

        echo "Writing docker-compose.yml..."
        lxc_exec "$selected" "echo '$compose_b64' | base64 -d > ${service_dir}/docker-compose.yml"

        echo "Writing .env (credentials)..."
        lxc_exec "$selected" "echo '$env_b64' | base64 -d > ${service_dir}/.env"
        lxc_exec "$selected" "chmod 600 ${service_dir}/.env"
        echo ""

        echo "Pulling image and starting database..."
        lxc_exec_live "$selected" "cd ${service_dir} && docker compose up -d 2>&1"
        echo ""

        echo "Current status:"
        lxc_exec "$selected" "docker ps --filter name=${service} --format '  {{.Names}}: {{.Status}}' 2>/dev/null"
        echo ""
        echo "=== Deployment finished ==="
    ) 2>&1 | show_progress_box "Deploying $service_name" 24 84

    local ip
    ip=$(get_container_ip "$selected")
    [[ -z "$ip" ]] && ip="<container-ip>"
    local conn="${conn_example//\{IP\}/$ip}"

    show_msg "$service_name Deployed" "$service_name deployed to container $selected.\n\nHost:Port : ${ip}:${db_port}\n${summary}\n\nConnect:\n  ${conn}\n\nCredentials saved in ${service_dir}/.env\nData persists in a Docker named volume.\n\nNote: the database listens on the container IP. Expose it beyond\nthe host only if you intend remote access."
}

# Database deployment menu
database_menu() {
    while true; do
        local choice
        choice=$(show_menu "Databases" "Select a database engine to deploy:" \
            "1" "MySQL (relational)" \
            "2" "PostgreSQL (relational)" \
            "3" "MongoDB (NoSQL document)" \
            "0" "Back")

        case "$choice" in
            1) db_deploy_wizard "mysql" "MySQL" ;;
            2) db_deploy_wizard "postgresql" "PostgreSQL" ;;
            3) db_deploy_wizard "mongodb" "MongoDB" ;;
            0|"") break ;;
        esac
    done
}

# Service deployment wizard
deploy_service_wizard() {
    local service="$1"
    local service_name="$2"

    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    local ct_array=()
    while read -r vmid status _ name; do
        [[ -z "$vmid" ]] && continue
        [[ "$status" != "running" ]] && continue
        ct_array+=("$vmid" "$name")
    done <<< "$containers"

    if [[ ${#ct_array[@]} -eq 0 ]]; then
        show_msg "No Running Containers" "No running containers found."
        return
    fi

    local selected
    selected=$(show_menu "Select Container" "Choose container to deploy $service_name:" "${ct_array[@]}")

    if [[ -n "$selected" ]]; then
        # Ask for deployment method
        local deploy_method
        deploy_method=$(show_menu "Deployment Method" "Choose how to deploy $service_name:" \
            "docker" "Docker-based (Recommended)" \
            "native" "Native installation")

        [[ -z "$deploy_method" ]] && return

        if [[ "$deploy_method" == "native" ]]; then
            # Native deployment
            if deploy_service_native "$selected" "$service" "$service_name"; then
                local ip
                ip=$(get_container_ip "$selected")

                local native_access_info=""
                # Get access info from plugin
                if is_plugin_service "$service"; then
                    native_access_info=$(get_plugin_native_access_info "$service" "$ip")
                fi
                # Generic fallback for unknown services
                [[ -z "$native_access_info" ]] && native_access_info="http://${ip}/"

                show_msg "Deployment Complete" "$service_name installed natively!\n\nContainer: $selected\nAccess: $native_access_info"
            else
                show_msg "Deployment Failed" "$service_name native installation failed.\n\nCheck container logs for details:\n  journalctl -u $service -n 50"
            fi
            return
        fi

        # Docker-based deployment
        show_info "Checking..." "Checking Docker installation..."
        local docker_check
        docker_check=$(lxc_exec "$selected" "docker --version 2>/dev/null")

        if [[ -z "$docker_check" ]]; then
            if show_yesno "Docker Required" "Docker is not installed in container $selected.\n\nInstall Docker now?"; then
                local os_type
                os_type=$(detect_container_os "$selected")
                docker_install_with_progress "$selected" "$os_type"

                # Re-check Docker after installation
                docker_check=$(lxc_exec "$selected" "docker --version 2>/dev/null")
                if [[ -z "$docker_check" ]]; then
                    show_msg "Docker Failed" "Docker installation failed. Cannot proceed with deployment."
                    return
                fi
            else
                return
            fi
        fi

        # FreeIPA requires a FQDN hostname before deployment
        if [[ "$service" == "freeipa" ]]; then
            local freeipa_fqdn
            freeipa_fqdn=$(show_input "FreeIPA Hostname" "Enter fully qualified domain name (FQDN) for FreeIPA.\nMust have at least two labels (e.g. ipa.home.lab):" "ipa.srv.local")
            [[ -z "$freeipa_fqdn" ]] && return
            # Validate FQDN has at least two labels
            if ! echo "$freeipa_fqdn" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'; then
                show_msg "Invalid Hostname" "Hostname must be a valid FQDN with at least two labels.\n\nExamples:\n  ipa.home.lab\n  ipa.srv.local\n  freeipa.mynetwork.lan"
                return
            fi
            export FREEIPA_FQDN="$freeipa_fqdn"
        fi

        if show_yesno "Confirm Deployment" "Deploy $service_name to container $selected via Docker?"; then
            if deploy_service_with_progress "$selected" "$service" "$service_name"; then
                local ip
                ip=$(get_container_ip "$selected")

                local access_info=""
                # Get access info from plugin
                if is_plugin_service "$service"; then
                    access_info=$(get_plugin_docker_access_info "$service" "$ip")
                fi
                # Generic fallback for unknown services
                [[ -z "$access_info" ]] && access_info="http://${ip}/"

                show_msg "Deployment Complete" "$service_name deployed successfully!\n\nAccess:\n$access_info"
            else
                show_msg "Deployment Failed" "$service_name deployment failed!\n\nPossible causes:\n- Docker features not enabled (run Check/fix in Docker menu)\n- Network issues pulling images\n- Insufficient resources\n\nCheck container logs for details."
            fi
        fi
    fi
}

# View deployed services
view_deployed_services() {
    local containers
    containers=$(pve_list_containers)
    if [[ -z "$containers" ]]; then
        show_msg "No Containers" "No containers found."
        return
    fi

    (
        echo "Deployed Services"
        echo "================="
        echo ""

        while read -r vmid status _ name; do
            [[ -z "$vmid" ]] && continue
            [[ "$status" != "running" ]] && continue

            docker_ps=$(lxc_exec "$vmid" "docker ps --format 'table {{.Names}}\t{{.Status}}' 2>/dev/null" | tail -n +2)

            if [[ -n "$docker_ps" ]]; then
                echo "Container $vmid ($name):"
                echo "$docker_ps" | sed 's/^/  /'
                echo ""
            fi
        done <<< "$containers"
    ) 2>&1 | show_progress_box "Deployed Services"
}

#######################################
# SETTINGS MENU
#######################################

settings_menu() {
    while true; do
        local choice
        choice=$(show_menu "Settings" "Configure PVE Manager:" \
            "1" "Default CPU cores (${DEFAULT_CPU:-2})" \
            "2" "Default RAM (${DEFAULT_RAM:-2048}MB)" \
            "3" "Default Disk (${DEFAULT_DISK:-8}GB)" \
            "4" "Default Bridge (${DEFAULT_BRIDGE:-vmbr0})" \
            "5" "Default Storage (${DEFAULT_STORAGE:-local})" \
            "6" "SSH Key Type (${SSH_KEY_TYPE:-ed25519})" \
            "7" "CA Certificate Validity (${CA_VALID_DAYS:-3650} days)" \
            "8" "Certificate Validity (${CERT_VALID_DAYS:-365} days)" \
            "9" "View log file" \
            "0" "Back to main menu")

        case "$choice" in
            1)
                local value
                value=$(show_input "Default CPU" "Enter default CPU cores:" "${DEFAULT_CPU:-2}")
                [[ -n "$value" ]] && save_config "DEFAULT_CPU" "$value" && DEFAULT_CPU="$value"
                ;;
            2)
                local value
                value=$(show_input "Default RAM" "Enter default RAM in MB:" "${DEFAULT_RAM:-2048}")
                [[ -n "$value" ]] && save_config "DEFAULT_RAM" "$value" && DEFAULT_RAM="$value"
                ;;
            3)
                local value
                value=$(show_input "Default Disk" "Enter default disk size in GB:" "${DEFAULT_DISK:-8}")
                [[ -n "$value" ]] && save_config "DEFAULT_DISK" "$value" && DEFAULT_DISK="$value"
                ;;
            4)
                local value
                value=$(show_input "Default Bridge" "Enter default network bridge:" "${DEFAULT_BRIDGE:-vmbr0}")
                [[ -n "$value" ]] && save_config "DEFAULT_BRIDGE" "$value" && DEFAULT_BRIDGE="$value"
                ;;
            5)
                local value
                value=$(show_input "Default Storage" "Enter default storage:" "${DEFAULT_STORAGE:-local}")
                [[ -n "$value" ]] && save_config "DEFAULT_STORAGE" "$value" && DEFAULT_STORAGE="$value"
                ;;
            6)
                local value
                value=$(show_menu "SSH Key Type" "Select SSH key type:" \
                    "ed25519" "Ed25519 (recommended)" \
                    "rsa" "RSA 4096-bit" \
                    "ecdsa" "ECDSA")
                [[ -n "$value" ]] && save_config "SSH_KEY_TYPE" "$value" && SSH_KEY_TYPE="$value"
                ;;
            7)
                local value
                value=$(show_input "CA Validity" "CA certificate validity in days:" "${CA_VALID_DAYS:-3650}")
                [[ -n "$value" ]] && save_config "CA_VALID_DAYS" "$value" && CA_VALID_DAYS="$value"
                ;;
            8)
                local value
                value=$(show_input "Cert Validity" "Certificate validity in days:" "${CERT_VALID_DAYS:-365}")
                [[ -n "$value" ]] && save_config "CERT_VALID_DAYS" "$value" && CERT_VALID_DAYS="$value"
                ;;
            9)
                if [[ -f "$LOG_FILE" ]]; then
                    show_textbox "Log File" "$LOG_FILE"
                else
                    show_msg "No Log" "Log file not found."
                fi
                ;;
            0|"")
                break
                ;;
        esac
    done
}

#######################################
# MAIN MENU & ENTRY POINT
#######################################

# Main menu
main_menu() {
    while true; do
        local connection_status="Not connected"
        [[ -n "$CURRENT_PVE" ]] && connection_status="Connected: $CURRENT_PVE"

        local choice
        choice=$(show_menu "PVE Manager v$VERSION" "Status: $connection_status\n\nSelect an option:" \
            "1" "Connect to PVE Server" \
            "2" "LXC Container Management" \
            "3" "VM Management" \
            "4" "Docker Setup" \
            "5" "SSH Key Management" \
            "6" "Service Deployment" \
            "7" "Certificate Management" \
            "8" "Settings" \
            "0" "Exit")

        case "$choice" in
            1) pve_connection_menu ;;
            2) lxc_management_menu ;;
            3) vm_management_menu ;;
            4) docker_setup_menu ;;
            5) ssh_management_menu ;;
            6) service_deployment_menu ;;
            7) certificate_menu ;;
            8) settings_menu ;;
            0|"")
                if show_yesno "Exit" "Are you sure you want to exit?"; then
                    clear
                    echo "Thank you for using PVE Manager!"
                    exit 0
                fi
                ;;
        esac
    done
}

# Show help
show_help() {
    cat << EOF
PVE Manager v$VERSION - Proxmox VE Management TUI

Usage: $(basename "$0") [OPTIONS]

Options:
  -h, --help      Show this help message
  -v, --version   Show version information
  --check         Check dependencies and exit
  --init          Initialize configuration only
  --acme-status   Show the ACME certificate and its deploy targets
  --acme-renew    Renew the ACME certificate if due, then re-deploy (headless)
  --acme-redeploy Re-push the current certificate to recorded targets (no CA call)
  --acme-renew-force
                  Force renewal even if not due (consumes rate-limit quota)

Features:
  - LXC container creation and management
  - VM management with QEMU Guest Agent support
  - Docker installation and configuration
  - SSH key management and distribution
  - Self-signed CA and certificate management
  - Service deployment (monitoring, dev tools, testing tools)

Configuration directory: $CONFIG_DIR

For more information, see the README.md file.
EOF
}

# Check mode
run_check() {
    echo "PVE Manager v$VERSION - Dependency Check"
    echo "========================================"
    echo ""

    local all_ok=true

    # Check dialog/whiptail
    echo -n "Checking dialog/whiptail... "
    if command -v dialog &>/dev/null; then
        echo "OK (dialog)"
    elif command -v whiptail &>/dev/null; then
        echo "OK (whiptail)"
    else
        echo "MISSING"
        all_ok=false
    fi

    # Check other dependencies
    for dep in ssh scp openssl curl; do
        echo -n "Checking $dep... "
        if command -v "$dep" &>/dev/null; then
            echo "OK"
        else
            echo "MISSING"
            all_ok=false
        fi
    done

    # Check bash version
    echo -n "Checking bash version... "
    if [[ "${BASH_VERSION%%.*}" -ge 4 ]]; then
        echo "OK ($BASH_VERSION)"
    else
        echo "FAIL ($BASH_VERSION, need 4.0+)"
        all_ok=false
    fi

    # Check if on PVE host
    echo -n "Checking PVE host... "
    if is_pve_host; then
        echo "YES (running on PVE)"
    else
        echo "NO (remote mode available)"
    fi

    # Check optional dependencies
    echo ""
    echo "Optional dependencies:"
    echo -n "  jq... "
    command -v jq &>/dev/null && echo "OK" || echo "not installed"

    echo ""
    if $all_ok; then
        echo "All required dependencies are installed."
        exit 0
    else
        echo "Some dependencies are missing. Please install them."
        exit 1
    fi
}

# Main entry point
main() {
    # Parse arguments
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            echo "PVE Manager v$VERSION"
            exit 0
            ;;
        --check)
            run_check
            ;;
        --init)
            init_config
            echo "Configuration initialized at $CONFIG_DIR"
            exit 0
            ;;
        --acme-renew|--acme-renew-force)
            # Non-interactive renewal for cron / systemd timers: renew if due,
            # then re-push to every recorded target. No dialog is used, so this
            # is safe to run headless.
            init_config
            load_config
            if is_pve_host; then
                pve_connect "local" &>/dev/null
            fi
            local _force=0
            [[ "${1}" == "--acme-renew-force" ]] && _force=1
            acme_renew_all "$_force"
            exit $?
            ;;
        --acme-redeploy)
            # Re-push the CURRENT certificate to every recorded target without
            # contacting the ACME CA. This is the hook for an external issuer
            # (e.g. a standalone acme.sh renew hook) to refresh guest targets
            # after it renews, so they cannot silently go stale.
            init_config
            load_config
            if is_pve_host; then
                pve_connect "local" &>/dev/null
            fi
            acme_redeploy_targets
            exit $?
            ;;
        --acme-status)
            init_config
            load_config
            acme_cert_summary
            echo ""
            acme_list_targets
            exit 0
            ;;
    esac

    # Initialize
    check_dependencies
    detect_dialog
    init_config
    load_config

    # Initialize and load plugins
    init_builtin_plugins
    load_plugins

    # Auto-connect to local PVE if running on PVE host
    if is_pve_host; then
        pve_connect "local" &>/dev/null
    fi

    # Start main menu
    main_menu
}

# Run main
main "$@"
