#!/bin/bash
PLUGINS_DIR="$(pwd)/plugins-test"
log_info(){ :; }
create_plugin_dir(){ local d="$PLUGINS_DIR/$1"; mkdir -p "$d"; echo "$d"; }
# Extract create_plugin_nginx() from the real script
sed -n '/^create_plugin_nginx() {/,/^}/p' /root/pve-manager/pve-manager.sh > /tmp/cpn.sh
source /tmp/cpn.sh
create_plugin_nginx
echo "=== generated files ==="
find "$PLUGINS_DIR/nginx" -type f | sort
echo
echo "=== bash -n install.sh ==="
bash -n "$PLUGINS_DIR/nginx/install.sh" && echo "install.sh OK" || echo "install.sh FAILED"
bash -n "$PLUGINS_DIR/nginx/remove.sh" && echo "remove.sh OK" || echo "remove.sh FAILED"
echo
echo "=== conf.d/default.conf (head) ==="
head -20 "$PLUGINS_DIR/nginx/conf.d/default.conf"
