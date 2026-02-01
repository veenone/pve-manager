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
# - Service deployment (monitoring, dev tools, testing tools)
#
# Version: 1.0.0
# License: MIT
#

set -o pipefail

#######################################
# CONFIGURATION & VARIABLES
#######################################

readonly VERSION="1.0.0"
readonly SCRIPT_NAME="PVE Manager"
readonly CONFIG_DIR="$HOME/.pve-manager"
readonly CONFIG_FILE="$CONFIG_DIR/config.conf"
readonly PROFILES_FILE="$CONFIG_DIR/profiles.conf"
readonly CA_DIR="$CONFIG_DIR/ca"
readonly CERTS_DIR="$CA_DIR/certs"
readonly SSH_DIR="$CONFIG_DIR/ssh"
readonly LOG_FILE="$CONFIG_DIR/pve-manager.log"
readonly TEMPLATES_DIR="$CONFIG_DIR/templates"
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
    mkdir -p "$CONFIG_DIR" "$CA_DIR" "$CERTS_DIR" "$SSH_DIR" "$TEMPLATES_DIR"
    chmod 700 "$CONFIG_DIR" "$CA_DIR" "$SSH_DIR"

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
EOF
    fi

    # Create empty profiles file if not exists
    if [[ ! -f "$PROFILES_FILE" ]]; then
        touch "$PROFILES_FILE"
    fi
}

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
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { [[ "${LOG_LEVEL:-INFO}" == "DEBUG" ]] && log "DEBUG" "$@"; }

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
show_progress_box() {
    local title="$1"
    local height="${2:-$DIALOG_HEIGHT}"
    local width="${3:-$DIALOG_WIDTH}"

    if [[ "$DIALOG_CMD" == "dialog" ]]; then
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --progressbox \
            "$height" "$width" 2>&1 >/dev/tty
    else
        # Whiptail doesn't have progressbox, collect output and show at end
        local output
        output=$(cat)
        local tmpfile="/tmp/pve-manager-wprog-$$.txt"
        echo "$output" > "$tmpfile"
        $DIALOG_CMD --backtitle "$SCRIPT_NAME v$VERSION" \
            --title "$title" --textbox "$tmpfile" \
            "$height" "$width" 3>&1 1>&2 2>&3
        rm -f "$tmpfile"
    fi
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
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" "$cmd"
    fi
}

# Execute command on PVE with live output
pve_exec_live() {
    local cmd="$1"

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        eval "$cmd" 2>&1
    else
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" "$cmd" 2>&1
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
    pve_exec "timeout $timeout_secs pct start $vmid" 2>&1
}

# Stop container (graceful shutdown with fallback to force stop)
lxc_stop() {
    local vmid="$1"
    local timeout_secs="${2:-15}"
    log_info "Stopping container $vmid (timeout: ${timeout_secs}s)"

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

# Execute command in container
lxc_exec() {
    local vmid="$1"
    shift
    local cmd="$*"

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        # Local: use bash -c with proper quoting
        pct exec "$vmid" -- /bin/bash -c "$cmd"
    else
        # Remote: use base64 encoding to avoid escaping issues
        local cmd_b64
        cmd_b64=$(echo -n "$cmd" | base64 -w0)
        # Pass base64 command and decode on remote
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" \
            "echo $cmd_b64 | base64 -d | pct exec $vmid -- /bin/bash -s"
    fi
}

# Execute command in container with timeout (default 10 seconds)
lxc_exec_timeout() {
    local vmid="$1"
    local timeout_secs="${2:-10}"
    shift 2
    local cmd="$*"

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        timeout "$timeout_secs" pct exec "$vmid" -- /bin/bash -c "$cmd"
    else
        local cmd_b64
        cmd_b64=$(echo -n "$cmd" | base64 -w0)
        timeout "$timeout_secs" ssh -o ConnectTimeout=5 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" \
            "echo $cmd_b64 | base64 -d | pct exec $vmid -- /bin/bash -s"
    fi
}

# Execute command in container with live output
lxc_exec_live() {
    local vmid="$1"
    shift
    local cmd="$*"

    if [[ "$IS_LOCAL_PVE" == true ]]; then
        pct exec "$vmid" -- /bin/bash -c "$cmd" 2>&1
    else
        local cmd_b64
        cmd_b64=$(echo -n "$cmd" | base64 -w0)
        ssh -o ConnectTimeout=10 -p "$CURRENT_PVE_PORT" \
            "${CURRENT_PVE_USER}@${CURRENT_PVE_HOST}" \
            "echo $cmd_b64 | base64 -d | pct exec $vmid -- /bin/bash -s" 2>&1
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

        # Disable AppArmor for Docker in LXC (creates systemd override)
        echo "Configuring Docker to work without AppArmor..."
        lxc_exec "$vmid" "mkdir -p /etc/systemd/system/docker.service.d"
        lxc_exec_live "$vmid" 'cat > /etc/systemd/system/docker.service.d/lxc-override.conf << EOF
[Service]
# Disable AppArmor for Docker in LXC containers
Environment="DOCKER_OPTS=--security-opt apparmor=unconfined"
ExecStart=
ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock --security-opt apparmor=unconfined
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
            0|"")
                break
                ;;
        esac
    done
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

    case "$service" in
        prometheus)
            cat << 'EOF'
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
            ;;
        grafana)
            cat << 'EOF'
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
            ;;
        loki)
            cat << 'EOF'
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
            ;;
        alloy)
            cat << 'EOF'
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
            ;;
        node-exporter)
            cat << 'EOF'
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
            ;;
        monitoring-stack)
            cat << 'EOF'
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
    volumes:
      - grafana_data:/var/lib/grafana
    depends_on:
      - prometheus

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

volumes:
  prometheus_data:
  grafana_data:
  loki_data:
EOF
            ;;
        sonarqube)
            cat << 'EOF'
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
            ;;
        nexus)
            cat << 'EOF'
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
            ;;
        gitea)
            cat << 'EOF'
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
            ;;
        jenkins)
            cat << 'EOF'
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
            ;;
        kiwi-tcms)
            cat << 'EOF'
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
            ;;
        selenium-grid)
            cat << 'EOF'
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
            ;;
        testlink)
            cat << 'EOF'
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
            ;;
        harbor)
            cat << 'EOF'
version: '3.8'
services:
  harbor-core:
    image: goharbor/harbor-core:v2.10.0
    container_name: harbor-core
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - CONFIG_PATH=/etc/harbor/app.conf
    volumes:
      - harbor_data:/data
      - ./harbor.yml:/etc/harbor/app.conf:ro
    depends_on:
      - harbor-db
      - harbor-redis

  harbor-portal:
    image: goharbor/harbor-portal:v2.10.0
    container_name: harbor-portal
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "80:8080"
    depends_on:
      - harbor-core

  harbor-db:
    image: goharbor/harbor-db:v2.10.0
    container_name: harbor-db
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=${HARBOR_DB_PASSWORD:-Harbor12345}
    volumes:
      - harbor_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

  harbor-redis:
    image: goharbor/redis-photon:v2.10.0
    container_name: harbor-redis
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    volumes:
      - harbor_redis:/var/lib/redis

  harbor-registry:
    image: goharbor/registry-photon:v2.10.0
    container_name: harbor-registry
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    ports:
      - "5000:5000"
    volumes:
      - harbor_registry:/storage
    environment:
      - REGISTRY_HTTP_SECRET=${HARBOR_SECRET:-harbor-secret-key}

  harbor-jobservice:
    image: goharbor/harbor-jobservice:v2.10.0
    container_name: harbor-jobservice
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    depends_on:
      - harbor-core
      - harbor-redis

volumes:
  harbor_data:
  harbor_db:
  harbor_redis:
  harbor_registry:
EOF
            ;;
        pihole)
            cat << 'EOF'
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
            ;;
        dependency-track)
            cat << 'EOF'
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
      # Increase memory for larger BOMs
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
            ;;
        keycloak)
            cat << 'EOF'
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
            ;;
        freeipa)
            cat << 'EOF'
version: '3.8'
services:
  freeipa:
    image: freeipa/freeipa-server:fedora-39
    container_name: freeipa
    restart: unless-stopped
    hostname: ipa.example.lan
    security_opt:
      - apparmor:unconfined
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=0
    environment:
      - IPA_SERVER_HOSTNAME=ipa.example.lan
      - IPA_SERVER_INSTALL_OPTS=-U -r EXAMPLE.LAN --no-ntp --no-host-dns
    ports:
      - "80:80"
      - "443:443"
      - "389:389"
      - "636:636"
      - "88:88"
      - "88:88/udp"
      - "464:464"
      - "464:464/udp"
      - "123:123/udp"
    volumes:
      - freeipa_data:/data
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    tmpfs:
      - /run
      - /tmp
    read_only: true
    # Note: First run will take several minutes for initial setup
    # Check logs: docker logs -f freeipa

volumes:
  freeipa_data:
EOF
            ;;
        postfix-relay)
            cat << 'EOF'
version: '3.8'
services:
  postfix:
    image: boky/postfix:latest
    container_name: postfix-relay
    restart: unless-stopped
    security_opt:
      - apparmor:unconfined
    environment:
      # Basic configuration
      - ALLOWED_SENDER_DOMAINS=${POSTFIX_ALLOWED_DOMAINS:-example.com}
      - HOSTNAME=${POSTFIX_HOSTNAME:-mail.example.com}
      # Relay configuration (optional - for external SMTP)
      - RELAYHOST=${POSTFIX_RELAYHOST:-}
      - RELAYHOST_USERNAME=${POSTFIX_RELAY_USER:-}
      - RELAYHOST_PASSWORD=${POSTFIX_RELAY_PASS:-}
      # TLS settings
      - SMTP_TLS_SECURITY_LEVEL=may
      # Message size limit (50MB)
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
            ;;
        traefik)
            cat << 'EOF'
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
            ;;
        *)
            echo ""
            return 1
            ;;
    esac
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

# Deploy service natively (without Docker)
deploy_service_native() {
    local vmid="$1"
    local service="$2"
    local service_name="$3"
    local deploy_result_file="/tmp/pve-deploy-native-result-$$.txt"

    log_info "Deploying $service natively to container $vmid"

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

        case "$service" in
            grafana)
                echo "Installing Grafana..."
                case "$os_type" in
                    debian|ubuntu)
                        lxc_exec_live "$vmid" "apt-get update"
                        lxc_exec_live "$vmid" "apt-get install -y apt-transport-https software-properties-common wget"
                        lxc_exec_live "$vmid" "wget -q -O /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key"
                        lxc_exec_live "$vmid" "echo 'deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main' | tee /etc/apt/sources.list.d/grafana.list"
                        lxc_exec_live "$vmid" "apt-get update"
                        lxc_exec_live "$vmid" "apt-get install -y grafana"
                        lxc_exec_live "$vmid" "systemctl daemon-reload"
                        lxc_exec_live "$vmid" "systemctl enable grafana-server"
                        lxc_exec_live "$vmid" "systemctl start grafana-server"
                        ;;
                    alpine)
                        lxc_exec_live "$vmid" "apk add --no-cache grafana"
                        lxc_exec_live "$vmid" "rc-update add grafana"
                        lxc_exec_live "$vmid" "rc-service grafana start"
                        ;;
                    *)
                        echo "ERROR: Unsupported OS for native Grafana installation"
                        echo "1" > "$deploy_result_file"
                        exit 1
                        ;;
                esac
                ;;

            prometheus)
                echo "Installing Prometheus..."
                case "$os_type" in
                    debian|ubuntu)
                        lxc_exec_live "$vmid" "apt-get update"
                        lxc_exec_live "$vmid" "apt-get install -y prometheus"
                        lxc_exec_live "$vmid" "systemctl enable prometheus"
                        lxc_exec_live "$vmid" "systemctl start prometheus"
                        ;;
                    alpine)
                        lxc_exec_live "$vmid" "apk add --no-cache prometheus"
                        lxc_exec_live "$vmid" "rc-update add prometheus"
                        lxc_exec_live "$vmid" "rc-service prometheus start"
                        ;;
                    *)
                        echo "ERROR: Unsupported OS for native Prometheus installation"
                        echo "1" > "$deploy_result_file"
                        exit 1
                        ;;
                esac
                ;;

            gitea)
                echo "Installing Gitea..."
                case "$os_type" in
                    debian|ubuntu)
                        lxc_exec_live "$vmid" "apt-get update"
                        lxc_exec_live "$vmid" "apt-get install -y git sqlite3"
                        lxc_exec_live "$vmid" "wget -O /usr/local/bin/gitea https://dl.gitea.com/gitea/1.21/gitea-1.21-linux-amd64"
                        lxc_exec_live "$vmid" "chmod +x /usr/local/bin/gitea"
                        lxc_exec_live "$vmid" "useradd -r -s /bin/bash -d /var/lib/gitea -m gitea 2>/dev/null || true"
                        lxc_exec_live "$vmid" "mkdir -p /var/lib/gitea/{custom,data,log} /etc/gitea"
                        lxc_exec_live "$vmid" "chown -R gitea:gitea /var/lib/gitea /etc/gitea"
                        lxc_exec_live "$vmid" "chmod 750 /var/lib/gitea/{custom,data,log} /etc/gitea"
                        # Create systemd service
                        lxc_exec "$vmid" "cat > /etc/systemd/system/gitea.service << 'GITEAEOF'
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
                        lxc_exec_live "$vmid" "systemctl daemon-reload"
                        lxc_exec_live "$vmid" "systemctl enable gitea"
                        lxc_exec_live "$vmid" "systemctl start gitea"
                        ;;
                    *)
                        echo "ERROR: Unsupported OS for native Gitea installation"
                        echo "1" > "$deploy_result_file"
                        exit 1
                        ;;
                esac
                ;;

            jenkins)
                echo "Installing Jenkins..."
                case "$os_type" in
                    debian|ubuntu)
                        lxc_exec_live "$vmid" "apt-get update"
                        lxc_exec_live "$vmid" "apt-get install -y fontconfig openjdk-17-jre"
                        lxc_exec_live "$vmid" "wget -O /usr/share/keyrings/jenkins-keyring.asc https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key"
                        lxc_exec_live "$vmid" "echo 'deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/' | tee /etc/apt/sources.list.d/jenkins.list"
                        lxc_exec_live "$vmid" "apt-get update"
                        lxc_exec_live "$vmid" "apt-get install -y jenkins"
                        lxc_exec_live "$vmid" "systemctl enable jenkins"
                        lxc_exec_live "$vmid" "systemctl start jenkins"
                        echo ""
                        echo "Getting initial admin password..."
                        sleep 10
                        lxc_exec_live "$vmid" "cat /var/lib/jenkins/secrets/initialAdminPassword 2>/dev/null || echo 'Password not ready yet'"
                        ;;
                    *)
                        echo "ERROR: Unsupported OS for native Jenkins installation"
                        echo "1" > "$deploy_result_file"
                        exit 1
                        ;;
                esac
                ;;

            kiwi-tcms)
                echo "Installing Kiwi TCMS..."
                echo "NOTE: Kiwi TCMS requires many dependencies. This may take 10-15 minutes."
                case "$os_type" in
                    debian|ubuntu)
                        # Setup locales first (required for PostgreSQL)
                        echo "Setting up locales..."
                        lxc_exec_live "$vmid" "apt-get update"
                        lxc_exec_live "$vmid" "apt-get install -y locales"
                        lxc_exec_live "$vmid" "sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen"
                        lxc_exec_live "$vmid" "locale-gen en_US.UTF-8"
                        lxc_exec_live "$vmid" "update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8"

                        # Install system dependencies including Node.js for frontend
                        echo "Installing system dependencies..."
                        lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip python3-venv python3-dev gcc libpq-dev postgresql postgresql-contrib nginx git libxml2-dev libxslt1-dev libffi-dev libssl-dev cargo pkg-config curl nodejs npm"

                        # Start PostgreSQL
                        lxc_exec_live "$vmid" "systemctl enable postgresql"
                        lxc_exec_live "$vmid" "systemctl start postgresql"

                        # Wait for PostgreSQL to be ready
                        echo "Waiting for PostgreSQL..."
                        sleep 5

                        # Verify PostgreSQL is running
                        lxc_exec_live "$vmid" "systemctl status postgresql --no-pager || true"

                        # Create database
                        lxc_exec_live "$vmid" "sudo -u postgres psql -c \"CREATE USER kiwi WITH PASSWORD 'kiwi';\" 2>/dev/null || true"
                        lxc_exec_live "$vmid" "sudo -u postgres psql -c \"CREATE DATABASE kiwi OWNER kiwi ENCODING 'UTF8' LC_COLLATE='en_US.UTF-8' LC_CTYPE='en_US.UTF-8' TEMPLATE template0;\" 2>/dev/null || true"
                        lxc_exec_live "$vmid" "sudo -u postgres psql -c \"ALTER USER kiwi CREATEDB;\" 2>/dev/null || true"

                        # Create kiwi user and directories
                        lxc_exec_live "$vmid" "useradd -r -m -d /opt/kiwi -s /bin/bash kiwi 2>/dev/null || true"
                        lxc_exec_live "$vmid" "mkdir -p /opt/kiwi /var/log/kiwi /Kiwi/static /Kiwi/uploads"

                        # Clone Kiwi TCMS from GitHub
                        echo "Cloning Kiwi TCMS from GitHub..."
                        lxc_exec_live "$vmid" "rm -rf /opt/kiwi/Kiwi"
                        lxc_exec_live "$vmid" "git clone --depth 1 https://github.com/kiwitcms/Kiwi.git /opt/kiwi/Kiwi"

                        # Install Node.js frontend dependencies
                        echo "Installing frontend dependencies (node_modules)..."
                        lxc_exec_live "$vmid" "cd /opt/kiwi/Kiwi/tcms && npm install 2>/dev/null || true"

                        # Create venv and install dependencies
                        echo "Creating virtual environment and installing dependencies..."
                        lxc_exec_live "$vmid" "python3 -m venv /opt/kiwi/venv"
                        lxc_exec_live "$vmid" "/opt/kiwi/venv/bin/pip install --upgrade pip setuptools wheel"
                        lxc_exec_live "$vmid" "/opt/kiwi/venv/bin/pip install psycopg2-binary gunicorn factory_boy"

                        # Install Kiwi TCMS requirements
                        echo "Installing Kiwi TCMS requirements (this may take a while)..."
                        lxc_exec_live "$vmid" "/opt/kiwi/venv/bin/pip install -r /opt/kiwi/Kiwi/requirements/base.txt"

                        # Create local settings file (uses /Kiwi/static which is Django's default)
                        lxc_exec "$vmid" "cat > /opt/kiwi/Kiwi/tcms/settings/local.py << 'SETTINGSEOF'
from tcms.settings.product import *

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

SECRET_KEY = 'change-me-to-something-secret-in-production-use-long-random-string'
ALLOWED_HOSTS = ['*']
DEBUG = False

# Use default Kiwi static paths
STATIC_ROOT = '/Kiwi/static'
MEDIA_ROOT = '/Kiwi/uploads'

# Disable HTTPS redirect for HTTP-only setup
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_PROXY_SSL_HEADER = None
SETTINGSEOF"

                        # Run migrations
                        echo "Running database migrations..."
                        lxc_exec_live "$vmid" "cd /opt/kiwi/Kiwi && /opt/kiwi/venv/bin/python manage.py migrate --settings=tcms.settings.local"

                        # Collect static files
                        echo "Collecting static files..."
                        lxc_exec_live "$vmid" "cd /opt/kiwi/Kiwi && /opt/kiwi/venv/bin/python manage.py collectstatic --noinput --settings=tcms.settings.local"

                        # Set permissions
                        lxc_exec_live "$vmid" "chown -R kiwi:kiwi /opt/kiwi"
                        lxc_exec_live "$vmid" "chown -R www-data:www-data /Kiwi/static /Kiwi/uploads"
                        lxc_exec_live "$vmid" "chmod -R 755 /Kiwi/static /Kiwi/uploads"

                        # Create systemd service
                        lxc_exec "$vmid" "cat > /etc/systemd/system/kiwi.service << 'KIWIEOF'
[Unit]
Description=Kiwi TCMS
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=kiwi
Group=kiwi
WorkingDirectory=/opt/kiwi/Kiwi
Environment=DJANGO_SETTINGS_MODULE=tcms.settings.local
ExecStart=/opt/kiwi/venv/bin/gunicorn --bind 127.0.0.1:8080 --workers 3 --timeout 120 tcms.wsgi:application
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
KIWIEOF"

                        # Configure nginx as reverse proxy
                        lxc_exec "$vmid" "cat > /etc/nginx/sites-available/kiwi << 'NGINXEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    client_max_body_size 100M;

    location /static/ {
        alias /Kiwi/static/;
        expires 30d;
        add_header Cache-Control \"public, immutable\";
    }

    location /uploads/ {
        alias /Kiwi/uploads/;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;
    }
}
NGINXEOF"
                        # Remove default site and enable kiwi
                        lxc_exec_live "$vmid" "rm -f /etc/nginx/sites-enabled/default"
                        lxc_exec_live "$vmid" "ln -sf /etc/nginx/sites-available/kiwi /etc/nginx/sites-enabled/kiwi"

                        # Test nginx configuration
                        echo "Testing nginx configuration..."
                        lxc_exec_live "$vmid" "nginx -t"

                        # Create superuser script
                        lxc_exec "$vmid" "cat > /opt/kiwi/create_superuser.sh << 'SUPEREOF'
#!/bin/bash
cd /opt/kiwi/Kiwi
export DJANGO_SETTINGS_MODULE=tcms.settings.local
/opt/kiwi/venv/bin/python manage.py createsuperuser
SUPEREOF"
                        lxc_exec_live "$vmid" "chmod +x /opt/kiwi/create_superuser.sh"

                        # Start services
                        echo "Starting services..."
                        lxc_exec_live "$vmid" "systemctl daemon-reload"
                        lxc_exec_live "$vmid" "systemctl enable kiwi nginx postgresql"
                        lxc_exec_live "$vmid" "systemctl restart postgresql"
                        lxc_exec_live "$vmid" "systemctl restart kiwi"
                        lxc_exec_live "$vmid" "systemctl restart nginx"

                        # Wait for services to start
                        echo "Waiting for services to start..."
                        sleep 5

                        # Verify services are running
                        echo ""
                        echo "=== Service Status ==="
                        lxc_exec_live "$vmid" "systemctl is-active postgresql && echo 'PostgreSQL: OK' || echo 'PostgreSQL: FAILED'"
                        lxc_exec_live "$vmid" "systemctl is-active kiwi && echo 'Kiwi: OK' || echo 'Kiwi: FAILED'"
                        lxc_exec_live "$vmid" "systemctl is-active nginx && echo 'Nginx: OK' || echo 'Nginx: FAILED'"

                        # Test local access
                        echo ""
                        echo "Testing local access..."
                        lxc_exec_live "$vmid" "curl -s -o /dev/null -w 'HTTP Status: %{http_code}\n' http://127.0.0.1/ || echo 'Local access test failed'"

                        # Show listening ports
                        echo ""
                        echo "Listening ports:"
                        lxc_exec_live "$vmid" "ss -tlnp | grep -E ':80|:8080' || netstat -tlnp 2>/dev/null | grep -E ':80|:8080'"

                        echo ""
                        echo "=== Kiwi TCMS Installation Complete ==="
                        echo "NOTE: Create admin user by running: /opt/kiwi/create_superuser.sh"
                        echo "Access Kiwi TCMS at http://<container-ip>/"
                        ;;
                    *)
                        echo "ERROR: Unsupported OS for native Kiwi TCMS installation"
                        echo "1" > "$deploy_result_file"
                        exit 1
                        ;;
                esac
                ;;

            testlink)
                # TestLink native installation (using Nginx + PHP-FPM)
                case "$os_type" in
                    debian|ubuntu)
                        echo "Installing TestLink natively on Debian/Ubuntu..."
                        echo ""

                        # Update packages
                        echo "Updating package lists..."
                        lxc_exec_live "$vmid" "apt-get update"

                        # Setup locale for MariaDB
                        echo "Setting up locale..."
                        lxc_exec_live "$vmid" "apt-get install -y locales"
                        lxc_exec_live "$vmid" "sed -i 's/# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen"
                        lxc_exec_live "$vmid" "locale-gen en_US.UTF-8"

                        # Install MariaDB
                        echo "Installing MariaDB..."
                        lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client"

                        # Start MariaDB
                        echo "Starting MariaDB..."
                        lxc_exec_live "$vmid" "systemctl start mariadb"
                        lxc_exec_live "$vmid" "systemctl enable mariadb"
                        sleep 2

                        # Clean up any existing database/user (for reinstallation)
                        echo "Setting up database..."
                        lxc_exec_live "$vmid" "mysql -e 'DROP DATABASE IF EXISTS testlink;' 2>/dev/null || true"
                        lxc_exec_live "$vmid" "mysql -e \"DROP USER IF EXISTS 'testlink'@'localhost';\" 2>/dev/null || true"
                        lxc_exec_live "$vmid" "mysql -e 'FLUSH PRIVILEGES;'"

                        # Create fresh database and user with full privileges
                        echo "Creating database..."
                        lxc_exec_live "$vmid" "mysql -e \"CREATE DATABASE testlink DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\""
                        lxc_exec_live "$vmid" "mysql -e \"CREATE USER 'testlink'@'localhost' IDENTIFIED BY 'testlink123';\""
                        # Grant all privileges including ability to create/drop tables and manage users
                        lxc_exec_live "$vmid" "mysql -e \"GRANT ALL PRIVILEGES ON testlink.* TO 'testlink'@'localhost' WITH GRANT OPTION;\""
                        # Also grant SELECT on mysql.user for user existence checks (needed by TestLink installer)
                        lxc_exec_live "$vmid" "mysql -e \"GRANT SELECT ON mysql.* TO 'testlink'@'localhost';\" 2>/dev/null || true"
                        lxc_exec_live "$vmid" "mysql -e 'FLUSH PRIVILEGES;'"

                        # Install Nginx and PHP-FPM
                        echo "Installing Nginx and PHP-FPM..."
                        # Purge existing nginx to ensure clean state
                        lxc_exec_live "$vmid" "apt-get purge -y nginx nginx-common nginx-core 2>/dev/null || true"
                        lxc_exec_live "$vmid" "apt-get autoremove -y 2>/dev/null || true"

                        # Install nginx and PHP with all required extensions (including composer for adodb update)
                        lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx php-fpm php-mysql php-gd php-xml php-mbstring php-ldap php-curl php-zip php-cli php-common git unzip wget curl file composer"

                        # Verify nginx.conf exists
                        if ! lxc_exec "$vmid" "test -f /etc/nginx/nginx.conf" 2>/dev/null; then
                            echo "ERROR: nginx.conf not found, reinstalling nginx..."
                            lxc_exec_live "$vmid" "apt-get purge -y nginx nginx-common nginx-core"
                            lxc_exec_live "$vmid" "apt-get install -y nginx"
                        fi

                        # Get PHP version for config paths
                        local php_version
                        php_version=$(lxc_exec "$vmid" "php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;' 2>/dev/null")
                        [[ -z "$php_version" ]] && php_version="8.2"
                        echo "Detected PHP version: $php_version"

                        # Download TestLink (using latest from GitHub for PHP 8 compatibility)
                        echo "Downloading TestLink..."
                        lxc_exec_live "$vmid" "rm -rf /var/www/testlink /tmp/testlink-code"
                        lxc_exec_live "$vmid" "mkdir -p /var/www/testlink"

                        # Clone latest TestLink from GitHub (has PHP 8 fixes)
                        echo "Cloning TestLink from GitHub (latest version with PHP 8 support)..."
                        lxc_exec_live "$vmid" "git clone --depth 1 https://github.com/TestLinkOpenSourceTRMS/testlink-code.git /tmp/testlink-code"

                        # Verify clone
                        if ! lxc_exec "$vmid" "test -f /tmp/testlink-code/index.php" 2>/dev/null; then
                            echo "ERROR: Failed to clone TestLink from GitHub"
                            echo "1" > "$deploy_result_file"
                            exit 1
                        fi

                        # Move files to final location
                        echo "Installing TestLink files..."
                        lxc_exec_live "$vmid" "cp -r /tmp/testlink-code/* /var/www/testlink/"
                        lxc_exec_live "$vmid" "rm -rf /tmp/testlink-code"

                        # Apply PHP 8 compatibility patches if needed
                        echo "Applying PHP 8 compatibility patches..."

                        # Create a PHP script to properly fix curly braces array/string access
                        # This is more reliable than sed for complex PHP syntax
                        local php_fixer='<?php
// PHP 8 Compatibility Fixer - converts curly braces array/string access to square brackets
// Usage: php fixer.php <directory>

function fixCurlyBraces($content) {
    // Pattern to match $variable{...} but not ${variable} or anonymous functions
    // We need to be careful not to match curly braces in other contexts
    $result = "";
    $len = strlen($content);
    $i = 0;

    while ($i < $len) {
        // Look for $ followed by variable name followed by {
        if ($content[$i] === "\$" && $i + 1 < $len) {
            // Check if this is ${var} syntax (variable variable) - skip it
            if ($content[$i + 1] === "{") {
                $result .= $content[$i];
                $i++;
                continue;
            }

            // Match variable name
            $varStart = $i;
            $i++; // skip $
            $varName = "";

            // Match variable name characters
            while ($i < $len && (ctype_alnum($content[$i]) || $content[$i] === "_")) {
                $varName .= $content[$i];
                $i++;
            }

            // Check if followed by { for array/string access
            if ($i < $len && $content[$i] === "{" && !empty($varName)) {
                // Find matching closing brace
                $braceDepth = 1;
                $exprStart = $i + 1;
                $j = $i + 1;

                while ($j < $len && $braceDepth > 0) {
                    if ($content[$j] === "{") $braceDepth++;
                    elseif ($content[$j] === "}") $braceDepth--;
                    $j++;
                }

                if ($braceDepth === 0) {
                    // Extract the expression inside braces
                    $expr = substr($content, $exprStart, $j - $exprStart - 1);
                    // Recursively fix the expression inside
                    $expr = fixCurlyBraces($expr);
                    // Output with square brackets
                    $result .= "\$" . $varName . "[" . $expr . "]";
                    $i = $j;
                    continue;
                }
            }

            // Not a curly brace access, output what we have
            $result .= "\$" . $varName;
            continue;
        }

        $result .= $content[$i];
        $i++;
    }

    return $result;
}

function processFile($file) {
    $content = file_get_contents($file);
    $original = $content;
    $fixed = fixCurlyBraces($content);

    if ($fixed !== $original) {
        file_put_contents($file, $fixed);
        echo "Fixed: $file\n";
        return true;
    }
    return false;
}

function processDirectory($dir) {
    $count = 0;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );

    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === "php") {
            if (processFile($file->getPathname())) {
                $count++;
            }
        }
    }
    return $count;
}

if ($argc < 2) {
    echo "Usage: php fixer.php <directory>\n";
    exit(1);
}

$dir = $argv[1];
if (!is_dir($dir)) {
    echo "Error: $dir is not a directory\n";
    exit(1);
}

$count = processDirectory($dir);
echo "Fixed $count files\n";
'
                        local fixer_b64
                        fixer_b64=$(echo "$php_fixer" | base64 -w0)
                        lxc_exec "$vmid" "echo '$fixer_b64' | base64 -d > /tmp/php8_fixer.php"

                        echo "Running PHP 8 compatibility fixer..."
                        lxc_exec_live "$vmid" "php /tmp/php8_fixer.php /var/www/testlink"
                        lxc_exec_live "$vmid" "rm -f /tmp/php8_fixer.php"

                        # Fix strftime deprecation - replace with date() where possible
                        lxc_exec_live "$vmid" "sed -i \"s/strftime('%Y%m%d'/date('Ymd'/g\" /var/www/testlink/config.inc.php 2>/dev/null || true"

                        # Update adodb library to PHP 8 compatible version
                        echo "Updating adodb library for PHP 8 compatibility..."
                        lxc_exec_live "$vmid" "rm -rf /var/www/testlink/vendor/adodb/adodb-php"
                        lxc_exec_live "$vmid" "git clone --depth 1 --branch v5.22.8 https://github.com/ADOdb/ADOdb.git /var/www/testlink/vendor/adodb/adodb-php 2>&1 || git clone --depth 1 https://github.com/ADOdb/ADOdb.git /var/www/testlink/vendor/adodb/adodb-php"

                        # Update Smarty library to PHP 8 compatible version (v4.x or v5.x)
                        echo "Updating Smarty library for PHP 8 compatibility..."
                        lxc_exec_live "$vmid" "rm -rf /var/www/testlink/vendor/smarty/smarty"
                        lxc_exec_live "$vmid" "mkdir -p /var/www/testlink/vendor/smarty"
                        lxc_exec_live "$vmid" "git clone --depth 1 --branch v4.5.3 https://github.com/smarty-php/smarty.git /var/www/testlink/vendor/smarty/smarty 2>&1 || git clone --depth 1 https://github.com/smarty-php/smarty.git /var/www/testlink/vendor/smarty/smarty"
                        lxc_exec_live "$vmid" "chown -R www-data:www-data /var/www/testlink/vendor/smarty"

                        # Apply additional mysqli driver fix for PHP 8
                        echo "Applying mysqli driver fix..."
                        local mysqli_fix='<?php
// PHP 8 compatibility fix for mysqli driver
if (!function_exists("adodb_mysqli_fix_applied")) {
    function adodb_mysqli_fix_applied() { return true; }
    // Ensure error reporting does not break on type errors
    set_error_handler(function($errno, $errstr, $errfile, $errline) {
        if (strpos($errstr, "mysqli") !== false && strpos($errstr, "must be of type") !== false) {
            return true; // Suppress mysqli type errors
        }
        return false;
    }, E_ALL);
}
'
                        local fix_b64
                        fix_b64=$(echo "$mysqli_fix" | base64 -w0)
                        lxc_exec "$vmid" "echo '$fix_b64' | base64 -d > /var/www/testlink/lib/functions/adodb_fix.php"
                        # Include the fix in the main config
                        lxc_exec_live "$vmid" "grep -q 'adodb_fix.php' /var/www/testlink/config.inc.php || sed -i '1a\\require_once(dirname(__FILE__).\"/lib/functions/adodb_fix.php\");' /var/www/testlink/config.inc.php 2>/dev/null || true"

                        # Final verification
                        if ! lxc_exec "$vmid" "test -f /var/www/testlink/index.php" 2>/dev/null; then
                            echo "ERROR: TestLink installation failed - index.php not found"
                            lxc_exec_live "$vmid" "ls -la /var/www/testlink/"
                            echo "1" > "$deploy_result_file"
                            exit 1
                        fi
                        echo "TestLink files installed successfully"

                        # Create directories that TestLink needs
                        lxc_exec_live "$vmid" "mkdir -p /var/testlink/logs /var/testlink/upload_area"
                        lxc_exec_live "$vmid" "mkdir -p /var/www/testlink/gui/templates_c"

                        # Set permissions - TestLink installer needs write access to several directories
                        echo "Setting permissions..."
                        lxc_exec_live "$vmid" "chown -R www-data:www-data /var/www/testlink"
                        lxc_exec_live "$vmid" "chown -R www-data:www-data /var/testlink"
                        lxc_exec_live "$vmid" "chmod -R 755 /var/www/testlink"
                        lxc_exec_live "$vmid" "chmod -R 777 /var/testlink"
                        # Make specific directories writable for installer
                        lxc_exec_live "$vmid" "chmod -R 777 /var/www/testlink/gui/templates_c 2>/dev/null || true"
                        lxc_exec_live "$vmid" "chmod 666 /var/www/testlink/config_db.inc.php 2>/dev/null || touch /var/www/testlink/config_db.inc.php && chmod 666 /var/www/testlink/config_db.inc.php"
                        lxc_exec_live "$vmid" "chown www-data:www-data /var/www/testlink/config_db.inc.php"

                        # Create custom_config.inc.php with correct TestLink format
                        echo "Creating configuration..."
                        local config_content='<?php
// Suppress deprecation warnings for older TestLink version (PHP 8.1+)
error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);

// Paths - these are required for TestLink
$tlCfg->log_path = "/var/testlink/logs/";
$g_repositoryPath = "/var/testlink/upload_area/";

// Language
$tlCfg->default_language = "en_US";

// Security - disable config check warnings
$tlCfg->config_check_warning_mode = "SILENT";
'
                        local config_b64
                        config_b64=$(echo "$config_content" | base64 -w0)
                        lxc_exec "$vmid" "echo '$config_b64' | base64 -d > /var/www/testlink/custom_config.inc.php"
                        lxc_exec_live "$vmid" "chown www-data:www-data /var/www/testlink/custom_config.inc.php"

                        # Pre-configure database connection to avoid installer issues
                        echo "Pre-configuring database connection..."
                        local db_config='<?php
// Database connection configuration
// Auto-generated by PVE Manager
define("DB_TYPE", "mysql");
define("DB_USER", "testlink");
define("DB_PASS", "testlink123");
define("DB_HOST", "localhost");
define("DB_NAME", "testlink");
define("DB_TABLE_PREFIX", "");

// Disable mysqli strict error reporting for PHP 8 compatibility
mysqli_report(MYSQLI_REPORT_OFF);
'
                        local db_config_b64
                        db_config_b64=$(echo "$db_config" | base64 -w0)
                        lxc_exec "$vmid" "echo '$db_config_b64' | base64 -d > /var/www/testlink/config_db.inc.php"
                        lxc_exec_live "$vmid" "chown www-data:www-data /var/www/testlink/config_db.inc.php"
                        lxc_exec_live "$vmid" "chmod 644 /var/www/testlink/config_db.inc.php"

                        # Add mysqli_report to the main config.inc.php to suppress strict errors
                        lxc_exec_live "$vmid" "grep -q 'mysqli_report' /var/www/testlink/config.inc.php || sed -i '2a\\mysqli_report(MYSQLI_REPORT_OFF);' /var/www/testlink/config.inc.php 2>/dev/null || true"

                        # Configure PHP-FPM
                        echo "Configuring PHP-FPM..."
                        # Find php.ini location
                        local php_ini="/etc/php/${php_version}/fpm/php.ini"
                        if ! lxc_exec "$vmid" "test -f $php_ini" 2>/dev/null; then
                            php_ini=$(lxc_exec "$vmid" "find /etc/php -name 'php.ini' -path '*/fpm/*' 2>/dev/null | head -1")
                        fi
                        echo "Using PHP config: $php_ini"

                        # Apply PHP settings
                        lxc_exec_live "$vmid" "sed -i 's/max_execution_time = 30/max_execution_time = 120/' $php_ini 2>/dev/null || true"
                        lxc_exec_live "$vmid" "sed -i 's/session.gc_maxlifetime = 1440/session.gc_maxlifetime = 60000/' $php_ini 2>/dev/null || true"
                        lxc_exec_live "$vmid" "sed -i 's/post_max_size = 8M/post_max_size = 64M/' $php_ini 2>/dev/null || true"
                        lxc_exec_live "$vmid" "sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 64M/' $php_ini 2>/dev/null || true"
                        lxc_exec_live "$vmid" "sed -i 's/memory_limit = 128M/memory_limit = 256M/' $php_ini 2>/dev/null || true"
                        # Enable error display for debugging (can be disabled later)
                        lxc_exec_live "$vmid" "sed -i 's/display_errors = Off/display_errors = On/' $php_ini 2>/dev/null || true"
                        lxc_exec_live "$vmid" "sed -i 's/display_startup_errors = Off/display_startup_errors = On/' $php_ini 2>/dev/null || true"

                        # Start PHP-FPM first so socket is created
                        echo "Starting PHP-FPM..."
                        lxc_exec_live "$vmid" "systemctl restart php${php_version}-fpm 2>/dev/null || systemctl restart php-fpm 2>/dev/null || systemctl restart php*-fpm"
                        lxc_exec_live "$vmid" "systemctl enable php${php_version}-fpm 2>/dev/null || systemctl enable php-fpm 2>/dev/null || true"
                        sleep 2

                        # Find the actual PHP-FPM socket path (now that PHP-FPM is running)
                        local php_sock
                        php_sock=$(lxc_exec "$vmid" "ls /run/php/php*-fpm.sock 2>/dev/null | head -1")
                        if [[ -z "$php_sock" ]]; then
                            php_sock="/run/php/php${php_version}-fpm.sock"
                        fi
                        echo "Using PHP-FPM socket: $php_sock"

                        # Configure Nginx virtual host
                        echo "Configuring Nginx..."
                        lxc_exec "$vmid" "cat > /etc/nginx/sites-available/testlink << NGINXEOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/testlink;
    index index.php index.html;

    client_max_body_size 64M;

    location / {
        try_files \\\$uri \\\$uri/ =404;
    }

    location ~ \\.php\\\$ {
        fastcgi_split_path_info ^(.+\\.php)(/.+)\\\$;
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

                        # Enable site
                        lxc_exec_live "$vmid" "rm -f /etc/nginx/sites-enabled/default"
                        lxc_exec_live "$vmid" "ln -sf /etc/nginx/sites-available/testlink /etc/nginx/sites-enabled/testlink"

                        # Test nginx configuration
                        echo "Testing nginx configuration..."
                        lxc_exec_live "$vmid" "nginx -t"

                        # Start nginx
                        echo "Starting Nginx..."
                        lxc_exec_live "$vmid" "systemctl restart nginx"
                        lxc_exec_live "$vmid" "systemctl enable nginx"

                        # Wait for services to start
                        sleep 3

                        # Verify services are running
                        echo ""
                        echo "=== Service Status ==="
                        lxc_exec_live "$vmid" "systemctl is-active mariadb && echo 'MariaDB: OK' || echo 'MariaDB: FAILED'"
                        lxc_exec_live "$vmid" "systemctl is-active nginx && echo 'Nginx: OK' || echo 'Nginx: FAILED'"
                        lxc_exec_live "$vmid" "systemctl is-active php${php_version}-fpm 2>/dev/null && echo 'PHP-FPM: OK' || systemctl is-active php*-fpm 2>/dev/null && echo 'PHP-FPM: OK' || echo 'PHP-FPM: FAILED'"

                        # Test local access
                        echo ""
                        echo "Testing local access..."
                        lxc_exec_live "$vmid" "curl -s -o /dev/null -w 'HTTP Status: %{http_code}\n' http://127.0.0.1/ || echo 'Local access test failed'"

                        echo ""
                        echo "=== TestLink Installation Complete ==="
                        echo "IMPORTANT: Complete installation via web browser:"
                        echo "  1. Go to http://<container-ip>/install/index.php"
                        echo "  2. Click 'New installation'"
                        echo "  3. Database is pre-configured (testlink/testlink123)"
                        echo "  4. When asked for DB details, use:"
                        echo "     - Database type: MySQL/MariaDB"
                        echo "     - Database host: localhost"
                        echo "     - Database name: testlink"
                        echo "     - Database user: testlink"
                        echo "     - Database password: testlink123"
                        echo "  5. After installation, delete /var/www/testlink/install directory"
                        echo ""
                        echo "If you see database errors, the DB is already configured."
                        echo "Skip to: http://<container-ip>/ after first login setup."
                        ;;
                    *)
                        echo "ERROR: Unsupported OS for native TestLink installation"
                        echo "1" > "$deploy_result_file"
                        exit 1
                        ;;
                esac
                ;;

            sonarqube)
                # SonarQube native installation
                case "$os_type" in
                    debian|ubuntu)
                        echo "Installing SonarQube natively on Debian/Ubuntu..."
                        echo ""

                        # System requirements check and configuration
                        echo "Configuring system settings..."
                        lxc_exec_live "$vmid" "sysctl -w vm.max_map_count=524288"
                        lxc_exec_live "$vmid" "sysctl -w fs.file-max=131072"
                        lxc_exec_live "$vmid" "echo 'vm.max_map_count=524288' >> /etc/sysctl.conf"
                        lxc_exec_live "$vmid" "echo 'fs.file-max=131072' >> /etc/sysctl.conf"

                        # Install dependencies
                        echo "Installing dependencies..."
                        lxc_exec_live "$vmid" "apt-get update"
                        lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jdk wget unzip postgresql postgresql-contrib"

                        # Start PostgreSQL
                        echo "Configuring PostgreSQL..."
                        lxc_exec_live "$vmid" "systemctl enable postgresql"
                        lxc_exec_live "$vmid" "systemctl start postgresql"
                        sleep 3

                        # Create database and user
                        lxc_exec_live "$vmid" "sudo -u postgres psql -c \"DROP DATABASE IF EXISTS sonarqube;\" 2>/dev/null || true"
                        lxc_exec_live "$vmid" "sudo -u postgres psql -c \"DROP USER IF EXISTS sonar;\" 2>/dev/null || true"
                        lxc_exec_live "$vmid" "sudo -u postgres psql -c \"CREATE USER sonar WITH ENCRYPTED PASSWORD 'sonar';\""
                        lxc_exec_live "$vmid" "sudo -u postgres psql -c \"CREATE DATABASE sonarqube OWNER sonar;\""
                        lxc_exec_live "$vmid" "sudo -u postgres psql -c \"GRANT ALL PRIVILEGES ON DATABASE sonarqube TO sonar;\""

                        # Create sonarqube user
                        echo "Creating SonarQube user..."
                        lxc_exec_live "$vmid" "useradd -r -m -d /opt/sonarqube -s /bin/bash sonarqube 2>/dev/null || true"

                        # Download and install SonarQube
                        echo "Downloading SonarQube..."
                        local sonar_version="10.4.1.88267"
                        lxc_exec_live "$vmid" "wget -q -O /tmp/sonarqube.zip https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-${sonar_version}.zip"

                        echo "Installing SonarQube..."
                        lxc_exec_live "$vmid" "rm -rf /opt/sonarqube"
                        lxc_exec_live "$vmid" "unzip -q /tmp/sonarqube.zip -d /opt/"
                        lxc_exec_live "$vmid" "mv /opt/sonarqube-${sonar_version} /opt/sonarqube"
                        lxc_exec_live "$vmid" "rm /tmp/sonarqube.zip"

                        # Configure SonarQube
                        echo "Configuring SonarQube..."
                        lxc_exec "$vmid" "cat >> /opt/sonarqube/conf/sonar.properties << 'SONAREOF'
# Database configuration
sonar.jdbc.username=sonar
sonar.jdbc.password=sonar
sonar.jdbc.url=jdbc:postgresql://localhost:5432/sonarqube

# Web server configuration
sonar.web.host=0.0.0.0
sonar.web.port=9000

# Elasticsearch configuration
sonar.search.javaOpts=-Xmx512m -Xms512m -XX:MaxDirectMemorySize=256m -XX:+HeapDumpOnOutOfMemoryError
SONAREOF"

                        # Set ownership
                        lxc_exec_live "$vmid" "chown -R sonarqube:sonarqube /opt/sonarqube"

                        # Set limits for sonarqube user
                        lxc_exec "$vmid" "cat >> /etc/security/limits.conf << 'LIMITSEOF'
sonarqube   -   nofile   131072
sonarqube   -   nproc    8192
LIMITSEOF"

                        # Create systemd service
                        lxc_exec "$vmid" "cat > /etc/systemd/system/sonarqube.service << 'SERVICEEOF'
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
SERVICEEOF"

                        # Start SonarQube
                        echo "Starting SonarQube..."
                        lxc_exec_live "$vmid" "systemctl daemon-reload"
                        lxc_exec_live "$vmid" "systemctl enable sonarqube"
                        lxc_exec_live "$vmid" "systemctl start sonarqube"

                        # Wait for startup
                        echo "Waiting for SonarQube to start (this may take 1-2 minutes)..."
                        sleep 30

                        echo ""
                        echo "=== SonarQube Installation Complete ==="
                        echo "Access: http://<container-ip>:9000"
                        echo "Default credentials: admin / admin"
                        echo "NOTE: First startup may take up to 2 minutes"
                        ;;
                    *)
                        echo "ERROR: Unsupported OS for native SonarQube installation"
                        echo "1" > "$deploy_result_file"
                        exit 1
                        ;;
                esac
                ;;

            pihole)
                # Pi-hole native installation
                case "$os_type" in
                    debian|ubuntu)
                        echo "Installing Pi-hole natively on Debian/Ubuntu..."
                        echo ""

                        # Install dependencies
                        echo "Installing dependencies..."
                        lxc_exec_live "$vmid" "apt-get update"
                        lxc_exec_live "$vmid" "DEBIAN_FRONTEND=noninteractive apt-get install -y curl git"

                        # Disable systemd-resolved if present (conflicts with Pi-hole)
                        echo "Configuring DNS settings..."
                        lxc_exec_live "$vmid" "systemctl disable systemd-resolved 2>/dev/null || true"
                        lxc_exec_live "$vmid" "systemctl stop systemd-resolved 2>/dev/null || true"
                        lxc_exec_live "$vmid" "rm -f /etc/resolv.conf"
                        lxc_exec_live "$vmid" "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"

                        # Create Pi-hole config directory
                        lxc_exec_live "$vmid" "mkdir -p /etc/pihole"

                        # Get container IP for setupVars
                        local container_ip
                        container_ip=$(get_container_ip "$vmid")

                        # Create setupVars.conf for unattended installation
                        lxc_exec "$vmid" "cat > /etc/pihole/setupVars.conf << SETUPEOF
PIHOLE_INTERFACE=eth0
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=all
WEBPASSWORD=
PIHOLE_DNS_1=8.8.8.8
PIHOLE_DNS_2=8.8.4.4
BLOCKING_ENABLED=true
SETUPEOF"

                        # Install Pi-hole using official installer
                        echo "Running Pi-hole installer (this may take several minutes)..."
                        lxc_exec_live "$vmid" "curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended"

                        # Set web password
                        echo "Setting admin password..."
                        lxc_exec_live "$vmid" "pihole -a -p admin"

                        # Verify installation
                        echo ""
                        echo "=== Service Status ==="
                        lxc_exec_live "$vmid" "systemctl is-active pihole-FTL && echo 'Pi-hole FTL: OK' || echo 'Pi-hole FTL: FAILED'"
                        lxc_exec_live "$vmid" "systemctl is-active lighttpd && echo 'Lighttpd: OK' || echo 'Lighttpd: FAILED'"

                        echo ""
                        echo "=== Pi-hole Installation Complete ==="
                        echo "Admin interface: http://<container-ip>/admin"
                        echo "Password: admin"
                        echo "DNS Server: <container-ip>:53"
                        echo ""
                        echo "To change password: pihole -a -p <newpassword>"
                        ;;
                    alpine)
                        echo "Installing Pi-hole on Alpine..."
                        echo "NOTE: Using gravity-sync compatible setup"

                        lxc_exec_live "$vmid" "apk update"
                        lxc_exec_live "$vmid" "apk add curl bash git sudo"

                        # Alpine requires special handling - use docker method instead
                        echo "WARNING: Native Pi-hole on Alpine is complex."
                        echo "Recommend using Docker deployment for Alpine."
                        echo "1" > "$deploy_result_file"
                        exit 1
                        ;;
                    *)
                        echo "ERROR: Unsupported OS for native Pi-hole installation"
                        echo "1" > "$deploy_result_file"
                        exit 1
                        ;;
                esac
                ;;

            *)
                echo "ERROR: Native installation not available for $service"
                echo "Please use Docker-based deployment instead."
                echo "1" > "$deploy_result_file"
                exit 1
                ;;
        esac

        echo ""
        echo "Verifying installation..."
        sleep 3

        # Check service status
        service_running=false
        case "$os_type" in
            debian|ubuntu)
                if lxc_exec "$vmid" "systemctl is-active --quiet $service 2>/dev/null"; then
                    service_running=true
                fi
                ;;
            alpine)
                if lxc_exec "$vmid" "rc-service $service status 2>/dev/null | grep -q started"; then
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
            prometheus|monitoring-stack)
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
        esac

        # Start the service
        echo "Pulling Docker images..."
        echo ""
        pull_output=$(lxc_exec "$vmid" "cd ${service_dir} && docker compose pull 2>&1")
        pull_status=$?
        echo "$pull_output"
        echo ""

        if [[ $pull_status -ne 0 ]]; then
            echo "ERROR: Failed to pull Docker images"
            echo "1" > "$deploy_result_file"
            exit 1
        fi

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
└─────────────────────────────────────────────────────────────┘

───────────────────────────────────────────────────────────────
  DEPLOYMENT OPTIONS:
  ─────────────────────────────────────────────────────────────
  [Docker]  All services support Docker-based deployment
  [Native]  Some services support native OS installation:
            Prometheus, Grafana, Gitea, Jenkins, Kiwi TCMS,
            TestLink, SonarQube, Pi-hole

───────────────────────────────────────────────────────────────
  Total Services: 21
═══════════════════════════════════════════════════════════════
"

    local tmpfile="/tmp/pve-services-list-$$.txt"
    echo "$services_info" > "$tmpfile"
    show_textbox "Supported Services" "$tmpfile" 30 70
    rm -f "$tmpfile"
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
            "5" "Reverse Proxy (Traefik)" \
            "6" "View deployed services" \
            "7" "Update/Redeploy service" \
            "8" "Stop service" \
            "9" "Remove service" \
            "10" "Enable HTTPS for service" \
            "11" "View supported services list" \
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
                deploy_service_wizard "traefik" "Traefik Reverse Proxy"
                ;;
            6)
                view_deployed_services
                ;;
            7)
                update_service_wizard
                ;;
            8)
                stop_service_wizard
                ;;
            9)
                remove_service_wizard
                ;;
            10)
                enable_https_wizard
                ;;
            11)
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

        # Pull latest images
        echo "Pulling latest images..."
        lxc_exec_live "$vmid" "cd $service_dir && docker compose pull 2>&1"
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

    (
        echo "=== Removing Native Service: $service ==="
        echo ""

        # Stop and disable the service
        echo "Stopping and disabling $service service..."
        lxc_exec_live "$vmid" "systemctl stop $service 2>/dev/null || true"
        lxc_exec_live "$vmid" "systemctl disable $service 2>/dev/null || true"
        echo ""

        case "$service" in
            kiwi)
                echo "Removing Kiwi TCMS..."

                # Stop related services
                lxc_exec_live "$vmid" "systemctl stop nginx 2>/dev/null || true"

                # Remove systemd service file
                lxc_exec_live "$vmid" "rm -f /etc/systemd/system/kiwi.service"

                # Remove nginx config
                lxc_exec_live "$vmid" "rm -f /etc/nginx/sites-enabled/kiwi"
                lxc_exec_live "$vmid" "rm -f /etc/nginx/sites-available/kiwi"

                # Remove application files
                lxc_exec_live "$vmid" "rm -rf /opt/kiwi"
                lxc_exec_live "$vmid" "rm -rf /Kiwi"

                # Remove database
                echo "Removing PostgreSQL database..."
                lxc_exec_live "$vmid" "sudo -u postgres psql -c 'DROP DATABASE IF EXISTS kiwi;' 2>/dev/null || true"
                lxc_exec_live "$vmid" "sudo -u postgres psql -c 'DROP USER IF EXISTS kiwi;' 2>/dev/null || true"

                # Remove user
                lxc_exec_live "$vmid" "userdel -r kiwi 2>/dev/null || true"

                # Restart nginx with default config
                lxc_exec_live "$vmid" "ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null || true"
                lxc_exec_live "$vmid" "systemctl restart nginx 2>/dev/null || true"
                ;;

            gitea)
                echo "Removing Gitea..."

                # Remove systemd service file
                lxc_exec_live "$vmid" "rm -f /etc/systemd/system/gitea.service"

                # Remove application files
                lxc_exec_live "$vmid" "rm -rf /var/lib/gitea"
                lxc_exec_live "$vmid" "rm -rf /etc/gitea"
                lxc_exec_live "$vmid" "rm -f /usr/local/bin/gitea"

                # Remove user
                lxc_exec_live "$vmid" "userdel -r gitea 2>/dev/null || true"
                ;;

            jenkins)
                echo "Removing Jenkins..."

                # Remove systemd service (installed by package)
                lxc_exec_live "$vmid" "apt-get purge -y jenkins 2>/dev/null || true"
                lxc_exec_live "$vmid" "apt-get autoremove -y 2>/dev/null || true"

                # Remove data directory
                lxc_exec_live "$vmid" "rm -rf /var/lib/jenkins"

                # Remove apt source
                lxc_exec_live "$vmid" "rm -f /etc/apt/sources.list.d/jenkins.list"
                lxc_exec_live "$vmid" "rm -f /usr/share/keyrings/jenkins-keyring.asc"
                ;;

            grafana)
                echo "Removing Grafana..."

                # Remove via package manager
                lxc_exec_live "$vmid" "apt-get purge -y grafana 2>/dev/null || true"
                lxc_exec_live "$vmid" "apt-get autoremove -y 2>/dev/null || true"

                # Remove data
                lxc_exec_live "$vmid" "rm -rf /var/lib/grafana"
                lxc_exec_live "$vmid" "rm -rf /etc/grafana"

                # Remove apt source
                lxc_exec_live "$vmid" "rm -f /etc/apt/sources.list.d/grafana.list"
                lxc_exec_live "$vmid" "rm -f /usr/share/keyrings/grafana.key"
                ;;

            prometheus)
                echo "Removing Prometheus..."

                # Remove via package manager
                lxc_exec_live "$vmid" "apt-get purge -y prometheus 2>/dev/null || true"
                lxc_exec_live "$vmid" "apt-get autoremove -y 2>/dev/null || true"

                # Remove data
                lxc_exec_live "$vmid" "rm -rf /var/lib/prometheus"
                lxc_exec_live "$vmid" "rm -rf /etc/prometheus"
                ;;

            testlink)
                echo "Removing TestLink..."

                # Stop Nginx
                lxc_exec_live "$vmid" "systemctl stop nginx 2>/dev/null || true"

                # Remove Nginx site config (but keep main nginx.conf)
                lxc_exec_live "$vmid" "rm -f /etc/nginx/sites-enabled/testlink"
                lxc_exec_live "$vmid" "rm -f /etc/nginx/sites-available/testlink"

                # Remove application files
                echo "Removing application files..."
                lxc_exec_live "$vmid" "rm -rf /var/www/testlink"
                lxc_exec_live "$vmid" "rm -rf /var/testlink"

                # Remove database and user completely
                echo "Removing MariaDB database..."
                lxc_exec_live "$vmid" "mysql -e 'DROP DATABASE IF EXISTS testlink;' 2>/dev/null || true"
                lxc_exec_live "$vmid" "mysql -e \"DROP USER IF EXISTS 'testlink'@'localhost';\" 2>/dev/null || true"
                lxc_exec_live "$vmid" "mysql -e 'FLUSH PRIVILEGES;' 2>/dev/null || true"

                # Ensure nginx.conf exists (reinstall if missing)
                echo "Restoring Nginx configuration..."
                if ! lxc_exec "$vmid" "test -f /etc/nginx/nginx.conf" 2>/dev/null; then
                    echo "nginx.conf missing, reinstalling nginx..."
                    lxc_exec_live "$vmid" "apt-get purge -y nginx nginx-common nginx-core 2>/dev/null || true"
                    lxc_exec_live "$vmid" "apt-get install -y nginx"
                fi

                # Restore default Nginx site
                lxc_exec_live "$vmid" "ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null || true"
                lxc_exec_live "$vmid" "systemctl restart nginx 2>/dev/null || true"
                ;;

            sonarqube)
                echo "Removing SonarQube..."

                # Stop service
                lxc_exec_live "$vmid" "systemctl stop sonarqube 2>/dev/null || true"
                lxc_exec_live "$vmid" "systemctl disable sonarqube 2>/dev/null || true"

                # Remove systemd service file
                lxc_exec_live "$vmid" "rm -f /etc/systemd/system/sonarqube.service"

                # Remove application files
                echo "Removing application files..."
                lxc_exec_live "$vmid" "rm -rf /opt/sonarqube"

                # Remove database
                echo "Removing PostgreSQL database..."
                lxc_exec_live "$vmid" "sudo -u postgres psql -c 'DROP DATABASE IF EXISTS sonarqube;' 2>/dev/null || true"
                lxc_exec_live "$vmid" "sudo -u postgres psql -c 'DROP USER IF EXISTS sonar;' 2>/dev/null || true"

                # Remove user
                lxc_exec_live "$vmid" "userdel -r sonarqube 2>/dev/null || true"

                # Remove sysctl settings
                lxc_exec_live "$vmid" "sed -i '/vm.max_map_count=524288/d' /etc/sysctl.conf 2>/dev/null || true"
                lxc_exec_live "$vmid" "sed -i '/fs.file-max=131072/d' /etc/sysctl.conf 2>/dev/null || true"

                # Remove limits
                lxc_exec_live "$vmid" "sed -i '/sonarqube.*nofile/d' /etc/security/limits.conf 2>/dev/null || true"
                lxc_exec_live "$vmid" "sed -i '/sonarqube.*nproc/d' /etc/security/limits.conf 2>/dev/null || true"
                ;;

            pihole)
                echo "Removing Pi-hole..."

                # Use Pi-hole's uninstall script if available
                if lxc_exec "$vmid" "test -f /etc/.pihole/automated\ install/uninstall.sh" 2>/dev/null; then
                    echo "Running Pi-hole uninstaller..."
                    lxc_exec_live "$vmid" "pihole uninstall --unattended 2>/dev/null || true"
                else
                    # Manual removal
                    echo "Manual Pi-hole removal..."

                    # Stop services
                    lxc_exec_live "$vmid" "systemctl stop pihole-FTL 2>/dev/null || true"
                    lxc_exec_live "$vmid" "systemctl stop lighttpd 2>/dev/null || true"
                    lxc_exec_live "$vmid" "systemctl disable pihole-FTL 2>/dev/null || true"
                    lxc_exec_live "$vmid" "systemctl disable lighttpd 2>/dev/null || true"

                    # Remove Pi-hole directories
                    lxc_exec_live "$vmid" "rm -rf /etc/pihole"
                    lxc_exec_live "$vmid" "rm -rf /etc/.pihole"
                    lxc_exec_live "$vmid" "rm -rf /opt/pihole"
                    lxc_exec_live "$vmid" "rm -rf /var/www/html/admin"
                    lxc_exec_live "$vmid" "rm -f /usr/local/bin/pihole"

                    # Remove lighttpd config
                    lxc_exec_live "$vmid" "rm -rf /etc/lighttpd"

                    # Remove packages
                    lxc_exec_live "$vmid" "apt-get purge -y pihole-FTL lighttpd 2>/dev/null || true"
                    lxc_exec_live "$vmid" "apt-get autoremove -y 2>/dev/null || true"
                fi

                # Restore DNS
                echo "Restoring DNS configuration..."
                lxc_exec_live "$vmid" "rm -f /etc/resolv.conf"
                lxc_exec_live "$vmid" "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
                lxc_exec_live "$vmid" "systemctl enable systemd-resolved 2>/dev/null || true"
                lxc_exec_live "$vmid" "systemctl start systemd-resolved 2>/dev/null || true"
                ;;

            *)
                echo "Generic removal for $service..."

                # Remove systemd service file
                lxc_exec_live "$vmid" "rm -f /etc/systemd/system/${service}.service"

                # Try to find and remove common paths
                lxc_exec_live "$vmid" "rm -rf /opt/$service 2>/dev/null || true"
                lxc_exec_live "$vmid" "rm -rf /var/lib/$service 2>/dev/null || true"
                lxc_exec_live "$vmid" "rm -rf /etc/$service 2>/dev/null || true"

                # Try to remove user
                lxc_exec_live "$vmid" "userdel -r $service 2>/dev/null || true"
                ;;
        esac

        # Reload systemd
        echo ""
        echo "Reloading systemd..."
        lxc_exec_live "$vmid" "systemctl daemon-reload"

        echo ""
        echo "=== Native Service Removed ==="

    ) 2>&1 | show_progress_box "Removing Native Service" 20 70

    show_msg "Service Removed" "$service (Native) has been removed from container $vmid."
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

    location /static/ {
        alias /Kiwi/static/;
        expires 30d;
        add_header Cache-Control \"public, immutable\";
    }

    location /uploads/ {
        alias /Kiwi/uploads/;
    }

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
            "5" "Harbor (Container Registry)" \
            "6" "Dependency-Track (SCA/SBOM)" \
            "0" "Back")

        case "$choice" in
            1) deploy_service_wizard "sonarqube" "SonarQube" ;;
            2) deploy_service_wizard "nexus" "Nexus Repository" ;;
            3) deploy_service_wizard "gitea" "Gitea" ;;
            4) deploy_service_wizard "jenkins" "Jenkins" ;;
            5) deploy_service_wizard "harbor" "Harbor" ;;
            6) deploy_service_wizard "dependency-track" "Dependency-Track" ;;
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
                case "$service" in
                    prometheus) native_access_info="http://${ip}:9090" ;;
                    grafana) native_access_info="http://${ip}:3000 (admin/admin)" ;;
                    gitea) native_access_info="http://${ip}:3000" ;;
                    jenkins) native_access_info="http://${ip}:8080\n\nInitial password: cat /var/lib/jenkins/secrets/initialAdminPassword" ;;
                    kiwi-tcms) native_access_info="http://${ip}/\n\nCreate admin user:\n  Run: /opt/kiwi/create_superuser.sh" ;;
                    testlink) native_access_info="http://${ip}/\n\nComplete setup at: http://${ip}/install/index.php\nDB: testlink, User: testlink, Password: testlink123\n\nAfter setup, delete: /var/www/testlink/install" ;;
                    sonarqube) native_access_info="http://${ip}:9000 (admin/admin)\n\nNote: First startup may take 1-2 minutes" ;;
                    pihole) native_access_info="Admin: http://${ip}/admin\nPassword: admin\nDNS Server: ${ip}:53\n\nTo change password: pihole -a -p <newpassword>" ;;
                    *) native_access_info="http://${ip}/" ;;
                esac

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

        if show_yesno "Confirm Deployment" "Deploy $service_name to container $selected via Docker?"; then
            if deploy_service_with_progress "$selected" "$service" "$service_name"; then
                local ip
                ip=$(get_container_ip "$selected")

                local access_info=""
                case "$service" in
                    prometheus) access_info="http://${ip}:9090" ;;
                    grafana) access_info="http://${ip}:3000 (admin/admin)" ;;
                    loki) access_info="http://${ip}:3100" ;;
                    monitoring-stack) access_info="Grafana: http://${ip}:3000\nPrometheus: http://${ip}:9090" ;;
                    sonarqube) access_info="http://${ip}:9000 (admin/admin)" ;;
                    nexus) access_info="http://${ip}:8081" ;;
                    gitea) access_info="http://${ip}:3000" ;;
                    jenkins) access_info="http://${ip}:8080" ;;
                    kiwi-tcms) access_info="https://${ip}:8443 (self-signed cert)\nNote: First startup takes 2-3 minutes for DB migrations" ;;
                    selenium-grid) access_info="http://${ip}:4444" ;;
                    testlink) access_info="http://${ip}/ (admin/admin123)\nNote: First startup takes 1-2 minutes for DB initialization" ;;
                    harbor) access_info="Portal: http://${ip}/ (admin/Harbor12345)\nRegistry: ${ip}:5000\nNote: First startup takes 2-3 minutes" ;;
                    traefik) access_info="Dashboard: http://${ip}:8080\nHTTP: http://${ip}\nHTTPS: https://${ip}" ;;
                    pihole) access_info="Admin: http://${ip}/admin (admin)\nDNS Server: ${ip}:53\n\nSet as DNS on clients to block ads" ;;
                    dependency-track) access_info="Frontend: http://${ip}:8080\nAPI Server: http://${ip}:8081\nDefault: admin/admin\n\nNote: First startup takes 2-3 minutes for DB init" ;;
                    keycloak) access_info="Admin Console: http://${ip}:8080\nDefault: admin/admin\n\nNote: First startup takes 1-2 minutes" ;;
                    freeipa) access_info="Web UI: https://${ip}/\nLDAP: ldap://${ip}:389\nLDAPS: ldaps://${ip}:636\nKerberos: ${ip}:88\n\nNote: First startup takes 5-10 minutes for setup\nCheck logs: docker logs -f freeipa" ;;
                    postfix-relay) access_info="SMTP: ${ip}:25\nSubmission: ${ip}:587\n\nConfigure apps to use this as SMTP relay\nSet POSTFIX_ALLOWED_DOMAINS env var for allowed senders" ;;
                esac

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
            "3" "Docker Setup" \
            "4" "SSH Key Management" \
            "5" "Service Deployment" \
            "6" "Certificate Management" \
            "7" "Settings" \
            "0" "Exit")

        case "$choice" in
            1) pve_connection_menu ;;
            2) lxc_management_menu ;;
            3) docker_setup_menu ;;
            4) ssh_management_menu ;;
            5) service_deployment_menu ;;
            6) certificate_menu ;;
            7) settings_menu ;;
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

Features:
  - LXC container creation and management
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
    esac

    # Initialize
    check_dependencies
    detect_dialog
    init_config
    load_config

    # Auto-connect to local PVE if running on PVE host
    if is_pve_host; then
        pve_connect "local" &>/dev/null
    fi

    # Start main menu
    main_menu
}

# Run main
main "$@"
