#!/bin/bash
# ======================================================================
# VLESS User Management Script for Sing-Box
# Author: AI Assistant (Based on User Requirements)
# Purpose: Add, list, and delete VLESS users in the Sing-Box configuration.
# Location: /usr/local/sbin/manage_proxy_users (when deployed)
# ======================================================================

# Exit on error, treat unset vars as error
set -euo pipefail

# --- Configuration ---
# These paths must match the paths used in the deployment script and Sing-Box setup
SINGBOX_CONFIG="/etc/sing-box/config.json"
USER_MAP_FILE="/etc/sing-box/user_map.txt"
BACKUP_DIR="/etc/sing-box/backups"
# User and Group that own the Sing-Box configuration files
SINGBOX_USER="singbox"
SINGBOX_GROUP="singbox"

# --- Helper Functions ---
log_info() { echo "[INFO] $(date +'%Y%m%d_%H%M%S') - $1"; }
log_error() { echo "[ERROR] $(date +'%Y%m%d_%H%M%S') - $1" >&2; }
check_root() {
    if [[ $EUID -ne 0 ]]; then
       log_error "This script must be run as root (or using sudo) to modify system files and reload services."
       exit 1
    fi
}
check_deps() {
    command -v jq >/dev/null 2>&1 || { log_error "jq is required but not installed. Please install it (e.g., apt install jq)."; exit 1; }
    command -v uuidgen >/dev/null 2>&1 || { log_error "uuidgen is required but not installed. Please install it (e.g., apt install uuid-runtime)."; exit 1; }
    command -v systemctl >/dev/null 2>&1 || { log_error "systemctl is required."; exit 1; }
}
backup_config() {
    # Ensure backup directory exists and has correct permissions
    mkdir -p "$BACKUP_DIR"
    chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "$BACKUP_DIR"
    chmod 750 "$BACKUP_DIR" # Owner rwx, group rx

    local backup_file="${BACKUP_DIR}/config.json_$(date +%Y%m%d_%H%M%S)"
    if cp "$SINGBOX_CONFIG" "$backup_file"; then
        log_info "Config backed up to $backup_file";
    else
        log_error "Failed to create backup file at $backup_file";
        # Decide if this is critical enough to stop
        # exit 1; # Uncomment to make backup failure critical
    fi
}
set_ownership_perms() {
    # Ensure config and map file have correct owner and restrictive permissions
    if chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "$SINGBOX_CONFIG" "$USER_MAP_FILE"; then
        chmod 640 "$SINGBOX_CONFIG" "$USER_MAP_FILE" # Owner rw, Group r, Other none
    else
      log_error "Failed to set ownership/permissions on configuration files."
    fi
}
reload_singbox() {
    log_info "Reloading Sing-Box service (via restart)..."
    # Use restart as Sing-Box might not have a reload mechanism for config changes
    if systemctl restart sing-box; then
        log_info "Sing-Box restarted successfully."
        return 0 # Success
    else
        log_error "!!! Failed to restart Sing-Box after config change. !!!"
        log_error "Check Sing-Box status ('systemctl status sing-box') and logs ('journalctl -u sing-box')."
        log_error "Attempting to restore previous config from latest backup..."

        local LATEST_BACKUP
        # Find the most recent backup file
        LATEST_BACKUP=$(ls -t "${BACKUP_DIR}/config.json_"* 2>/dev/null | head -n 1)

        if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP" ]; then
            if cp "$LATEST_BACKUP" "$SINGBOX_CONFIG"; then
                log_info "Successfully restored config from $LATEST_BACKUP."
                set_ownership_perms # Ensure restored file has correct perms too
                log_info "Attempting restart again with restored config..."
                # Try restarting again with the restored config
                if systemctl restart sing-box; then
                     log_info "Sing-Box restarted successfully with restored config."
                     log_error "The previous config change caused an error and was reverted."
                     return 1 # Indicate failure despite recovery
                else
                     log_error "!!! Failed to restart Sing-Box even after restoring backup. MANUAL INTERVENTION REQUIRED. !!!"
                     return 1 # Indicate failure
                fi
            else
                 log_error "!!! Failed to copy backup file $LATEST_BACKUP to $SINGBOX_CONFIG. MANUAL INTERVENTION REQUIRED. !!!"
                 return 1 # Indicate failure
            fi
        else
             log_error "!!! No backup found in $BACKUP_DIR to restore. MANUAL INTERVENTION REQUIRED. !!!"
             return 1 # Indicate failure
        fi
    fi
}

# --- Command Functions ---

add_user() {
    local username="$1"
    # Validate username presence and format
    if [ -z "$username" ]; then log_error "Username cannot be empty."; usage; exit 1; fi
    if ! [[ "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then log_error "Invalid username format. Use only alphanumeric characters, hyphens (-), or underscores (_)."; exit 1; fi

    # Check if username already exists in the map file
    if grep -q -x -e "${username}:.*" "$USER_MAP_FILE"; then # Use -x for whole line match (username part)
        log_error "Username '$username' already exists in map file (${USER_MAP_FILE}).";
        exit 1;
    fi

    # Generate a new UUID
    local new_uuid; new_uuid=$(uuidgen)

    # Double-check if this UUID somehow already exists in the config (extremely unlikely)
    if jq -e --arg uuid "$new_uuid" '(.inbounds[] | select(.tag == "vless-in").users[] | select(.uuid == $uuid))' "$SINGBOX_CONFIG" > /dev/null; then
        log_error "Generated UUID collision detected ($new_uuid). This is highly unusual. Please try again.";
        exit 1;
    fi

    log_info "Attempting to add user '$username' with UUID: $new_uuid"

    # 1. Add to map file first (less critical if this fails before config change)
    echo "${username}:${new_uuid}" >> "$USER_MAP_FILE"
    set_ownership_perms # Update map file perms

    # 2. Backup the current config
    backup_config

    # 3. Add UUID to Sing-Box config using jq
    local temp_config; temp_config=$(mktemp)
    # Use jq to add the new user object to the 'users' array within the 'vless-in' inbound
    if jq --arg uuid "$new_uuid" '
        # Find the vless-in inbound object and modify its users array
        (.inbounds[] | select(.tag == "vless-in").users) += [{"uuid": $uuid, "flow": ""}]
    ' "$SINGBOX_CONFIG" > "$temp_config"; then
        # If jq succeeded, replace the original config with the temp file
        mv "$temp_config" "$SINGBOX_CONFIG"
    else
        log_error "Failed to update $SINGBOX_CONFIG using jq. Check JSON syntax if manually edited.";
        rm -f "$temp_config" # Clean up temp file
        # Attempt to reload anyway, which should trigger the restore logic if jq failed badly
        reload_singbox
        exit 1 # Exit indicating failure
    fi

    # 4. Set ownership and permissions on the modified config file
    set_ownership_perms

    # 5. Reload Sing-Box and report final status
    if reload_singbox; then
        log_info "User '$username' added successfully. UUID: $new_uuid"
    else
        # The reload_singbox function already logs errors and attempts restore
        log_error "User addition for '$username' failed because the service could not be reloaded. The configuration may have been restored."
        exit 1 # Exit indicating failure
    fi
}

list_users() {
    log_info "--- User List ---"
    log_info "[Format: Username:UUID (from ${USER_MAP_FILE})]"
    if [ -s "$USER_MAP_FILE" ]; then
        # Sort the map file for better readability
        sort "$USER_MAP_FILE"
    else
        log_info "(No users found in map file)"
    fi
    echo # Blank line

    log_info "[UUIDs currently active in Sing-Box config (${SINGBOX_CONFIG})]"
    # Use jq to extract UUIDs, check if array exists and has elements
    if jq -e '.inbounds[]? | select(.tag == "vless-in") | .users? | length > 0' "$SINGBOX_CONFIG" > /dev/null 2>&1; then
       # If users array exists and is not empty, print UUIDs
       jq -r '.inbounds[] | select(.tag == "vless-in") | .users[] .uuid' "$SINGBOX_CONFIG" | sort
    else
       log_info "(No VLESS users found in Sing-Box config)"
    fi
    log_info "--- End List ---"
}

delete_user() {
    local identifier="$1"
    local uuid_to_delete=""
    local username_to_delete="" # Track username for logging

    if [ -z "$identifier" ]; then log_error "Username or UUID must be provided for deletion."; usage; exit 1; fi

    # Determine if identifier is UUID or username
    # Basic check: does it look like a UUID?
    if [[ "$identifier" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        uuid_to_delete="$identifier"
        log_info "Attempting to delete by UUID: $uuid_to_delete"
        # Find associated username in map for logging/completeness
        username_to_delete=$(grep -e ":${uuid_to_delete}$" "$USER_MAP_FILE" | cut -d':' -f1)
        [[ -z "$username_to_delete" ]] && username_to_delete="(Username not found in map)"
    else
        # Assume it's a username
        username_to_delete="$identifier"
        log_info "Attempting to delete by username: $username_to_delete"
        local found_line
        # Match the line starting exactly with the username followed by ':'
        found_line=$(grep -e "^${username_to_delete}:" "$USER_MAP_FILE")
        if [ -n "$found_line" ]; then
            uuid_to_delete=$(echo "$found_line" | cut -d':' -f2)
            log_info "Found corresponding UUID: $uuid_to_delete"
        else
            log_error "Username '$username_to_delete' not found in map file (${USER_MAP_FILE}). Cannot determine UUID to delete.";
            exit 1;
        fi
    fi

    # Verify that the UUID actually exists in the Sing-Box config before proceeding
    if ! jq -e --arg uuid "$uuid_to_delete" '(.inbounds[] | select(.tag == "vless-in").users[] | select(.uuid == $uuid))' "$SINGBOX_CONFIG" > /dev/null; then
         log_error "UUID $uuid_to_delete not found in the active Sing-Box config (${SINGBOX_CONFIG}). User might have been deleted already."
         # Perform map file cleanup just in case
         if grep -q -e ":${uuid_to_delete}$" "$USER_MAP_FILE"; then
             log_info "UUID found in map file. Removing dangling map entry for '$username_to_delete'..."
             # Use sed to delete the line matching the UUID at the end
             sed -i.bak "/:${uuid_to_delete}$/d" "$USER_MAP_FILE"; rm -f "${USER_MAP_FILE}.bak"
             set_ownership_perms
             log_info "Dangling map entry removed."
         fi
         exit 1 # Exit as the user isn't in the active config
     fi

    log_info "Proceeding to delete user '$username_to_delete' (UUID: $uuid_to_delete)"

    # 1. Delete from map file
    if grep -q -e ":${uuid_to_delete}$" "$USER_MAP_FILE"; then
        log_info "Removing user from map file (${USER_MAP_FILE})...";
        sed -i.bak "/:${uuid_to_delete}$/d" "$USER_MAP_FILE"; rm -f "${USER_MAP_FILE}.bak";
        set_ownership_perms
    else
        log_info "UUID $uuid_to_delete was not found in the map file (maybe removed previously or added manually?).";
    fi

    # 2. Backup the current config
    backup_config

    # 3. Delete UUID from Sing-Box config using jq
    local temp_config; temp_config=$(mktemp)
    # Use jq to filter the 'users' array, keeping only elements whose UUID does *not* match the one to delete
    if jq --arg uuid "$uuid_to_delete" '
        (.inbounds[] | select(.tag == "vless-in").users) |= map(select(.uuid != $uuid))
    ' "$SINGBOX_CONFIG" > "$temp_config"; then
        mv "$temp_config" "$SINGBOX_CONFIG"
    else
        log_error "Failed to update $SINGBOX_CONFIG using jq during deletion."; rm -f "$temp_config";
        reload_singbox # Attempt reload, should trigger restore
        exit 1
    fi

    # 4. Set ownership and permissions
    set_ownership_perms

    # 5. Reload Sing-Box and report status
    if reload_singbox; then
        log_info "User '$username_to_delete' (UUID: $uuid_to_delete) deleted successfully."
    else
        log_error "User deletion for '$username_to_delete' failed because the service could not be reloaded. The configuration may have been restored."
        exit 1
    fi
}

usage() {
  echo "Usage: $0 <command> [options]"
  echo "Commands:"
  echo "  add <username>       Add a new VLESS user (generates unique UUID)."
  echo "  del <username|uuid>  Delete a VLESS user by username (from map) or exact UUID."
  echo "  list | ls            List users from map file and UUIDs from active config."
  echo ""
  echo "Example:"
  echo "  sudo $0 add my_new_user"
  echo "  sudo $0 list"
  echo "  sudo $0 del my_new_user"
  echo "  sudo $0 del a1b2c3d4-e5f6-7890-1234-567890abcdef"
}

# --- Main Script Logic ---
check_root
check_deps

# Ensure map file exists and has correct permissions before running commands
# This guards against errors if the file was somehow deleted.
touch "$USER_MAP_FILE"; set_ownership_perms

# Ensure config file exists
if [ ! -f "$SINGBOX_CONFIG" ]; then
    log_error "Sing-Box configuration file not found at ${SINGBOX_CONFIG}";
    exit 1;
fi

# Parse command line arguments
if [ $# -eq 0 ]; then
  usage
  exit 1
fi

COMMAND=$1
shift # Remove command from arguments, remaining args passed to functions

case $COMMAND in
  add)
    add_user "$@"
    ;;
  del | delete)
    delete_user "$@"
    ;;
  list | ls)
    list_users
    ;;
  *)
    log_error "Unknown command: $COMMAND"
    usage
    exit 1
    ;;
esac

exit 0 # Explicitly exit with success if command completes
