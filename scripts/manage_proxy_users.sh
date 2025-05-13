#!/bin/bash
# ======================================================================
# Proxy User Management Script for Sing-Box (VLESS & Hysteria2)
# Version 2.0
# Author: AI Assistant & User
# Purpose: Add, list, and delete VLESS and Hysteria2 users.
# ======================================================================

set -euo pipefail

# --- Configuration ---
SINGBOX_CONFIG="/etc/sing-box/config.json"
VLESS_USER_MAP_FILE="/etc/sing-box/vless_user_map.txt" # Stores username:uuid for VLESS
HY2_USER_MAP_FILE="/etc/sing-box/hy2_user_map.txt"     # Stores username (only) for Hysteria2
BACKUP_DIR="/etc/sing-box/backups"
SINGBOX_USER="singbox"  # User that runs sing-box and owns its files
SINGBOX_GROUP="singbox" # Group for sing-box

VLESS_INBOUND_TAG="vless-in" # Tag for VLESS inbound in Sing-Box config
HY2_INBOUND_TAG="hy2-in"     # Tag for Hysteria2 inbound in Sing-Box config

# --- Helper Functions ---
log_info() { echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"; }
log_error() { echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2; }
log_warn() { echo "[WARN] $(date +'%Y-%m-%d %H:%M:%S') - $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
       log_error "This script must be run as root (or using sudo)."
       exit 1
    fi
}

check_deps() {
    command -v jq >/dev/null 2>&1 || { log_error "jq is required but not installed. Please install it (e.g., apt install jq)."; exit 1; }
    command -v uuidgen >/dev/null 2>&1 || { log_error "uuidgen is required but not installed. Please install it (e.g., apt install uuid-runtime)."; exit 1; }
    command -v systemctl >/dev/null 2>&1 || { log_error "systemctl is required for service management."; exit 1; }
}

backup_config() {
    # Ensure backup directory exists and has correct permissions
    if ! mkdir -p "$BACKUP_DIR"; then log_error "Failed to create backup directory: $BACKUP_DIR"; exit 1; fi
    if ! chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "$BACKUP_DIR"; then log_warn "Failed to set ownership on backup directory."; fi
    if ! chmod 750 "$BACKUP_DIR"; then log_warn "Failed to set permissions on backup directory."; fi

    local backup_file="${BACKUP_DIR}/config.json_$(date +'%Y%m%d_%H%M%S')"
    if cp "$SINGBOX_CONFIG" "$backup_file"; then
        log_info "Config backed up to $backup_file";
    else
        log_error "CRITICAL: Failed to create backup file at $backup_file. Aborting operation.";
        exit 1; # Backup failure is critical before modifying config
    fi
}

set_ownership_perms_config() {
    if ! chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "$SINGBOX_CONFIG"; then log_warn "Failed to set ownership on ${SINGBOX_CONFIG}"; fi
    if ! chmod 640 "$SINGBOX_CONFIG"; then log_warn "Failed to set permissions on ${SINGBOX_CONFIG}"; fi
}

set_ownership_perms_map() {
    local map_file="$1"
    touch "$map_file" # Ensure it exists before chown/chmod
    if ! chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "$map_file"; then log_warn "Failed to set ownership on ${map_file}"; fi
    if ! chmod 640 "$map_file"; then log_warn "Failed to set permissions on ${map_file}"; fi
}

reload_singbox() {
    log_info "Attempting to reload/restart Sing-Box service..."
    # Attempt reload first, as it's less disruptive
    if systemctl is-active --quiet sing-box && systemctl reload sing-box &>/dev/null; then
        log_info "Sing-Box reloaded successfully."
        # Brief pause to see if it crashes post-reload
        sleep 1
        if systemctl is-active --quiet sing-box; then
            return 0 # Reload successful and service is still active
        else
            log_warn "Sing-Box became inactive after reload attempt. Will try full restart."
        fi
    elif ! systemctl is-active --quiet sing-box; then
        log_info "Sing-Box was not active. Will try to start it."
    else
        log_info "Reload not supported or failed. Will try full restart."
    fi

    # If reload failed or service was inactive, try restart
    if systemctl restart sing-box; then
        log_info "Sing-Box (re)started successfully."
        return 0
    else
        log_error "!!! Failed to restart/reload Sing-Box after configuration change. !!!"
        log_error "Please check Sing-Box status ('systemctl status sing-box') and logs ('journalctl -u sing-box --no-pager -n 50')."
        
        local LATEST_BACKUP
        LATEST_BACKUP=$(ls -t "${BACKUP_DIR}/config.json_"* 2>/dev/null | head -n 1)

        if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP" ]; then
            log_info "Attempting to restore previous config from: $LATEST_BACKUP"
            if cp "$LATEST_BACKUP" "$SINGBOX_CONFIG"; then
                log_info "Successfully restored config from $LATEST_BACKUP."
                set_ownership_perms_config # Ensure restored file has correct perms too
                log_info "Attempting (re)start again with restored config..."
                if systemctl restart sing-box; then
                     log_info "Sing-Box (re)started successfully with restored config."
                     log_error "The previous config change caused an error and has been reverted."
                     return 1 # Indicate failure of the original operation despite recovery
                else
                     log_error "!!! CRITICAL: Failed to (re)start Sing-Box even after restoring backup. MANUAL INTERVENTION REQUIRED. !!!"
                     return 1
                fi
            else
                 log_error "!!! CRITICAL: Failed to copy backup file $LATEST_BACKUP to $SINGBOX_CONFIG. MANUAL INTERVENTION REQUIRED. !!!"
                 return 1
            fi
        else
             log_error "!!! CRITICAL: No backup found in $BACKUP_DIR to restore. MANUAL INTERVENTION REQUIRED. !!!"
             return 1
        fi
    fi
}

# --- VLESS User Functions ---
add_vless_user() {
    local username="$1"
    if [ -z "$username" ]; then log_error "VLESS username cannot be empty."; usage; exit 1; fi
    if ! [[ "$username" =~ ^[a-zA-Z0-9_.-]+$ ]]; then log_error "Invalid VLESS username format. Use alphanumeric, underscore, hyphen, dot."; exit 1; fi
    if grep -q -x -e "${username}:.*" "$VLESS_USER_MAP_FILE"; then log_error "VLESS username '$username' already exists in map file."; exit 1; fi

    local new_uuid; new_uuid=$(uuidgen)
    if jq -e --arg uuid "$new_uuid" --arg tag "$VLESS_INBOUND_TAG" \
        '(.inbounds[] | select(.tag == $tag).users[]? | select(.uuid == $uuid))' \
        "$SINGBOX_CONFIG" > /dev/null; then
        log_error "Generated VLESS UUID collision ($new_uuid). This is highly unusual. Please try again."; exit 1;
    fi

    log_info "Attempting to add VLESS user '$username' with UUID: $new_uuid"
    echo "${username}:${new_uuid}" >> "$VLESS_USER_MAP_FILE"; set_ownership_perms_map "$VLESS_USER_MAP_FILE"
    
    backup_config
    local temp_config; temp_config=$(mktemp)
    jq --arg uuid "$new_uuid" --arg tag "$VLESS_INBOUND_TAG" \
       '(.inbounds[] | select(.tag == $tag).users) += [{"uuid": $uuid, "flow": ""}]' \
       "$SINGBOX_CONFIG" > "$temp_config" || { 
           log_error "jq command failed during VLESS user addition."; rm -f "$temp_config"; reload_singbox; exit 1; 
       }
    mv "$temp_config" "$SINGBOX_CONFIG"; set_ownership_perms_config
    
    if reload_singbox; then log_info "VLESS user '$username' added successfully. UUID: $new_uuid";
    else log_error "VLESS user '$username' addition failed because the service could not be reloaded/restarted."; exit 1; fi
}

list_vless_users() {
    log_info "--- VLESS User List ---"
    log_info "[Format: Username:UUID (from ${VLESS_USER_MAP_FILE})]"
    if [ -s "$VLESS_USER_MAP_FILE" ]; then sort "$VLESS_USER_MAP_FILE"; else log_info "(No users found in VLESS map file)"; fi
    echo ""
    log_info "[UUIDs currently active in Sing-Box config (${SINGBOX_CONFIG} for tag '${VLESS_INBOUND_TAG}')]"
    if jq -e --arg tag "$VLESS_INBOUND_TAG" '(.inbounds[]? | select(.tag == $tag) | .users? | length > 0)' "$SINGBOX_CONFIG" > /dev/null 2>&1; then
       jq -r --arg tag "$VLESS_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .users[] .uuid' "$SINGBOX_CONFIG" | sort
    else log_info "(No VLESS users found in Sing-Box config for tag '${VLESS_INBOUND_TAG}')"; fi
    log_info "--- End VLESS List ---"
}

delete_vless_user() {
    local identifier="$1"
    if [ -z "$identifier" ]; then log_error "VLESS username or UUID must be provided for deletion."; usage; exit 1; fi

    local uuid_to_delete=""
    local username_to_delete=""

    if [[ "$identifier" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; then # UUID format
        uuid_to_delete="$identifier"
        username_to_delete=$(grep -e ":${uuid_to_delete}$" "$VLESS_USER_MAP_FILE" | cut -d':' -f1)
        [[ -z "$username_to_delete" ]] && username_to_delete="(Username not found in map for this UUID)"
    else # Assume username
        username_to_delete="$identifier"
        local found_line; found_line=$(grep -e "^${username_to_delete}:" "$VLESS_USER_MAP_FILE")
        if [ -n "$found_line" ]; then
            uuid_to_delete=$(echo "$found_line" | cut -d':' -f2)
        else
            log_error "VLESS username '$username_to_delete' not found in map file (${VLESS_USER_MAP_FILE})."; exit 1;
        fi
    fi

    if ! jq -e --arg uuid "$uuid_to_delete" --arg tag "$VLESS_INBOUND_TAG" \
        '(.inbounds[] | select(.tag == $tag).users[]? | select(.uuid == $uuid))' \
        "$SINGBOX_CONFIG" > /dev/null; then
         log_warn "VLESS UUID $uuid_to_delete (for user '$username_to_delete') not found in Sing-Box config."
         if grep -q -e ":${uuid_to_delete}$" "$VLESS_USER_MAP_FILE"; then # Check map file
             log_info "Removing dangling VLESS map entry for '$username_to_delete'..."
             sed -i.bak "/:${uuid_to_delete}$/d" "$VLESS_USER_MAP_FILE"; rm -f "${VLESS_USER_MAP_FILE}.bak"
             set_ownership_perms_map "$VLESS_USER_MAP_FILE"
         fi
         exit 0 # Not an error if already gone from config
     fi

    log_info "Proceeding to delete VLESS user '$username_to_delete' (UUID: $uuid_to_delete)"
    if grep -q -e ":${uuid_to_delete}$" "$VLESS_USER_MAP_FILE"; then
        sed -i.bak "/:${uuid_to_delete}$/d" "$VLESS_USER_MAP_FILE"; rm -f "${VLESS_USER_MAP_FILE}.bak"; set_ownership_perms_map "$VLESS_USER_MAP_FILE"; fi

    backup_config
    local temp_config; temp_config=$(mktemp)
    jq --arg uuid "$uuid_to_delete" --arg tag "$VLESS_INBOUND_TAG" \
       '(.inbounds[] | select(.tag == $tag).users) |= map(select(.uuid != $uuid))' \
       "$SINGBOX_CONFIG" > "$temp_config" || {
           log_error "jq command failed during VLESS user deletion."; rm -f "$temp_config"; reload_singbox; exit 1;
       }
    mv "$temp_config" "$SINGBOX_CONFIG"; set_ownership_perms_config

    if reload_singbox; then log_info "VLESS user '$username_to_delete' deleted successfully.";
    else log_error "VLESS user '$username_to_delete' deletion failed (service reload issue)."; exit 1; fi
}

# --- Hysteria2 User Functions ---
add_hy2_user() {
    local username="$1"
    local password="$2"
    if [ -z "$username" ] || [ -z "$password" ]; then log_error "Hysteria2 username AND password are required."; usage; exit 1; fi
    if ! [[ "$username" =~ ^[a-zA-Z0-9_.-]+$ ]]; then log_error "Invalid Hysteria2 username format. Use alphanumeric, underscore, hyphen, dot."; exit 1; fi
    # Basic password check - ensure it's not obviously trivial, though this is weak.
    if [ ${#password} -lt 8 ]; then log_warn "Hysteria2 password for '$username' is shorter than 8 characters. Consider a stronger password."; fi


    if jq -e --arg name "$username" --arg tag "$HY2_INBOUND_TAG" \
        '(.inbounds[] | select(.tag == $tag).users[]? | select(.name == $name))' \
        "$SINGBOX_CONFIG" > /dev/null; then
        log_error "Hysteria2 username '$username' already exists in Sing-Box config."; exit 1;
    fi
    # Also check map file
    if grep -q -x -e "^${username}$" "$HY2_USER_MAP_FILE"; then log_warn "Hysteria2 username '$username' found in map file but not in config. This is unusual. Will proceed to add to config."; fi


    log_info "Attempting to add Hysteria2 user '$username'"
    echo "${username}" >> "$HY2_USER_MAP_FILE"; set_ownership_perms_map "$HY2_USER_MAP_FILE" # Map stores only username

    backup_config
    local temp_config; temp_config=$(mktemp)
    jq --arg name "$username" --arg pass "$password" --arg tag "$HY2_INBOUND_TAG" \
       '(.inbounds[] | select(.tag == $tag).users) += [{"name": $name, "password": $pass}]' \
       "$SINGBOX_CONFIG" > "$temp_config" || {
           log_error "jq command failed during Hysteria2 user addition."; rm -f "$temp_config"; reload_singbox; exit 1;
       }
    mv "$temp_config" "$SINGBOX_CONFIG"; set_ownership_perms_config

    if reload_singbox; then log_info "Hysteria2 user '$username' added successfully.";
    else log_error "Hysteria2 user '$username' addition failed (service reload issue)."; exit 1; fi
}

list_hy2_users() {
    log_info "--- Hysteria2 User List ---"
    log_info "[Usernames (from ${HY2_USER_MAP_FILE})]"
    if [ -s "$HY2_USER_MAP_FILE" ]; then sort "$HY2_USER_MAP_FILE"; else log_info "(No users found in Hysteria2 map file)"; fi
    echo ""
    log_info "[Usernames currently in Sing-Box config (${SINGBOX_CONFIG} for tag '${HY2_INBOUND_TAG}') - Passwords are not displayed]"
    if jq -e --arg tag "$HY2_INBOUND_TAG" '(.inbounds[]? | select(.tag == $tag) | .users? | length > 0)' "$SINGBOX_CONFIG" > /dev/null 2>&1; then
       # List users that have a 'name' field
       jq -r --arg tag "$HY2_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .users[] | .name? | select(. != null)' "$SINGBOX_CONFIG" | sort
       # Identify if there are users without a 'name' (shouldn't happen with this script but good for diagnostics)
       if jq -e --arg tag "$HY2_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .users[] | select(.name == null)' "$SINGBOX_CONFIG" > /dev/null; then
           log_warn "Warning: Some Hysteria2 users in config do not have a 'name' field."
       fi
    else log_info "(No Hysteria2 users found in Sing-Box config for tag '${HY2_INBOUND_TAG}')"; fi
    log_info "--- End Hysteria2 List ---"
}

delete_hy2_user() {
    local username="$1"
    if [ -z "$username" ]; then log_error "Hysteria2 username must be provided for deletion."; usage; exit 1; fi

    if ! jq -e --arg name "$username" --arg tag "$HY2_INBOUND_TAG" \
        '(.inbounds[] | select(.tag == $tag).users[]? | select(.name == $name))' \
        "$SINGBOX_CONFIG" > /dev/null; then
         log_warn "Hysteria2 username '$username' not found in Sing-Box config."
         if grep -q -x -e "^${username}$" "$HY2_USER_MAP_FILE"; then # Check map file
             log_info "Removing dangling Hysteria2 map entry for '$username'..."
             sed -i.bak "/^${username}$/d" "$HY2_USER_MAP_FILE"; rm -f "${HY2_USER_MAP_FILE}.bak"
             set_ownership_perms_map "$HY2_USER_MAP_FILE"
         fi
         exit 0 # Not an error if already gone from config
     fi

    log_info "Proceeding to delete Hysteria2 user '$username'"
    if grep -q -x -e "^${username}$" "$HY2_USER_MAP_FILE"; then
        sed -i.bak "/^${username}$/d" "$HY2_USER_MAP_FILE"; rm -f "${HY2_USER_MAP_FILE}.bak"; set_ownership_perms_map "$HY2_USER_MAP_FILE"; fi

    backup_config
    local temp_config; temp_config=$(mktemp)
    jq --arg name "$username" --arg tag "$HY2_INBOUND_TAG" \
       '(.inbounds[] | select(.tag == $tag).users) |= map(select(.name != $name))' \
       "$SINGBOX_CONFIG" > "$temp_config" || {
           log_error "jq command failed during Hysteria2 user deletion."; rm -f "$temp_config"; reload_singbox; exit 1;
       }
    mv "$temp_config" "$SINGBOX_CONFIG"; set_ownership_perms_config

    if reload_singbox; then log_info "Hysteria2 user '$username' deleted successfully.";
    else log_error "Hysteria2 user '$username' deletion failed (service reload issue)."; exit 1; fi
}

usage() {
  echo "Usage: $0 <command> [arguments...]"
  echo ""
  echo "VLESS User Management (via tag: '$VLESS_INBOUND_TAG'):"
  echo "  $0 add_vless <username>"
  echo "     Adds a new VLESS user with a generated UUID."
  echo "  $0 del_vless <username | uuid>"
  echo "     Deletes a VLESS user by their username (from map) or exact UUID."
  echo "  $0 list_vless"
  echo "     Lists VLESS users from the map file and UUIDs from Sing-Box config."
  echo ""
  echo "Hysteria2 User Management (via tag: '$HY2_INBOUND_TAG'):"
  echo "  $0 add_hy2 <username> <password>"
  echo "     Adds a new Hysteria2 user with the given username and password."
  echo "  $0 del_hy2 <username>"
  echo "     Deletes a Hysteria2 user by their username."
  echo "  $0 list_hy2"
  echo "     Lists Hysteria2 usernames from the map file and Sing-Box config."
  echo ""
  echo "Example:"
  echo "  sudo $0 add_vless my_user_vless"
  echo "  sudo $0 add_hy2 my_user_hy2 MyStr0ngP@ssw0rd"
  echo "  sudo $0 list_vless"
  echo "  sudo $0 list_hy2"
  echo "  sudo $0 del_hy2 my_user_hy2"
}

# --- Main Script Logic ---
check_root
check_deps

# Ensure map files exist with correct permissions before any operation
set_ownership_perms_map "$VLESS_USER_MAP_FILE"
set_ownership_perms_map "$HY2_USER_MAP_FILE"

# Ensure Sing-Box config file exists
if [ ! -f "$SINGBOX_CONFIG" ]; then
    log_error "Sing-Box configuration file not found at: ${SINGBOX_CONFIG}";
    exit 1;
fi

# Parse command line arguments
if [ $# -eq 0 ]; then
  usage
  exit 1
fi

COMMAND=$1
shift # Remove command from arguments, rest are passed to functions

case $COMMAND in
  add_vless)          add_vless "$@";;
  del_vless)          delete_vless "$@";;
  list_vless)         list_vless;;

  add_hy2)            add_hy2 "$@";;
  del_hy2)            delete_hy2 "$@";;
  list_hy2)           list_hy2;;
  
  *)
    log_error "Unknown command: $COMMAND"
    usage
    exit 1
    ;;
esac

exit 0 # Explicitly exit with success if command completes
