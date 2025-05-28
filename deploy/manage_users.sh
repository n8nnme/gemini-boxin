#!/bin/bash

set -euo pipefail

# Configuration
BASE_DIR="/opt/ssb"
CONFIG_DIR="$BASE_DIR/configs"
TEMPLATES_DIR="$BASE_DIR/templates"
USERS_DIR="$CONFIG_DIR/users"
SERVER_CONFIG="/etc/sing-box/config.json"
SERVER_CONF="$BASE_DIR/server.conf"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_usage() {
    echo "Usage: $0 {add|list|del|show} [username]"
    echo "Commands:"
    echo "  add <username>  - Add new user and generate client config"
    echo "  list           - List all users"
    echo "  del <username> - Delete user"
    echo "  show <username> - Show user client config"
}

# Load server configuration
load_server_config() {
    if [[ ! -f "$SERVER_CONF" ]]; then
        print_error "Server configuration not found. Run deploy.sh first."
        exit 1
    fi
    source "$SERVER_CONF"
}

# Generate secure random string
generate_random_string() {
    local length=${1:-46}
    openssl rand -base64 $((length * 3 / 4)) | tr -d '=+/\n' | cut -c1-$length
}

# Generate UUID
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# Add new user
add_user() {
    local username="$1"
    if [[ -z "$username" ]]; then
        print_error "Username required"
        exit 1
    fi

    # Check if user already exists
    local user_dir="$USERS_DIR/$username"
    if [[ -d "$user_dir" ]]; then
        print_error "User $username already exists"
        exit 1
    fi

    print_status "Adding user: $username"

    # Create user directory
    mkdir -p "$user_dir"

    # Generate user credentials
    local hysteria2_password=$(generate_random_string 46)
    local httpupgrade_path="/$(generate_random_string 47)"
    local user_uuid=$(generate_uuid)

    # Save user credentials
    cat > "$user_dir/credentials.txt" << EOF
Username: $username
UUID: $user_uuid
Hysteria2 Password: $hysteria2_password
HTTPUpgrade Path: $httpupgrade_path
Generated: $(date)
EOF

    # Generate client configuration
    sed -e "s|\${SERVER_IP}|$SERVER_IP|g" \
        -e "s|\${HOST}|$DOMAIN|g" \
        -e "s|\${HYSTERIA2_PORT}|$HYSTERIA2_PORT|g" \
        -e "s|\${VLESS_PORT}|$VLESS_PORT|g" \
        -e "s|\${BANDWIDTH_UP}|$BANDWIDTH_UP|g" \
        -e "s|\${BANDWIDTH_DOWN}|$BANDWIDTH_DOWN|g" \
        -e "s|\${HYSTERIA2_PASSWORD}|$hysteria2_password|g" \
        -e "s|\${HYSTERIA2_OBFS_PASSWORD}|$HYSTERIA2_OBFS_PASSWORD|g" \
        -e "s|\${HTTPUPGRADE_PATH}|$httpupgrade_path|g" \
        -e "s|\${USER_UUID}|$user_uuid|g" \
        -e "s|\${DEFAULT_OUTBOUND}|hy2-out|g" \
        "$TEMPLATES_DIR/client-template.json" > "$user_dir/client-config.json"

    # Update server configuration with new user
    update_server_config "$username" "$user_uuid" "$hysteria2_password" "$httpupgrade_path"

    print_status "User $username added successfully!"
    echo "Client config: $user_dir/client-config.json"
    echo "Credentials: $user_dir/credentials.txt"
}

# Update server configuration with new user
update_server_config() {
    local username="$1"
    local user_uuid="$2"
    local hysteria2_password="$3"
    local httpupgrade_path="$4"

    # Create backup
    sudo cp "$SERVER_CONFIG" "$SERVER_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"

    # Update hysteria2 users
    jq --arg name "$username" --arg password "$hysteria2_password" \
       '.inbounds[0].users += [{"name": $name, "password": $password}]' \
       "$SERVER_CONFIG" > /tmp/server_config_temp.json

    # Update vless users  
    jq --arg name "$username" --arg uuid "$user_uuid" \
       '.inbounds[1].users += [{"name": $name, "uuid": $uuid}]' \
       /tmp/server_config_temp.json > /tmp/server_config_final.json

    # Apply updated configuration
    sudo mv /tmp/server_config_final.json "$SERVER_CONFIG"
    sudo chown "$MAIN_USER:$MAIN_USER" "$SERVER_CONFIG"

    # Restart sing-box service
    sudo systemctl reload sing-box

    print_status "Server configuration updated and reloaded"
}

# List all users
list_users() {
    print_status "Listing all users:"
    
    if [[ ! -d "$USERS_DIR" ]] || [[ -z "$(ls -A "$USERS_DIR" 2>/dev/null)" ]]; then
        echo "No users found"
        return
    fi

    echo "Username | UUID | Created"
