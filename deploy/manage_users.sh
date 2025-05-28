#!/bin/bash
set -euo pipefail

BASE_DIR="/opt/ssb"
CONFIG_DIR="$BASE_DIR/configs"
TEMPLATES_DIR="$BASE_DIR/templates"
USERS_DIR="$CONFIG_DIR/users"
SERVER_CONFIG="/etc/sing-box/config.json"
SERVER_CONF="$BASE_DIR/server.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_banner() { echo -e "${BLUE}$1${NC}"; }

load_server_config() {
    if [[ ! -f "$SERVER_CONF" ]]; then
        print_error "Server configuration not found. Run deploy.sh first."
        exit 1
    fi
    source "$SERVER_CONF"
}

generate_random_string() {
    local length=${1:-46}
    openssl rand -base64 $((length * 3 / 4)) | tr -d '=+/\n' | cut -c1-$length
}

generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

add_user() {
    local username="$1"
    if [[ -z "$username" ]]; then
        print_error "Username required"
        exit 1
    fi

    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "Username can only contain letters, numbers, hyphens and underscores"
        exit 1
    fi

    local user_dir="$USERS_DIR/$username"
    if [[ -d "$user_dir" ]]; then
        print_error "User $username already exists"
        exit 1
    fi

    print_status "Adding user: $username"
    mkdir -p "$user_dir"

    local hysteria2_password=$(generate_random_string 46)
    local httpupgrade_path="/$(generate_random_string 47)"
    local user_uuid=$(generate_uuid)

    cat > "$user_dir/credentials.txt" << EOL
Username: $username
UUID: $user_uuid
Hysteria2 Password: $hysteria2_password
HTTPUpgrade Path: $httpupgrade_path
Generated: $(date)
Server: $DOMAIN
EOL

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
        "$TEMPLATES_DIR/sing-box/client-template.json" > "$user_dir/client-config.json"

    update_server_config "$username" "$user_uuid" "$hysteria2_password" "$httpupgrade_path"
    
    echo
    print_banner "=== User $username Added Successfully ==="
    echo "Client config: $user_dir/client-config.json"
    echo "Credentials: $user_dir/credentials.txt"
    echo
    echo "Download commands:"
    echo "scp root@$SERVER_IP:$user_dir/client-config.json ./"
    echo "cat $user_dir/client-config.json"
}

update_server_config() {
    local username="$1" user_uuid="$2" hysteria2_password="$3" httpupgrade_path="$4"

    cp "$SERVER_CONFIG" "$SERVER_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"

    jq --arg name "$username" --arg password "$hysteria2_password" \
       '.inbounds[0].users += [{"name": $name, "password": $password}]' \
       "$SERVER_CONFIG" > /tmp/server_temp.json

    jq --arg name "$username" --arg uuid "$user_uuid" \
       '.inbounds[1].users += [{"name": $name, "uuid": $uuid}]' \
       /tmp/server_temp.json > /tmp/server_final.json

    mv /tmp/server_final.json "$SERVER_CONFIG"
    chown "$MAIN_USER:$MAIN_USER" "$SERVER_CONFIG"
    
    if systemctl reload sing-box; then
        print_status "Server configuration updated and reloaded"
    else
        print_error "Failed to reload sing-box service"
        exit 1
    fi
}

list_users() {
    print_banner "=== User List ==="
    if [[ ! -d "$USERS_DIR" ]] || [[ -z "$(ls -A "$USERS_DIR" 2>/dev/null)" ]]; then
        echo "No users found"
        return
    fi

    printf "%-15s %-36s %-20s %-15s\n" "Username" "UUID" "Created" "Status"
    printf "%-15s %-36s %-20s %-15s\n" "--------" "----" "-------" "------"
    
    for user_dir in "$USERS_DIR"/*; do
        if [[ -d "$user_dir" ]]; then
            local username=$(basename "$user_dir")
            local cred_file="$user_dir/credentials.txt"
            
            if [[ -f "$cred_file" ]]; then
                local uuid=$(grep "UUID:" "$cred_file" | cut -d' ' -f2)
                local created=$(grep "Generated:" "$cred_file" | cut -d' ' -f2 | cut -d' ' -f1)
                local status="Active"
                
                if ! jq -e --arg uuid "$uuid" '.inbounds[1].users[] | select(.uuid == $uuid)' "$SERVER_CONFIG" >/dev/null 2>&1; then
                    status="Inactive"
                fi
                
                printf "%-15s %-36s %-20s %-15s\n" "$username" "$uuid" "$created" "$status"
            fi
        fi
    done
    echo
    echo "Total users: $(ls -1 "$USERS_DIR" 2>/dev/null | wc -l)"
}

del_user() {
    local username="$1"
    if [[ -z "$username" ]]; then
        print_error "Username required"
        exit 1
    fi

    local user_dir="$USERS_DIR/$username"
    if [[ ! -d "$user_dir" ]]; then
        print_error "User $username does not exist"
        exit 1
    fi

    local user_uuid=""
    if [[ -f "$user_dir/credentials.txt" ]]; then
        user_uuid=$(grep "UUID:" "$user_dir/credentials.txt" | cut -d' ' -f2)
    fi

    if [[ -n "$user_uuid" ]]; then
        cp "$SERVER_CONFIG" "$SERVER_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
        
        jq --arg name "$username" \
           '.inbounds[0].users = [.inbounds[0].users[] | select(.name != $name)]' \
           "$SERVER_CONFIG" > /tmp/server_temp.json

        jq --arg uuid "$user_uuid" \
           '.inbounds[1].users = [.inbounds[1].users[] | select(.uuid != $uuid)]' \
           /tmp/server_temp.json > /tmp/server_final.json

        mv /tmp/server_final.json "$SERVER_CONFIG"
        chown "$MAIN_USER:$MAIN_USER" "$SERVER_CONFIG"
        
        if systemctl reload sing-box; then
            print_status "User removed from server configuration"
        else
            print_error "Failed to reload sing-box service"
        fi
    fi

    rm -rf "$user_dir"
    print_status "User $username deleted successfully"
}

show_user() {
    local username="$1"
    if [[ -z "$username" ]]; then
        print_error "Username required"
        exit 1
    fi

    local user_dir="$USERS_DIR/$username"
    if [[ ! -d "$user_dir" ]]; then
        print_error "User $username does not exist"
        exit 1
    fi

    print_banner "=== User $username Configuration ==="
    echo "Client Config: $user_dir/client-config.json"
    echo "Credentials: $user_dir/credentials.txt"
    echo
    
    if [[ -f "$user_dir/credentials.txt" ]]; then
        echo "=== Credentials ==="
        cat "$user_dir/credentials.txt"
        echo
    fi
    
    echo "=== Download Commands ==="
    echo "scp root@$SERVER_IP:$user_dir/client-config.json ./$username-config.json"
    echo "wget -O $username-config.json http://$SERVER_IP/configs/users/$username/client-config.json"
    echo
    
    echo "=== QR Code (if available) ==="
    if command -v qrencode &> /dev/null; then
        local config_content=$(cat "$user_dir/client-config.json" | base64 -w 0)
        echo "sing-box://$config_content" | qrencode -t UTF8
    else
        echo "Install qrencode to generate QR codes: apt install qrencode"
    fi
}

status() {
    print_banner "=== System Status ==="
    
    echo "Sing-box Service:"
    if systemctl is-active --quiet sing-box; then
        echo "  Status: Running"
        echo "  Uptime: $(systemctl show sing-box --property=ActiveEnterTimestamp --value | xargs -I {} date -d {} +'%Y-%m-%d %H:%M:%S')"
    else
        echo "  Status: Not Running"
    fi
    
    echo
    echo "Fail2ban Status:"
    if systemctl is-active --quiet fail2ban; then
        echo "  Status: Running"
        fail2ban-client status 2>/dev/null | grep "Jail list:" || echo "  No active jails"
    else
        echo "  Status: Not Running"
    fi
    
    echo
    echo "Certificate Status:"
    if [[ -f "/etc/letsencrypt/live/$DOMAIN/cert.pem" ]]; then
        local cert_expiry=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/$DOMAIN/cert.pem" | cut -d= -f2)
        echo "  Certificate expires: $cert_expiry"
    else
        echo "  No certificate found"
    fi
    
    echo
    echo "Firewall Status:"
    ufw status | head -3
    
    echo
    echo "Server Configuration:"
    echo "  Domain: $DOMAIN"
    echo "  Server IP: $SERVER_IP"
    echo "  Hysteria2 Port: $HYSTERIA2_PORT"
    echo "  VLESS Port: $VLESS_PORT"
    
    echo
    echo "Active Users: $(ls -1 "$USERS_DIR" 2>/dev/null | wc -l)"
}

backup_users() {
    local backup_file="$CONFIG_DIR/users-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
    
    if [[ -d "$USERS_DIR" ]]; then
        tar -czf "$backup_file" -C "$CONFIG_DIR" users
        print_status "Users backed up to: $backup_file"
    else
        print_error "No users directory found"
        exit 1
    fi
}

restore_users() {
    local backup_file="$1"
    
    if [[ -z "$backup_file" ]]; then
        print_error "Backup file required"
        exit 1
    fi
    
    if [[ ! -f "$backup_file" ]]; then
        print_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    print_warning "This will overwrite existing users. Continue? (y/N)"
    read -r response
    if [[ "$response" != "y" && "$response" != "Y" ]]; then
        print_status "Restore cancelled"
        exit 0
    fi
    
    tar -xzf "$backup_file" -C "$CONFIG_DIR"
    print_status "Users restored from: $backup_file"
    print_status "Run 'rebuild-server-config' to update server configuration"
}

rebuild_server_config() {
    print_status "Rebuilding server configuration from user data..."
    
    cp "$SERVER_CONFIG" "$SERVER_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
    
    jq '.inbounds[0].users = [] | .inbounds[1].users = []' "$SERVER_CONFIG" > /tmp/server_clean.json
    
    for user_dir in "$USERS_DIR"/*; do
        if [[ -d "$user_dir" ]]; then
            local username=$(basename "$user_dir")
            local cred_file="$user_dir/credentials.txt"
            
            if [[ -f "$cred_file" ]]; then
                local uuid=$(grep "UUID:" "$cred_file" | cut -d' ' -f2)
                local hysteria2_password=$(grep "Hysteria2 Password:" "$cred_file" | cut -d' ' -f3)
                
                jq --arg name "$username" --arg password "$hysteria2_password" \
                   '.inbounds[0].users += [{"name": $name, "password": $password}]' \
                   /tmp/server_clean.json > /tmp/server_temp.json
                
                jq --arg name "$username" --arg uuid "$uuid" \
                   '.inbounds[1].users += [{"name": $name, "uuid": $uuid}]' \
                   /tmp/server_temp.json > /tmp/server_clean.json
            fi
        fi
    done
    
    mv /tmp/server_clean.json "$SERVER_CONFIG"
    chown "$MAIN_USER:$MAIN_USER" "$SERVER_CONFIG"
    
    if systemctl reload sing-box; then
        print_status "Server configuration rebuilt and reloaded"
    else
        print_error "Failed to reload sing-box service"
    fi
}

print_usage() {
    cat << EOF
Usage: $0 <command> [options]

Commands:
  add <username>          Add new user
  list                    List all users
  del <username>          Delete user
  show <username>         Show user configuration
  status                  Show system status
  backup                  Backup all users
  restore <backup-file>   Restore users from backup
  rebuild-server-config   Rebuild server config from user data

Examples:
  $0 add alice
  $0 show alice
  $0 del alice
  $0 backup
  $0 restore users-backup-20250101_120000.tar.gz
EOF
}

load_server_config
mkdir -p "$USERS_DIR"

case "${1:-}" in
    add) add_user "${2:-}" ;;
    list) list_users ;;
    del) del_user "${2:-}" ;;
    show) show_user "${2:-}" ;;
    status) status ;;
    backup) backup_users ;;
    restore) restore_users "${2:-}" ;;
    rebuild-server-config) rebuild_server_config ;;
    *) print_usage; exit 1 ;;
esac
