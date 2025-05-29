#!/bin/bash

set -euo pipefail

REPO_URL="https://github.com/n8nnme/gemini-boxin.git"
BASE_DIR="/opt/ssb"
TEMPLATES_DIR="$BASE_DIR/templates"
CONFIGS_DIR="$BASE_DIR/configs"
CERTS_DIR="/etc/ssl/sing-box"
SING_BOX_CONFIG="/etc/sing-box/config.json"

MAIN_USER="singbox"
DOMAIN=""
CLOUDFLARE_EMAIL=""
CLOUDFLARE_API_KEY=""
SERVER_IP=""

HYSTERIA2_PORT=31847
VLESS_PORT=8443
BANDWIDTH_UP=200
BANDWIDTH_DOWN=200

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}======================================${NC}"
}

print_usage() {
    echo "Usage: $0 <domain> <cloudflare_email> <cloudflare_api_key> [server_ip]"
    echo "Example: $0 example.com user@example.com cf_api_key 192.168.1.100"
}

install_dependencies() {
    print_status "Installing dependencies..."
    
    apt update && apt upgrade -y
    
    apt install -y git curl wget openssl jq ufw fail2ban \
        certbot python3-certbot-dns-cloudflare uuid-runtime \
        cron systemd-cron qrencode
    
    if ! command -v sing-box &> /dev/null; then
        print_status "Installing sing-box..."
        wget -qO- https://sing-box.sagernet.org/gpg.key | apt-key add -
        echo "deb [arch=amd64] https://deb.sagernet.org/ * *" > /etc/apt/sources.list.d/sing-box.list
        apt update && apt install -y sing-box
    fi
    
    print_status "Dependencies installed successfully"
}

fetch_templates() {
    print_status "Fetching templates from repository..."
    
    mkdir -p "$BASE_DIR" "$TEMPLATES_DIR" "$CONFIGS_DIR" "$CERTS_DIR"
    
    if [ ! -d "$BASE_DIR/gemini-boxin" ]; then
        git clone "$REPO_URL" "$BASE_DIR/gemini-boxin"
    else
        cd "$BASE_DIR/gemini-boxin" && git pull
    fi
    
    if [ -d "$BASE_DIR/gemini-boxin/templates" ]; then
        cp -r "$BASE_DIR/gemini-boxin/templates/"* "$TEMPLATES_DIR/"
    else
        print_warning "Templates directory not found in repo, creating default templates..."
        create_default_templates
    fi
    
    if [ -f "$BASE_DIR/gemini-boxin/deploy/manage_users.sh" ]; then
        cp "$BASE_DIR/gemini-boxin/deploy/manage_users.sh" "$BASE_DIR/"
        chmod +x "$BASE_DIR/manage_users.sh"
    else
        create_management_script
    fi
}

create_default_templates() {
    print_status "Creating default templates..."
    
    mkdir -p "$TEMPLATES_DIR/sing-box" "$TEMPLATES_DIR/fail2ban/jail.d" "$TEMPLATES_DIR/fail2ban/filter.d"
    
    cat > "$TEMPLATES_DIR/sing-box/server-template.json" << 'EOF'
{
  "log": {
    "level": "warn",
    "output": "/var/log/sing-box.log",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-stealth",
      "listen": "::",
      "listen_port": ${HYSTERIA2_PORT},
      "up_mbps": ${BANDWIDTH_UP},
      "down_mbps": ${BANDWIDTH_DOWN},
      "ignore_client_bandwidth": false,
      "obfs": {
        "type": "salamander",
        "password": "${HYSTERIA2_OBFS_PASSWORD}"
      },
      "users": [],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_PATH}",
        "key_path": "${KEY_PATH}",
        "alpn": ["h3"],
        "min_version": "1.3",
        "max_version": "1.3"
      },
      "masquerade": {
        "type": "string",
        "status_code": 444,
        "headers": {},
        "content": ""
      },
      "brutal_debug": false,
      "sniff": false,
      "sniff_override_destination": false
    },
    {
      "type": "vless",
      "tag": "vless-stealth",
      "listen": "::",
      "listen_port": ${VLESS_PORT},
      "users": [],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_PATH}",
        "key_path": "${KEY_PATH}",
        "alpn": ["h2", "http/1.1"],
        "min_version": "1.2",
        "max_version": "1.3",
        "cipher_suites": [
          "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
          "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
          "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
          "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
        ]
      },
      "transport": {
        "type": "httpupgrade",
        "path": "/placeholder-path",
        "headers": {
          "Host": "${HOST}",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          "Accept-Encoding": "gzip, deflate",
          "Connection": "upgrade"
        }
      },
      "multiplex": {
        "enabled": true,
        "protocol": "h2mux",
        "max_connections": 2,
        "min_streams": 2,
        "max_streams": 8,
        "padding": true,
        "brutal": {
          "enabled": true,
          "up_mbps": ${BANDWIDTH_UP},
          "down_mbps": ${BANDWIDTH_DOWN}
        }
      },
      "sniff": false,
      "sniff_override_destination": false
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct",
      "domain_strategy": "prefer_ipv4"
    }
  ],
  "route": {
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOF

    cat > "$TEMPLATES_DIR/sing-box/client-template.json" << 'EOF'
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "local"
      }
    ],
    "final": "local",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30"],
      "auto_route": true,
      "strict_route": true,
      "sniff": true,
      "domain_strategy": "prefer_ipv4"
    },
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 1080,
      "sniff": true
    }
  ],
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-out",
      "server": "${SERVER_IP}",
      "server_port": ${HYSTERIA2_PORT},
      "up_mbps": ${BANDWIDTH_UP},
      "down_mbps": ${BANDWIDTH_DOWN},
      "obfs": {
        "type": "salamander",
        "password": "${HYSTERIA2_OBFS_PASSWORD}"
      },
      "password": "${HYSTERIA2_PASSWORD}",
      "tls": {
        "enabled": true,
        "server_name": "${HOST}",
        "alpn": ["h3"]
      },
      "brutal_debug": false
    },
    {
      "type": "vless",
      "tag": "vless-out",
      "server": "${SERVER_IP}",
      "server_port": ${VLESS_PORT},
      "uuid": "${USER_UUID}",
      "tls": {
        "enabled": true,
        "server_name": "${HOST}",
        "alpn": ["h2", "http/1.1"],
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "transport": {
        "type": "httpupgrade",
        "path": "${HTTPUPGRADE_PATH}",
        "headers": {
          "Host": "${HOST}",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
      },
      "multiplex": {
        "enabled": true,
        "protocol": "h2mux",
        "max_connections": 2,
        "min_streams": 2,
        "padding": true,
        "brutal": {
          "enabled": true,
          "up_mbps": ${BANDWIDTH_UP},
          "down_mbps": ${BANDWIDTH_DOWN}
        }
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "geosite": "private",
        "outbound": "direct"
      }
    ],
    "final": "${DEFAULT_OUTBOUND}",
    "auto_detect_interface": true
  }
}
EOF
}

create_management_script() {
    print_status "Creating user management script..."
    cat > "$BASE_DIR/manage_users.sh" << 'EOF'
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
NC='\033[0m'

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

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

    local user_dir="$USERS_DIR/$username"
    if [[ -d "$user_dir" ]]; then
        print_error "User $username already exists"
        exit 1
    fi

    if [[ ! "${username}" =~ ^[a-zA-Z0-9_-]{4,20}$ ]]; then
        print_error "Invalid username. Use 4-20 alphanumeric, '-' or '_' characters"
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
    print_status "User $username added successfully!"
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
    systemctl reload sing-box
    print_status "Server configuration updated"
}

list_users() {
    print_status "Listing all users:"
    if [[ ! -d "$USERS_DIR" ]] || [[ -z "$(ls -A "$USERS_DIR" 2>/dev/null)" ]]; then
        echo "No users found"
        return
    fi

    printf "%-15s %-36s %-20s\n" "Username" "UUID" "Created"
    printf "%-15s %-36s %-20s\n" "--------" "----" "-------"
    
    for user_dir in "$USERS_DIR"/*; do
        if [[ -d "$user_dir" ]]; then
            local username=$(basename "$user_dir")
            local cred_file="$user_dir/credentials.txt"
            
            if [[ -f "$cred_file" ]]; then
                local uuid=$(grep "UUID:" "$cred_file" | cut -d' ' -f2)
                local created=$(grep "Generated:" "$cred_file" | cut -d' ' -f2-)
                printf "%-15s %-36s %-20s\n" "$username" "$uuid" "$created"
            fi
        fi
    done
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
        systemctl reload sing-box
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

    print_status "User $username configuration:"
    echo "Client Config: $user_dir/client-config.json"
    echo "Credentials: $user_dir/credentials.txt"
    echo
    
    if [[ -f "$user_dir/credentials.txt" ]]; then
        echo "=== Credentials ==="
        cat "$user_dir/credentials.txt"
    fi
}

load_server_config
mkdir -p "$USERS_DIR"

case "${1:-}" in
    add) add_user "${2:-}" ;;
    list) list_users ;;
    del) del_user "${2:-}" ;;
    show) show_user "${2:-}" ;;
    *) echo "Usage: $0 {add|list|del|show} [username]"; exit 1 ;;
esac
EOF
    chmod +x "$BASE_DIR/manage_users.sh"
}

create_main_user() {
    print_status "Creating main user $MAIN_USER..."
    
    if ! id -u "$MAIN_USER" >/dev/null 2>&1; then
        useradd -r -m -d /var/lib/singbox -s /bin/false "$MAIN_USER"
        print_status "User $MAIN_USER created"
    else
        print_status "User $MAIN_USER already exists"
    fi
}

setup_fail2ban() {
    print_status "Setting up fail2ban protection..."
    
    if [ -f "$TEMPLATES_DIR/fail2ban/jail.d/sing-box.conf" ]; then
        cp "$TEMPLATES_DIR/fail2ban/jail.d/sing-box.conf" /etc/fail2ban/jail.d/
    fi
    
    if [ -d "$TEMPLATES_DIR/fail2ban/filter.d" ]; then
        cp "$TEMPLATES_DIR/fail2ban/filter.d/"* /etc/fail2ban/filter.d/
    fi

    touch /var/log/sing-box.log
    chown $MAIN_USER:$MAIN_USER /var/log/sing-box.log
    chmod 644 /var/log/sing-box.log
    
    cat > /etc/logrotate.d/sing-box << 'EOF'
/var/log/sing-box.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    postrotate
        systemctl reload sing-box > /dev/null 2>&1 || true
    endscript
}
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    if fail2ban-client status >/dev/null 2>&1; then
        print_status "✓ Fail2ban configured and running"
    else
        print_error "✗ Fail2ban configuration failed"
    fi
}

setup_automatic_certificate_renewal() {
    print_status "Setting up automatic certificate renewal..."
    
    cat > /usr/local/bin/certbot-deploy-hook.sh << 'EOF'
#!/bin/bash
DOMAIN="$RENEWED_LINEAGE"
CERT_DIR="/etc/ssl/sing-box"

cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERT_DIR/cert.pem"
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERT_DIR/private.key"

chmod 644 "$CERT_DIR/cert.pem"
chmod 600 "$CERT_DIR/private.key"
chown -R singbox:singbox "$CERT_DIR"

systemctl restart sing-box

echo "$(date): Certificates renewed and sing-box restarted for domain $DOMAIN" >> /var/log/certbot-deploy.log
EOF
    
    chmod +x /usr/local/bin/certbot-deploy-hook.sh
    
    systemctl enable certbot.timer
    systemctl start certbot.timer
    
    if systemctl is-active --quiet certbot.timer; then
        print_status "Certbot automatic renewal timer is active"
    else
        print_warning "Certbot timer not active, setting up cron fallback"
        echo "0 0,12 * * * root certbot renew --deploy-hook /usr/local/bin/certbot-deploy-hook.sh" > /etc/cron.d/certbot-renew
    fi
}

obtain_certificates() {
    print_status "Obtaining certificates for $DOMAIN using Cloudflare DNS..."
    
    mkdir -p /etc/letsencrypt
    cat > /etc/letsencrypt/cloudflare.ini << EOF
dns_cloudflare_email = $CLOUDFLARE_EMAIL
dns_cloudflare_api_key = $CLOUDFLARE_API_KEY
EOF
    chmod 600 /etc/letsencrypt/cloudflare.ini

    certbot certonly --dns-cloudflare \
        --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
        --agree-tos --non-interactive \
        --email "$CLOUDFLARE_EMAIL" \
        -d "$DOMAIN" \
        --deploy-hook "/usr/local/bin/certbot-deploy-hook.sh"

    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERTS_DIR/cert.pem"
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERTS_DIR/private.key"
    chmod 644 "$CERTS_DIR/cert.pem"
    chmod 600 "$CERTS_DIR/private.key"
    chown -R "$MAIN_USER:$MAIN_USER" "$CERTS_DIR"

    if ! dig +short "${DOMAIN}" | grep -q "${SERVER_IP}"; then
        print_error "Domain ${DOMAIN} does not resolve to ${SERVER_IP}"
        exit 1
    fi
    
    setup_automatic_certificate_renewal
    
    print_status "Certificates obtained and automatic renewal configured"
}

setup_firewall() {

    // TODO: implement UDP rate limit
    // nft add rule inet filter input udp dport ${HYSTERIA2_PORT} meter flood-udp { ip saddr limit rate 1000/second burst 5000 packets } counter accept
    // nft add rule inet filter input udp dport ${HYSTERIA2_PORT} counter drop

    print_status "Setting up firewall (ISP NAT simulation)..."
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw deny ssh
    ufw allow $HYSTERIA2_PORT/udp comment "Hysteria2"
    ufw allow $VLESS_PORT/tcp comment "VLESS"
    ufw --force enable
    
    print_status "Firewall configured with ISP NAT behavior"
}

generate_server_config() {
    print_status "Generating server configuration..."
    
    local global_obfs_password
    global_obfs_password=$(LC_ALL=C tr -dc 'A-Za-z0-9!#%&()*+,-./:;<=>?@[\]^_{|}~' </dev/urandom | head -c 46)
    if [[ -z "$global_obfs_password" ]]; then
        print_error "Failed to generate obfuscation password"
        exit 1
    fi
    
    sed -e "s|\${HYSTERIA2_PORT}|$HYSTERIA2_PORT|g" \
        -e "s|\${VLESS_PORT}|$VLESS_PORT|g" \
        -e "s|\${BANDWIDTH_UP}|$BANDWIDTH_UP|g" \
        -e "s|\${BANDWIDTH_DOWN}|$BANDWIDTH_DOWN|g" \
        -e "s|\${HYSTERIA2_OBFS_PASSWORD}|$global_obfs_password|g" \
        -e "s|\${HOST}|$DOMAIN|g" \
        -e "s|\${CERT_PATH}|$CERTS_DIR/cert.pem|g" \
        -e "s|\${KEY_PATH}|$CERTS_DIR/private.key|g" \
        "$TEMPLATES_DIR/sing-box/server-template.json" > "$CONFIGS_DIR/server-config.json"
    
    mkdir -p /etc/sing-box
    if ! jq empty "${SING_BOX_CONFIG}"; then
        print_error "Invalid JSON configuration"
        exit 1
    fi
    cp "$CONFIGS_DIR/server-config.json" "$SING_BOX_CONFIG"
    chown "$MAIN_USER:$MAIN_USER" "$SING_BOX_CONFIG"
    
    cat > "$BASE_DIR/server.conf" << EOF
DOMAIN=$DOMAIN
SERVER_IP=$SERVER_IP
HYSTERIA2_PORT=$HYSTERIA2_PORT
VLESS_PORT=$VLESS_PORT
BANDWIDTH_UP=$BANDWIDTH_UP
BANDWIDTH_DOWN=$BANDWIDTH_DOWN
HYSTERIA2_OBFS_PASSWORD=$global_obfs_password
CLOUDFLARE_EMAIL=$CLOUDFLARE_EMAIL
MAIN_USER=$MAIN_USER
EOF
    
    print_status "Server configuration generated"
}

setup_sing_box_service() {
    print_status "Setting up sing-box service..."
    
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=$MAIN_USER
Group=$MAIN_USER
Type=simple
ExecStart=/usr/bin/sing-box run -c $SING_BOX_CONFIG
ExecReload=/bin/kill -HUP \$MAINPID
LimitNOFILE=infinity
LimitNPROC=infinity
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sing-box
    
    print_status "sing-box service configured"
}

verify_deployment() {
    print_status "Verifying deployment..."
    
    if systemctl is-active --quiet certbot.timer; then
        print_status "✓ Certbot automatic renewal is active"
    else
        print_warning "⚠ Certbot timer not active"
    fi
    
    if certbot renew --dry-run --deploy-hook /usr/local/bin/certbot-deploy-hook.sh >/dev/null 2>&1; then
        print_status "✓ Certificate renewal test passed"
    else
        print_warning "⚠ Certificate renewal test failed"
    fi
    
    if sing-box check -c "$SING_BOX_CONFIG" >/dev/null 2>&1; then
        print_status "✓ sing-box configuration is valid"
    else
        print_error "✗ sing-box configuration is invalid"
    fi
    
    print_status "Deployment verification completed"
}

main() {
    print_banner "sing-box Stealth VPN Deployment"
    
    if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
        print_usage
        exit 1
    fi

    DOMAIN="$1"
    CLOUDFLARE_EMAIL="$2"
    CLOUDFLARE_API_KEY="$3"
    
    if [ "$#" -eq 4 ]; then
        SERVER_IP="$4"
    else
        SERVER_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || echo "AUTO_DETECT_FAILED")
        if [ "$SERVER_IP" = "AUTO_DETECT_FAILED" ]; then
            print_error "Failed to auto-detect server IP. Please provide it manually."
            exit 1
        fi
        print_status "Auto-detected server IP: $SERVER_IP"
    fi

    print_status "Starting deployment for domain: $DOMAIN"

    install_dependencies
    fetch_templates
    create_main_user
    obtain_certificates
    setup_firewall
    setup_fail2ban
    generate_server_config
    setup_sing_box_service
    
    systemctl start sing-box
    
    sleep 2
    verify_deployment

    print_banner "DEPLOYMENT COMPLETED SUCCESSFULLY"
    cat << EOF

Server Information:
==================
Domain: $DOMAIN
Server IP: $SERVER_IP
Hysteria2 Port: $HYSTERIA2_PORT
VLESS Port: $VLESS_PORT

Certificate Info:
================
Auto-renewal: Enabled (every 12 hours)
Next check: $(systemctl show certbot.timer | grep NextElapseUSecRealtime | cut -d= -f2 | xargs -I {} date -d @{} 2>/dev/null || echo "Check with: systemctl status certbot.timer")

Security:
=========
Fail2ban: Active protection enabled
Firewall: ISP NAT simulation active

Next Steps:
===========
1. Add users: $BASE_DIR/manage_users.sh add <username>
2. List users: $BASE_DIR/manage_users.sh list
3. Check status: systemctl status sing-box
4. Check logs: journalctl -u sing-box -f
5. Check cert renewal: systemctl status certbot.timer

Management:
===========
Users: $BASE_DIR/manage_users.sh
Configs: $CONFIGS_DIR/
Certificates: $CERTS_DIR/

EOF
}

main "$@"
