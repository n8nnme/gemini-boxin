#!/bin/bash

# ==============================================================================
# Deploy Secure Proxy Platform (HAProxy, Sing-Box, Flask Subscription App)
#
# Version: 1.9 (Random initial Hy2 username, simplified Hy2 user add, direct Hy2 listen)
# Author: AI Assistant & User
# Date: $(date +%Y-%m-%d)
# ==============================================================================

# --- Script Setup ---
set -uo pipefail # Exit on unset variables, error in pipelines. -e managed per function.
# set -x # Uncomment for detailed debugging

# --- Determine Project Root ---
SCRIPT_DIR_ABS="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR_ABS")" # Assumes this script is in a 'scripts' or similar subdir of project root

# --- Helper Functions ---
log_info() { echo "[INFO] $(date --iso-8601=seconds) - $1"; }
log_error() { echo "[ERROR] $(date --iso-8601=seconds) - $1" >&2; }
log_warn() { echo "[WARN] $(date --iso-8601=seconds) - $1"; }

check_command() {
    if ! command -v "$1" &>/dev/null; then
        log_error "$1 command not found. Please install required dependencies."
        exit 1
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (or using sudo)."
        exit 1
    fi
}

generate_random_string() {
    local length="${1:-32}"
    local random_data
    local result

    if command -v openssl &>/dev/null; then
        # Generate more bytes than needed to account for base64/hex encoding expansion
        random_data=$(openssl rand -hex $((length * 2)) 2>/dev/null | tr -dc 'a-zA-Z0-9' 2>/dev/null | fold -w "$length" 2>/dev/null | head -n 1)
        if [[ -n "$random_data" ]] && [[ ${#random_data} -ge "$((length / 2))" ]]; then # Check if we got something substantial
            echo "$random_data" | head -c "$length" # Ensure exact length
            return 0
        else
            log_warn "openssl rand method for generate_random_string failed or produced short string. Falling back."
        fi
    fi

    log_info "generate_random_string: Using /dev/urandom fallback for length $length"
    result=$(
        ( # Start subshell
            trap '' PIPE # Ignore SIGPIPE for commands in this subshell
            LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w "$length" | head -n 1
        ) # End subshell
    )
    local subshell_status=$?

    if [[ -z "$result" ]] || { [[ "$subshell_status" -ne 0 ]] && [[ "$subshell_status" -ne 141 ]]; }; then
        log_error "generate_random_string (/dev/urandom) failed to produce output (length: $length, status: $subshell_status)"
        return 1
    fi
    echo "$result"
    return 0
}

generate_urlsafe_base64() {
    local input_string="$1"
    local result
    if [[ -z "$input_string" ]]; then log_error "generate_urlsafe_base64 received empty input."; return 1; fi
    result=$( (trap '' PIPE; echo -n "$input_string" | base64 | tr -d '=' | tr '/+' '_-') )
    local subshell_status=$?
    if [[ -z "$result" ]] || { [[ "$subshell_status" -ne 0 ]] && [[ "$subshell_status" -ne 141 ]]; }; then
        log_error "generate_urlsafe_base64 failed for input (status: $subshell_status): $input_string"; return 1;
    fi
    echo "$result"; return 0
}

_cleanup_resources() {
    log_info "Performing resource cleanup..."
    if [ -n "${CLOUDFLARE_INI_TEMP:-}" ] && [ -f "${CLOUDFLARE_INI_TEMP}" ]; then
        rm -f "${CLOUDFLARE_INI_TEMP}"
        log_info "Removed temporary file: ${CLOUDFLARE_INI_TEMP}"
    fi
}

cleanup_exit() {
    local exit_code="${1:-1}" # Default to 1 if no exit code is provided
    _cleanup_resources
    log_info "Exiting script (Code: ${exit_code})."
    if [[ "$exit_code" -eq 141 ]]; then log_error "Script terminated with SIGPIPE (141). This often indicates an issue with a command in a pipeline.";
    elif [[ "$exit_code" -ne 0 ]]; then log_error "Script terminated due to an error (Code: $exit_code)."; fi
    exit "${exit_code}"
}
# Trap EXIT signal to ensure cleanup runs, and other common termination signals
trap 'cleanup_exit $?' EXIT
trap 'cleanup_exit 130' SIGHUP SIGINT SIGQUIT SIGTERM # Common termination signals

# --- Configuration Variables (Defaults & Placeholders) ---
MAIN_DOMAIN="" SUBSCRIPTION_DOMAIN="" CLOUDFLARE_EMAIL=""
CLOUDFLARE_API_TOKEN="" CLOUDFLARE_API_KEY=""
HYSTERIA2_PORT="31216" VLESS_HTTPUPGRADE_PORT="8443" SUBSCRIPTION_SITE_PORT="443"
SINGBOX_VLESS_LISTEN_PORT="10001" # For HAProxy backend
SUBSCRIPTION_APP_LISTEN_PORT="5000"
VLESS_UUID_INITIAL="" VLESS_PATH="" HYSTERIA2_PASSWORD="" HYSTERIA2_OBFS_PASSWORD="" INITIAL_HY2_USERNAME="" # Will be generated
INITIAL_HY2_USERNAME_PREFIX="hy2u_" # Prefix for the generated initial Hysteria2 username
SUBSCRIPTION_SECRET_STRING="" SUBSCRIPTION_BASE64_PATH="" API_BASE64_PATH_PREFIX=""
HAPROXY_CERT_DIR="/etc/haproxy/certs" LETSENCRYPT_LIVE_DIR="/etc/letsencrypt/live"
SINGBOX_INSTALL_DIR="/usr/local/bin" SINGBOX_CONFIG_DIR="/etc/sing-box"
SINGBOX_CERT_DIR="/etc/sing-box/certs"
# Map file paths used by manage_proxy_users.sh (defined here for consistency, not directly used by this script)
SINGBOX_VLESS_USER_MAP_FILE="/etc/sing-box/vless_user_map.txt"
SINGBOX_HY2_USER_MAP_FILE="/etc/sing-box/hy2_user_map.txt"
SINGBOX_BACKUP_DIR="/etc/sing-box/backups" SUBSCRIPTION_APP_DIR="/var/www/subscription_app"
MANAGEMENT_SCRIPT_PATH="/usr/local/sbin/manage_proxy_users"
CLOUDFLARE_INI_TEMP="${SCRIPT_DIR_ABS}/cloudflare.ini.deployscript.$$" # Temp file in script dir
FAIL2BAN_MAXRETRY=5 FAIL2BAN_FINDTIME="10m" FAIL2BAN_BANTIME="1h"
SINGBOX_USER="singbox" SINGBOX_GROUP="singbox"
SUBAPP_USER="subapp" SUBAPP_GROUP="subapp"
HAPROXY_USER="haproxy" HAPROXY_GROUP="haproxy"

# --- Paths to Template Files ---
TEMPLATE_HAPROXY_CFG="${PROJECT_ROOT}/config_templates/haproxy/haproxy.cfg.template" # HAProxy config, no Hysteria2
TEMPLATE_SINGBOX_SERVICE="${PROJECT_ROOT}/config_templates/systemd/sing-box.service.template"
TEMPLATE_SUBAPP_SERVICE="${PROJECT_ROOT}/config_templates/systemd/subscription-app.service.template"
TEMPLATE_FAIL2BAN_FILTER="${PROJECT_ROOT}/config_templates/fail2ban/filter.d/haproxy-custom.conf"
TEMPLATE_FAIL2BAN_JAIL="${PROJECT_ROOT}/config_templates/fail2ban/jail.d/haproxy-custom.conf"
TEMPLATE_SINGBOX_JSON="${PROJECT_ROOT}/config_templates/sing-box/config.json.template" # v1.6 with empty Hy2 users array
TEMPLATE_CERTBOT_HOOK="${PROJECT_ROOT}/config_templates/certbot/renewal-hook.sh.template"
SOURCE_FLASK_APP_PY="${PROJECT_ROOT}/services/subscription_app/app.py"
SOURCE_FLASK_INDEX_HTML="${PROJECT_ROOT}/services/subscription_app/templates/index.html"
SOURCE_FLASK_STATIC_README="${PROJECT_ROOT}/services/subscription_app/static/README.md"
SOURCE_MANAGE_USERS_SCRIPT="${PROJECT_ROOT}/scripts/manage_proxy_users.sh" # Expected v2.2

# --- Helper Function for Processing Templates ---
process_template() {
    local template_file="$1"; local output_file="$2"; local temp_processed_file; local var_name
    if [ ! -f "$template_file" ]; then log_error "Template file not found: $template_file"; return 1; fi
    temp_processed_file=$(mktemp) || { log_error "Failed to create temp file."; return 1; }
    cp "$template_file" "$temp_processed_file" || { log_error "Failed to copy template to $temp_processed_file"; rm -f "$temp_processed_file"; return 1; }

    local vars_to_substitute=(
        MAIN_DOMAIN SUBSCRIPTION_DOMAIN CLOUDFLARE_EMAIL
        HYSTERIA2_PORT HYSTERIA2_PASSWORD HYSTERIA2_OBFS_PASSWORD # INITIAL_HY2_USERNAME not typically in templates
        VLESS_HTTPUPGRADE_PORT SUBSCRIPTION_SITE_PORT
        SINGBOX_VLESS_LISTEN_PORT SUBSCRIPTION_APP_LISTEN_PORT
        VLESS_UUID_INITIAL VLESS_PATH
        SUBSCRIPTION_BASE64_PATH API_BASE64_PATH_PREFIX
        HAPROXY_CERT_DIR LETSENCRYPT_LIVE_DIR
        SINGBOX_INSTALL_DIR SINGBOX_CONFIG_DIR SINGBOX_CERT_DIR SUBSCRIPTION_APP_DIR
        FAIL2BAN_MAXRETRY FAIL2BAN_FINDTIME FAIL2BAN_BANTIME
        SINGBOX_USER SINGBOX_GROUP SUBAPP_USER SUBAPP_GROUP HAPROXY_USER HAPROXY_GROUP
    )

    for var_name in "${vars_to_substitute[@]}"; do
        if [ -n "${!var_name+x}" ]; then # Check if var is set
            local var_value="${!var_name}"
            # Robust escaping for sed. Escape backslash, ampersand, the chosen delimiter (#), and double quotes for JSON.
            local escaped_value
            escaped_value=$(echo "$var_value" | sed -e 's/\\/\\\\/g' -e 's/\&/\\\&/g' -e 's/#/\\#/g' -e 's/"/\\"/g')
            sed -i "s#\${${var_name}}#${escaped_value}#g" "$temp_processed_file" || {
                log_error "Sed substitution failed for \${${var_name}} in ${template_file}"; rm -f "$temp_processed_file"; return 1;
            }
        fi
    done

    mkdir -p "$(dirname "$output_file")" || { log_error "Failed to create dir for $(dirname "$output_file")"; rm -f "$temp_processed_file"; return 1; }
    mv "$temp_processed_file" "$output_file" || { log_error "Failed to move temp file to ${output_file}"; rm -f "$temp_processed_file"; return 1; }
    log_info "Processed template '${template_file##*/}' to '${output_file}'"; return 0
}

# --- Function to run a command and trigger cleanup_exit on failure ---
run_cmd_or_exit() {
    "$@"
    local status=$?
    if [ $status -ne 0 ]; then
        log_error "Command failed with status $status: $*"
        exit $status # Trap will call cleanup_exit with this status
    fi
    return 0 # Explicitly return 0 on success
}

# --- Step 1: Pre-flight Checks & User Input ---
pre_flight_checks() {
    local prev_opts; prev_opts=$(set +o); set -e # Manage -e locally for this function

    check_root
    log_info "Starting pre-flight checks and gathering information..."
    local required_cmds=(
        curl jq uuidgen python3 base64 tr head fold date systemctl apt-get useradd groupadd getent install
        find tar touch read select sed mktemp mv cp rm mkdir chmod chown dirname sleep cat
    )
    for cmd in "${required_cmds[@]}"; do run_cmd_or_exit check_command "$cmd"; done

    log_info "Gathering domain and Cloudflare information..."
    # Use read with -r to prevent backslash escapes if user inputs them
    read -r -p "Enter main domain for proxy services (e.g., proxy.yourdomain.com): " MAIN_DOMAIN
    read -r -p "Enter domain for subscription website (e.g., subscribe.yourdomain.com): " SUBSCRIPTION_DOMAIN
    read -r -p "Enter Cloudflare account email (for Let's Encrypt): " CLOUDFLARE_EMAIL
    if [[ -z "$MAIN_DOMAIN" || -z "$SUBSCRIPTION_DOMAIN" || -z "$CLOUDFLARE_EMAIL" ]]; then log_error "Domains and email cannot be empty."; exit 1; fi
    if [[ "$MAIN_DOMAIN" == "$SUBSCRIPTION_DOMAIN" ]]; then log_error "Main proxy domain and subscription domain must be different."; exit 1; fi

    log_info "Choose Cloudflare API credential type:"
    PS3="Select credential type (1 or 2 then Enter): "
    local cred_choice_done=false
    while ! $cred_choice_done; do
        # Ensure select choices are properly quoted if they contain spaces
        select cred_type_sel_var in "API Token (Recommended)" "Global API Key"; do
            case "$REPLY" in
                1)
                    read -r -s -p "Enter Cloudflare API Token: " CLOUDFLARE_API_TOKEN; echo "" # -s for silent, -r for raw
                    if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then log_error "API Token cannot be empty."; continue; fi # Loop back
                    echo "dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}" > "${CLOUDFLARE_INI_TEMP}"; cred_choice_done=true; break ;;
                2)
                    read -r -s -p "Enter Cloudflare Global API Key: " CLOUDFLARE_API_KEY; echo ""
                    if [[ -z "$CLOUDFLARE_API_KEY" ]]; then log_error "API Key cannot be empty."; continue; fi
                    # Using cat with a heredoc for multi-line content
                    cat << EOF_INI > "${CLOUDFLARE_INI_TEMP}"
dns_cloudflare_email = ${CLOUDFLARE_EMAIL}
dns_cloudflare_api_key = ${CLOUDFLARE_API_KEY}
EOF_INI
                    cred_choice_done=true; break ;;
                *) echo "Invalid choice '$REPLY'. Please select 1 or 2."; continue ;; # Loop back on invalid input
            esac
        done
    done
    run_cmd_or_exit chmod 400 "${CLOUDFLARE_INI_TEMP}"; log_info "Created secure Cloudflare credentials file: ${CLOUDFLARE_INI_TEMP}"

    log_info "Generating secrets..."
    VLESS_UUID_INITIAL=$(uuidgen); log_info "  - VLESS_UUID_INITIAL generated: ${VLESS_UUID_INITIAL} (for reference, not auto-added)"
    local VLESS_PATH_TEMP; VLESS_PATH_TEMP=$(generate_random_string 16); VLESS_PATH="/${VLESS_PATH_TEMP}"; log_info "  - VLESS_PATH generated: ${VLESS_PATH}"
    local HYSTERIA2_PASSWORD_TEMP; HYSTERIA2_PASSWORD_TEMP=$(generate_random_string 24); HYSTERIA2_PASSWORD="${HYSTERIA2_PASSWORD_TEMP}"; log_info "  - HYSTERIA2_PASSWORD generated."
    local HYSTERIA2_OBFS_PASSWORD_TEMP; HYSTERIA2_OBFS_PASSWORD_TEMP=$(generate_random_string 24); HYSTERIA2_OBFS_PASSWORD="${HYSTERIA2_OBFS_PASSWORD_TEMP}"; log_info "  - HYSTERIA2_OBFS_PASSWORD generated."
    local INITIAL_HY2_USERNAME_RND; INITIAL_HY2_USERNAME_RND=$(generate_random_string 16); INITIAL_HY2_USERNAME="${INITIAL_HY2_USERNAME_PREFIX}${INITIAL_HY2_USERNAME_RND}"; log_info "  - INITIAL_HY2_USERNAME generated: ${INITIAL_HY2_USERNAME}"
    local SUBSCRIPTION_SECRET_STRING_TEMP1; SUBSCRIPTION_SECRET_STRING_TEMP1=$(generate_random_string 20); SUBSCRIPTION_SECRET_STRING="sub-${SUBSCRIPTION_SECRET_STRING_TEMP1}"; log_info "  - SUBSCRIPTION_SECRET_STRING generated."
    local SUBSCRIPTION_BASE64_PATH_TEMP1; SUBSCRIPTION_BASE64_PATH_TEMP1=$(generate_urlsafe_base64 "${SUBSCRIPTION_SECRET_STRING}-page"); SUBSCRIPTION_BASE64_PATH="/${SUBSCRIPTION_BASE64_PATH_TEMP1}"; log_info "  - SUBSCRIPTION_BASE64_PATH generated: ${SUBSCRIPTION_BASE64_PATH}"
    local API_BASE64_PATH_PREFIX_TEMP1; API_BASE64_PATH_PREFIX_TEMP1=$(generate_urlsafe_base64 "${SUBSCRIPTION_SECRET_STRING}-api"); API_BASE64_PATH_PREFIX="/${API_BASE64_PATH_PREFIX_TEMP1}"; log_info "  - API_BASE64_PATH_PREFIX generated: ${API_BASE64_PATH_PREFIX}"
    log_info "Secret generation complete."

    log_info "--- Configuration Summary (Review Carefully!) ---"
    echo "  Main Proxy Domain:        ${MAIN_DOMAIN}"
    echo "  Subscription Domain:      ${SUBSCRIPTION_DOMAIN}"
    echo "  Cloudflare Email:         ${CLOUDFLARE_EMAIL}"
    echo "  VLESS Port (TCP, via HAProxy): ${VLESS_HTTPUPGRADE_PORT}"
    echo "  VLESS Path:               ${VLESS_PATH}"
    echo "  Hysteria2 Port (UDP, direct): ${HYSTERIA2_PORT}"
    echo "  Hysteria2 Initial Username: ${INITIAL_HY2_USERNAME} (SAVE THIS!)"
    echo "  Hysteria2 Initial Password: ${HYSTERIA2_PASSWORD} (SAVE THIS!)"
    echo "  Hysteria2 OBFS Password:  ${HYSTERIA2_OBFS_PASSWORD} (SAVE THIS!)"
    echo "  Subscription Port (TCP, via HAProxy):  ${SUBSCRIPTION_SITE_PORT}"
    echo "  Subscription Page Path:   ${SUBSCRIPTION_BASE64_PATH} (SAVE THIS!)"
    echo "  Subscription API Prefix:  ${API_BASE64_PATH_PREFIX} (SAVE THIS!)"
    echo "  Cloudflare creds file:    ${CLOUDFLARE_INI_TEMP} (will be auto-deleted on exit)"
    echo "----------------------------------------"
    read -r -p "DNS records for both domains MUST point to this server's IP. Proceed with deployment? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then log_info "Deployment aborted by user."; exit 0; fi

    eval "$prev_opts" # Restore original shell options
}

# --- Step 2: Install Dependencies & Create Users ---
install_dependencies() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Updating package lists and installing system dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    run_cmd_or_exit apt-get update -y
    run_cmd_or_exit apt-get install -y \
        haproxy \
        certbot python3-certbot-dns-cloudflare \
        python3-pip python3-venv python3-full \
        fail2ban \
        jq curl unzip coreutils uuid-runtime \
        rsyslog socat # Added socat

    log_info "Creating service users (${SINGBOX_USER}, ${SUBAPP_USER}) and groups..."
    for group_name in "$SINGBOX_GROUP" "$SUBAPP_GROUP"; do
        if ! getent group "$group_name" > /dev/null; then run_cmd_or_exit groupadd --system "$group_name"; log_info "Group '$group_name' created.";
        else log_info "Group '$group_name' already exists."; fi
    done
    if ! id -u "$SINGBOX_USER" > /dev/null 2>&1; then
        run_cmd_or_exit useradd --system --gid "$SINGBOX_GROUP" --home-dir /var/lib/singbox --no-create-home --shell /usr/sbin/nologin "$SINGBOX_USER"
        log_info "User '$SINGBOX_USER' created."; run_cmd_or_exit mkdir -p /var/lib/singbox && run_cmd_or_exit chown "$SINGBOX_USER":"$SINGBOX_GROUP" /var/lib/singbox
    else log_info "User '$SINGBOX_USER' already exists."; fi
    if ! id -u "$SUBAPP_USER" > /dev/null 2>&1; then
        run_cmd_or_exit mkdir -p "$(dirname "$SUBSCRIPTION_APP_DIR")"
        run_cmd_or_exit useradd --system --gid "$SUBAPP_GROUP" --home-dir "$SUBSCRIPTION_APP_DIR" --no-create-home --shell /usr/sbin/nologin "$SUBAPP_USER"
        log_info "User '$SUBAPP_USER' created.";
    else log_info "User '$SUBAPP_USER' already exists."; fi

    log_info "Enabling and starting HAProxy and Fail2ban (Fail2ban will be reloaded later)..."
    run_cmd_or_exit systemctl enable haproxy; run_cmd_or_exit systemctl start haproxy
    run_cmd_or_exit systemctl enable fail2ban; run_cmd_or_exit systemctl start fail2ban
    log_info "System dependencies installed and base services configured."
    eval "$prev_opts"
}

# Step 3: Setup SSL Certificates
setup_certificates() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Setting up SSL certificates via Certbot/Cloudflare..."
    run_cmd_or_exit mkdir -p "${HAPROXY_CERT_DIR}" "${SINGBOX_CERT_DIR}"
    if [[ ! -f "${CLOUDFLARE_INI_TEMP}" ]]; then log_error "Cloudflare credentials file missing: ${CLOUDFLARE_INI_TEMP}"; exit 1; fi

    log_info "Obtaining/renewing certificate for Main Domain: ${MAIN_DOMAIN}..."
    run_cmd_or_exit certbot certonly --dns-cloudflare --dns-cloudflare-credentials "${CLOUDFLARE_INI_TEMP}" \
        --dns-cloudflare-propagation-seconds 60 -d "${MAIN_DOMAIN}" --email "${CLOUDFLARE_EMAIL}" \
        --agree-tos --non-interactive --preferred-challenges dns --keep-until-expiring --renew-with-new-domains --uir
    
    run_cmd_or_exit bash -c "cat \"${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/fullchain.pem\" \"${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/privkey.pem\" > \"${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem\""
    run_cmd_or_exit chown root:"${HAPROXY_GROUP}" "${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem"; run_cmd_or_exit chmod 640 "${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem"
    
    run_cmd_or_exit cp "${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/fullchain.pem" "${SINGBOX_CERT_DIR}/hysteria2.cert.pem"
    run_cmd_or_exit cp "${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/privkey.pem" "${SINGBOX_CERT_DIR}/hysteria2.key.pem"
    run_cmd_or_exit chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_CERT_DIR}/hysteria2.cert.pem" "${SINGBOX_CERT_DIR}/hysteria2.key.pem"
    run_cmd_or_exit chmod 640 "${SINGBOX_CERT_DIR}/hysteria2.cert.pem" "${SINGBOX_CERT_DIR}/hysteria2.key.pem"
    log_info "Certs for ${MAIN_DOMAIN} processed for HAProxy and Sing-Box."

    log_info "Obtaining/renewing certificate for Subscription Domain: ${SUBSCRIPTION_DOMAIN}..."
    run_cmd_or_exit certbot certonly --dns-cloudflare --dns-cloudflare-credentials "${CLOUDFLARE_INI_TEMP}" \
        --dns-cloudflare-propagation-seconds 60 -d "${SUBSCRIPTION_DOMAIN}" --email "${CLOUDFLARE_EMAIL}" \
        --agree-tos --non-interactive --preferred-challenges dns --keep-until-expiring --renew-with-new-domains --uir
    run_cmd_or_exit bash -c "cat \"${LETSENCRYPT_LIVE_DIR}/${SUBSCRIPTION_DOMAIN}/fullchain.pem\" \"${LETSENCRYPT_LIVE_DIR}/${SUBSCRIPTION_DOMAIN}/privkey.pem\" > \"${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem\""
    run_cmd_or_exit chown root:"${HAPROXY_GROUP}" "${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem"; run_cmd_or_exit chmod 640 "${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem"
    log_info "Certs for ${SUBSCRIPTION_DOMAIN} processed for HAProxy."

    log_info "Setting up Certbot auto-renewal hook from template..."
    local RENEWAL_HOOK_SCRIPT_DEST="/etc/letsencrypt/renewal-hooks/deploy/process_certs_and_reload.sh"
    run_cmd_or_exit mkdir -p "$(dirname "$RENEWAL_HOOK_SCRIPT_DEST")"
    run_cmd_or_exit process_template "${TEMPLATE_CERTBOT_HOOK}" "${RENEWAL_HOOK_SCRIPT_DEST}"
    run_cmd_or_exit chmod +x "$RENEWAL_HOOK_SCRIPT_DEST"
    log_info "Created Certbot renewal hook: $RENEWAL_HOOK_SCRIPT_DEST"
    if ! systemctl list-timers | grep -q 'certbot.timer'; then
        log_info "Certbot timer not active, enabling/starting.";
        systemctl enable certbot.timer &>/dev/null || log_warn "Could not enable certbot.timer"
        systemctl start certbot.timer &>/dev/null || log_warn "Could not start certbot.timer"
    else log_info "Certbot timer is active."; fi
    eval "$prev_opts"
}

# Step 4: Setup Sing-Box
setup_singbox() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Setting up Sing-Box..."
    run_cmd_or_exit mkdir -p "${SINGBOX_INSTALL_DIR}" "${SINGBOX_CONFIG_DIR}" "${SINGBOX_CERT_DIR}" "${SINGBOX_BACKUP_DIR}"
    run_cmd_or_exit chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_CONFIG_DIR}" "${SINGBOX_CERT_DIR}" "${SINGBOX_BACKUP_DIR}"
    run_cmd_or_exit chmod 750 "${SINGBOX_CONFIG_DIR}" "${SINGBOX_CERT_DIR}" "${SINGBOX_BACKUP_DIR}"

    log_info "Getting latest Sing-Box URL for linux-amd64..."
    LATEST_SINGBOX_URL=$(curl -fsSL --retry 3 --retry-delay 5 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.assets[] | select(.name | test("linux-amd64(-v[23])?.tar.gz$")) | .browser_download_url' | head -n 1)
    if [ -z "$LATEST_SINGBOX_URL" ] || [ "$LATEST_SINGBOX_URL" == "null" ]; then log_error "Could not get Sing-Box download URL."; exit 1; fi
    log_info "Downloading Sing-Box from ${LATEST_SINGBOX_URL}..."; run_cmd_or_exit curl -Lo sing-box.tar.gz "${LATEST_SINGBOX_URL}"
    
    local SINGBOX_TMP_EXTRACT="singbox_extract_tmp_$$"; run_cmd_or_exit mkdir -p "$SINGBOX_TMP_EXTRACT"
    log_info "Extracting Sing-Box..."
    if ! tar -xzf sing-box.tar.gz -C "$SINGBOX_TMP_EXTRACT" --strip-components=1 2>/dev/null; then
        log_info "Stripping components failed, trying extraction without stripping...";
        run_cmd_or_exit tar -xzf sing-box.tar.gz -C "$SINGBOX_TMP_EXTRACT"
    fi
    local SINGBOX_EXEC_PATH; SINGBOX_EXEC_PATH=$(find "$SINGBOX_TMP_EXTRACT" -name 'sing-box' -type f -print -quit)
    if [ -n "$SINGBOX_EXEC_PATH" ] && [ -f "$SINGBOX_EXEC_PATH" ]; then
        run_cmd_or_exit install -m 755 "$SINGBOX_EXEC_PATH" "${SINGBOX_INSTALL_DIR}/sing-box"
    else
        log_error "Sing-box executable not found in downloaded archive."; rm -rf "$SINGBOX_TMP_EXTRACT" sing-box.tar.gz; exit 1;
    fi
    rm -rf "$SINGBOX_TMP_EXTRACT" sing-box.tar.gz; log_info "Sing-Box installed to ${SINGBOX_INSTALL_DIR}/sing-box."

    log_info "Creating Sing-Box configuration from template (Hysteria2 users array will be empty)..."
    run_cmd_or_exit process_template "${TEMPLATE_SINGBOX_JSON}" "${SINGBOX_CONFIG_DIR}/config.json" # Uses v1.6 template
    run_cmd_or_exit chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_CONFIG_DIR}/config.json"
    run_cmd_or_exit chmod 640 "${SINGBOX_CONFIG_DIR}/config.json"

    run_cmd_or_exit touch "${SINGBOX_VLESS_USER_MAP_FILE}"; run_cmd_or_exit chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_VLESS_USER_MAP_FILE}"; run_cmd_or_exit chmod 640 "${SINGBOX_VLESS_USER_MAP_FILE}"
    run_cmd_or_exit touch "${SINGBOX_HY2_USER_MAP_FILE}"; run_cmd_or_exit chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_HY2_USER_MAP_FILE}"; run_cmd_or_exit chmod 640 "${SINGBOX_HY2_USER_MAP_FILE}"

    log_info "Copying user management script (expected v2.2)..."
    if [ ! -f "$SOURCE_MANAGE_USERS_SCRIPT" ]; then log_error "User management script not found at ${SOURCE_MANAGE_USERS_SCRIPT}"; exit 1; fi
    run_cmd_or_exit cp "${SOURCE_MANAGE_USERS_SCRIPT}" "${MANAGEMENT_SCRIPT_PATH}"
    run_cmd_or_exit chmod 755 "${MANAGEMENT_SCRIPT_PATH}" # Ensure it's executable

    log_info "Adding initial Hysteria2 user ('${INITIAL_HY2_USERNAME}') via management script..."
    # This call uses manage_proxy_users.sh v2.2 which expects username and password for add_hy2
    if run_cmd_or_exit "${MANAGEMENT_SCRIPT_PATH}" add_hy2 "${INITIAL_HY2_USERNAME}" "${HYSTERIA2_PASSWORD}"; then
        log_info "Initial Hysteria2 user '${INITIAL_HY2_USERNAME}' added successfully."
        # manage_proxy_users.sh handles the Sing-Box reload/restart
    else
        log_error "Failed to add initial Hysteria2 user. Deployment halted. Check logs from manage_proxy_users.sh."
        exit 1
    fi

    log_info "Creating Sing-Box systemd service file..."
    run_cmd_or_exit process_template "${TEMPLATE_SINGBOX_SERVICE}" "/etc/systemd/system/sing-box.service"
    run_cmd_or_exit systemctl daemon-reload
    run_cmd_or_exit systemctl enable sing-box || log_warn "Failed to enable sing-box service."
    log_info "Sing-Box setup complete. Service started/reloaded by user management script."
    eval "$prev_opts"
}

# Step 5: Setup Subscription Flask App (same as v1.8)
setup_subscription_app() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Setting up Python Flask subscription application..."
    run_cmd_or_exit mkdir -p "${SUBSCRIPTION_APP_DIR}/templates" "${SUBSCRIPTION_APP_DIR}/static"
    run_cmd_or_exit chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "$(dirname "$SUBSCRIPTION_APP_DIR")"
    run_cmd_or_exit chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "${SUBSCRIPTION_APP_DIR}"
    run_cmd_or_exit chmod 750 "${SUBSCRIPTION_APP_DIR}"
    log_info "Creating Python virtual environment in ${SUBSCRIPTION_APP_DIR}/venv..."
    run_cmd_or_exit python3 -m venv "${SUBSCRIPTION_APP_DIR}/venv"
    run_cmd_or_exit chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "${SUBSCRIPTION_APP_DIR}/venv"
    log_info "Installing Flask/Gunicorn into venv..."
    run_cmd_or_exit "${SUBSCRIPTION_APP_DIR}/venv/bin/pip" install --upgrade pip
    run_cmd_or_exit "${SUBSCRIPTION_APP_DIR}/venv/bin/pip" install Flask gunicorn
    log_info "Copying Flask application files...";
    if [ ! -f "$SOURCE_FLASK_APP_PY" ]; then log_error "Flask app.py not found: ${SOURCE_FLASK_APP_PY}"; exit 1; fi
    run_cmd_or_exit cp "${SOURCE_FLASK_APP_PY}" "${SUBSCRIPTION_APP_DIR}/app.py"
    if [ ! -f "$SOURCE_FLASK_INDEX_HTML" ]; then log_error "Flask index.html not found: ${SOURCE_FLASK_INDEX_HTML}"; exit 1; fi
    run_cmd_or_exit cp "${SOURCE_FLASK_INDEX_HTML}" "${SUBSCRIPTION_APP_DIR}/templates/index.html"
    if [ -f "$SOURCE_FLASK_STATIC_README" ]; then run_cmd_or_exit cp "${SOURCE_FLASK_STATIC_README}" "${SUBSCRIPTION_APP_DIR}/static/README.md";
    else log_warn "Static README for Flask app not found at ${SOURCE_FLASK_STATIC_README}."; fi
    run_cmd_or_exit chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "${SUBSCRIPTION_APP_DIR}"
    run_cmd_or_exit find "${SUBSCRIPTION_APP_DIR}" -type d -exec chmod 750 {} \;
    run_cmd_or_exit find "${SUBSCRIPTION_APP_DIR}" -type f -exec chmod 640 {} \;
    run_cmd_or_exit find "${SUBSCRIPTION_APP_DIR}/venv/bin/" -type f -user "${SUBAPP_USER}" -exec chmod u+x {} \;
    run_cmd_or_exit chmod u+x "${SUBSCRIPTION_APP_DIR}/venv/bin/activate"
    log_info "Creating systemd service for Flask app..."
    run_cmd_or_exit process_template "${TEMPLATE_SUBAPP_SERVICE}" "/etc/systemd/system/subscription-app.service"
    run_cmd_or_exit systemctl daemon-reload
    run_cmd_or_exit systemctl enable subscription-app || log_warn "Failed to enable subscription-app service."
    log_info "Subscription Flask app setup complete."
    eval "$prev_opts"
}

# --- Step 6: Setup HAProxy --- (same as v1.8, ensure template does not have Hy2)
setup_haproxy() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Configuring HAProxy and its logging..."
    local HAPROXY_LOG_FILE="/var/log/haproxy.log"
    local HAPROXY_RSYSLOG_CONF="/etc/rsyslog.d/49-haproxy.conf" # For rsyslog config

    # Check if HAProxy logging is already configured in rsyslog
    if [ ! -f "$HAPROXY_RSYSLOG_CONF" ] || ! grep -q "haproxy.log" "$HAPROXY_RSYSLOG_CONF" 2>/dev/null; then
         log_info "Configuring rsyslog for HAProxy logging to ${HAPROXY_LOG_FILE}..."
         # This rsyslog config assumes HAProxy global log directive is: log 127.0.0.1:514 local0
         # Or if HAProxy logs to /dev/log, a simpler rsyslog rule is needed.
         # For `log /dev/log local0` in haproxy.cfg:
         echo 'local0.*    -/var/log/haproxy.log' > "$HAPROXY_RSYSLOG_CONF"
         echo '& stop' >> "$HAPROXY_RSYSLOG_CONF" # For older rsyslog to stop processing after this rule

         run_cmd_or_exit touch "${HAPROXY_LOG_FILE}"
         run_cmd_or_exit chown syslog:syslog "${HAPROXY_LOG_FILE}"
         run_cmd_or_exit chmod 640 "${HAPROXY_LOG_FILE}"
         log_info "Restarting rsyslog to apply HAProxy logging configuration..."
         run_cmd_or_exit systemctl restart rsyslog || log_warn "Failed to restart rsyslog. HAProxy logs might not appear correctly."
         sleep 2
    else
        log_info "Rsyslog configuration for HAProxy seems to exist at $HAPROXY_RSYSLOG_CONF."
        if [ ! -f "$HAPROXY_LOG_FILE" ]; then
            run_cmd_or_exit touch "${HAPROXY_LOG_FILE}"; run_cmd_or_exit chown syslog:syslog "${HAPROXY_LOG_FILE}"; run_cmd_or_exit chmod 640 "${HAPROXY_LOG_FILE}"; fi
    fi

    log_info "Creating HAProxy configuration file from template (NO Hysteria2)..."
    run_cmd_or_exit process_template "${TEMPLATE_HAPROXY_CFG}" "/etc/haproxy/haproxy.cfg"
    log_info "Validating HAProxy configuration..."
    if haproxy -c -f /etc/haproxy/haproxy.cfg; then log_info "HAProxy configuration syntax check passed.";
    else log_error "HAProxy configuration check FAILED! Review /etc/haproxy/haproxy.cfg"; exit 1; fi
    log_info "HAProxy configuration complete."
    eval "$prev_opts"
}

# --- Step 7: Setup Fail2ban --- (same as v1.8)
setup_fail2ban() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Configuring Fail2ban for HAProxy logs..."
    local HAPROXY_LOG_FILE="/var/log/haproxy.log"
    if [ ! -f "$HAPROXY_LOG_FILE" ]; then
        log_warn "HAProxy log file ${HAPROXY_LOG_FILE} does not exist. Creating..."
        run_cmd_or_exit touch "${HAPROXY_LOG_FILE}"; run_cmd_or_exit chown syslog:syslog "${HAPROXY_LOG_FILE}"; run_cmd_or_exit chmod 640 "${HAPROXY_LOG_FILE}";
    fi
    local FAIL2BAN_FILTER_DEST="/etc/fail2ban/filter.d/haproxy-custom.conf"
    log_info "Copying Fail2ban filter from ${TEMPLATE_FAIL2BAN_FILTER} to ${FAIL2BAN_FILTER_DEST}"
    if [ ! -f "$TEMPLATE_FAIL2BAN_FILTER" ]; then log_error "Fail2ban filter template not found: ${TEMPLATE_FAIL2BAN_FILTER}"; exit 1; fi
    run_cmd_or_exit mkdir -p "$(dirname "$FAIL2BAN_FILTER_DEST")"; run_cmd_or_exit cp "${TEMPLATE_FAIL2BAN_FILTER}" "${FAIL2BAN_FILTER_DEST}"
    local FAIL2BAN_JAIL_DEST="/etc/fail2ban/jail.d/haproxy-custom.conf"
    log_info "Creating Fail2ban jail config from template ${TEMPLATE_FAIL2BAN_JAIL} to ${FAIL2BAN_JAIL_DEST}"
    run_cmd_or_exit process_template "${TEMPLATE_FAIL2BAN_JAIL}" "${FAIL2BAN_JAIL_DEST}"
    log_info "Reloading Fail2ban service to apply new HAProxy configuration..."
    run_cmd_or_exit systemctl reload fail2ban || {
        log_error "Fail2ban reload failed. Checking status and logs...";
        systemctl status fail2ban --no-pager -l; journalctl -u fail2ban -n 50 --no-pager; exit 1;
    }
    log_info "Fail2ban setup for HAProxy complete."
    eval "$prev_opts"
}

# Step 8: Setup Firewall (same as v1.8)
setup_firewall() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Configuring firewall (ufw)..."; run_cmd_or_exit check_command "ufw"
    run_cmd_or_exit ufw default deny incoming; run_cmd_or_exit ufw default allow outgoing
    log_info "Allowing essential services (SSH, HAProxy ports, Hysteria2 direct UDP)..."
    run_cmd_or_exit ufw allow ssh comment 'SSH Access'
    run_cmd_or_exit ufw allow "${SUBSCRIPTION_SITE_PORT}/tcp" comment "Subscription Site (via HAProxy)"
    run_cmd_or_exit ufw allow "${VLESS_HTTPUPGRADE_PORT}/tcp" comment "VLESS (via HAProxy)"
    run_cmd_or_exit ufw allow "${HYSTERIA2_PORT}/udp" comment "Hysteria2 (direct to Sing-Box)"
    run_cmd_or_exit ufw allow from 127.0.0.1 comment 'Loopback In'; run_cmd_or_exit ufw allow to 127.0.0.1 comment 'Loopback Out'
    run_cmd_or_exit ufw limit ssh comment 'Rate Limit SSH'
    if ! ufw status | grep -qw active; then log_info "Enabling firewall..."; run_cmd_or_exit ufw --force enable;
    else log_info "Reloading firewall..."; run_cmd_or_exit ufw reload; fi
    log_info "Current firewall status:"; run_cmd_or_exit ufw status verbose
    log_info "Firewall configured."
    eval "$prev_opts"
}

# Step 9: Start/Restart Services (same as v1.8)
start_services() {
    log_info "Starting/Restarting main services..."
    systemctl restart haproxy || log_warn "Failed to restart haproxy."
    systemctl restart subscription-app || log_warn "Failed to restart subscription-app."
    systemctl restart fail2ban || log_warn "Failed to restart fail2ban."
    if ! systemctl is-active --quiet sing-box; then
        log_warn "Sing-Box was not active post-setup, attempting to start it."
        systemctl start sing-box || log_warn "Failed to start sing-box."
    else log_info "Sing-Box is active (expected from its setup process)."; fi

    log_info "Waiting briefly for services to initialize (5s)..."; sleep 5
    log_info "Verifying service statuses:"
    local failed_svcs=0
    for svc in haproxy sing-box subscription-app fail2ban; do
        if systemctl is-active --quiet "$svc"; then log_info "  - ${svc}: Active";
        else log_error "  - ${svc}: FAILED or Inactive"; failed_svcs=$((failed_svcs + 1)); fi
    done
    local flask_url="http://127.0.0.1:${SUBSCRIPTION_APP_LISTEN_PORT}${SUBSCRIPTION_BASE64_PATH}"
    local flask_health_url="http://127.0.0.1:${SUBSCRIPTION_APP_LISTEN_PORT}/health"
    if curl --fail --silent --head --max-time 3 "${flask_url}" &>/dev/null || \
       (curl --fail --silent --head --max-time 3 "${flask_health_url}" &>/dev/null) ; then
         log_info "  - Subscription app responding locally.";
    else log_error "  - Subscription app NOT responding locally. Check: journalctl -u subscription-app"; failed_svcs=$((failed_svcs + 1)); fi

    if [ $failed_svcs -gt 0 ]; then log_warn "One or more services may have failed. Review logs.";
    else log_info "All primary services appear to be running correctly."; fi
}

# --- Step 10: Main Execution Orchestration ---
main() {
    log_info "Starting Secure Proxy Platform Deployment v1.9..."
    run_cmd_or_exit pre_flight_checks
    run_cmd_or_exit install_dependencies
    run_cmd_or_exit setup_certificates
    run_cmd_or_exit setup_singbox       # Adds initial Hy2 user & starts/reloads Sing-Box
    run_cmd_or_exit setup_subscription_app
    run_cmd_or_exit setup_haproxy
    run_cmd_or_exit setup_fail2ban
    run_cmd_or_exit setup_firewall
    start_services

    log_info ""
    log_info "--- Deployment Complete ---"
    echo "=================================================================================="
    echo " [IMPORTANT] Configuration Details - SAVE THIS SECURELY!"
    echo "=================================================================================="
    echo " ### Proxy Service (${MAIN_DOMAIN}) ###"
    echo "   - VLESS Port (TCP, via HAProxy): ${VLESS_HTTPUPGRADE_PORT}"
    echo "   - VLESS Path (Secret):           ${VLESS_PATH}"
    echo "   - Hysteria2 Port (UDP, direct):  ${HYSTERIA2_PORT}"
    echo "   - Hysteria2 Initial Username:    ${INITIAL_HY2_USERNAME}"
    echo "   - Hysteria2 Initial Password:    ${HYSTERIA2_PASSWORD}"
    echo "   - Hysteria2 OBFS Password:       ${HYSTERIA2_OBFS_PASSWORD}"
    echo ""
    echo " ### Subscription Website (${SUBSCRIPTION_DOMAIN}) ###"
    echo "   - ACCESS URL (Use this exact link):"
    echo "     https://${SUBSCRIPTION_DOMAIN}:${SUBSCRIPTION_SITE_PORT}${SUBSCRIPTION_BASE64_PATH}"
    echo "   - API Path Prefix (Internal):     ${API_BASE64_PATH_PREFIX}"
    echo ""
    echo " ### User Management Script: ${MANAGEMENT_SCRIPT_PATH} ###"
    echo "   VLESS Users:"
    echo "     sudo ${MANAGEMENT_SCRIPT_PATH} add_vless <username>"
    echo "     sudo ${MANAGEMENT_SCRIPT_PATH} list_vless"
    echo "     sudo ${MANAGEMENT_SCRIPT_PATH} del_vless <username_or_uuid>"
    echo "   Hysteria2 Users:"
    echo "     sudo ${MANAGEMENT_SCRIPT_PATH} add_hy2 <username> <password>"
    echo "     sudo ${MANAGEMENT_SCRIPT_PATH} list_hy2"
    echo "     sudo ${MANAGEMENT_SCRIPT_PATH} del_hy2 <username>"
    echo ""
    echo " ### Security Notes ###"
    echo "   - Runtime services run as non-root: ${SINGBOX_USER}, ${SUBAPP_USER}, ${HAPROXY_USER}."
    echo "   - Subscription/API paths are obscured."
    echo "   - Unmatched requests to HAProxy are dropped."
    echo "   - Fail2ban is active for HAProxy logs. Check: sudo fail2ban-client status haproxy-http-drop"
    echo ""
    echo " ### Other Information ###"
    echo "   - DNS records for ${MAIN_DOMAIN} and ${SUBSCRIPTION_DOMAIN} must point to this server's IP."
    echo "   - SSL Certificates auto-renew via Certbot."
    echo "   - Review logs: journalctl -u <service_name>, /var/log/haproxy.log, /var/log/fail2ban.log"
    echo "=================================================================================="
}

# --- Run Main Function ---
main "$@"
exit 0 # Explicit success exit
