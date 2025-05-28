# Secure Proxy Platform - Deployment Script

This directory contains the main deployment script (`deploy_proxy_platform.sh`) responsible for setting up the entire Secure Proxy Platform on a target server.

## Purpose

The `deploy_proxy_platform.sh` script automates the installation and configuration of all necessary components, including:

*   HAProxy (Frontend, TLS, Routing, Rate Limiting)
*   Sing-Box (VLESS + Hysteria2 backend)
*   Flask Subscription Web Application (with obscured paths)
*   Certbot with Cloudflare DNS for SSL certificates
*   Fail2ban for security hardening
*   UFW Firewall configuration
*   Necessary users, groups, and permissions for non-root runtime
*   A command-line VLESS user management utility

## Prerequisites

Before running the deployment script, ensure the following conditions are met:

1.  **Server OS:** A fresh installation of a Debian-based Linux distribution (e.g., Debian 11/12, Ubuntu 20.04/22.04) is recommended. The script uses `apt-get`.
2.  **Root Access:** You must run the script as the `root` user or using `sudo`.
3.  **DNS Records:** **Crucially**, you must have already configured the DNS `A` (and/or `AAAA` for IPv6) records for both your chosen **main proxy domain** and **subscription domain** to point to the public IP address of the target server. Certbot requires this for domain validation. Propagation might take time.
4.  **Cloudflare Account:** You need a Cloudflare account managing the DNS for your domains.
5.  **Cloudflare API Credentials:** You need either a Cloudflare **API Token** (Recommended, with Zone:Read and DNS:Edit permissions for your domains) or your **Global API Key**. The script will prompt for this.

## Usage

1.  Place the `deploy_proxy_platform.sh` script on the target server (e.g., via `scp` or cloning the repository).
2.  Navigate to the directory containing the script in your server's terminal.
3.  Make the script executable: `chmod +x deploy_proxy_platform.sh`
4.  Run the script with root privileges: `sudo ./deploy_proxy_platform.sh`
5.  Follow the on-screen prompts to enter your domain names, Cloudflare email, and Cloudflare API credentials.
6.  Review the configuration summary carefully before confirming.

## Script Input & Credentials

The script will prompt for:

*   Main domain name (for VLESS/Hysteria2 services).
*   Subscription domain name (for the web interface).
*   Cloudflare account email address.
*   Choice between Cloudflare API Token or Global API Key.
*   The selected Cloudflare credential (input will be hidden).

The script creates a temporary file named `cloudflare.ini` in the current directory to pass credentials to Certbot. This file is created with restrictive permissions (`400`) and is **automatically deleted** by the script after the certificate acquisition process is complete (or if the script exits prematurely via the cleanup trap).

## Script Output

Upon successful completion, the script will display a summary containing:

*   Your generated **Hysteria2 Password**.
*   The unique, randomly generated Base64 **Subscription Page Path**.
*   The unique, randomly generated Base64 **Subscription API Prefix**.
*   The initial **VLESS UUID** (though users will be added with unique UUIDs later).
*   Instructions on how to use the VLESS user management script (`/usr/local/sbin/manage_proxy_users`).

**SAVE THIS OUTPUT SECURELY!** The Base64 paths and the Hysteria2 password are required to access and use the platform.

## Post-Deployment Steps

After the script finishes successfully:

1.  **Save Output:** Ensure you have saved the summary information provided by the script.
2.  **Background Image:** Place your desired background image for the subscription page at `/var/www/subscription_app/static/background.jpg`.
3.  **Add User:** Add your first VLESS user using the management script: `sudo /usr/local/sbin/manage_proxy_users add your_username`.
4.  **Test:** Access the unique subscription URL, generate links, and test client connections.
5.  **Monitor:** Check service statuses and logs (`journalctl`, `/var/log/haproxy.log`, `/var/log/fail2ban.log`).

## Idempotency

This script is primarily designed for **initial setup** on a clean server. While some steps might be safe to re-run (like certificate renewal), re-running the entire script on an already configured system may lead to unexpected results or configuration conflicts. For updates, consider modifying specific configuration files or creating separate update scripts.

## Security

*   Never commit your Cloudflare API credentials directly into version control. The script handles the temporary file securely.
*   Ensure your server is kept up-to-date with security patches.
*   Review firewall rules (`sudo ufw status verbose`) and Fail2ban logs regularly.
