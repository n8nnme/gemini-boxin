# SSB if we smoke offen

## Overview

This project provides an automated deployment solution for setting up a secure and feature-rich personal proxy platform. It leverages modern tools like HAProxy, Sing-Box, and Python Flask, focusing on security, obscurity, and ease of management.

The platform is designed to offer VLESS (via HTTP Upgrade) and Hysteria2 proxy services, fronted by HAProxy for TLS termination, routing, and basic protection. A simple Python Flask web application provides an obscured interface for users to obtain client configuration import links.

## Goals

*   **Secure Proxy Services:** Provide reliable VLESS and Hysteria2 proxy endpoints.
*   **Obscurity:** Hide the subscription interface and proxy paths from casual scanning using unpredictable Base64-encoded URLs.
*   **Automated Deployment:** Simplify setup on Debian-based systems using a comprehensive bash script.
*   **Automated TLS:** Integrate Certbot with Cloudflare DNS validation for easy SSL certificate acquisition and renewal.
*   **Security Hardening:**
    *   Run runtime services (Sing-Box, Flask App) as dedicated non-root users.
    *   Implement Fail2ban rules to automatically block IPs probing invalid paths or triggering rate limits.
    *   Configure HAProxy to silently drop invalid connections.
*   **User Management:** Provide a simple command-line tool for managing VLESS users (UUIDs).

## Architecture

The platform consists of the following core components interacting on a single server:

1.  **HAProxy:**
    *   Acts as the public-facing entry point.
    *   Listens on standard ports (e.g., 443 for subscription, 8443 for VLESS) and UDP port for Hysteria2.
    *   Terminates TLS using certificates obtained via Certbot.
    *   Routes requests based on port and path (including obscured Base64 paths).
    *   Forwards valid proxy traffic to backend Sing-Box instances (running on localhost).
    *   Forwards subscription web traffic to the Flask application (running on localhost).
    *   Silently drops requests to invalid paths.
    *   Provides basic UDP rate limiting.
2.  **Sing-Box:**
    *   Runs as a backend service, listening only on localhost.
    *   Handles the VLESS (via HTTP transport) and Hysteria2 protocols.
    *   Authenticates users based on managed UUIDs (VLESS) or password (Hysteria2).
    *   Uses its own TLS configuration (obtained via Certbot) for Hysteria2.
    *   Runs as a dedicated non-root user ('singbox').
3.  **Flask Subscription App:**
    *   A simple Python web application run via Gunicorn.
    *   Listens only on localhost.
    *   Serves the subscription frontend HTML page via an obscured Base64 path.
    *   Provides an API endpoint (also via an obscured Base64 path prefix) to dynamically generate Sing-Box client configuration JSON files.
    *   Runs as a dedicated non-root user ('subapp').
4.  **Certbot:**
    *   Automates the acquisition and renewal of TLS certificates using Let's Encrypt.
    *   Uses the Cloudflare DNS plugin for domain validation.
    *   A deployment hook script handles copying/processing certificates and reloading relevant services (HAProxy, Sing-Box).
5.  **Fail2ban:**
    *   Monitors HAProxy logs for dropped/rejected connections.
    *   Uses custom filters and jails to automatically block offending IP addresses using 'iptables'.
6.  **UFW:**
    *   Provides basic firewall rules to allow only necessary ports (SSH, 443/tcp, 8443/tcp, 31216/udp).

## Features

*   VLESS over TLS (HTTP Upgrade) endpoint.
*   Hysteria2 (Password Auth, TLS) endpoint.
*   Obscured subscription page and API endpoints via random Base64 paths.
*   Automated deployment script ('deployment/deploy_proxy_platform.s').
*   Automated TLS certificate management (Certbot + Cloudflare).
*   Runtime services execute as non-root users ('singbox', 'subapp', 'haproxy').
*   HAProxy silent connection dropping for invalid paths.
*   HAProxy UDP connection rate limiting.
*   Fail2ban integration to block malicious IPs based on HAProxy logs.
*   Command-line script ('scripts/manage_proxy_users.sh') for VLESS user management.
*   Systemd service files for managing Sing-Box and the Flask application.

## Directory Structure

```plaintext
secure-proxy-platform/
├── deployment/               # Main deployment script and related info
├── config_templates/         # Reference configuration templates
├── services/                 # Runtime application code (Flask app)
├── scripts/                  # Helper/management scripts (user management)
├── .gitignore                # Git ignore rules
└── README.md                 # This file: Project overview
```

## Getting Started / Deployment

1.  **Prerequisites:** Ensure you have a Debian-based server, root/sudo access, correctly configured DNS records pointing to your server's IP, and Cloudflare API credentials.
2.  **Deployment Script:** The primary method for setting up the platform is using the automated script.
3.  **Detailed Instructions:** Please refer to the README file within the 'deployment' directory for detailed prerequisites and step-by-step instructions on running the 'deploy_proxy_platform.sh' script.

    ```bash
    cd deployment
    less README.md
    # Follow instructions within that file
    ```

## Usage

### Accessing the Subscription Page

*   After successful deployment, the script will output the **unique, randomly generated URL** for the subscription page (e.g., 'https://your-sub-domain.com:443/RaNdOmB4se64P4th').
*   **You must use this exact URL** to access the web interface. Accessing the domain root or any other path will result in a dropped connection.
*   Enter a valid username (created via the management script) into the input field and click the buttons to generate 'sing-box:/' import links for your clients.

### Managing VLESS Users

*   A command-line script is installed at '/usr/local/sbin/manage_proxy_users'.
*   Use 'sudo' to run the script.
*   **Add User:** 'sudo /usr/local/sbin/manage_proxy_users add <new_username>' (Generates a unique UUID)
*   **List Users:** 'sudo /usr/local/sbin/manage_proxy_users list' (Shows username-UUID mapping and active config UUIDs)
*   **Delete User:** 'sudo /usr/local/sbin/manage_proxy_users del <username_or_uuid>'

## Security Considerations

*   **Non-Root Execution:** Core runtime services operate under dedicated low-privilege users. Administrative tasks (deployment, user management) still require 'sudo'.
*   **Obscurity:** Base64 paths provide obscurity against casual scanning but are **not encryption**. Anyone who obtains the path can access the resource.
*   **Authentication:** Primary security relies on strong VLESS UUIDs and the Hysteria2 password.
*   **Fail2ban:** Provides active defense against brute-force or scanning attempts targeting invalid resources. Monitor its logs ('/var/log/fail2ban.log') and status ('sudo fail2ban-client status').
*   **Updates:** Regularly update the server OS, HAProxy, Sing-Box, Python packages, and other dependencies.

## Customization

*   **Ports:** Default ports (8443, 31216, 443) can be modified within the 'deploy_proxy_platform.sh' script before running. Firewall rules will need corresponding adjustments.
*   **Passwords/Secrets:** The script generates random secrets. For specific requirements, you might modify the generation logic.
*   **Flask App:** The subscription application ('services/subscription_app/app.py') logic can be extended (e.g., add actual user validation, different config generation).
*   **HAProxy/Sing-Box Configs:** Advanced users can modify the configurations generated by the script or the templates directly for fine-tuning. Remember that script re-runs might overwrite manual changes unless the script is modified.
*   **Fail2ban Parameters:** 'maxretry', 'findtime', and 'bantime' can be adjusted in the deployment script or directly in '/etc/fail2ban/jail.d/haproxy-custom.conf'.

## License

This project is likely under the MIT License if not specified otherwise. See individual components for their respective licenses.
