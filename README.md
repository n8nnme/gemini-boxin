```markdown
# Gemini-Boxin: Stealth VPN Infrastructure

A complete sing-box based stealth VPN solution with maximum security and invisibility features for residential ISP connections.

## Features

- **Maximum Stealth**: ISP NAT firewall simulation with 444 masquerade responses
- **Dual Protocol**: Hysteria2 + VLESS with HTTPUpgrade transport
- **Advanced Security**: Salamander obfuscation, TLS 1.3, multiplex with padding
- **Auto SSL**: Cloudflare DNS certificate management with auto-renewal
- **Fail2ban Protection**: Multi-layer protection against attacks and scanning
- **User Management**: Easy user addition/removal with unique credentials

## Quick Start

### Prerequisites
- Debian 12 VPS with root access
- Domain name managed by Cloudflare
- Cloudflare API credentials

### Installation

```bash
# Clone repository
git clone https://github.com/n8nnme/gemini-boxin.git
cd gemini-boxin

# Copy deploy scripts
sudo cp deploy/* /opt/ssb/
sudo chmod +x /opt/ssb/*.sh

# Run deployment
sudo /opt/ssb/deploy.sh your-domain.com your-email@cloudflare.com your-cloudflare-api-key
```

### User Management

```bash
# Add new user
sudo /opt/ssb/manage_users.sh add alice

# List all users
sudo /opt/ssb/manage_users.sh list

# Show user configuration
sudo /opt/ssb/manage_users.sh show alice

# Delete user
sudo /opt/ssb/manage_users.sh del alice
```

## Security Features

### Network Level
- ISP NAT firewall simulation (all ports filtered except VPN)
- UFW configuration with residential behavior
- No server signatures or identifying headers

### Protocol Level
- **Hysteria2**: Salamander obfuscation, TLS 1.3, H3 ALPN
- **VLESS**: HTTPUpgrade transport, H2MUX multiplex, Chrome TLS fingerprint
- 46-47 character random passwords and paths per user
- 444 status code masquerade for invalid requests

### Application Level
- Fail2ban protection with custom rules
- Automatic certificate renewal via Certbot + Cloudflare DNS
- Log rotation and security event monitoring
- Service isolation with dedicated user accounts

## Configuration

### Default Ports
- **Hysteria2**: 31847/UDP
- **VLESS**: 8443/TCP

### Generated Files
- **Server Config**: `/etc/sing-box/config.json`
- **User Configs**: `/opt/ssb/configs/users//client-config.json`
- **SSL Certificates**: `/etc/ssl/sing-box/`

## Client Configuration

Download the generated client configuration and use with:
- **sing-box** (Official client)
- **Nekoray** (GUI client)
- **Husi** (Mobile client)

## Monitoring

```bash
# Check service status
systemctl status sing-box

# View logs
journalctl -u sing-box -f

# Check fail2ban status
sudo fail2ban-client status

# Check certificate renewal
systemctl status certbot.timer
```

## Security Considerations

1. **Change SSH port** after deployment
2. **Use key-based SSH authentication** only
3. **Regular system updates** via unattended-upgrades
4. **Monitor fail2ban logs** for attack patterns
5. **Backup user configurations** regularly

## Troubleshooting

### Certificate Issues
```bash
# Test certificate renewal
sudo certbot renew --dry-run

# Check certificate status
sudo certbot certificates
```

### Service Issues
```bash
# Check configuration
sudo sing-box check -c /etc/sing-box/config.json

# Restart service
sudo systemctl restart sing-box

# Check firewall
sudo ufw status
```

### User Connection Issues
```bash
# Verify user exists
sudo /opt/ssb/manage_users.sh list

# Check user configuration
sudo /opt/ssb/manage_users.sh show 

# Regenerate user config
sudo /opt/ssb/manage_users.sh del 
sudo /opt/ssb/manage_users.sh add 
```

## Disclaimer

This software is provided for educational and legitimate privacy purposes only. Users are responsible for compliance with local laws and regulations.

## Support

- **Issues**: [GitHub Issues](https://github.com/n8nnme/gemini-boxin/issues)
- **Documentation**: [Wiki](https://github.com/n8nnme/gemini-boxin/wiki)
- **Security**: Report security issues privately to howtobecandyy2@outlook.com

## **Repository Structure**

```
gemini-boxin/
├── README.md
├── deploy/
│   ├── deploy.sh
│   └── manage_users.sh
└── templates/
    ├── fail2ban/
    │   ├── jail.d/
    │   │   └── sing-box.conf
    │   └── filter.d/
    │       ├── sing-box-auth.conf
    │       ├── sing-box-brute.conf
    |       ├── sing-box-flood.conf
    |       ├── sing-box-recon.conf
    │       └── sing-box-scan.conf
    |       
    └── sing-box/
        ├── client-template.json
        └── server-template.json
```
