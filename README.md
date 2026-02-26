# 🛡️ CyberPanel Security Suite

A modular, secure, production-ready CyberPanel plugin for managing **Fail2ban**, **GeoIP Analytics**, and **Country Blocking** — designed for future expansion into a full Security Suite.

**Version:** 1.3  
**Author:** [S M Mehdi Akram](https://www.facebook.com/smmehdiakram)  
**Company:** [Royal Technologies](https://royaltechbd.com/)  
**License:** MIT  
**Repository:** [github.com/mehdiakram/cyberpanel-security-suite](https://github.com/mehdiakram/cyberpanel-security-suite)

---

## ✨ Features

- **Dashboard** — Real-time Fail2ban status, jail count, banned IP count, last 10 banned IPs
- **Jail Manager** — View all active jails with detailed stats
- **Banned IPs** — View, search, ban/unban IPs across all jails
- **🌍 GeoIP Analytics** — See where attacks come from, country stats with flag emojis, bar charts
- **🚫 Country Blocking** — Block/unblock entire countries with ipset+iptables, searchable list
- **Logs Viewer** — Read-only view of `/var/log/fail2ban.log` with auto-refresh
- **Settings** — Plugin info, service controls, future module roadmap
- **Security Hardened** — Admin-only access, CSRF protection, rate limiting, whitelisted commands, input validation, subprocess safety

---

## 📋 Supported Environments

| OS | Supported |
|---|---|
| Ubuntu 18.04 | ✅ |
| Ubuntu 20.04 | ✅ |
| Ubuntu 22.04 | ✅ |
| AlmaLinux 8 | ✅ |
| AlmaLinux 9 | ✅ |
| CloudLinux 8 | ✅ |

**Requirements:**
- CyberPanel (with OpenLiteSpeed) installed
- Fail2ban installed (auto-installed by installer)
- ipset installed (auto-installed by installer for country blocking)
- Root access
- Minimum 1024MB RAM, 10GB disk space

---

## 🚀 Quick Install (One-Line)

SSH into your server as **root** and run:

```bash
bash <(curl -s https://raw.githubusercontent.com/mehdiakram/cyberpanel-security-suite/main/install.sh)
```

That's it! After installation, go to **CyberPanel → Security Suite**.

---

## 📦 Manual Installation

```bash
# 1. Clone the repository
git clone https://github.com/mehdiakram/cyberpanel-security-suite.git

# 2. Run the installer
cd cyberpanel-security-suite
bash install.sh
```

---

## 🗑️ Uninstall

```bash
bash <(curl -s https://raw.githubusercontent.com/mehdiakram/cyberpanel-security-suite/main/uninstall.sh)
```

Or manually:

```bash
cd /path/to/cyberpanel-security-suite
bash uninstall.sh
```

---

## 🏗️ Project Structure

```
cyberpanel-security-suite/
│
├── securitysuite/
│   ├── __init__.py              # Package init
│   ├── views.py                 # Page + AJAX API views
│   ├── urls.py                  # URL routing
│   ├── permissions.py           # Admin-only + rate limiting decorators
│   ├── services/
│   │   ├── fail2ban_service.py  # Fail2ban command layer (secure)
│   │   ├── geoip_service.py     # IP geolocation (ip-api.com)
│   │   ├── country_block_service.py # Country blocking (ipset+iptables)
│   │   └── system_service.py    # Logging + system utilities
│   ├── templates/securitysuite/
│   │   ├── base.html            # Layout template (all CSS/JS inlined)
│   │   ├── overview.html        # Dashboard
│   │   ├── jails.html           # Jail manager
│   │   ├── banned_ips.html      # Banned IP management
│   │   ├── geoip.html           # GeoIP analytics
│   │   ├── country_block.html   # Country blocking
│   │   ├── logs.html            # Log viewer
│   │   └── settings.html        # Settings / info
│   └── static/securitysuite/
│       ├── css/securitysuite.css # Styles
│       └── js/securitysuite.js  # AJAX logic
│
├── install.sh                   # Installer (auto-installs fail2ban + ipset)
├── uninstall.sh                 # Uninstaller script
├── README.md
└── LICENSE
```

---

## 🔒 Security

| Security Measure | Implementation |
|---|---|
| Shell Injection Prevention | `subprocess.run()` with argument list — NO `shell=True` |
| Input Validation | `ipaddress` module for IPs, regex for jail names |
| Access Control | Admin-only decorator on every view |
| CSRF Protection | Django CSRF middleware + token in AJAX headers |
| Command Whitelisting | Only pre-approved fail2ban commands |
| Timeout Protection | 10-second subprocess timeout |
| Log Safety | Read-only viewer, whitelisted paths, ANSI stripped |
| Rate Limiting | In-memory per-IP rate limiter on all API endpoints |

### Allowed Commands Only

```
fail2ban-client status
fail2ban-client status <jail>
fail2ban-client reload
fail2ban-client set <jail> banip <ip>
fail2ban-client set <jail> unbanip <ip>
systemctl restart fail2ban
systemctl is-active fail2ban
```

No dynamic shell input. No raw output rendered.

---

## 🗺️ Roadmap (Future Modules)

- 🔥 CSF Firewall Manager
- 🛠️ ModSecurity Control
- 📊 Brute Force Heatmap
- ⚡ Rate Limiting Rules
- 📧 Email / Telegram Alerts

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

Please ensure:
- No `shell=True` in subprocess calls
- All user input is validated
- New features have admin-only access
- Follow the existing modular service architecture

---

## 📝 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**S M Mehdi Akram**  
🌐 [Royal Technologies](https://royaltechbd.com/)  
📘 [Facebook](https://www.facebook.com/smmehdiakram)  
💻 [GitHub](https://github.com/mehdiakram)

---

> Built with ❤️ by [Royal Technologies](https://royaltechbd.com/) for the CyberPanel community.
