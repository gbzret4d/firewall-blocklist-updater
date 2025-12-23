# 🔥 Ultimate Firewall Blocklist Updater & CrowdSec Installer

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=flat-square)
![OS](https://img.shields.io/badge/OS-Debian%20%7C%20Ubuntu%20%7C%20CentOS%20%7C%20RHEL-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)
![CrowdSec](https://img.shields.io/badge/Security-CrowdSec%20Integrated-yellow?style=flat-square)

A comprehensive, **automated security suite** for Linux servers.
This tool combines the static protection of massive **IPSet Blocklists** with the dynamic, real-time behavioral analysis of **CrowdSec**.

It is designed to be "Set & Forget": Run the installer once, and your server stays protected with automatic updates every 6 hours.

---

## ✨ Features

* **🌍 Multi-OS Support:**
    * Works out-of-the-box on **Debian, Ubuntu, CentOS, RHEL, Fedora, AlmaLinux**.
    * Automatically detects your package manager (`apt` or `yum/dnf`).
* **🛡️ Deep CrowdSec Integration:**
    * Automatically installs **CrowdSec Security Engine** & **Firewall Bouncer**.
    * **Auto-Enrollment:** Connects your instance to the CrowdSec Console if a key is provided.
    * **AbuseIPDB Reporting:** Automatically reports attackers to AbuseIPDB via CrowdSec (optional).
    * **Fixes Common Bugs:** Automatically patches known CrowdSec plugin issues (e.g., crashing on `dummy`/`email` plugins).
* **⚡ High Performance:**
    * Uses `ipset` (kernel level) instead of thousands of single `iptables` rules.
    * Can handle **200,000+ blocked IPs** with zero performance impact.
* **📦 Smart Blocklist Management:**
    * **Universal Extractor:** Handles `.txt`, `.zip`, and `.gz` blocklists automatically.
    * **Deduplication:** Removes duplicate IPs across different lists to save memory.
    * **Private IP Filter:** Ensures you never accidentally lock yourself out (filters 192.168.x.x, 10.x.x.x, etc.).
* **🤖 Threat Intelligence:**
    * Includes **HoneyDB** API support to fetch bad hosts.
    * Pre-configured with high-confidence lists (Spamhaus DROP, DShield, GreenSnow, etc.).
* **🔄 Auto-Updates:**
    * Installs a **Systemd Timer** that updates blocklists every 6 hours.
    * The script itself checks for updates from this repository automatically.

---

## 🚀 Installation

You can install the entire suite with a single command. The interactive installer will guide you through the configuration (API keys, Whitelisting, etc.).

**Run this on your server:**

```bash
wget -O - https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main/install.sh | sudo bash
```

*(Note: The command above downloads the script directly and runs it with root privileges.)*

### What the installer does:
1.  **Cleans up** broken or old CrowdSec installations.
2.  **Installs** dependencies (`curl`, `ipset`, `iptables`, `unzip`, `crowdsec`).
3.  **Configures** the Firewall Bouncer automatically (fixing common API key race conditions).
4.  **Sets up** the Blocklist Updater service and timer.
5.  **Enrolls** your instance to the CrowdSec Console (if you provide a key).

---

## ⚙️ Configuration

### 1. Interactive Wizard (Recommended)
You can change your settings (API Keys, Whitelisted Countries, etc.) at any time by running the built-in wizard:

```bash
sudo update-firewall-blocklists.sh --configure
```

### 2. Manual Configuration
All settings are stored in a simple environment file:

```bash
sudo nano /usr/local/etc/firewall-blocklist-updater/firewall-blocklist-keys.env
```

**Key Variables:**
* `WHITELIST_COUNTRIES="DE AT CH"` (ISO Codes to never block)
* `BLOCKLIST_COUNTRIES="CN RU KP"` (ISO Codes to always block)
* `ABUSEIPDB_API_KEY` (Your v2 API Key for reporting)
* `CROWDSEC_ENROLL_KEY` (From your CrowdSec Console)

### 3. Managing Sources
You can add or remove blocklist URLs in this file:
```bash
sudo nano /usr/local/etc/firewall-blocklist-updater/firewall-blocklists/blocklist.sources
```
*Supports raw text files, ZIP, and GZIP URLs.*

---

## 🛠 Usage & Commands

**Manually run an update:**
```bash
sudo update-firewall-blocklists.sh
```

**Check the logs:**
```bash
sudo tail -f /var/log/firewall-blocklist-updater.log
```

**Check blocked IPs (IPSet):**
```bash
# List all sets
sudo ipset list -n

# Check if an IP is blocked
sudo ipset test blocklist_all 1.2.3.4
```

**Check CrowdSec Status:**
```bash
# Show metrics
sudo cscli metrics

# Show connected bouncers
sudo cscli bouncers list
```

---

## ❓ Troubleshooting

**CrowdSec Service fails to start?**
The installer includes a fix for a known bug where "dummy" or "email" plugins cause CrowdSec to crash when notifications are enabled. If you still have issues manually:
```bash
# This command fixes broken plugin names
cd /usr/lib/crowdsec/plugins/ 
sudo mv http notification-http 2>/dev/null
sudo mv email notification-email 2>/dev/null
sudo rm dummy 2>/dev/null
sudo systemctl restart crowdsec
```

**I don't see my instance in the CrowdSec Console?**
1.  Run `sudo cscli console enroll <YOUR_KEY>` manually.
2.  Restart the service: `sudo systemctl restart crowdsec`.
3.  Go to [app.crowdsec.net](https://app.crowdsec.net) and click **"Accept"** on the new instance.

---

## 📜 License

This project is licensed under the MIT License.

**Disclaimer:** This script modifies your firewall rules. While it includes safety mechanisms (whitelisting, private IP filtering), always ensure you have OOB (Out-of-Band) access (e.g., VNC/Console) to your server before applying firewall rules remotely.