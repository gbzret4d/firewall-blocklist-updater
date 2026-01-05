# 🛡️ Ultimate Firewall & CrowdSec Auto-Hardener

![Version](https://img.shields.io/badge/version-v17.64-success?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian%20%7C%20AlmaLinux%20%7C%20Rocky-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

> **Current Stable Release:** v17.64 (Silent Mode & Smart Enroll)

This is a **production-grade, "set-and-forget" security suite** for Linux servers. It turns a fresh server into a fortress within seconds by installing CrowdSec, setting up a high-performance Iptables firewall, and deploying massive IP blocklists.

It is designed to be **self-healing** and **self-updating**, ensuring your server remains protected against new threats without manual intervention.

---

## ✨ Key Features

### 🧠 Intelligent Automation
* **Smart Enrollment:** Automatically detects if the server is already linked to your CrowdSec Console. Prevents duplicate entries and "re-enrollment loops" on re-runs.
* **Auto-Update System:** A systemd timer checks for script updates hourly.
* **Silent Operation:** In `v17.64+`, the system runs silently in the background. You only receive Telegram notifications if something goes **wrong** (e.g., empty blocklists or update failures).

### 🛡️ Deep Security Layer
* **CrowdSec Integration:** Full installation of the Security Engine + Iptables Bouncer. Automatically fixes common API port conflicts (e.g., port 8080 -> 42000).
* **Endlessh (SSH Tarpit):** Moves your real SSH port and spins up a "trap" on port 2222. Attackers / bots get stuck in an infinite loop, wasting their resources while keeping your logs clean.
* **Performance:** Uses **IPSet** (kernel-level hash sets) to handle over **150,000 blocked IPs** with zero performance impact on the CPU.

### 🌍 Massive Threat Intelligence
Aggregates and cleans feeds from top-tier security providers:
* *Spamhaus (DROP/EDROP)*
* *Abuse.ch (Feodo Tracker, SSL Blacklist)*
* *DShield / SANS ISC*
* *Emerging Threats (Compromised IPs)*
* *GreenSnow & Blocklist.de*
* *AbuseIPDB (Confidence 100)*
* *And many more...*

### 🐳 Infrastructure Compatible
* **Docker Safe:** Automatically detects Docker and inserts firewall rules into the `DOCKER-USER` chain. Your containers remain reachable, but the bad guys are blocked *before* they hit your apps.
* **Cloudflare & DynDNS:** Automatically whitelists your dynamic home IP and Cloudflare ranges.

---

## 🚀 Installation

Run this one-liner on your server as **root** (or use `sudo`).

### Quick Start
Replace the variables with your own values.

```bash
wget -O - [https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main/install.sh](https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main/install.sh) | sudo \
  ABUSEIPDB_API_KEY="YOUR_API_KEY" \
  CROWDSEC_ENROLL_KEY="YOUR_ENROLL_KEY" \
  DYNDNS_HOST="my-home.dyndns.org" \
  WHITELIST_COUNTRIES="AT DE US" \
  BLOCKLIST_COUNTRIES="" \
  TELEGRAM_BOT_TOKEN="123456:ABC-DEF..." \
  TELEGRAM_CHAT_ID="987654321" \
  bash
```

### Configuration Variables

| Variable | Required? | Description |
| :--- | :--- | :--- |
| `CROWDSEC_ENROLL_KEY` | **Yes** | Get this from your [CrowdSec Console](https://app.crowdsec.net). Links your instance. |
| `ABUSEIPDB_API_KEY` | No | If set, CrowdSec bans are automatically reported to AbuseIPDB. |
| `DYNDNS_HOST` | No | Your private DynDNS domain (e.g., from DuckDNS). This IP is always whitelisted. |
| `WHITELIST_COUNTRIES` | No | ISO country codes (space-separated) to **never** block (e.g., `AT DE`). |
| `BLOCKLIST_COUNTRIES` | No | ISO country codes to **always** block (Geo-Blocking). |
| `TELEGRAM_BOT_TOKEN` | No | Bot Token for error alerts. |
| `TELEGRAM_CHAT_ID` | No | Chat ID where alerts are sent. |

---

## 🛠 verification

After the installation completes, verify that all systems are operational.

### 1. Check Firewall Status
Ensure the blocklists are loaded into the kernel. You should see a high number of entries (usually >150,000).

```bash
ipset list blocklist_all -t
```

### 2. Check CrowdSec
Verify that the bouncer is registered and the agent is running.

```bash
cscli metrics
cscli bouncers list
```

### 3. Check Auto-Updater
Ensure the systemd timer is active (waiting for the next hour).

```bash
systemctl status firewall-blocklist-updater.timer
```

---

## 📂 Architecture

The installer is non-destructive but opinionated. It places files in standard Linux locations:

* **Logic:** `/usr/local/bin/update-firewall-blocklists.sh`
    * *The brain. Downloads lists, parses versions, updates firewall.*
* **Config:** `/usr/local/etc/firewall-blocklist-updater/`
    * *Stores your API keys and source URLs.*
* **Logs:** `/var/log/firewall-blocklist-updater.log`
    * *Includes log rotation to prevent disk filling.*
* **Systemd:**
    * `firewall-blocklist-updater.service` (The execution unit)
    * `firewall-blocklist-updater.timer` (The scheduler)

---

## ❓ FAQ

**Q: I ran the installer again manually. Did I break anything?**
A: **No.** The script is idempotent. It detects that CrowdSec is already enrolled and that configurations exist. It simply refreshes the installation and updates the script to the latest version.

**Q: How do I view the logs?**
A: `tail -f /var/log/firewall-blocklist-updater.log`

**Q: How do I whitelist an IP manually?**
A: The script whitelists `1.1.1.1`, `1.0.0.1`, and private ranges (`192.168.x.x`, `10.x.x.x`) by default. To add more, edit the script logic or use your `DYNDNS_HOST` variable.

---

## ⚠️ Disclaimer

This script modifies `iptables` rules. While it includes safety nets (like Docker preservation and failsafe DNS), it is a powerful tool.
* Ensure you have **out-of-band access** (VNC/Console) to your server in case you lock yourself out.
* The author is not responsible for any connectivity loss or data loss.

**License:** MIT