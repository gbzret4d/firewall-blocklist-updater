#!/bin/bash
set -e

# --- Firewall & Sensor Installer (v8.0) ---
# - Adapted for update-firewall-blocklists.sh v8.1
# - REMOVED: HoneyDB & Old CrowdSec Hacks
# - FEAT: Supports yum, dnf, apt, zypper
# - FEAT: Sets up clean Environment

echo "============================================="
echo "   FIREWALL & CROWDSEC INSTALLER (v8.0)      "
echo "============================================="

# --- CONFIG & DEFAULTS ---
# Extensive List provided in previous version
DEFAULT_LISTS=(
    "Spamhaus DROP|https://www.spamhaus.org/drop/drop.txt"
    "Spamhaus EDROP|https://www.spamhaus.org/drop/edrop.txt"
    "Spamhaus IPv6|https://www.spamhaus.org/drop/dropv6.txt"
    "DShield|https://feeds.dshield.org/block.txt"
    "Feodo Tracker|https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    "SSLBL Abuse.ch|https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
    "IPSum Level 3|https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
    "GreenSnow|https://blocklist.greensnow.co/greensnow.txt"
    "Blocklist.de All|https://lists.blocklist.de/lists/all.txt"
    "EmergingThreats Block|https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    "EmergingThreats Compromised|https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    "BinaryDefense|https://www.binarydefense.com/banlist.txt"
    "AbuseIPDB 100%|https://github.com/borestad/blocklist-abuseipdb/raw/refs/heads/main/abuseipdb-s100-7d.ipv4"
    "BruteForce High|https://github.com/ShadowWhisperer/IPs/raw/refs/heads/master/BruteForce/High"
    "Malware Hackers|https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Malware/Hackers"
    "ThreatFox IOCs|https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/refs/heads/main/ips.txt"
    "CobaltStrike IPs|https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/cobaltstrike_ips.txt"
    "AlienVault|https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/refs/heads/master/alienvault.txt"
    "CINS Score|https://cinsscore.com/list/ci-badguys.txt"
    "Tor Exit Nodes|https://check.torproject.org/torbulkexitlist"
)

# --- 1. SYSTEM CHECK ---
echo ">>> 1. SYSTEM CHECK..."
if [[ $EUID -ne 0 ]]; then
   echo "❌ Error: This script must be run as root."
   exit 1
fi

CS_INSTALLED=false
if command -v crowdsec >/dev/null; then
    CS_INSTALLED=true
    echo " -> CrowdSec detected."
else
    echo " -> CrowdSec not installed."
fi

# --- 2. ENVIRONMENT MAPPING ---
ABUSE_KEY="${ABUSEIPDB_API_KEY:-}"
CS_ENROLL="${CROWDSEC_ENROLL_KEY:-}"
DYNDNS="${DYNDNS_HOST:-}"
WL_COUNTRIES="${WHITELIST_COUNTRIES:-}"
BL_COUNTRIES="${BLOCKLIST_COUNTRIES:-}"
TG_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TG_CHAT="${TELEGRAM_CHAT_ID:-}"

# Logic: Auto-install CrowdSec if Key is provided or already installed
INSTALL_CS="n"
if [[ -n "$CS_ENROLL" ]] || [[ "$CS_INSTALLED" = true ]]; then
    INSTALL_CS="y"
fi

# --- 3. USER INPUT ---
echo ""
echo "--- INSTALLATION OPTIONS ---"

if [ -z "$CS_ENROLL" ] && [ "$CS_INSTALLED" = false ]; then
    read -p "Do you want to install CrowdSec & Sensors? (Y/n): " DO_CS
    [[ "$DO_CS" =~ ^[Nn]$ ]] && INSTALL_CS="n" || INSTALL_CS="y"
fi

if [ "$INSTALL_CS" = "y" ]; then
    echo " -> CrowdSec setup active."
    if [ -z "$ABUSE_KEY" ]; then
        read -p "Enter AbuseIPDB API Key (Leave EMPTY to disable): " ABUSE_KEY
    fi
    if [ -z "$CS_ENROLL" ] && [ "$CS_INSTALLED" = false ]; then
        read -p "Enter CrowdSec Enroll Key (Leave EMPTY to skip): " CS_ENROLL
    fi
fi

# HoneyDB REMOVED

echo ""
echo "--- BLOCKLIST SELECTION ---"
if [[ -n "$ABUSEIPDB_API_KEY" ]]; then
    echo " -> Automated Mode detected. Using ALL default blocklists."
    CUST_LISTS="n"
else
    read -p "Do you want to customize the blocklist selection? (y/N): " CUST_LISTS
fi

SELECTED_URLS=()
if [[ "$CUST_LISTS" =~ ^[Yy]$ ]]; then
    for entry in "${DEFAULT_LISTS[@]}"; do
        name="${entry%%|*}"
        url="${entry#*|}"
        read -p "Include '$name'? (Y/n): " yn
        if [[ ! "$yn" =~ ^[Nn]$ ]]; then SELECTED_URLS+=("$url"); fi
    done
else
    for entry in "${DEFAULT_LISTS[@]}"; do SELECTED_URLS+=("${entry#*|}"); done
fi

echo ""
echo "--- SETTINGS ---"
if [ -z "$DYNDNS" ]; then
    read -p "Enter DynDNS Hostname (Leave EMPTY to skip): " DYNDNS
fi
if [ -z "$WL_COUNTRIES" ]; then
    read -p "Enter Whitelisted Countries (e.g. 'DE AT', leave EMPTY for NONE): " WL_COUNTRIES
fi
if [ -z "$BL_COUNTRIES" ]; then
    read -p "Enter Blocklisted Countries (e.g. 'CN RU', leave EMPTY for NONE): " BL_COUNTRIES
fi
if [ -z "$TG_TOKEN" ]; then
    read -p "Enter Telegram Bot Token (Leave EMPTY to skip): " TG_TOKEN
fi
if [[ -n "$TG_TOKEN" ]] && [ -z "$TG_CHAT" ]; then
    read -p "Enter Telegram Chat ID: " TG_CHAT
fi

# --- 4. EXECUTION ---
echo ""
echo ">>> 2. PREPARING ENVIRONMENT..."
# Robust dependency installation for multiple OS
if command -v apt-get >/dev/null; then
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do echo "Waiting for apt lock..."; sleep 2; done
    apt-get update -qq && apt-get install -y curl ipset iptables dnsutils unzip file gnupg iproute2
elif command -v dnf >/dev/null; then
    dnf install -y curl ipset iptables bind-utils unzip file iproute
elif command -v yum >/dev/null; then
    yum install -y curl ipset iptables bind-utils unzip file iproute
elif command -v zypper >/dev/null; then
    zypper install -y curl ipset iptables bind-utils unzip file iproute2
else
    echo "⚠️ Warning: Unknown package manager. Please ensure 'curl ipset iptables unzip' are installed."
fi

# --- 5. CROWDSEC ---
if [ "$INSTALL_CS" = "y" ]; then
    echo ">>> 3. SETTING UP CROWDSEC..."
    if ! command -v crowdsec >/dev/null; then
        echo " -> Installing CrowdSec Repos..."
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash 2>/dev/null || \
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash 2>/dev/null
        
        echo " -> Installing CrowdSec Package..."
        if command -v apt-get >/dev/null; then apt-get install -y crowdsec; 
        elif command -v dnf >/dev/null; then dnf install -y crowdsec; 
        elif command -v yum >/dev/null; then yum install -y crowdsec; 
        elif command -v zypper >/dev/null; then zypper install -y crowdsec; fi
    fi
    
    # Enroll
    if [[ -n "$CS_ENROLL" ]]; then
        echo " -> Enrolling instance..."
        cscli console enroll "$CS_ENROLL" --overwrite || echo "Enrollment warning (key might be used or invalid)."
    fi

    # AbuseIPDB Config
    if [[ -n "$ABUSE_KEY" ]]; then
        mkdir -p /etc/crowdsec/notifications
        cat <<NOTIFY > /etc/crowdsec/notifications/abuseipdb.yaml
type: http
name: abuseipdb
log_level: info
format: |
  {
    "ip": "{{range . -}}{{.Source.IP}}{{end}}",
    "categories": "18,22",
    "comment": "Blocked by CrowdSec. Scenario: {{range . -}}{{.Scenario}}{{end}}",
    "key": "$ABUSE_KEY"
  }
url: https://api.abuseipdb.com/api/v2/report
method: POST
headers:
  Content-Type: application/json
  Accept: application/json
NOTIFY
        
        # Add notification to profile
        if ! grep -q "abuseipdb" /etc/crowdsec/profiles.yaml; then
             if grep -q "notifications:" /etc/crowdsec/profiles.yaml; then
                 sed -i '/notifications:/a \ - abuseipdb' /etc/crowdsec/profiles.yaml
             else
                 echo "notifications:" >> /etc/crowdsec/profiles.yaml
                 echo " - abuseipdb" >> /etc/crowdsec/profiles.yaml
             fi
        fi
    fi

    if ! command -v crowdsec-firewall-bouncer >/dev/null; then
        echo " -> Installing Firewall Bouncer..."
        if command -v apt-get >/dev/null; then apt-get install -y crowdsec-firewall-bouncer-iptables; 
        else yum install -y crowdsec-firewall-bouncer-iptables; fi
    fi
    
    systemctl restart crowdsec
    systemctl restart crowdsec-firewall-bouncer
fi

# --- 6. UPDATER SCRIPT ---
echo ">>> 4. INSTALLING BLOCKLIST UPDATER..."
cd /tmp
rm -rf firewall-blocklist-updater
git clone https://github.com/gbzret4d/firewall-blocklist-updater.git
cd firewall-blocklist-updater
cp update-firewall-blocklists.sh /usr/local/bin/
chmod +x /usr/local/bin/update-firewall-blocklists.sh
mkdir -p /usr/local/etc/firewall-blocklist-updater/firewall-blocklists
mkdir -p /usr/local/etc/firewall-blocklist-updater/backups

# Write Selected Sources
: > "/usr/local/etc/firewall-blocklist-updater/firewall-blocklists/blocklist.sources"
for url in "${SELECTED_URLS[@]}"; do echo "$url" >> "/usr/local/etc/firewall-blocklist-updater/firewall-blocklists/blocklist.sources"; done

# Write Keys & Config (CLEAN - No HoneyDB)
cat <<ENV > /usr/local/etc/firewall-blocklist-updater/firewall-blocklist-keys.env
ABUSEIPDB_API_KEY="$ABUSE_KEY"
DYNDNS_HOST="$DYNDNS"
WHITELIST_COUNTRIES="$WL_COUNTRIES"
BLOCKLIST_COUNTRIES="$BL_COUNTRIES"
TELEGRAM_BOT_TOKEN="$TG_TOKEN"
TELEGRAM_CHAT_ID="$TG_CHAT"
ENV
chmod 600 /usr/local/etc/firewall-blocklist-updater/firewall-blocklist-keys.env

# Systemd Service
cat <<SERV > /etc/systemd/system/firewall-blocklist-updater.service
[Unit]
Description=Firewall Blocklist Updater
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-firewall-blocklists.sh
SERV

# Systemd Timer (HOURLY)
cat <<TIME > /etc/systemd/system/firewall-blocklist-updater.timer
[Unit]
Description=Run Firewall Blocklist Updater Hourly

[Timer]
OnCalendar=hourly
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
TIME

systemctl daemon-reload
systemctl enable --now firewall-blocklist-updater.timer

echo ">>> 5. RUNNING INITIAL UPDATE..."
/usr/local/bin/update-firewall-blocklists.sh

echo ""
echo "✅ INSTALLATION COMPLETE!"
echo "   To setup Sensors (Endlessh), run: update-firewall-blocklists.sh --configure"