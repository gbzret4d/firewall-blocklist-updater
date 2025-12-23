#!/bin/bash
set -e

# --- Advanced Installer (v6.3 - Full List Support) ---
# - Full CrowdSec Integration
# - Supports Environment Variables for Headless Install
# - Fixes CrowdSec Plugin crashes (slack, splunk, http, email)
# - HoneyDB Support added
# - INCLUDES ALL 30+ BLOCKLIST SOURCES

echo "============================================="
echo "   FIREWALL & CROWDSEC INSTALLER (v6.3)      "
echo "============================================="

# --- CONFIG & DEFAULTS ---
# Updated to include ALL lists provided by user
DEFAULT_LISTS=(
    "Spamhaus DROP|https://www.spamhaus.org/drop/drop.txt"
    "Spamhaus EDROP|https://www.spamhaus.org/drop/edrop.txt"
    "Spamhaus IPv6|https://www.spamhaus.org/drop/dropv6.txt"
    "DShield|https://feeds.dshield.org/block.txt"
    "Feodo Tracker|https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    "SSLBL Abuse.ch|https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
    "IPSum Level 3|https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
    "GreenSnow|https://blocklist.greensnow.co/greensnow.txt"
    "GreenSnow (FireHOL)|https://iplists.firehol.org/files/greensnow.ipset"
    "Blocklist.de All|https://lists.blocklist.de/lists/all.txt"
    "Blocklist.de (Export)|https://www.blocklist.de/downloads/export-ips_all.txt"
    "EmergingThreats Block|https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    "EmergingThreats Compromised|https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    "ET Compromised (FireHOL)|https://iplists.firehol.org/files/et_compromised.ipset"
    "BinaryDefense|https://www.binarydefense.com/banlist.txt"
    "BinaryDefense (FireHOL)|https://iplists.firehol.org/files/bds_atif.ipset"
    "BinaryDefense (CPS)|https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/refs/heads/master/binarydefense.txt"
    "AbuseIPDB 100%|https://github.com/borestad/blocklist-abuseipdb/raw/refs/heads/main/abuseipdb-s100-7d.ipv4"
    "BruteForce High|https://github.com/ShadowWhisperer/IPs/raw/refs/heads/master/BruteForce/High"
    "BruteForce Extreme|https://github.com/ShadowWhisperer/IPs/raw/refs/heads/master/BruteForce/Extreme"
    "Malware Hackers|https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Malware/Hackers"
    "Malicious IP (40k)|https://github.com/romainmarcoux/malicious-ip/raw/refs/heads/main/full-40k.txt"
    "Malicious Outgoing (40k)|https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/full-outgoing-ip-40k.txt"
    "ThreatFox IOCs|https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/refs/heads/main/ips.txt"
    "CobaltStrike IPs|https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/cobaltstrike_ips.txt"
    "AlienVault|https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/refs/heads/master/alienvault.txt"
    "CPS Compromised|https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/compromised-ips.txt"
    "Illuminate|https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/illuminate.txt"
    "CINS Score|https://cinsscore.com/list/ci-badguys.txt"
    "Botvrij IOC|http://www.botvrij.eu/data/ioclist.ip-dst.raw"
    "CyberCrime|https://iplists.firehol.org/files/cybercrime.ipset"
    "MyIP (FireHOL)|https://iplists.firehol.org/files/myip.ipset"
)

# --- 1. SYSTEM CHECK ---
echo ">>> 1. SYSTEM CHECK..."
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
HONEY_ID="${HONEYDB_API_ID:-}"
HONEY_KEY="${HONEYDB_API_KEY:-}"
DYNDNS="${DYNDNS_HOST:-}"
WL_COUNTRIES="${WHITELIST_COUNTRIES:-}"
BL_COUNTRIES="${BLOCKLIST_COUNTRIES:-}"

# Logic: Auto-install CrowdSec if Key is provided or already installed
INSTALL_CS="n"
if [[ -n "$CS_ENROLL" ]] || [[ "$CS_INSTALLED" = true ]]; then
    INSTALL_CS="y"
fi

# --- 3. USER INPUT (Only asks if variables are empty) ---
echo ""
echo "--- INSTALLATION OPTIONS ---"

if [ -z "$CS_ENROLL" ] && [ "$CS_INSTALLED" = false ]; then
    read -p "Do you want to install CrowdSec? (Y/n): " DO_CS
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

# HoneyDB
if [ -z "$HONEY_ID" ]; then
    read -p "Enter HoneyDB API ID (Leave EMPTY to skip): " HONEY_ID
fi
if [[ -n "$HONEY_ID" ]] && [ -z "$HONEY_KEY" ]; then
    read -p "Enter HoneyDB API Key: " HONEY_KEY
fi

echo ""
echo "--- BLOCKLIST SELECTION ---"
# Automated mode skips list selection unless interactive
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

# --- 4. EXECUTION ---
echo ""
echo ">>> 2. PREPARING ENVIRONMENT..."
if command -v apt-get >/dev/null; then
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do echo "Waiting for apt lock..."; sleep 2; done
    apt-get update -qq && apt-get install -y curl ipset iptables python3 dnsutils unzip file gnupg
else
    yum install -y curl ipset iptables python3 bind-utils unzip file
fi

# --- 5. CROWDSEC ---
if [ "$INSTALL_CS" = "y" ]; then
    echo ">>> 3. SETTING UP CROWDSEC..."
    if ! command -v crowdsec >/dev/null; then
        if command -v apt-get >/dev/null; then
            curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
            apt-get install -y crowdsec
        else
            curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash
            yum install -y crowdsec
        fi
    fi
    
    # --- CRITICAL FIX: Rename broken plugins (http, email, slack, splunk) ---
    mkdir -p /usr/lib/crowdsec/plugins/
    cd /usr/lib/crowdsec/plugins/ 2>/dev/null || true
    rm dummy 2>/dev/null || true
    for plugin in http email slack splunk; do
        if [[ -f "$plugin" ]]; then
            echo " -> Fixing plugin name: $plugin"
            mv "$plugin" "notification-$plugin" 2>/dev/null || true
        fi
    done
    chmod 755 /usr/lib/crowdsec/plugins/* 2>/dev/null || true
    # --- END FIX ---

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
        
        cat <<PROF > /etc/crowdsec/profiles.yaml
name: default_ip_remediation
debug: false
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 4h
notifications:
 - abuseipdb
on_success: break
PROF
    else
        cat <<PROF > /etc/crowdsec/profiles.yaml
name: default_ip_remediation
debug: false
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 4h
on_success: break
PROF
    fi

    if ! command -v crowdsec-firewall-bouncer >/dev/null; then
        if command -v apt-get >/dev/null; then apt-get install -y crowdsec-firewall-bouncer-iptables; else yum install -y crowdsec-firewall-bouncer-iptables; fi
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

# Write Selected Sources (NOW INCLUDES ALL USER LISTS)
: > "/usr/local/etc/firewall-blocklist-updater/firewall-blocklists/blocklist.sources"
for url in "${SELECTED_URLS[@]}"; do echo "$url" >> "/usr/local/etc/firewall-blocklist-updater/firewall-blocklists/blocklist.sources"; done

# Write Keys & Config
cat <<ENV > /usr/local/etc/firewall-blocklist-updater/firewall-blocklist-keys.env
ABUSEIPDB_API_KEY="$ABUSE_KEY"
HONEYDB_API_ID="$HONEY_ID"
HONEYDB_API_KEY="$HONEY_KEY"
DYNDNS_HOST="$DYNDNS"
WHITELIST_COUNTRIES="$WL_COUNTRIES"
BLOCKLIST_COUNTRIES="$BL_COUNTRIES"
ENV
chmod 600 /usr/local/etc/firewall-blocklist-updater/firewall-blocklist-keys.env

# Systemd Service
cat <<SERV > /etc/systemd/system/firewall-blocklist-updater.service
[Unit]
Description=Firewall Blocklist Updater
After=network.target

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