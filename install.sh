#!/bin/bash
set -e

# --- Firewall & Sensor Installer (v10.0) ---
# - FIX: Deep Clean of Plugin Directory before start
# - FIX: Validates CrowdSec Config before restart
# - LISTS: Full 32 User Sources

# --- CONFIGURATION MAPPING ---
ABUSE_KEY="${ABUSEIPDB_API_KEY:-}"
CS_ENROLL="${CROWDSEC_ENROLL_KEY:-}"
DYNDNS="${DYNDNS_HOST:-}"
WL_COUNTRIES="${WHITELIST_COUNTRIES:-}"
BL_COUNTRIES="${BLOCKLIST_COUNTRIES:-}"
TG_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TG_CHAT="${TELEGRAM_CHAT_ID:-}"

echo "============================================="
echo "   FIREWALL & CROWDSEC INSTALLER (v10.0)     "
echo "============================================="

# --- 1. USER LIST SET ---
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
    "Blocklist.de Export|https://www.blocklist.de/downloads/export-ips_all.txt"
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

# --- 2. SYSTEM CHECK ---
if [[ $EUID -ne 0 ]]; then echo "❌ Error: Run as root."; exit 1; fi

# --- 3. PREPARING ENVIRONMENT ---
echo ">>> 1. INSTALLING DEPENDENCIES..."
if command -v apt-get >/dev/null; then
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do sleep 1; done
    apt-get update -qq
    apt-get install -y curl ipset iptables dnsutils unzip file gnupg iproute2
elif command -v dnf >/dev/null; then
    dnf install -y curl ipset iptables bind-utils unzip file iproute
elif command -v yum >/dev/null; then
    yum install -y curl ipset iptables bind-utils unzip file iproute
elif command -v zypper >/dev/null; then
    zypper install -y curl ipset iptables bind-utils unzip file iproute2
fi

# --- 4. CROWDSEC INSTALLATION ---
CS_INSTALLED=false
if command -v crowdsec >/dev/null; then CS_INSTALLED=true; fi

if [[ -n "$CS_ENROLL" ]] || [[ "$CS_INSTALLED" == "false" ]]; then
    echo ">>> 2. SETTING UP CROWDSEC..."
    
    if [[ "$CS_INSTALLED" == "false" ]]; then
        if [ -f /etc/debian_version ]; then
            curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash 2>/dev/null
            apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables
        elif [ -f /etc/redhat-release ]; then
            curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash 2>/dev/null
            yum install -y crowdsec crowdsec-firewall-bouncer-iptables
        fi
    fi

    # CLEANUP PLUGINS
    if [[ -d "/usr/lib/crowdsec/plugins" ]]; then
        rm -f /usr/lib/crowdsec/plugins/dummy
        rm -f /usr/lib/crowdsec/plugins/install.sh
        rm -f /usr/lib/crowdsec/plugins/update-firewall-blocklists.sh
    fi
    
    if command -v cscli >/dev/null; then
        cscli hub update >/dev/null 2>&1 || true
        cscli notifications update >/dev/null 2>&1 || true
    fi

    # Enroll
    if [[ -n "$CS_ENROLL" ]]; then
        echo " -> Enrolling..."
        cscli console enroll "$CS_ENROLL" --overwrite || true
    fi

    # AbuseIPDB Config
    if [[ -n "$ABUSE_KEY" ]]; then
        mkdir -p /etc/crowdsec/notifications
        cat <<YAML > /etc/crowdsec/notifications/abuseipdb.yaml
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
YAML

        # Add to profile
        if ! grep -q "abuseipdb" /etc/crowdsec/profiles.yaml 2>/dev/null; then
            cat <<YAML > /etc/crowdsec/profiles.yaml
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
YAML
        fi
    fi

    # Install Bouncer
    if ! command -v crowdsec-firewall-bouncer >/dev/null; then
        if command -v apt-get >/dev/null; then apt-get install -y crowdsec-firewall-bouncer-iptables; 
        else yum install -y crowdsec-firewall-bouncer-iptables; fi
    fi
    
    # Check Config & Restart
    if command -v crowdsec >/dev/null; then
        if crowdsec -c /etc/crowdsec/config.yaml -t >/dev/null 2>&1; then
            systemctl restart crowdsec
            systemctl enable --now crowdsec-firewall-bouncer || true
        else
            echo "⚠️ CrowdSec config invalid. Skipping restart."
        fi
    fi
fi

# --- 5. INSTALL UPDATER SCRIPT ---
echo ">>> 3. INSTALLING UPDATER..."
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/usr/local/etc/firewall-blocklist-updater"

mkdir -p "$CONF_DIR/firewall-blocklists"
mkdir -p "$CONF_DIR/backups"

curl -sfL "https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main/update-firewall-blocklists.sh" -o "$INSTALL_DIR/update-firewall-blocklists.sh"
chmod +x "$INSTALL_DIR/update-firewall-blocklists.sh"

# Create Source List
: > "$CONF_DIR/firewall-blocklists/blocklist.sources"
for entry in "${DEFAULT_LISTS[@]}"; do
    echo "${entry#*|}" >> "$CONF_DIR/firewall-blocklists/blocklist.sources"
done

# Create Config File
cat <<ENV > "$CONF_DIR/firewall-blocklist-keys.env"
ABUSEIPDB_API_KEY="$ABUSE_KEY"
DYNDNS_HOST="$DYNDNS"
WHITELIST_COUNTRIES="$WL_COUNTRIES"
BLOCKLIST_COUNTRIES="$BL_COUNTRIES"
TELEGRAM_BOT_TOKEN="$TG_TOKEN"
TELEGRAM_CHAT_ID="$TG_CHAT"
ENV
chmod 600 "$CONF_DIR/firewall-blocklist-keys.env"

# --- 6. SYSTEMD SETUP ---
cat <<SERV > /etc/systemd/system/firewall-blocklist-updater.service
[Unit]
Description=Firewall Blocklist Updater
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/update-firewall-blocklists.sh
SERV

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

# --- 7. INITIAL RUN ---
echo ">>> 4. RUNNING INITIAL UPDATE..."
$INSTALL_DIR/update-firewall-blocklists.sh

echo ""
echo "✅ INSTALLATION COMPLETE!"