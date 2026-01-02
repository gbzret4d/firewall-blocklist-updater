#!/bin/bash
# INSTALLER: Strict mode
set -e
set -o pipefail

# --- FIREWALL & CROWDSEC INSTALLER (v17.32 - CLEAN SLATE) ---
# - ACTION: Removes old scripts/configs before installing.
# - FEAT: AbuseIPDB Reporting Bridge (CrowdSec -> AbuseIPDB).
# - FEAT: Docker Support (IPTables DOCKER-USER chain & CS Collection).
# - OS: Legacy Debian/Ubuntu compatible.

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a 
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
INSTALLER_VERSION="v17.32"

# --- 1. CONFIGURATION ---
# Keys werden übernommen oder aus alten Configs gerettet, falls vorhanden
EXISTING_CONF="/usr/local/etc/firewall-blocklist-updater/firewall-blocklist-keys.env"
if [[ -f "$EXISTING_CONF" ]]; then
    set +e; source "$EXISTING_CONF"; set -e
fi

# Hier deine Keys eintragen oder als Umgebungsvariable übergeben
ABUSE_KEY="${ABUSEIPDB_API_KEY:-${ABUSEIPDB_API_KEY:-}}"
CS_ENROLL="${CROWDSEC_ENROLL_KEY:-${CROWDSEC_ENROLL_KEY:-}}"
DYNDNS="${DYNDNS_HOST:-${DYNDNS_HOST:-}}"
WL_COUNTRIES="${WHITELIST_COUNTRIES:-${WHITELIST_COUNTRIES:-AT}}" 
BL_COUNTRIES="${BLOCKLIST_COUNTRIES:-${BLOCKLIST_COUNTRIES:-}}"
TG_TOKEN="${TELEGRAM_BOT_TOKEN:-${TELEGRAM_BOT_TOKEN:-}}"
TG_CHAT="${TELEGRAM_CHAT_ID:-${TELEGRAM_CHAT_ID:-}}"
REPO_URL="https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main"

# --- 2. THE CLEANUP (KILL SWITCH) ---
echo "🧹 Cleaning up old installations..."
# Stop Services
systemctl stop firewall-blocklist-updater.timer firewall-blocklist-updater.service endlessh crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
systemctl disable firewall-blocklist-updater.timer firewall-blocklist-updater.service 2>/dev/null || true

# Remove Files
rm -rf /usr/local/bin/update-firewall-blocklists.sh
rm -rf /etc/systemd/system/firewall-blocklist-updater.*
rm -f /var/run/firewall-updater.lock
rm -rf /tmp/firewall-blocklists

# Flush Firewall (Safety: Allow Input first)
iptables -P INPUT ACCEPT
iptables -F
iptables -X
if command -v ipset >/dev/null; then 
    ipset destroy blocklist_all 2>/dev/null || true
    ipset destroy allowed_whitelist 2>/dev/null || true
    ipset flush 2>/dev/null || true
fi
# Restore Safety Rule for SSH
iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- 3. SYSTEM PREP ---
echo "📦 Installing Dependencies..."
# DNS Fix
if ! ping -c 1 -W 2 google.com >/dev/null 2>&1; then
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
fi

# Package Install
if command -v apt-get >/dev/null; then
    apt-get update -qq || true
    apt-get install -y curl wget ipset iptables unzip dnsutils gnupg logrotate || true
    # Install Endlessh if missing
    if ! command -v endlessh >/dev/null; then apt-get install -y endlessh || true; fi
elif command -v yum >/dev/null; then
    yum install -y curl wget ipset iptables unzip bind-utils endlessh
fi

# --- 4. CROWDSEC SETUP ---
echo "🛡️ Setting up CrowdSec..."
CS_INSTALLED=false
if command -v crowdsec >/dev/null; then CS_INSTALLED=true; fi

if [[ "$CS_INSTALLED" == "false" ]]; then
    curl -s -4 https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash 2>/dev/null || true
    if command -v apt-get >/dev/null; then
        apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables || true
    else
        yum install -y crowdsec crowdsec-firewall-bouncer-iptables || true
    fi
fi

# FIX: Plugin Crashes (History Fix)
rm -f /usr/lib/crowdsec/plugins/dummy 2>/dev/null || true
for plugin in http email slack splunk; do
    if [[ -f "/usr/lib/crowdsec/plugins/$plugin" ]]; then
        mv "/usr/lib/crowdsec/plugins/$plugin" "/usr/lib/crowdsec/plugins/notification-$plugin" 2>/dev/null || true
    fi
done

# CONFIG: AbuseIPDB Bridge
if [[ -n "$ABUSE_KEY" ]]; then
    echo "🌉 Building AbuseIPDB Bridge..."
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
    # Activate in profiles.yaml
    if ! grep -q "abuseipdb" /etc/crowdsec/profiles.yaml 2>/dev/null; then
        # Simple append if not present (assuming default structure)
        if grep -q "notifications:" /etc/crowdsec/profiles.yaml; then
            sed -i '/notifications:/a \ - abuseipdb' /etc/crowdsec/profiles.yaml
        else
            echo -e "notifications:\n - abuseipdb" >> /etc/crowdsec/profiles.yaml
        fi
    fi
fi

# CONFIG: Docker
if command -v docker >/dev/null; then
    echo "🐳 Docker detected. Installing CrowdSec Docker Collection..."
    cscli collections install crowdsecurity/docker --force >/dev/null 2>&1 || true
    systemctl restart crowdsec
fi

# Enrollment
if [[ -n "$CS_ENROLL" ]]; then 
    cscli console enroll "$CS_ENROLL" --overwrite || true
fi
systemctl enable --now crowdsec || true
systemctl restart crowdsec || true

# --- 5. UPDATER SETUP ---
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/usr/local/etc/firewall-blocklist-updater"
mkdir -p "$CONF_DIR/firewall-blocklists" "$CONF_DIR/backups"

# --- SOURCES (Your Full 32 List) ---
cat <<SOURCES > "$CONF_DIR/firewall-blocklists/blocklist.sources"
https://www.spamhaus.org/drop/drop.txt
https://www.spamhaus.org/drop/edrop.txt
https://www.spamhaus.org/drop/dropv6.txt
https://feeds.dshield.org/block.txt
https://feodotracker.abuse.ch/downloads/ipblocklist.txt
https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt
https://blocklist.greensnow.co/greensnow.txt
https://iplists.firehol.org/files/greensnow.ipset
https://lists.blocklist.de/lists/all.txt
https://www.blocklist.de/downloads/export-ips_all.txt
https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
https://rules.emergingthreats.net/blockrules/compromised-ips.txt
https://iplists.firehol.org/files/et_compromised.ipset
https://www.binarydefense.com/banlist.txt
https://iplists.firehol.org/files/bds_atif.ipset
https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/refs/heads/master/binarydefense.txt
https://github.com/borestad/blocklist-abuseipdb/raw/refs/heads/main/abuseipdb-s100-7d.ipv4
https://github.com/ShadowWhisperer/IPs/raw/refs/heads/master/BruteForce/High
https://github.com/ShadowWhisperer/IPs/raw/refs/heads/master/BruteForce/Extreme
https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Malware/Hackers
https://github.com/romainmarcoux/malicious-ip/raw/refs/heads/main/full-40k.txt
https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/full-outgoing-ip-40k.txt
https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/refs/heads/main/ips.txt
https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/cobaltstrike_ips.txt
https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/refs/heads/master/alienvault.txt
https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/compromised-ips.txt
https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/illuminate.txt
https://cinsscore.com/list/ci-badguys.txt
http://www.botvrij.eu/data/ioclist.ip-dst.raw
https://iplists.firehol.org/files/cybercrime.ipset
https://iplists.firehol.org/files/myip.ipset
https://iplists.firehol.org/files/firehol_level1.netset
https://iplists.firehol.org/files/sblam.ipset
https://iplists.firehol.org/files/firehol_webclient.netset
https://iplists.firehol.org/files/firehol_level2.netset
https://iplists.firehol.org/files/botscout_7d.ipset
SOURCES

# --- UPDATER SCRIPT ---
cat << EOF_UPDATER > "$INSTALL_DIR/update-firewall-blocklists.sh"
#!/bin/bash
# v17.32 - Clean Install Version
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="\$BASE_DIR/firewall-blocklists"
KEYFILE="\${KEYFILE:-\$BASE_DIR/firewall-blocklist-keys.env}"
LOGFILE="/var/log/firewall-blocklist-updater.log"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Logging
log() { echo -e "\$(date '+%Y-%m-%d %H:%M:%S') [INFO] \$*" | tee -a "\$LOGFILE"; }

# Load Keys
if [[ -f "\$KEYFILE" ]]; then set -a; source "\$KEYFILE"; set +a; fi

# Telegram (Error Only)
send_telegram() { 
    if [[ -n "\${TELEGRAM_BOT_TOKEN:-}" && -n "\${TELEGRAM_CHAT_ID:-}" ]]; then 
        local MSG="<b>[\$(hostname)]</b> \$1"
        curl -s -4 -X POST "https://api.telegram.org/bot\$TELEGRAM_BOT_TOKEN/sendMessage" -d chat_id="\$TELEGRAM_CHAT_ID" -d text="\$MSG" -d parse_mode="HTML" >/dev/null || true
    fi 
}

# Lock
LOCKFILE="/var/run/firewall-updater.lock"
if [ -f "\$LOCKFILE" ]; then
    if [ \$(find "\$LOCKFILE" -mmin +20) ]; then rm -f "\$LOCKFILE"; else exit 0; fi
fi
touch "\$LOCKFILE"
trap 'rm -f "\$LOCKFILE" /tmp/firewall-blocklists/*' EXIT

mkdir -p "\$BASE_DIR" "\$CONFIG_DIR" /tmp/firewall-blocklists

# Helper
extract_ips() {
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "\$1" | grep -vE "^0\.0\.0\.0$" > "\$2" || true
}

# 1. Whitelist
: > "\$TMPDIR/wl_raw.lst"
for c in \${WHITELIST_COUNTRIES:-}; do 
    curl -sfL -4 "https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset" >> "\$TMPDIR/wl_raw.lst" || true
done
if [[ -n "\$DYNDNS_HOST" ]]; then dig +short "\$DYNDNS_HOST" >> "\$TMPDIR/wl_raw.lst" || true; fi
extract_ips "\$TMPDIR/wl_raw.lst" "\$TMPDIR/wl.v4"

# 2. Blocklist (Wget Batch)
: > "\$TMPDIR/bl_raw.lst"
: > "\$TMPDIR/urls_clean.txt"
if [[ -f "\$CONFIG_DIR/blocklist.sources" ]]; then
    grep -vE "^\s*#|^$" "\$CONFIG_DIR/blocklist.sources" | tr -d '\r' > "\$TMPDIR/urls_clean.txt"
    wget --inet4-only --timeout=15 --tries=2 --user-agent="\$USER_AGENT" -i "\$TMPDIR/urls_clean.txt" -O - >> "\$TMPDIR/bl_raw.lst" 2>/dev/null || true
fi
for c in \${BLOCKLIST_COUNTRIES:-}; do 
    curl -sfL -4 "https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset" >> "\$TMPDIR/bl_raw.lst" || true
done
extract_ips "\$TMPDIR/bl_raw.lst" "\$TMPDIR/bl.v4"

# Filter
comm -23 <(sort "\$TMPDIR/bl.v4") <(sort "\$TMPDIR/wl.v4") > "\$TMPDIR/bl_final.v4"

# Load IPSet
ipset create allowed_whitelist hash:net family inet hashsize 4096 maxelem 2000000 -exist 2>/dev/null || true
ipset flush allowed_whitelist
sed "s/^/add allowed_whitelist /" "\$TMPDIR/wl.v4" | ipset restore -! 2>/dev/null

ipset create blocklist_all hash:net family inet hashsize 4096 maxelem 2000000 -exist 2>/dev/null || true
ipset create blocklist_tmp hash:net family inet hashsize 4096 maxelem 2000000 -exist 2>/dev/null || true
ipset flush blocklist_tmp
sed "s/^/add blocklist_tmp /" "\$TMPDIR/bl_final.v4" | ipset restore -! 2>/dev/null
ipset swap blocklist_tmp blocklist_all
ipset destroy blocklist_tmp 2>/dev/null || true

# Apply Rules
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C INPUT -m set --match-set allowed_whitelist src -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -m set --match-set allowed_whitelist src -j ACCEPT
iptables -C INPUT -m set --match-set blocklist_all src -j DROP 2>/dev/null || iptables -A INPUT -m set --match-set blocklist_all src -j DROP

# Docker Rules (Insert if Docker exists)
if iptables -L DOCKER-USER >/dev/null 2>&1; then
    iptables -C DOCKER-USER -m set --match-set allowed_whitelist src -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -m set --match-set allowed_whitelist src -j ACCEPT
    iptables -C DOCKER-USER -m set --match-set blocklist_all src -j DROP 2>/dev/null || iptables -A DOCKER-USER -m set --match-set blocklist_all src -j DROP
fi

count=\$(ipset list blocklist_all -t | grep "Number of entries" | cut -d: -f2)
log "Finished. Blocked IPv4: \$count"

if [[ "\$count" -lt 10000 ]]; then
    send_telegram "⚠️ WARNING: Low blocklist count (\$count). Check logs."
fi
EOF_UPDATER
chmod +x "$INSTALL_DIR/update-firewall-blocklists.sh"

# --- 6. KEYS ---
cat <<ENV > "$CONF_DIR/firewall-blocklist-keys.env"
ABUSEIPDB_API_KEY="$ABUSE_KEY"
DYNDNS_HOST="$DYNDNS"
WHITELIST_COUNTRIES="$WL_COUNTRIES"
BLOCKLIST_COUNTRIES="$BL_COUNTRIES"
TELEGRAM_BOT_TOKEN="$TG_TOKEN"
TELEGRAM_CHAT_ID="$TG_CHAT"
ENV
chmod 600 "$CONF_DIR/firewall-blocklist-keys.env"

# --- 7. SERVICES ---
cat <<SERV > /etc/systemd/system/firewall-blocklist-updater.service
[Unit]
Description=Firewall Blocklist Updater
After=network.target network-online.target
[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/update-firewall-blocklists.sh
[Install]
WantedBy=multi-user.target
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

# Endlessh Service
cat <<SERV > /lib/systemd/system/endlessh.service
[Unit]
Description=Endlessh SSH Tarpit
After=network.target
[Service]
Type=simple
Restart=always
ExecStart=/usr/bin/endlessh -v -p 2222
[Install]
WantedBy=multi-user.target
SERV
systemctl daemon-reload
if command -v endlessh >/dev/null; then systemctl enable --now endlessh || true; fi

echo "🚀 Running initial update (this takes time)..."
$INSTALL_DIR/update-firewall-blocklists.sh

echo "✅ INSTALLATION COMPLETE! (AbuseIPDB Bridge Active)"