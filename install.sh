#!/bin/bash
set -e
set -o pipefail

# --- Firewall & Sensor Installer (v14.1 - MERGED) ---
# - PAYLOAD: Includes your specific v11.6 Updater with 43 Lists
# - COMPAT: Debian/Ubuntu/RHEL/CentOS/Rocky/Alma/Fedora
# - FEAT: Auto-Cleanup, Deep Diagnostics, CrowdSec Boost
# - SAFETY: Docker Check, Non-Interactive

export DEBIAN_FRONTEND=noninteractive
CURRENT_TASK="Initializing"

# --- CONFIGURATION MAPPING ---
# Diese Variablen werden in das Updater-Skript übernommen
ABUSE_KEY="${ABUSEIPDB_API_KEY:-}"
CS_ENROLL="${CROWDSEC_ENROLL_KEY:-}"
DYNDNS="${DYNDNS_HOST:-}"
WL_COUNTRIES="${WHITELIST_COUNTRIES:-}"
BL_COUNTRIES="${BLOCKLIST_COUNTRIES:-}"
TG_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TG_CHAT="${TELEGRAM_CHAT_ID:-}"

# --- 0. HELPER FUNCTIONS ---
send_msg() {
    if [[ -n "$TG_TOKEN" && -n "$TG_CHAT" ]]; then
        curl -s -X POST "https://api.telegram.org/bot$TG_TOKEN/sendMessage" \
            -d chat_id="$TG_CHAT" -d text="$1" -d parse_mode="HTML" >/dev/null || true
    fi
}

handle_error() {
    local line=$1
    echo "❌ CRITICAL ERROR at line $line during task: '$CURRENT_TASK'"
    send_msg "🚨 <b>INSTALL CRASHED</b> on <code>$(hostname)</code>%0A%0A<b>Task:</b> $CURRENT_TASK%0A<b>Line:</b> $line%0A<b>OS:</b> $(grep -E '^(ID|PRETTY_NAME)=' /etc/os-release | head -n 1)%0A%0APlease forward this message."
}
trap 'handle_error $LINENO' ERR

echo "============================================="
echo "   FIREWALL & CROWDSEC INSTALLER (v14.1)     "
echo "============================================="

if [[ $EUID -ne 0 ]]; then echo "❌ Error: Run as root."; exit 1; fi

# --- 1. SMART OS DETECTION ---
CURRENT_TASK="Detecting OS & Package Manager"
PM="" 

wait_for_apt() {
    local max_retries=30
    local count=0
    if ! command -v fuser >/dev/null && ! command -v lsof >/dev/null; then return; fi
    while [ $count -lt $max_retries ]; do
        if command -v fuser >/dev/null; then
            if ! fuser /var/lib/dpkg/lock >/dev/null 2>&1 && ! fuser /var/lib/apt/lists/lock >/dev/null 2>&1 && ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then return 0; fi
        else
             if ! lsof /var/lib/dpkg/lock >/dev/null 2>&1; then return 0; fi
        fi
        echo "⏳ Waiting for apt lock... ($count/$max_retries)"
        sleep 2
        ((count++))
    done
    echo "⚠️ Warning: APT lock wait timed out."
}

if command -v apt-get >/dev/null; then
    echo "🔍 Detected: Debian / Ubuntu Family"
    PM="apt-get"
    update_repo() { wait_for_apt; apt-get update -qq; }
    install_pkg() { wait_for_apt; apt-get install -y "$@" || (sleep 5; wait_for_apt; apt-get install -y "$@"); }
    
elif command -v dnf >/dev/null; then
    echo "🔍 Detected: RHEL 8+ / Rocky / Alma / Fedora"
    PM="dnf"
    update_repo() { :; }
    install_pkg() { dnf install -y "$@"; }
    dnf install -y epel-release || true

elif command -v yum >/dev/null; then
    echo "🔍 Detected: Legacy CentOS / RHEL 7"
    PM="yum"
    update_repo() { :; }
    install_pkg() { yum install -y "$@"; }
    yum install -y epel-release || true

else
    echo "❌ CRITICAL: Unsupported OS."
    exit 1
fi

# --- 2. INSTALL DEPENDENCIES & TIME SYNC ---
CURRENT_TASK="Installing Base Dependencies"
echo ">>> 1. INSTALLING DEPENDENCIES via $PM..."

update_repo
install_pkg curl ipset iptables unzip file gnupg iproute logrotate endlessh

if [[ "$PM" == "apt-get" ]]; then
    install_pkg dnsutils apt-transport-https iproute2 psmisc
    systemctl enable --now systemd-timesyncd 2>/dev/null || install_pkg chrony
else
    install_pkg bind-utils iproute chrony
    systemctl enable --now chronyd 2>/dev/null || true
fi

# --- 3. STORAGE OPTIMIZATION ---
CURRENT_TASK="Configuring Log Cleanup"
echo ">>> 2. CONFIGURING AUTO-CLEANUP..."

# A) Limit System Journal
mkdir -p /etc/systemd/journald.conf.d
cat <<EOF > /etc/systemd/journald.conf.d/00-limit-size.conf
[Journal]
SystemMaxUse=500M
SystemMaxFileSize=100M
MaxRetentionSec=2weeks
EOF
systemctl restart systemd-journald || true

# B) Daily Cleanup Script
cat <<EOF > /usr/local/bin/daily-system-cleanup.sh
#!/bin/bash
journalctl --vacuum-size=500M >/dev/null 2>&1
if command -v apt-get >/dev/null; then apt-get clean; elif command -v dnf >/dev/null; then dnf clean all; fi
EOF
chmod +x /usr/local/bin/daily-system-cleanup.sh

# C) Timer setup
cat <<SERV > /etc/systemd/system/daily-system-cleanup.service
[Unit]
Description=Daily System Cleanup
[Service]
Type=oneshot
ExecStart=/usr/local/bin/daily-system-cleanup.sh
SERV

cat <<TIME > /etc/systemd/system/daily-system-cleanup.timer
[Unit]
Description=Run Daily Cleanup
[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true
[Install]
WantedBy=timers.target
TIME

systemctl daemon-reload
systemctl enable --now daily-system-cleanup.timer

# --- 4. CROWDSEC SETUP ---
CURRENT_TASK="CrowdSec Setup"
CS_INSTALLED=false
if command -v crowdsec >/dev/null; then CS_INSTALLED=true; fi

if [[ -n "$CS_ENROLL" ]] || [[ "$CS_INSTALLED" == "false" ]]; then
    echo ">>> 3. SETTING UP CROWDSEC..."
    
    if [[ "$CS_INSTALLED" == "false" ]]; then
        CURRENT_TASK="Installing CrowdSec Repos"
        if [[ "$PM" == "apt-get" ]]; then
            curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash 2>/dev/null
        else
            curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash 2>/dev/null
        fi
        install_pkg crowdsec crowdsec-firewall-bouncer-iptables
    fi

    rm -f /usr/lib/crowdsec/plugins/{dummy,install.sh,update-firewall-blocklists.sh} 2>/dev/null || true
    
    CURRENT_TASK="Waiting for CrowdSec LAPI"
    echo "⏳ Waiting for CrowdSec API to warm up..."
    for i in {1..20}; do
        if systemctl is-active --quiet crowdsec; then
            if cscli lapi status >/dev/null 2>&1; then echo " -> CrowdSec is ready."; break; fi
        fi
        sleep 2
    done

    if command -v cscli >/dev/null; then
        CURRENT_TASK="Installing CS Collections"
        echo " -> Updating Hub..."
        cscli hub update >/dev/null 2>&1 || true
        cscli notifications update >/dev/null 2>&1 || true
        
        cscli collections install crowdsecurity/whitelist-good-actors --force >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/linux --force >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/sshd --force >/dev/null 2>&1 || true
        
        if command -v docker >/dev/null; then
            echo " -> Docker detected. Installing Docker Collection."
            cscli collections install crowdsecurity/docker --force >/dev/null 2>&1 || true
        fi
    fi

    if [[ -n "$CS_ENROLL" ]]; then
        CURRENT_TASK="Enrolling CrowdSec"
        cscli console enroll "$CS_ENROLL" --overwrite || true
    fi

    if [[ -n "$ABUSE_KEY" ]]; then
        CURRENT_TASK="Configuring AbuseIPDB"
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

    if ! command -v crowdsec-firewall-bouncer >/dev/null; then
        install_pkg crowdsec-firewall-bouncer-iptables
    fi
fi

# --- 5. UPDATER INSTALLATION (YOUR V11.6 CODE) ---
CURRENT_TASK="Installing Updater Script"
echo ">>> 4. INSTALLING UPDATER..."
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/usr/local/etc/firewall-blocklist-updater"
mkdir -p "$CONF_DIR/firewall-blocklists" "$CONF_DIR/backups"

# --- WRITE THE UPDATER SCRIPT (v11.6 with 43 lists) ---
cat << 'EOF_UPDATER' > "$INSTALL_DIR/update-firewall-blocklists.sh"
#!/bin/bash
set -euo pipefail
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SCRIPT_VERSION="v11.6"
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="$BASE_DIR/firewall-blocklists"
KEYFILE="${KEYFILE:-$BASE_DIR/firewall-blocklist-keys.env}"
SOURCE_FILE="$CONFIG_DIR/blocklist.sources"
CUSTOM_WL_FILE="$CONFIG_DIR/whitelist.custom"
BACKUP_DIR="$BASE_DIR/backups"
REPO_RAW_URL="https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main/update-firewall-blocklists.sh"
LOCKFILE="/var/run/firewall-updater.lock"
LOGFILE="/var/log/firewall-blocklist-updater.log"
MAX_LOG_SIZE=$((5 * 1024 * 1024))

DRY_RUN=0
IPV6_ENABLED=1
USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

RECOMMENDED_LISTS=(
    "Spamhaus DROP|https://www.spamhaus.org/drop/drop.txt"
    "Spamhaus EDROP|https://www.spamhaus.org/drop/edrop.txt"
    "Spamhaus IPv6|https://www.spamhaus.org/drop/dropv6.txt"
    "DShield|https://feeds.dshield.org/block.txt"
    "Feodo Tracker IPs|https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    "SSLBL Abuse.ch|https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
    "BruteForceBlocker|https://danger.rulez.sk/projects/bruteforceblocker/blist.php"
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
    "Feodo Tracker CSV|https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    "Viriback C2 Tracker|https://tracker.viriback.com/last30.php"
    "Feodo Recommended|https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    "SSLBL RPZ|https://sslbl.abuse.ch/blacklist/sslbl.rpz"
    "CINS Score|https://cinsscore.com/list/ci-badguys.txt"
    "Botvrij IOC|http://www.botvrij.eu/data/ioclist.ip-dst.raw"
    "CyberCrime|https://iplists.firehol.org/files/cybercrime.ipset"
    "MyIP (FireHOL)|https://iplists.firehol.org/files/myip.ipset"
    "FireHOL Level 1|https://iplists.firehol.org/files/firehol_level1.netset"
    "SBLAM|https://iplists.firehol.org/files/sblam.ipset"
    "FireHOL Webclient|https://iplists.firehol.org/files/firehol_webclient.netset"
    "FireHOL Level 2|https://iplists.firehol.org/files/firehol_level2.netset"
    "BotScout 7d|https://iplists.firehol.org/files/botscout_7d.ipset"
)

manage_log_size() {
    if [[ -f "$LOGFILE" ]]; then
        local size=$(stat -c%s "$LOGFILE" 2>/dev/null || stat -f%z "$LOGFILE" 2>/dev/null || echo 0)
        if [[ $size -gt $MAX_LOG_SIZE ]]; then tail -n 2000 "$LOGFILE" > "${LOGFILE}.tmp" && mv "${LOGFILE}.tmp" "$LOGFILE"; fi
    fi
}
log() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" | tee -a "$LOGFILE"; }
warn() { echo -e "\033[0;33m$(date '+%Y-%m-%d %H:%M:%S') [WARN] $*\033[0m" | tee -a "$LOGFILE"; }
dry() { echo -e "\033[0;36m[DRY-RUN] $*\033[0m"; }

cleanup() { rm -f "$LOCKFILE" /tmp/firewall-blocklists/* 2>/dev/null || true; }
trap cleanup EXIT INT TERM

HAS_FLOCK=0; if command -v flock >/dev/null; then HAS_FLOCK=1; fi
mkdir -p "$BASE_DIR" "$CONFIG_DIR" "$BACKUP_DIR" /tmp/firewall-blocklists

check_ipv6_stack() {
    if [[ ! -f /proc/net/if_inet6 ]]; then return 1; fi
    if ! command -v ip6tables >/dev/null; then return 1; fi
    return 0
}

load_env_vars() {
  if [[ -f "$KEYFILE" ]]; then
    set +u; set -a; source "$KEYFILE"; set +a; set -u
    WHITELIST_COUNTRIES=$(echo "${WHITELIST_COUNTRIES:-}" | tr -cd 'A-Za-z ')
    BLOCKLIST_COUNTRIES=$(echo "${BLOCKLIST_COUNTRIES:-}" | tr -cd 'A-Za-z ')
  fi
}
load_env_vars

perform_auto_update() {
  if [[ "${1:-}" == "--post-update" ]]; then log "[AUTO-UPDATE] Update to $SCRIPT_VERSION successful."; return 0; fi
  if [[ $DRY_RUN -eq 1 ]]; then return 0; fi
  # DISABLED SELF-UPDATE TO PREVENT OVERWRITING CUSTOM LISTS
  return 0
}

check_connectivity() {
    if ! curl -s --head --request GET https://1.1.1.1 > /dev/null; then warn "No internet."; exit 0; fi
}

send_telegram() {
    if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" -d text="$1" -d parse_mode="HTML" >/dev/null || true
    fi
}

repair_environment() {
    local HN=$(hostname)
    if ! grep -q "127.0.1.1 $HN" /etc/hosts; then
        echo "127.0.1.1 $HN" >> /etc/hosts
        log "🔧 Fixed missing hostname in /etc/hosts"
    fi
    systemctl stop endlessh.socket >/dev/null 2>&1 || true
    systemctl disable endlessh.socket >/dev/null 2>&1 || true
}

# --- CROWDSEC API RESCUE ---
fix_crowdsec_api() {
    log "🚑 CrowdSec API Rescue Mode..."
    local API_PORT=0
    for (( p=42000; p<=42010; p++ )); do
        if ! ss -tuln | grep -q ":$p "; then API_PORT=$p; break; fi
    done
    if [[ $API_PORT -eq 0 ]]; then 
        warn "❌ Fatal: Could not find free port in 42000-42010 range."
        return 1
    fi
    log "🔍 Selected CrowdSec API Port: $API_PORT (Localhost Only)"
    sed -i "s/127.0.0.1:[0-9]\{4,5\}/127.0.0.1:$API_PORT/g" /etc/crowdsec/config.yaml
    sed -i "s/127.0.0.1:[0-9]\{4,5\}/127.0.0.1:$API_PORT/g" /etc/crowdsec/local_api_credentials.yaml
    if [[ -f "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml" ]]; then
        sed -i "s/127.0.0.1:[0-9]\{4,5\}/127.0.0.1:$API_PORT/g" /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        log "🔧 Updated Bouncer config to Port $API_PORT"
    fi
    if ! cscli machines list -o json 2>/dev/null | grep -q "login"; then
        log "Regenerating machine credentials..."
        cscli machines add --auto --force --file /etc/crowdsec/local_api_credentials.yaml || true
    fi
}

install_sensors() {
    repair_environment
    echo ">>> Installing Sensors..."
    
    local EL_PORT=0
    for (( p=2222; p<=2232; p++ )); do
        if ! ss -tuln | grep -q ":$p "; then EL_PORT=$p; break; else
            local PID=$(ss -lptn "sport = :$p" | grep -o 'pid=[0-9]*' | cut -d= -f2 | head -n1 || true)
            local PNAME=""; if [[ -n "$PID" ]]; then PNAME=$(ps -p "$PID" -o comm= 2>/dev/null || echo "unknown"); fi
            if [[ "$PNAME" == "endlessh" ]]; then kill "$PID" 2>/dev/null || true; sleep 1; EL_PORT=$p; break; fi
        fi
    done

    if [[ $EL_PORT -eq 0 ]]; then warn "❌ ERROR: No free ports found 2222-2232!"; return 1; fi

    if ! command -v endlessh >/dev/null; then
        if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y endlessh
        elif command -v yum >/dev/null; then yum install -y endlessh; fi
    fi

    mkdir -p /etc/endlessh
    if [[ -d /etc/endlessh ]]; then
        echo "Port $EL_PORT" > /etc/endlessh/config
        echo "Delay 10000" >> /etc/endlessh/config
        echo "LogLevel 1" >> /etc/endlessh/config
        echo "BindFamily 4" >> /etc/endlessh/config
        
        cat <<SERV > /lib/systemd/system/endlessh.service
[Unit]
Description=Endlessh SSH Tarpit (Custom)
Documentation=man:endlessh(1)
Requires=network-online.target
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=30s
ExecStart=/usr/bin/endlessh -v -f /etc/endlessh/config
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes

[Install]
WantedBy=multi-user.target
SERV
        systemctl daemon-reload
        if ! systemctl enable --now endlessh; then warn "Endlessh failed start on $EL_PORT"; else systemctl restart endlessh; log "✅ Endlessh running on port $EL_PORT"; fi
    fi

    if command -v cscli >/dev/null; then
        cscli collections install crowdsecurity/endlessh --force >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/iptables --force >/dev/null 2>&1 || true
        
        if ! grep -q "type: endlessh" /etc/crowdsec/acquis.yaml 2>/dev/null; then
            echo " -> Adding Sensor config to CrowdSec..."
            cp /etc/crowdsec/acquis.yaml /etc/crowdsec/acquis.yaml.bak 2>/dev/null || true
            echo "" >> /etc/crowdsec/acquis.yaml
            if [[ -s /etc/crowdsec/acquis.yaml ]]; then echo "---" >> /etc/crowdsec/acquis.yaml; fi
            cat <<YAML >> /etc/crowdsec/acquis.yaml
filenames:
  - /var/log/syslog
  - /var/log/messages
labels:
  type: endlessh
YAML
            rm -f /usr/lib/crowdsec/plugins/* 2>/dev/null || true
            if crowdsec -c /etc/crowdsec/config.yaml -t >/dev/null 2>&1; then
                systemctl restart crowdsec
                echo "✅ Sensors Configured."
            else
                echo "❌ Config invalid. Starting EMERGENCY REPAIR (API Rescue)..."
                fix_crowdsec_api
                rm -f /usr/lib/crowdsec/plugins/* 2>/dev/null || true
                cat <<YAML_CLEAN > /etc/crowdsec/acquis.yaml
filenames:
  - /var/log/auth.log
  - /var/log/syslog
labels:
  type: syslog
---
YAML_CLEAN
                echo "" >> /etc/crowdsec/acquis.yaml
                cat <<YAML_APPEND >> /etc/crowdsec/acquis.yaml
filenames:
  - /var/log/syslog
  - /var/log/messages
labels:
  type: endlessh
YAML_APPEND
                systemctl restart crowdsec
                systemctl restart crowdsec-firewall-bouncer || true
                if systemctl is-active --quiet crowdsec; then
                    log "✅ CrowdSec successfully repaired and restarted."
                else
                    warn "❌ CrowdSec repair failed. Please check logs manually."
                fi
            fi
        fi
    fi
}

menu_geo() {
    echo -e "\n--- 🌍 Geo-Blocking Settings ---"
    read -p "Whitelist Countries (e.g. DE AT): " wl
    if [[ -n "$wl" ]]; then sed -i "s|^WHITELIST_COUNTRIES=.*|WHITELIST_COUNTRIES=\"$wl\"|" "$KEYFILE"; fi
    read -p "Blocklist Countries (e.g. CN RU): " bl
    if [[ -n "$bl" ]]; then sed -i "s|^BLOCKLIST_COUNTRIES=.*|BLOCKLIST_COUNTRIES=\"$bl\"|" "$KEYFILE"; fi
}

menu_lists() {
    echo -e "\n--- 📋 Manage Blocklist Sources ---"
    [[ ! -f "$SOURCE_FILE" ]] && touch "$SOURCE_FILE"
    local current_content=$(cat "$SOURCE_FILE")
    local new_content=""
    echo "Select lists to ENABLE (y) or DISABLE (n/Enter):"
    for entry in "${RECOMMENDED_LISTS[@]}"; do
        local name="${entry%%|*}"
        local url="${entry#*|}"
        if echo "$current_content" | grep -Fq "$url"; then
            read -p "$(echo -e "[\033[1;32mx\033[0m] $name") - Keep? (Y/n): " yn
            if [[ ! "$yn" =~ ^[Nn]$ ]]; then new_content+="$url"$'\n'; fi
        else
            read -p "$(echo -e "[ ] $name") - Enable? (y/N): " yn
            if [[ "$yn" =~ ^[Yy]$ ]]; then new_content+="$url"$'\n'; fi
        fi
    done
    echo "$new_content" > "$SOURCE_FILE"; echo "✅ Selection saved."
}

interactive_menu() {
    while true; do
        clear
        echo "=== Firewall Admin Menu ($SCRIPT_VERSION) ==="
        echo "1) 🌍 Geo-Blocking"
        echo "2) 📋 Select Blocklists"
        echo "3) 🪤 Install Sensors"
        echo "4) 🔄 Run Update NOW"
        echo "0) Exit"
        read -p "Select: " opt
        case $opt in
            1) menu_geo ;;
            2) menu_lists ;;
            3) install_sensors; read -p "Press Enter..." ;;
            4) main; read -p "Press Enter..." ;;
            0) exit 0 ;;
        esac
    done
}

TMPDIR="/tmp/firewall-blocklists"
IPSET_WL="allowed_whitelist"; IPSET_BL="blocklist_all"
IPSET_HASH_SIZE=4096; IPSET_MAX_ELEM=2000000

get_set_count() { ipset list "$1" -t 2>/dev/null | grep "Number of entries" | cut -d: -f2 | tr -d ' ' || echo 0; }

smart_extract() {
    local f="$1"
    if gzip -t "$f" 2>/dev/null; then zcat "$f"; elif unzip -t "$f" 2>/dev/null; then unzip -p "$f"; else cat "$f"; fi
}

download_lists() {
  local out="$1"; shift; local srcs=("$@")
  : > "$TMPDIR/merge.lst"
  for u in "${srcs[@]}"; do
      local f=$(basename "$u" | sed "s/[^a-zA-Z0-9._-]/_/g")
      if curl -sfL --connect-timeout 10 --retry 1 -A "$USER_AGENT" "$u" -o "$TMPDIR/$f"; then
          if [[ -s "$TMPDIR/$f" ]]; then
              smart_extract "$TMPDIR/$f" >> "$TMPDIR/merge.lst" || true
              echo "" >> "$TMPDIR/merge.lst"
          fi
      fi
  done
  sed -i 's/[#;].*//g' "$TMPDIR/merge.lst"
  sort -u "$TMPDIR/merge.lst" > "$out"
}

extract_ips() {
    local input="$1"; local output="$2"; local family="$3"
    [[ ! -f "$input" ]] && touch "$output" && return 0
    if [[ "$family" == "inet" ]]; then
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$input" | awk -F'[./]' '{valid=1; for(i=1;i<=4;i++)if($i>255)valid=0; if(NF>4&&$NF>32)valid=0; if(valid)print $0}' | grep -vE "^0\.0\.0\.0$" > "$output" || true
    else
        grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?' "$input" | grep -vE "^::" > "$output" || true
    fi
}

load_ipset() {
  local file="$1"; local setname="$2"; local family="$3"
  if [[ "$family" == "inet6" && $IPV6_ENABLED -eq 0 ]]; then return 0; fi
  ipset create $setname hash:net family $family hashsize $IPSET_HASH_SIZE maxelem $IPSET_MAX_ELEM -exist 2>/dev/null || true
  if [[ ! -s "$file" ]]; then ipset flush $setname 2>/dev/null || true; return 0; fi
  ipset flush "${setname}_tmp" 2>/dev/null || ipset create "${setname}_tmp" hash:net family $family hashsize $IPSET_HASH_SIZE maxelem $IPSET_MAX_ELEM -exist
  if ! sed "s/^/add ${setname}_tmp /" "$file" | ipset restore -! 2>/dev/null; then
      warn "Partial ipset restore for $setname"
  fi
  ipset swap "${setname}_tmp" "$setname"
  ipset destroy "${setname}_tmp" 2>/dev/null || true
}

update_dyndns() {
  [[ -z "$DYNDNS_HOST" ]] && return 0
  local ip=$(dig +short "$DYNDNS_HOST" | head -n1 || true)
  if [[ -n "$ip" ]]; then
     local t="$IPSET_WL"; [[ "$ip" =~ : ]] && t="${IPSET_WL}_v6"
     ipset add "$t" "$ip" -exist 2>/dev/null || true
  fi
}

main() {
  if [[ "${1:-}" == "--dry-run" ]]; then DRY_RUN=1; echo "⚠️ DRY-RUN"; fi
  if [[ "${1:-}" == "--setup-sensors" ]]; then install_sensors; exit 0; fi

  [[ "${1:-}" != "--post-update" && "${1:-}" != "--configure" && $DRY_RUN -eq 0 ]] && perform_auto_update "${1:-}"
  manage_log_size
  log "=== Update Start $SCRIPT_VERSION ==="
  repair_environment
  
  if [[ $HAS_FLOCK -eq 1 && $DRY_RUN -eq 0 ]]; then 
      exec 9>"$LOCKFILE"
      if ! flock -n 9; then echo "[ERROR] Locked."; exit 1; fi
  fi
  
  check_connectivity
  if check_ipv6_stack; then IPV6_ENABLED=1; log "ℹ️ IPv6 Support detected (Kernel)."; else IPV6_ENABLED=0; log "ℹ️ No IPv6 Support detected. Skipping."; fi
  
  local cnt_old_v4=$(get_set_count "$IPSET_BL")
  local cnt_old_v6=$(get_set_count "${IPSET_BL}_v6")

  log "Processing..."
  : > "$TMPDIR/wl_raw.lst"
  local wl=(); [[ -f "$CONFIG_DIR/whitelist.sources" ]] && mapfile -t wl < <(grep -vE '^\s*#' "$CONFIG_DIR/whitelist.sources" || true)
  for c in $WHITELIST_COUNTRIES; do wl+=("https://iplists.firehol.org/files/geolite2_country/country_${c,,}.netset"); done
  download_lists "$TMPDIR/wl_raw.lst" "${wl[@]}"
  [[ -f "$CUSTOM_WL_FILE" ]] && cat "$CUSTOM_WL_FILE" >> "$TMPDIR/wl_raw.lst"
  extract_ips "$TMPDIR/wl_raw.lst" "$TMPDIR/wl.v4" "inet"
  extract_ips "$TMPDIR/wl_raw.lst" "$TMPDIR/wl.v6" "inet6"

  local bl=(); [[ -f "$CONFIG_DIR/blocklist.sources" ]] && mapfile -t bl < <(grep -vE '^\s*#' "$CONFIG_DIR/blocklist.sources" || true)
  for c in $BLOCKLIST_COUNTRIES; do bl+=("https://iplists.firehol.org/files/geolite2_country/country_${c,,}.netset"); done
  download_lists "$TMPDIR/bl_raw.lst" "${bl[@]}"
  
  local line_count=$(wc -l < "$TMPDIR/bl_raw.lst" || echo 0)
  if [[ $line_count -lt 10000 ]]; then
      warn "⚠️ SAFETY STOP: Only $line_count IPs found. Keeping old rules."
      if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]]; then send_telegram "⚠️ Update Skipped: Too few IPs ($line_count)"; fi
      exit 0
  fi
  
  extract_ips "$TMPDIR/bl_raw.lst" "$TMPDIR/bl.v4" "inet"
  extract_ips "$TMPDIR/bl_raw.lst" "$TMPDIR/bl.v6" "inet6"

  grep -vE "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)" "$TMPDIR/bl.v4" | sort -u | comm -23 - <(sort -u "$TMPDIR/wl.v4") > "$TMPDIR/bl_final.v4" || true
  sort -u "$TMPDIR/bl.v6" | comm -23 - <(sort -u "$TMPDIR/wl.v6") > "$TMPDIR/bl_final.v6" || true

  load_ipset "$TMPDIR/wl.v4" "$IPSET_WL" "inet"
  load_ipset "$TMPDIR/bl_final.v4" "$IPSET_BL" "inet"
  load_ipset "$TMPDIR/wl.v6" "${IPSET_WL}_v6" "inet6"
  load_ipset "$TMPDIR/bl_final.v6" "${IPSET_BL}_v6" "inet6"

  if [[ $DRY_RUN -eq 0 ]]; then
      iptables -C INPUT -m set --match-set "$IPSET_BL" src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set "$IPSET_BL" src -j DROP
      if iptables -L DOCKER-USER >/dev/null 2>&1; then
          iptables -C DOCKER-USER -m set --match-set "$IPSET_BL" src -j DROP 2>/dev/null || iptables -I DOCKER-USER -m set --match-set "$IPSET_BL" src -j DROP
      fi
      if [[ $IPV6_ENABLED -eq 1 ]]; then
          command -v ip6tables >/dev/null && { ip6tables -C INPUT -m set --match-set "${IPSET_BL}_v6" src -j DROP 2>/dev/null || ip6tables -I INPUT -m set --match-set "${IPSET_BL}_v6" src -j DROP; }
      fi
      if command -v crowdsec >/dev/null; then
          iptables -C INPUT -m limit --limit 10/min -j LOG --log-prefix "IPTables-Dropped: " 2>/dev/null || iptables -A INPUT -m limit --limit 10/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
      fi
  fi
  
  update_dyndns
  local cnt_new_v4=$(get_set_count "$IPSET_BL")
  local cnt_new_v6=$(get_set_count "${IPSET_BL}_v6")
  local diff_v4=$((cnt_new_v4 - cnt_old_v4))
  log "Finished [IPv4: $cnt_new_v4 ($diff_v4), IPv6: $cnt_new_v6]"
  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]]; then send_telegram "🛡️ Update: IPv4 $cnt_new_v4 ($diff_v4)"; fi
}

[[ "${1:-}" == "--configure" || "${1:-}" == "-i" ]] && interactive_menu
main "${1:-}"
EOF_UPDATER
chmod +x "$INSTALL_DIR/update-firewall-blocklists.sh"

# Logrotate for Updater (Keeps logs clean)
cat <<LOG > /etc/logrotate.d/firewall-blocklist-updater
/var/log/firewall-blocklist-updater.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root root
}
LOG

touch "$CONF_DIR/firewall-blocklists/blocklist.sources"
cat <<ENV > "$CONF_DIR/firewall-blocklist-keys.env"
ABUSEIPDB_API_KEY="$ABUSE_KEY"
DYNDNS_HOST="$DYNDNS"
WHITELIST_COUNTRIES="$WL_COUNTRIES"
BLOCKLIST_COUNTRIES="$BL_COUNTRIES"
TELEGRAM_BOT_TOKEN="$TG_TOKEN"
TELEGRAM_CHAT_ID="$TG_CHAT"
ENV
chmod 600 "$CONF_DIR/firewall-blocklist-keys.env"

# Services
cat <<SERV > /etc/systemd/system/firewall-blocklist-updater.service
[Unit]
Description=Firewall Blocklist Updater
After=network.target network-online.target
Wants=network-online.target
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
systemctl enable --now firewall-blocklist-updater.service
systemctl enable --now firewall-blocklist-updater.timer

# --- 6. ENDLESSH CONFIGURATION ---
CURRENT_TASK="Configuring Endlessh"
echo ">>> 5. CONFIGURING ENDLESSH..."
# Ensure Endlessh is configured properly
if command -v endlessh >/dev/null; then
    mkdir -p /etc/endlessh
    echo "Port 2222" > /etc/endlessh/config
    echo "Delay 10000" >> /etc/endlessh/config
    echo "LogLevel 1" >> /etc/endlessh/config
    echo "BindFamily 4" >> /etc/endlessh/config
    
    # Enable and Restart to load config
    systemctl enable endlessh 2>/dev/null || true
    systemctl restart endlessh 2>/dev/null || true
    echo " -> Endlessh configured on Port 2222."
fi

CURRENT_TASK="Running Initial Update"
echo ">>> 6. RUNNING INITIAL UPDATE..."
$INSTALL_DIR/update-firewall-blocklists.sh

# --- 7. HEALTH CHECK ---
CURRENT_TASK="Final Diagnostics"
echo ">>> 7. FINAL HEALTH CHECK..."
FAILED_SERVICES=""
get_status() { systemctl is-active --quiet $1 && echo "Active" || echo "Failed"; }

[[ "$(get_status crowdsec)" == "Active" ]] && echo "✅ CrowdSec: OK" || { echo "❌ CrowdSec: FAIL"; FAILED_SERVICES+="- CrowdSec%0A"; }
[[ "$(get_status endlessh)" == "Active" ]] && echo "✅ Endlessh: OK" || { echo "❌ Endlessh: FAIL"; FAILED_SERVICES+="- Endlessh%0A"; }
[[ "$(get_status daily-system-cleanup.timer)" == "Active" ]] && echo "✅ Cleanup: OK" || { echo "❌ Cleanup: FAIL"; FAILED_SERVICES+="- Cleanup Timer%0A"; }

# Docker IPTables Check
if command -v iptables >/dev/null && iptables -L DOCKER-USER >/dev/null 2>&1; then
    if iptables -C DOCKER-USER -m set --match-set blocklist_all src -j DROP 2>/dev/null; then
        echo "✅ Docker Protection: OK"
    else
        echo "⚠️ Docker Protection: Rule Missing"
    fi
fi

if [[ -n "$FAILED_SERVICES" ]]; then
    send_msg "⚠️ <b>INSTALL WARNING</b> on <code>$(hostname)</code>%0A%0AThe following services failed:%0A$FAILED_SERVICES"
    echo "⚠️ Warnings sent to Telegram."
else
    echo "✅ INSTALLATION COMPLETE!"
fi