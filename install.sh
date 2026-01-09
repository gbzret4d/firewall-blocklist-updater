#!/bin/bash
# INSTALLER: Strict mode
set -e
set -o pipefail

# --- FIREWALL & CROWDSEC INSTALLER (v17.65 - HONEYPOT MODE) ---
# - FEAT: Added HONEYPOT_MODE variable.
#         If "true": Allows blocklisted IPs to hit port 2222 (Endlessh) to generate AbuseIPDB reports.
# - CORE: Silent Mode, Smart Enroll, Auto-Update, Docker Safe.

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a 
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
INSTALLER_VERSION="v17.65"
UPDATE_URL="https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main/install.sh"

echo ""
echo "========================================================"
echo "   🚀 STARTING FIREWALL & CROWDSEC INSTALLER $INSTALLER_VERSION"
echo "========================================================"
echo ""

# --- 1. FIREWALL & SYSTEM PREP ---
echo "🔥 Resetting Firewall (Docker Safe Mode)..."
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

if command -v docker >/dev/null; then
    echo "🐳 Docker detected. Performing surgical firewall cleanup..."
    iptables -F INPUT
    iptables -F OUTPUT
    if iptables -L DOCKER-USER >/dev/null 2>&1; then
        iptables -F DOCKER-USER
    fi
else
    iptables -F
    iptables -X
fi

if command -v ipset >/dev/null; then ipset flush 2>/dev/null || true; fi

if ! ping -c 1 -W 2 google.com >/dev/null 2>&1; then
    echo "nameserver 1.1.1.1" > /etc/resolv.conf 2>/dev/null || true
    echo "nameserver 1.0.0.1" >> /etc/resolv.conf 2>/dev/null || true
fi

# --- 2. CLEANUP ---
echo "🧹 Cleaning up..."
systemctl stop firewall-blocklist-updater.timer firewall-blocklist-updater.service endlessh crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
pkill -9 -f crowdsec 2>/dev/null || true
systemctl reset-failed crowdsec 2>/dev/null || true
rm -rf /usr/local/bin/update-firewall-blocklists.sh
rm -f /var/run/firewall-updater.lock
rm -rf /tmp/firewall-blocklists

# --- 3. REPO & INSTALL ---
echo "📦 Preparing Repositories..."
if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y curl gnupg ca-certificates lsb-release
    if [ ! -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
        curl -s -4 https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    fi
    apt-get update -qq
elif command -v yum >/dev/null; then
    yum install -y curl
    if ! rpm -q epel-release >/dev/null 2>&1; then yum install -y epel-release || true; fi
    if command -v crb >/dev/null; then crb enable; fi
    curl -s -4 https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash
fi

echo "📦 Installing Core Packages..."
if command -v apt-get >/dev/null; then
    apt-get install --reinstall -y -o Dpkg::Options::="--force-confmiss" \
        wget ipset iptables unzip dnsutils logrotate endlessh iproute2 \
        crowdsec crowdsec-firewall-bouncer-iptables
elif command -v yum >/dev/null; then
    yum install -y wget ipset iptables unzip bind-utils iproute crowdsec crowdsec-firewall-bouncer-iptables
    yum install -y endlessh || echo "⚠️ Warning: endlessh not found in repos. Skipping."
fi

systemctl enable --now logrotate.timer || true

# --- 4. CROWDSEC CONFIG ---
echo "🛡️ Setting up CrowdSec Plugins..."
PDIR="/usr/lib/crowdsec/plugins"
if [[ -d "$PDIR" ]]; then
    for p in http email slack splunk; do
        if [[ -f "$PDIR/$p" && ! -f "$PDIR/notification-$p" ]]; then
            cp "$PDIR/$p" "$PDIR/notification-$p"
            chmod +x "$PDIR/notification-$p"
        fi
        if [[ -f "$PDIR/$p" ]]; then rm -f "$PDIR/$p"; fi
    done
    rm -f "$PDIR/dummy" 2>/dev/null || true
fi

configure_crowdsec_port() {
    echo "⚙️ Configuring CrowdSec Port (Target: 42000+)..."
    pkill -9 -f crowdsec 2>/dev/null || true
    local API_PORT=0
    for (( p=42000; p<=42010; p++ )); do
        if ! ss -tuln | grep -q ":$p "; then API_PORT=$p; break; fi
    done
    if [[ $API_PORT -eq 0 ]]; then echo "❌ No free port found!"; exit 1; fi
    
    sed -i "s/127.0.0.1:[0-9]\{4,5\}/127.0.0.1:$API_PORT/g" /etc/crowdsec/config.yaml 2>/dev/null || true
    if [[ -f "/etc/crowdsec/local_api_credentials.yaml" ]]; then
        sed -i "s/127.0.0.1:[0-9]\{4,5\}/127.0.0.1:$API_PORT/g" /etc/crowdsec/local_api_credentials.yaml
    fi
    
    systemctl restart crowdsec || true
    sleep 5
}
configure_crowdsec_port

fix_bouncer_config() {
    echo "🔧 Force-Syncing Bouncer..."
    local B_CONF="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    sed -i "s/api_url:.*/api_url: http:\/\/127.0.0.1:42000\//" "$B_CONF" 2>/dev/null || true
    
    if ! cscli bouncers list -o json 2>/dev/null | grep -q "firewall-bouncer"; then
        cscli bouncers delete firewall-bouncer-auto 2>/dev/null || true
        local NEW_KEY=$(cscli bouncers add firewall-bouncer-auto -o raw)
        if [ -n "$NEW_KEY" ]; then
            sed -i "s/api_key:.*/api_key: $NEW_KEY/" "$B_CONF"
        fi
    fi
    systemctl restart crowdsec
    sleep 3
    systemctl enable --now crowdsec-firewall-bouncer
    systemctl restart crowdsec-firewall-bouncer
}

EXISTING_CONF="/usr/local/etc/firewall-blocklist-updater/firewall-blocklist-keys.env"
if [[ -f "$EXISTING_CONF" ]]; then set +e; source "$EXISTING_CONF"; set -e; fi
ABUSE_KEY="${ABUSEIPDB_API_KEY:-${ABUSEIPDB_API_KEY:-}}"
CS_ENROLL="${CROWDSEC_ENROLL_KEY:-${CROWDSEC_ENROLL_KEY:-}}"
DYNDNS="${DYNDNS_HOST:-${DYNDNS_HOST:-}}"
WL_COUNTRIES="${WHITELIST_COUNTRIES:-${WHITELIST_COUNTRIES:-AT}}" 
BL_COUNTRIES="${BLOCKLIST_COUNTRIES:-${BLOCKLIST_COUNTRIES:-}}"
TG_TOKEN="${TELEGRAM_BOT_TOKEN:-${TELEGRAM_BOT_TOKEN:-}}"
TG_CHAT="${TELEGRAM_CHAT_ID:-${TELEGRAM_CHAT_ID:-}}"
# New Variable for v17.65
H_MODE="${HONEYPOT_MODE:-${HONEYPOT_MODE:-false}}"

if [[ -n "$ABUSE_KEY" ]]; then
    mkdir -p /etc/crowdsec/notifications
    cat <<YAML > /etc/crowdsec/notifications/abuseipdb.yaml
type: http
name: abuseipdb
log_level: info
format: |
  {
    "ip": "{{range . -}}{{.Source.IP}}{{end}}",
    "categories": "{{range . -}}{{if contains \"ssh\" .Scenario}}18,22{{else if contains \"scan\" .Scenario}}14{{else}}18{{end}}{{end}}",
    "comment": "Blocked by CrowdSec. Scenario: {{range . -}}{{.Scenario}}{{end}}",
    "key": "$ABUSE_KEY"
  }
url: https://api.abuseipdb.com/api/v2/report
method: POST
headers:
  Content-Type: application/json
  Accept: application/json
YAML
    cp /etc/crowdsec/profiles.yaml /etc/crowdsec/profiles.yaml.bak 2>/dev/null || true
    cat <<PROFILE > /etc/crowdsec/profiles.yaml
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
PROFILE
fi

if command -v docker >/dev/null; then cscli collections install crowdsecurity/docker --force >/dev/null 2>&1 || true; fi

fix_bouncer_config

# --- SMART ENROLL CHECK (V17.65) ---
if [[ -n "$CS_ENROLL" ]]; then 
    if cscli console status 2>&1 | grep -E -i -q "manual|connected|enrolled"; then
        echo "✅ Already enrolled. Skipping re-enrollment."
    else
        echo "☁️ Enrolling..."
        cscli console enroll "$CS_ENROLL" --overwrite || true
    fi
fi

# --- 6. UPDATER CONFIG ---
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/usr/local/etc/firewall-blocklist-updater"
mkdir -p "$CONF_DIR/firewall-blocklists" "$CONF_DIR/backups"

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

cat << EOF_UPDATER > "$INSTALL_DIR/update-firewall-blocklists.sh"
#!/bin/bash
# v17.65 - AUTO UPDATE (HONEYPOT SUPPORT)
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="\$BASE_DIR/firewall-blocklists"
KEYFILE="\${KEYFILE:-\$BASE_DIR/firewall-blocklist-keys.env}"
LOGFILE="/var/log/firewall-blocklist-updater.log"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
CURRENT_VERSION="$INSTALLER_VERSION"
REPO_URL="$UPDATE_URL"

log() { echo -e "\$(date '+%Y-%m-%d %H:%M:%S') [INFO] \$*" | tee -a "\$LOGFILE"; }
load_env_vars() { if [[ -f "\$KEYFILE" ]]; then set -a; source "\$KEYFILE"; set +a; fi; }
load_env_vars

send_telegram() { 
    if [[ -n "\${TELEGRAM_BOT_TOKEN:-}" && -n "\${TELEGRAM_CHAT_ID:-}" ]]; then 
        local HN=\$(hostname)
        local IP=\$(curl -s -4 --max-time 2 http://ip-api.com/csv/?fields=query || echo "Unknown")
        local MSG="<b>[\$HN] (\$IP)</b>%0A\$1"
        curl -s -4 -X POST "https://api.telegram.org/bot\$TELEGRAM_BOT_TOKEN/sendMessage" -d chat_id="\$TELEGRAM_CHAT_ID" -d text="\$MSG" -d parse_mode="HTML" >/dev/null || true
    fi 
}

check_for_updates() {
    local LATEST_SCRIPT="/tmp/latest_install.sh"
    local RAND=\$RANDOM
    if curl -s -f "\$REPO_URL?t=\$RAND" -o "\$LATEST_SCRIPT"; then
        local LATEST_VERSION=\$(grep 'INSTALLER_VERSION="' "\$LATEST_SCRIPT" | cut -d'"' -f2 | tr -cd 'v0-9.')
        if [[ -n "\$LATEST_VERSION" && "\$LATEST_VERSION" != "\$CURRENT_VERSION" ]]; then
            log "🚀 New version found: \$LATEST_VERSION (Current: \$CURRENT_VERSION). Self-updating..."
            chmod +x "\$LATEST_SCRIPT"
            export DEBIAN_FRONTEND=noninteractive
            export NEEDRESTART_MODE=a
            sleep 2
            bash "\$LATEST_SCRIPT" >> "\$LOGFILE" 2>&1
            exit 0
        fi
    fi
}

check_for_updates

run_maintenance() {
    if command -v apt-get >/dev/null; then apt-get clean >/dev/null 2>&1 || true; fi
    if command -v journalctl >/dev/null; then
        local ROOT_SIZE=\$(df -BG / | tail -1 | awk '{print \$2}' | tr -d 'G')
        local VAC_SIZE="200M"
        if [[ "\$ROOT_SIZE" -lt 10 ]]; then VAC_SIZE="50M"; elif [[ "\$ROOT_SIZE" -lt 20 ]]; then VAC_SIZE="150M"; elif [[ "\$ROOT_SIZE" -lt 50 ]]; then VAC_SIZE="300M"; else VAC_SIZE="500M"; fi
        journalctl --vacuum-size=\$VAC_SIZE >/dev/null 2>&1 || true
    fi
}

if [ -f "/var/run/firewall-updater.lock" ]; then
    if [ \$(find "/var/run/firewall-updater.lock" -mmin +20) ]; then rm -f "/var/run/firewall-updater.lock"; else echo "Already Running."; exit 0; fi
fi
touch "/var/run/firewall-updater.lock"
trap 'rm -f "/var/run/firewall-updater.lock" /tmp/firewall-blocklists/*' EXIT

mkdir -p "\$BASE_DIR" "\$CONFIG_DIR" /tmp/firewall-blocklists
TMPDIR="/tmp/firewall-blocklists"
log "=== Start \$CURRENT_VERSION (Honeypot: \${HONEYPOT_MODE:-false}) ==="

run_maintenance

# 1. Whitelist
: > "\$TMPDIR/wl_raw.lst"
echo "1.1.1.1" >> "\$TMPDIR/wl_raw.lst"
echo "1.0.0.1" >> "\$TMPDIR/wl_raw.lst"
echo "10.0.0.0/8" >> "\$TMPDIR/wl_raw.lst"
echo "172.16.0.0/12" >> "\$TMPDIR/wl_raw.lst"
echo "192.168.0.0/16" >> "\$TMPDIR/wl_raw.lst"

for c in \${WHITELIST_COUNTRIES:-}; do 
    curl -sfL -4 "https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset" >> "\$TMPDIR/wl_raw.lst" || true
done
if [[ -n "\$DYNDNS_HOST" ]]; then dig +short "\$DYNDNS_HOST" >> "\$TMPDIR/wl_raw.lst" || true; fi
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "\$TMPDIR/wl_raw.lst" | grep -vE "^0\.0\.0\.0$" > "\$TMPDIR/wl.v4"

# 2. Blocklist
: > "\$TMPDIR/bl_raw.lst"
if [[ -f "\$CONFIG_DIR/blocklist.sources" ]]; then
    while read -r line; do
        line=\$(echo "\$line" | tr -d '\r' | xargs)
        [[ "\$line" =~ ^#.*$ ]] && continue
        [[ -z "\$line" ]] && continue
        echo -n "Downloading \$line ... "
        if wget --inet4-only --timeout=10 --tries=2 --user-agent="\$USER_AGENT" -qO- "\$line" >> "\$TMPDIR/bl_raw.lst"; then
            echo "OK"
            echo "" >> "\$TMPDIR/bl_raw.lst"
        else
            echo "FAIL"
            log "Failed: \$line"
        fi
    done < "\$CONFIG_DIR/blocklist.sources"
fi

for c in \${BLOCKLIST_COUNTRIES:-}; do 
    curl -sfL -4 "https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset" >> "\$TMPDIR/bl_raw.lst" || true
done
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "\$TMPDIR/bl_raw.lst" | grep -vE "^0\.0\.0\.0$" > "\$TMPDIR/bl.v4"

# Filter
comm -23 <(sort "\$TMPDIR/bl.v4") <(sort "\$TMPDIR/wl.v4") > "\$TMPDIR/bl_final.v4"

# IPSet
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
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -i lo -j ACCEPT
iptables -C INPUT -p udp --sport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -p udp --sport 53 -j ACCEPT
iptables -C INPUT -p tcp --sport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p tcp --sport 53 -j ACCEPT
iptables -C INPUT -m set --match-set allowed_whitelist src -j ACCEPT 2>/dev/null || iptables -I INPUT 5 -m set --match-set allowed_whitelist src -j ACCEPT

# --- HONEYPOT LOGIC ---
if [[ "\${HONEYPOT_MODE:-false}" == "true" ]]; then
    # Allow traffic to endlessh (2222) even from blocklisted IPs
    iptables -C INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
fi

iptables -C INPUT -m set --match-set blocklist_all src -j DROP 2>/dev/null || iptables -A INPUT -m set --match-set blocklist_all src -j DROP

if iptables -L DOCKER-USER >/dev/null 2>&1; then
    iptables -C DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -C DOCKER-USER -m set --match-set allowed_whitelist src -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 2 -m set --match-set allowed_whitelist src -j ACCEPT
    iptables -C DOCKER-USER -m set --match-set blocklist_all src -j DROP 2>/dev/null || iptables -A DOCKER-USER -m set --match-set blocklist_all src -j DROP
    iptables -C DOCKER-USER -j RETURN 2>/dev/null || iptables -A DOCKER-USER -j RETURN
fi

count=\$(ipset list blocklist_all -t | grep "Number of entries" | cut -d: -f2)
log "Finished. Blocked IPv4: \$count"

if [[ "\$count" -lt 10000 ]]; then
    send_telegram "⚠️ WARNING: Low blocklist count (\$count). Check logs."
fi
EOF_UPDATER
chmod +x "$INSTALL_DIR/update-firewall-blocklists.sh"

cat <<ENV > "$CONF_DIR/firewall-blocklist-keys.env"
ABUSEIPDB_API_KEY="$ABUSE_KEY"
DYNDNS_HOST="$DYNDNS"
WHITELIST_COUNTRIES="$WL_COUNTRIES"
BLOCKLIST_COUNTRIES="$BL_COUNTRIES"
TELEGRAM_BOT_TOKEN="$TG_TOKEN"
TELEGRAM_CHAT_ID="$TG_CHAT"
HONEYPOT_MODE="$H_MODE"
ENV
chmod 600 "$CONF_DIR/firewall-blocklist-keys.env"

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
Description=Hourly Update
[Timer]
OnCalendar=hourly
RandomizedDelaySec=300
Persistent=true
[Install]
WantedBy=timers.target
TIME
systemctl daemon-reload

cat <<SERV > /lib/systemd/system/endlessh.service
[Unit]
Description=Endlessh
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

echo "🚀 Running initial update..."
$INSTALL_DIR/update-firewall-blocklists.sh

# Start timer AFTER manual run
systemctl enable --now firewall-blocklist-updater.timer

echo "✅ INSTALLATION COMPLETE! CrowdSec (Port 42000+) & Firewall running."