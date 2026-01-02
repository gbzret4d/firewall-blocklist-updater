#!/bin/bash
# INSTALLER: Strict mode for setup
set -e
set -o pipefail

# --- FIREWALL & CROWDSEC INSTALLER (v17.27 - RESTORED ROBUSTNESS) ---
# - LOGIC: Reverted to the "heavy" logic of older versions that worked.
# - FIX: Hardcoded Mozilla User-Agent (Spamhaus/DShield unblock).
# - FIX: Wget Batch Mode (Stable downloads for 40+ lists).
# - LIST: Exact list provided by user (~170k IPs).

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a 
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
INSTALLER_VERSION="v17.27"

# --- 0. SAFETY FIRST (ANTI-LOCKOUT) ---
iptables -P INPUT ACCEPT
iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Kill old processes
rm -f /var/run/firewall-updater.lock
pkill -f update-firewall-blocklists.sh || true

# Flush old rules (Safe)
iptables -F
iptables -X
if command -v ipset >/dev/null; then ipset flush 2>/dev/null || true; fi

# Restore established connection safety
iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- 0.1 DNS REPAIR ---
if ! ping -c 1 -W 2 google.com >/dev/null 2>&1; then
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
fi

# --- 1. CONFIG ---
EXISTING_CONF="/usr/local/etc/firewall-blocklist-updater/firewall-blocklist-keys.env"
if [[ -f "$EXISTING_CONF" ]]; then
    set +e; source "$EXISTING_CONF"; set -e
fi

ABUSE_KEY="${ABUSEIPDB_API_KEY:-${ABUSEIPDB_API_KEY:-}}"
CS_ENROLL="${CROWDSEC_ENROLL_KEY:-${CROWDSEC_ENROLL_KEY:-}}"
DYNDNS="${DYNDNS_HOST:-${DYNDNS_HOST:-}}"
WL_COUNTRIES="${WHITELIST_COUNTRIES:-${WHITELIST_COUNTRIES:-AT}}" 
BL_COUNTRIES="${BLOCKLIST_COUNTRIES:-${BLOCKLIST_COUNTRIES:-}}"
TG_TOKEN="${TELEGRAM_BOT_TOKEN:-${TELEGRAM_BOT_TOKEN:-}}"
TG_CHAT="${TELEGRAM_CHAT_ID:-${TELEGRAM_CHAT_ID:-}}"
REPO_URL="https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main"

# --- PACKAGES ---
if command -v dpkg >/dev/null; then dpkg --configure -a || true; fi
if command -v apt-get >/dev/null; then
    apt-get -o Acquire::ForceIPv4=true update -qq || apt-get update -qq || true
    apt-get -o Acquire::ForceIPv4=true install -y curl wget ipset iptables unzip endlessh dnsutils || apt-get install -y curl wget ipset iptables unzip endlessh dnsutils
elif command -v yum >/dev/null; then
    yum install -y curl wget ipset iptables unzip endlessh bind-utils
fi

mkdir -p /etc/systemd/journald.conf.d
echo -e "[Journal]\nSystemMaxUse=500M\nSystemMaxFileSize=100M\nMaxRetentionSec=2weeks" > /etc/systemd/journald.conf.d/00-limit-size.conf
systemctl restart systemd-journald || true

# --- CROWDSEC ---
CS_INSTALLED=false
if command -v crowdsec >/dev/null; then CS_INSTALLED=true; fi
if [[ "$CS_INSTALLED" == "false" ]]; then
    curl -s -4 https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash 2>/dev/null || true
    apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables || true
fi
systemctl enable --now crowdsec || true

INSTALL_DIR="/usr/local/bin"
CONF_DIR="/usr/local/etc/firewall-blocklist-updater"
mkdir -p "$CONF_DIR/firewall-blocklists" "$CONF_DIR/backups"

# --- THE FULL LIST (RESTORED) ---
cat <<SOURCES > "$CONF_DIR/firewall-blocklists/blocklist.sources"
# --- High Confidence ---
https://www.spamhaus.org/drop/drop.txt
https://www.spamhaus.org/drop/edrop.txt
https://www.spamhaus.org/drop/dropv6.txt
https://feeds.dshield.org/block.txt
https://feodotracker.abuse.ch/downloads/ipblocklist.txt
https://sslbl.abuse.ch/blacklist/sslipblacklist.txt

# --- Aggregators ---
https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt
https://blocklist.greensnow.co/greensnow.txt
https://iplists.firehol.org/files/greensnow.ipset
https://lists.blocklist.de/lists/all.txt
https://www.blocklist.de/downloads/export-ips_all.txt

# --- Threat Intel & Mirrors ---
https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
https://rules.emergingthreats.net/blockrules/compromised-ips.txt
https://iplists.firehol.org/files/et_compromised.ipset
https://www.binarydefense.com/banlist.txt
https://iplists.firehol.org/files/bds_atif.ipset
https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/refs/heads/master/binarydefense.txt

# --- GitHub Lists ---
https://github.com/borestad/blocklist-abuseipdb/raw/refs/heads/main/abuseipdb-s100-7d.ipv4
https://github.com/ShadowWhisperer/IPs/raw/refs/heads/master/BruteForce/High
https://github.com/ShadowWhisperer/IPs/raw/refs/heads/master/BruteForce/Extreme
https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Malware/Hackers
https://github.com/romainmarcoux/malicious-ip/raw/refs/heads/main/full-40k.txt
https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/full-outgoing-ip-40k.txt

# --- IOCs & C2 ---
https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/refs/heads/main/ips.txt
https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/cobaltstrike_ips.txt
https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/refs/heads/master/alienvault.txt
https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/compromised-ips.txt
https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/illuminate.txt

# --- FireHOL Collections ---
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

# --- WRITE UPDATER (ROBUST MODE) ---
cat << EOF_UPDATER > "$INSTALL_DIR/update-firewall-blocklists.sh"
#!/bin/bash
# ROBUST BATCH MODE
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SCRIPT_VERSION="v11.27"
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="\$BASE_DIR/firewall-blocklists"
KEYFILE="\${KEYFILE:-\$BASE_DIR/firewall-blocklist-keys.env}"
SOURCE_FILE="\$CONFIG_DIR/blocklist.sources"
CUSTOM_WL_FILE="\$CONFIG_DIR/whitelist.custom"
LOCKFILE="/var/run/firewall-updater.lock"
LOGFILE="/var/log/firewall-blocklist-updater.log"
# Mozilla User Agent - REQUIRED for Spamhaus/DShield
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

log() { echo -e "\$(date '+%Y-%m-%d %H:%M:%S') [INFO] \$*" | tee -a "\$LOGFILE"; }

if [ -f "\$LOCKFILE" ]; then
    if [ \$(find "\$LOCKFILE" -mmin +20) ]; then rm -f "\$LOCKFILE"; else echo "Running."; exit 0; fi
fi
touch "\$LOCKFILE"
trap 'rm -f "\$LOCKFILE" /tmp/firewall-blocklists/*' EXIT

mkdir -p "\$BASE_DIR" "\$CONFIG_DIR" /tmp/firewall-blocklists

load_env_vars() { if [[ -f "\$KEYFILE" ]]; then set -a; source "\$KEYFILE"; set +a; fi; }
load_env_vars
if ! getent hosts google.com >/dev/null 2>&1; then echo "nameserver 8.8.8.8" > /etc/resolv.conf; fi

perform_auto_update() {
    local TMP="/tmp/install_latest.sh"
    curl -sL -4 "\$REPO_URL/install.sh" -o "\$TMP" || return 0
    local NEW=\$(grep -oE 'SCRIPT_VERSION="v[0-9]+\.[0-9]+"' "\$TMP" | head -n1 | cut -d'"' -f2)
    if [[ -n "\$NEW" && "\$NEW" != "\$SCRIPT_VERSION" ]]; then
        log "Update found: \$NEW. Installing..."
        bash "\$TMP"
        exit 0
    fi
}
log "=== Start \$SCRIPT_VERSION ==="
perform_auto_update

TMPDIR="/tmp/firewall-blocklists"
IPSET_WL="allowed_whitelist"
IPSET_BL="blocklist_all"

extract_ips() {
    local input="\$1"; local output="\$2";
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "\$input" | grep -vE "^0\.0\.0\.0$" > "\$output" || true
}

load_ipset() {
  local file="\$1"; local setname="\$2"
  # Robust load: create empty set first to avoid crashes
  ipset create \$setname hash:net family inet hashsize 4096 maxelem 2000000 -exist 2>/dev/null || true
  ipset flush "\${setname}_tmp" 2>/dev/null || ipset create "\${setname}_tmp" hash:net family inet hashsize 4096 maxelem 2000000 -exist
  if [[ -s "\$file" ]]; then sed "s/^/add \${setname}_tmp /" "\$file" | ipset restore -! 2>/dev/null; fi
  ipset swap "\${setname}_tmp" "\$setname"
  ipset destroy "\${setname}_tmp" 2>/dev/null || true
}

# 1. Whitelist
: > "\$TMPDIR/wl_raw.lst"
for c in \${WHITELIST_COUNTRIES:-}; do 
    curl -sfL -4 "https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset" >> "\$TMPDIR/wl_raw.lst" || true
done
if [[ -n "\$DYNDNS_HOST" ]]; then dig +short "\$DYNDNS_HOST" >> "\$TMPDIR/wl_raw.lst" || true; fi
[[ -f "\$CUSTOM_WL_FILE" ]] && cat "\$CUSTOM_WL_FILE" >> "\$TMPDIR/wl_raw.lst"
extract_ips "\$TMPDIR/wl_raw.lst" "\$TMPDIR/wl.v4"

# 2. Blocklist (WGET BATCH + MOZILLA UA)
: > "\$TMPDIR/bl_raw.lst"
: > "\$TMPDIR/urls_clean.txt"

if [[ -f "\$CONFIG_DIR/blocklist.sources" ]]; then
    # Sanitize inputs (strip CR)
    grep -vE "^\s*#|^$" "\$CONFIG_DIR/blocklist.sources" | tr -d '\r' > "\$TMPDIR/urls_clean.txt"
    
    log "Downloading lists (Stealth Batch Mode)..."
    # WGET BATCH:
    # --inet4-only: Prevent IPv6 timeouts
    # --user-agent: Pretend to be Firefox to bypass WAFs
    # -i: Batch mode
    wget --inet4-only --timeout=15 --tries=2 --user-agent="\$USER_AGENT" -i "\$TMPDIR/urls_clean.txt" -O - >> "\$TMPDIR/bl_raw.lst" 2>/dev/null || true
fi

for c in \${BLOCKLIST_COUNTRIES:-}; do 
    curl -sfL -4 "https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset" >> "\$TMPDIR/bl_raw.lst" || true
done

extract_ips "\$TMPDIR/bl_raw.lst" "\$TMPDIR/bl.v4"

# Filter
comm -23 <(sort "\$TMPDIR/bl.v4") <(sort "\$TMPDIR/wl.v4") > "\$TMPDIR/bl_final.v4"
load_ipset "\$TMPDIR/wl.v4" "\$IPSET_WL"
load_ipset "\$TMPDIR/bl_final.v4" "\$IPSET_BL"

# 3. Apply Firewall
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C INPUT -m set --match-set "\$IPSET_WL" src -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -m set --match-set "\$IPSET_WL" src -j ACCEPT
iptables -C INPUT -m set --match-set "\$IPSET_BL" src -j DROP 2>/dev/null || iptables -A INPUT -m set --match-set "\$IPSET_BL" src -j DROP
iptables -I INPUT 3 -p udp --sport 53 -j ACCEPT 2>/dev/null || true
iptables -I INPUT 3 -p tcp --sport 53 -j ACCEPT 2>/dev/null || true

if iptables -L DOCKER-USER >/dev/null 2>&1; then
    iptables -C DOCKER-USER -m set --match-set "\$IPSET_WL" src -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -m set --match-set "\$IPSET_WL" src -j ACCEPT
    iptables -C DOCKER-USER -m set --match-set "\$IPSET_BL" src -j DROP 2>/dev/null || iptables -A DOCKER-USER -m set --match-set "\$IPSET_BL" src -j DROP
fi

count=\$(ipset list \$IPSET_BL -t | grep "Number of entries" | cut -d: -f2)
log "Finished. Blocked IPv4: \$count"
EOF_UPDATER
chmod +x "$INSTALL_DIR/update-firewall-blocklists.sh"

# Services
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
systemctl enable --now firewall-blocklist-updater.timer

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

rm -f /var/run/firewall-updater.lock
echo "🚀 Running initial update (this takes time)..."
$INSTALL_DIR/update-firewall-blocklists.sh

echo "✅ INSTALLATION COMPLETE!"