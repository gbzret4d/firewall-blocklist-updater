#!/bin/bash
# INSTALLER: Strict mode
set -e
set -o pipefail

# --- FIREWALL & CROWDSEC INSTALLER (v17.22 - THE MISSING LINK FIX) ---
# - FIX: Re-added the blocklist.sources generation (was missing in v17.21).
# - FIX: Creates empty ipsets unconditionally so iptables never crashes on startup.
# - LOGIC: Whitelist > Blocklist. IPv4 Enforced.

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a 
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
INSTALLER_VERSION="v17.22"

# --- 0. IMMEDIATE SAFETY NET ---
# Allow existing connections immediately
iptables -P INPUT ACCEPT
iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Cleanup
rm -f /var/run/firewall-updater.lock
pkill -f update-firewall-blocklists.sh || true

# Flush (Safe)
iptables -F
iptables -X
if command -v ipset >/dev/null; then ipset flush 2>/dev/null || true; fi

# Restore Safety Rule
iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# --- 0.1 DNS REPAIR ---
if ! ping -c 1 -W 2 google.com >/dev/null 2>&1; then
    echo "⚠️ DNS Repair initiated..."
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    sleep 2
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

# --- HELPER FUNCTIONS ---
get_server_identity() {
    SERVER_IP="Unknown"
    local INFO=$(curl -s -4 --max-time 3 http://ip-api.com/csv/?fields=query || true)
    if [[ -n "$INFO" ]]; then SERVER_IP=$(echo "$INFO" | cut -d',' -f1); fi
}

send_msg() {
    if [[ -n "$TG_TOKEN" && -n "$TG_CHAT" ]]; then
        curl -s -4 -X POST "https://api.telegram.org/bot$TG_TOKEN/sendMessage" \
            -d chat_id="$TG_CHAT" -d text="$1" -d parse_mode="HTML" >/dev/null || true
    fi
}

echo "============================================="
echo "   FIREWALL & CROWDSEC INSTALLER ($INSTALLER_VERSION) "
echo "============================================="

# --- PACKAGES ---
if command -v dpkg >/dev/null; then dpkg --configure -a || true; fi

if command -v apt-get >/dev/null; then
    PM="apt-get"
    apt-get -o Acquire::ForceIPv4=true update -qq || apt-get update -qq || true
    install_pkg() { apt-get -o Acquire::ForceIPv4=true install -y "$@" || apt-get install -y "$@" || (sleep 5; apt-get install -y "$@"); }
    purge_pkg() { apt-get purge -y "$@"; apt-get autoremove -y; }
elif command -v dnf >/dev/null; then
    PM="dnf"; install_pkg() { dnf install -y "$@"; }
    purge_pkg() { dnf remove -y "$@"; }
elif command -v yum >/dev/null; then
    PM="yum"; install_pkg() { yum install -y "$@"; }
    purge_pkg() { yum remove -y "$@"; }
else echo "❌ Unsupported OS"; exit 1; fi

install_pkg curl ipset iptables unzip file gnupg logrotate endlessh

if [[ "$PM" == "apt-get" ]]; then
    install_pkg dnsutils apt-transport-https psmisc iproute2
    systemctl enable --now systemd-timesyncd 2>/dev/null || install_pkg chrony
else
    install_pkg bind-utils iproute chrony
    systemctl enable --now chronyd 2>/dev/null || true
fi

mkdir -p /etc/systemd/journald.conf.d
echo -e "[Journal]\nSystemMaxUse=500M\nSystemMaxFileSize=100M\nMaxRetentionSec=2weeks" > /etc/systemd/journald.conf.d/00-limit-size.conf
systemctl restart systemd-journald || true

# --- CROWDSEC ---
CS_INSTALLED=false
if command -v crowdsec >/dev/null; then CS_INSTALLED=true; fi

setup_crowdsec() {
    if [[ "$CS_INSTALLED" == "false" ]]; then
        if [[ "$PM" == "apt-get" ]]; then 
            curl -s -4 https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash 2>/dev/null
        else 
            curl -s -4 https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash 2>/dev/null
        fi
        install_pkg crowdsec || return 1
    fi
    install_pkg crowdsec-firewall-bouncer-iptables || true
    
    mkdir -p /etc/crowdsec
    if [[ ! -s /etc/crowdsec/acquis.yaml ]]; then
        echo -e "filenames:\n  - /var/log/syslog\n  - /var/log/auth.log\n  - /var/log/messages\nlabels:\n  type: syslog\n---" > /etc/crowdsec/acquis.yaml
    fi
    
    if [[ -n "$CS_ENROLL" ]]; then 
        if [[ ! -f "/etc/crowdsec/online_api_credentials.yaml" ]]; then
            cscli console enroll "$CS_ENROLL" --overwrite || true
        fi
    fi
    systemctl restart crowdsec || true
}
setup_crowdsec || echo "⚠️ CrowdSec setup failed, ignoring..."

INSTALL_DIR="/usr/local/bin"
CONF_DIR="/usr/local/etc/firewall-blocklist-updater"
mkdir -p "$CONF_DIR/firewall-blocklists" "$CONF_DIR/backups"

# --- RE-ADDED MISSING SOURCE FILE GENERATION ---
cat <<SOURCES > "$CONF_DIR/firewall-blocklists/blocklist.sources"
# --- High Confidence ---
https://www.spamhaus.org/drop/drop.txt
https://www.spamhaus.org/drop/edrop.txt
https://www.spamhaus.org/drop/dropv6.txt
https://feeds.dshield.org/block.txt
https://feodotracker.abuse.ch/downloads/ipblocklist.txt
https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
https://danger.rulez.sk/projects/bruteforceblocker/blist.php

# --- Aggregators ---
https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt
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
https://threatview.io/Downloads/IP-High-Confidence-Feed.txt
https://dataplane.org/vncrfb.txt
http://vxvault.net/URL_List.php
https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv

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
https://feodotracker.abuse.ch/downloads/ipblocklist.csv
https://tracker.viriback.com/last30.php
https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt
https://sslbl.abuse.ch/blacklist/sslbl.rpz
https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt
https://urlhaus.abuse.ch/downloads/csv_recent/

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

# --- WRITE UPDATER ---
cat << EOF_UPDATER > "$INSTALL_DIR/update-firewall-blocklists.sh"
#!/bin/bash
# NO set -e
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SCRIPT_VERSION="v11.22"
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="\$BASE_DIR/firewall-blocklists"
KEYFILE="\${KEYFILE:-\$BASE_DIR/firewall-blocklist-keys.env}"
SOURCE_FILE="\$CONFIG_DIR/blocklist.sources"
CUSTOM_WL_FILE="\$CONFIG_DIR/whitelist.custom"
LOCKFILE="/var/run/firewall-updater.lock"
LOGFILE="/var/log/firewall-blocklist-updater.log"
MAX_LOG_SIZE=$((5 * 1024 * 1024))
REPO_URL="$REPO_URL"

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

# 4. Helpers
extract_ips() {
    local input="\$1"; local output="\$2"; local family="\$3"
    [[ ! -f "\$input" ]] && touch "\$output" && return 0
    if [[ "\$family" == "inet" ]]; then 
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "\$input" | grep -vE "^0\.0\.0\.0$" > "\$output" || true
    else 
        grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?' "\$input" | grep -vE "^::" > "\$output" || true
    fi
}

load_ipset() {
  local file="\$1"; local setname="\$2"; local family="\$3"
  if [[ "\$family" == "inet6" ]]; then if [ ! -f /proc/net/if_inet6 ]; then return 0; fi; fi
  
  # ALWAYS create set, even if empty, to prevent iptables crash
  ipset create \$setname hash:net family \$family hashsize 4096 maxelem 2000000 -exist 2>/dev/null || true
  ipset flush "\${setname}_tmp" 2>/dev/null || ipset create "\${setname}_tmp" hash:net family \$family hashsize 4096 maxelem 2000000 -exist
  
  if [[ -s "\$file" ]]; then
      sed "s/^/add \${setname}_tmp /" "\$file" | ipset restore -! 2>/dev/null
  fi
  
  ipset swap "\${setname}_tmp" "\$setname"
  ipset destroy "\${setname}_tmp" 2>/dev/null || true
}

# 5. Build Lists
# Initialize sets immediately to avoid "set does not exist" error
ipset create \$IPSET_WL hash:net family inet hashsize 4096 maxelem 2000000 -exist 2>/dev/null || true
ipset create \$IPSET_BL hash:net family inet hashsize 4096 maxelem 2000000 -exist 2>/dev/null || true

: > "\$TMPDIR/wl_raw.lst"
for c in \${WHITELIST_COUNTRIES:-}; do 
    curl -sfL -4 "https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset" >> "\$TMPDIR/wl_raw.lst" || true
done
if [[ -n "\$DYNDNS_HOST" ]]; then
    dig +short "\$DYNDNS_HOST" >> "\$TMPDIR/wl_raw.lst" || dig +short @8.8.8.8 "\$DYNDNS_HOST" >> "\$TMPDIR/wl_raw.lst" || true
fi
[[ -f "\$CUSTOM_WL_FILE" ]] && cat "\$CUSTOM_WL_FILE" >> "\$TMPDIR/wl_raw.lst"

extract_ips "\$TMPDIR/wl_raw.lst" "\$TMPDIR/wl.v4" "inet"
extract_ips "\$TMPDIR/wl_raw.lst" "\$TMPDIR/wl.v6" "inet6"

: > "\$TMPDIR/bl_raw.lst"
if [[ -f "\$CONFIG_DIR/blocklist.sources" ]]; then
    while read -r line; do
        [[ "\$line" =~ ^#.*$ ]] && continue
        [[ -z "\$line" ]] && continue
        curl -sfL -4 --connect-timeout 10 --retry 2 "\$line" >> "\$TMPDIR/bl_raw.lst" || log "Skipped: \$line"
        echo "" >> "\$TMPDIR/bl_raw.lst"
    done < "\$CONFIG_DIR/blocklist.sources"
fi

for c in \${BLOCKLIST_COUNTRIES:-}; do 
    curl -sfL -4 "https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset" >> "\$TMPDIR/bl_raw.lst" || true
done

extract_ips "\$TMPDIR/bl_raw.lst" "\$TMPDIR/bl.v4" "inet"
extract_ips "\$TMPDIR/bl_raw.lst" "\$TMPDIR/bl.v6" "inet6"

comm -23 <(sort "\$TMPDIR/bl.v4") <(sort "\$TMPDIR/wl.v4") > "\$TMPDIR/bl_final.v4"
comm -23 <(sort "\$TMPDIR/bl.v6") <(sort "\$TMPDIR/wl.v6") > "\$TMPDIR/bl_final.v6"

load_ipset "\$TMPDIR/wl.v4" "\$IPSET_WL" "inet"
load_ipset "\$TMPDIR/bl_final.v4" "\$IPSET_BL" "inet"
load_ipset "\$TMPDIR/wl.v6" "\${IPSET_WL}_v6" "inet6"
load_ipset "\$TMPDIR/bl_final.v6" "\${IPSET_BL}_v6" "inet6"

# 6. Apply Firewall
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

cat <<SERV > /lib/systemd/system/endlessh.service
[Unit]
Description=Endlessh SSH Tarpit
Requires=network-online.target
After=network-online.target
[Service]
Type=simple
Restart=always
RestartSec=30s
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