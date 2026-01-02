#!/bin/bash
# Install script keeps strict mode to fail on setup errors, 
# BUT the generated updater will be permissive.
set -e
set -o pipefail

# --- FIREWALL & CROWDSEC INSTALLER (v17.19 - FAULT TOLERANT) ---
# - FIX: Removed 'set -e' from the generated updater script. One bad list won't kill the firewall.
# - FIX: Stripped Endlessh service to bare minimum to run on ANY kernel (OpenVZ/LXC support).
# - FIX: Brutal DNS & IPv4 enforcement.

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a 
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
INSTALLER_VERSION="v17.19"

# --- 0. PRE-FLIGHT: CLEANUP ---
# Kill any hanging processes from previous bad runs
pkill -f update-firewall-blocklists.sh || true
rm -f /var/run/firewall-updater.lock

# Flush firewall to ensure we have connectivity for the install
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
if command -v ipset >/dev/null; then ipset flush 2>/dev/null || true; fi

# --- 0.1 DNS REPAIR ---
if ! ping -c 1 -W 2 google.com >/dev/null 2>&1; then
    echo "⚠️ DNS broken. Overwriting /etc/resolv.conf..."
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

# --- HELPER FUNCTIONS ---
get_server_identity() {
    SERVER_IP="Unknown"; SERVER_CC="??"
    if command -v curl >/dev/null; then
        local INFO=$(curl -s --max-time 3 http://ip-api.com/csv/?fields=query,countryCode || true)
        if [[ -n "$INFO" ]]; then SERVER_IP=$(echo "$INFO" | cut -d',' -f1); SERVER_CC=$(echo "$INFO" | cut -d',' -f2); fi
    fi
}

send_msg() {
    if [[ -n "$TG_TOKEN" && -n "$TG_CHAT" ]]; then
        curl -s -X POST "https://api.telegram.org/bot$TG_TOKEN/sendMessage" \
            -d chat_id="$TG_CHAT" -d text="$1" -d parse_mode="HTML" >/dev/null || true
    fi
}

# --- INSTALLER ---
echo "============================================="
echo "   FIREWALL & CROWDSEC INSTALLER ($INSTALLER_VERSION) "
echo "============================================="

# Fix DPKG if broken
if command -v dpkg >/dev/null; then dpkg --configure -a || true; fi

if command -v apt-get >/dev/null; then
    PM="apt-get"
    apt-get update -qq || true 
    install_pkg() { apt-get install -y "$@" || (sleep 5; apt-get install -y "$@"); }
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

configure_and_start_crowdsec() {
    # Check if running
    if systemctl is-active --quiet crowdsec; then
        if cscli lapi status >/dev/null 2>&1; then return 0; fi
    fi

    # Minimal Config patch
    mkdir -p /etc/crowdsec
    if [[ ! -s /etc/crowdsec/acquis.yaml ]]; then
        echo -e "filenames:\n  - /var/log/syslog\n  - /var/log/auth.log\n  - /var/log/messages\nlabels:\n  type: syslog\n---" > /etc/crowdsec/acquis.yaml
    fi
    
    systemctl restart crowdsec || true
    sleep 5
    return 0
}

if [[ -n "$CS_ENROLL" ]] || [[ "$CS_INSTALLED" == "false" ]]; then
    if [[ "$CS_INSTALLED" == "false" ]]; then
        if [[ "$PM" == "apt-get" ]]; then curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash 2>/dev/null
        else curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash 2>/dev/null; fi
        install_pkg crowdsec
    fi
    
    install_pkg crowdsec-firewall-bouncer-iptables
    configure_and_start_crowdsec || true # Don't crash installer if CS fails

    if command -v cscli >/dev/null; then
        cscli hub update >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/linux --force >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/sshd --force >/dev/null 2>&1 || true
    fi

    if [[ -n "$CS_ENROLL" ]]; then 
        if [[ ! -f "/etc/crowdsec/online_api_credentials.yaml" ]]; then
            cscli console enroll "$CS_ENROLL" --overwrite || true
            systemctl restart crowdsec || true
        fi
    fi
fi

INSTALL_DIR="/usr/local/bin"
CONF_DIR="/usr/local/etc/firewall-blocklist-updater"
mkdir -p "$CONF_DIR/firewall-blocklists" "$CONF_DIR/backups"

# --- WRITE UPDATER (NO STRICT MODE) ---
cat << EOF_UPDATER > "$INSTALL_DIR/update-firewall-blocklists.sh"
#!/bin/bash
# NO set -e HERE! We want to continue even if one list fails.
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SCRIPT_VERSION="v11.19"
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="\$BASE_DIR/firewall-blocklists"
KEYFILE="\${KEYFILE:-\$BASE_DIR/firewall-blocklist-keys.env}"
SOURCE_FILE="\$CONFIG_DIR/blocklist.sources"
CUSTOM_WL_FILE="\$CONFIG_DIR/whitelist.custom"
LOCKFILE="/var/run/firewall-updater.lock"
LOGFILE="/var/log/firewall-blocklist-updater.log"
MAX_LOG_SIZE=$((5 * 1024 * 1024))
REPO_URL="$REPO_URL"

# Logging
log() { echo -e "\$(date '+%Y-%m-%d %H:%M:%S') [INFO] \$*" | tee -a "\$LOGFILE"; }

# Check lock
if [ -f "\$LOCKFILE" ]; then
    # If lock is older than 20 mins, kill it
    if [ \$(find "\$LOCKFILE" -mmin +20) ]; then
        rm -f "\$LOCKFILE"
    else
        echo "Already running."
        exit 0
    fi
fi
touch "\$LOCKFILE"

# Cleanup on exit
trap 'rm -f "\$LOCKFILE" /tmp/firewall-blocklists/*' EXIT

mkdir -p "\$BASE_DIR" "\$CONFIG_DIR" /tmp/firewall-blocklists

# Vars
load_env_vars() { if [[ -f "\$KEYFILE" ]]; then set -a; source "\$KEYFILE"; set +a; fi; }
load_env_vars

# DNS Fix
if ! getent hosts google.com >/dev/null 2>&1; then echo "nameserver 8.8.8.8" > /etc/resolv.conf; fi

# Auto Update
perform_auto_update() {
    local TMP="/tmp/install_latest.sh"
    # Try IPv4 force
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

# Download Logic - ERROR TOLERANT
download_lists() {
  local out="\$1"; shift; local srcs=("\$@"); : > "\$TMPDIR/merge.lst"
  for u in "\${srcs[@]}"; do
      # Ignore errors with || true
      curl -sfL -4 --connect-timeout 15 --retry 2 -A "FirewallUpdater" "\$u" >> "\$TMPDIR/merge.lst" || log "Failed: \$u"
      echo "" >> "\$TMPDIR/merge.lst"
  done
  sort -u "\$TMPDIR/merge.lst" > "\$out"
}

# Extraction
extract_ips() {
    local input="\$1"; local output="\$2"; local family="\$3"
    [[ ! -f "\$input" ]] && touch "\$output" && return 0
    if [[ "\$family" == "inet" ]]; then 
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "\$input" | grep -vE "^0\.0\.0\.0$" > "\$output" || true
    else 
        grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?' "\$input" | grep -vE "^::" > "\$output" || true
    fi
}

# IPSet Loader
load_ipset() {
  local file="\$1"; local setname="\$2"; local family="\$3"
  # Check if IPv6 supported
  if [[ "\$family" == "inet6" ]]; then
      if [ ! -f /proc/net/if_inet6 ]; then return 0; fi
  fi
  
  ipset create \$setname hash:net family \$family hashsize 4096 maxelem 2000000 -exist 2>/dev/null || true
  ipset flush "\${setname}_tmp" 2>/dev/null || ipset create "\${setname}_tmp" hash:net family \$family hashsize 4096 maxelem 2000000 -exist
  
  # Load fast
  sed "s/^/add \${setname}_tmp /" "\$file" | ipset restore -! 2>/dev/null
  ipset swap "\${setname}_tmp" "\$setname"
  ipset destroy "\${setname}_tmp" 2>/dev/null || true
}

# Main Logic
: > "\$TMPDIR/wl_raw.lst"
# Countries
for c in \${WHITELIST_COUNTRIES:-}; do 
    curl -sfL -4 "https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset" >> "\$TMPDIR/wl_raw.lst" || true
done
# DynDNS
if [[ -n "\$DYNDNS_HOST" ]]; then
    dig +short "\$DYNDNS_HOST" >> "\$TMPDIR/wl_raw.lst" || dig +short @8.8.8.8 "\$DYNDNS_HOST" >> "\$TMPDIR/wl_raw.lst" || true
fi
[[ -f "\$CUSTOM_WL_FILE" ]] && cat "\$CUSTOM_WL_FILE" >> "\$TMPDIR/wl_raw.lst"

extract_ips "\$TMPDIR/wl_raw.lst" "\$TMPDIR/wl.v4" "inet"
extract_ips "\$TMPDIR/wl_raw.lst" "\$TMPDIR/wl.v6" "inet6"

# Blocklists
local bl=(); [[ -f "\$CONFIG_DIR/blocklist.sources" ]] && mapfile -t bl < <(grep -vE '^\s*#' "\$CONFIG_DIR/blocklist.sources")
for c in \${BLOCKLIST_COUNTRIES:-}; do bl+=("https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset"); done

download_lists "\$TMPDIR/bl_raw.lst" "\${bl[@]}"

extract_ips "\$TMPDIR/bl_raw.lst" "\$TMPDIR/bl.v4" "inet"
extract_ips "\$TMPDIR/bl_raw.lst" "\$TMPDIR/bl.v6" "inet6"

# Remove Whitelisted
comm -23 <(sort "\$TMPDIR/bl.v4") <(sort "\$TMPDIR/wl.v4") > "\$TMPDIR/bl_final.v4"
comm -23 <(sort "\$TMPDIR/bl.v6") <(sort "\$TMPDIR/wl.v6") > "\$TMPDIR/bl_final.v6"

load_ipset "\$TMPDIR/wl.v4" "\$IPSET_WL" "inet"
load_ipset "\$TMPDIR/bl_final.v4" "\$IPSET_BL" "inet"
load_ipset "\$TMPDIR/wl.v6" "\${IPSET_WL}_v6" "inet6"
load_ipset "\$TMPDIR/bl_final.v6" "\${IPSET_BL}_v6" "inet6"

# Firewall Rules (Idempotent)
# 1. Whitelist ACCEPT
iptables -C INPUT -m set --match-set "\$IPSET_WL" src -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -m set --match-set "\$IPSET_WL" src -j ACCEPT
# 2. Blocklist DROP
iptables -C INPUT -m set --match-set "\$IPSET_BL" src -j DROP 2>/dev/null || iptables -A INPUT -m set --match-set "\$IPSET_BL" src -j DROP

# DNS Allow (Safety)
iptables -I INPUT 1 -p udp --sport 53 -j ACCEPT
iptables -I INPUT 1 -p tcp --sport 53 -j ACCEPT

# Docker
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

# --- SIMPLIFIED ENDLESSH ---
# No fancy security features that crash on old kernels
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

# Run update immediately
$INSTALL_DIR/update-firewall-blocklists.sh

echo "✅ INSTALLATION COMPLETE!"