#!/bin/bash
# v17.65 - ULTRA-HYBRID (Full v11.7 Logic + v17.65 Features)
set -euo pipefail
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# --- CONFIGURATION ---
SCRIPT_VERSION="v17.65"
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="$BASE_DIR/firewall-blocklists"
KEYFILE="${KEYFILE:-$BASE_DIR/firewall-blocklist-keys.env}"
LOCKFILE="/var/run/firewall-updater.lock"
LOGFILE="/var/log/firewall-blocklist-updater.log"
MAX_LOG_SIZE=$((5 * 1024 * 1024))
USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
REPO_URL="https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main/install.sh"
IPV6_ENABLED=1

# --- CORE FUNCTIONS (v11.7) ---
manage_log_size() {
    if [[ -f "$LOGFILE" ]]; then
        local size=$(stat -c%s "$LOGFILE" 2>/dev/null || echo 0)
        if [[ $size -gt $MAX_LOG_SIZE ]]; then 
            tail -n 2000 "$LOGFILE" > "${LOGFILE}.tmp" && mv "${LOGFILE}.tmp" "$LOGFILE"
        fi
    fi
}

log() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" | tee -a "$LOGFILE"; }

cleanup() { rm -f "$LOCKFILE" /tmp/firewall-blocklists/* 2>/dev/null || true; }
trap cleanup EXIT INT TERM

repair_environment() {
    local HN=$(hostname)
    if ! grep -q "127.0.1.1 $HN" /etc/hosts; then echo "127.0.1.1 $HN" >> /etc/hosts; fi
}

check_connectivity() {
    if ! curl -s --head --request GET https://1.1.1.1 > /dev/null; then
        echo "No connectivity."; exit 0
    fi
}

# --- UPDATE LOGIC (v17.65) ---
check_for_updates() {
    local LATEST_SCRIPT="/tmp/latest_install.sh"
    if curl -s -f "$REPO_URL?t=$RANDOM" -o "$LATEST_SCRIPT"; then
        local LATEST_V=$(grep 'INSTALLER_VERSION="' "$LATEST_SCRIPT" | cut -d'"' -f2 | tr -cd 'v0-9.')
        if [[ -n "$LATEST_V" && "$LATEST_V" != "$SCRIPT_VERSION" ]]; then
            log "🚀 New version $LATEST_V found. Updating..."
            chmod +x "$LATEST_SCRIPT"
            bash "$LATEST_SCRIPT" >> "$LOGFILE" 2>&1
            exit 0
        fi
    fi
}

send_telegram() { 
    if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then 
        local HN=$(hostname)
        local MSG="<b>[$HN]</b>%0A$1"
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" -d chat_id="$TELEGRAM_CHAT_ID" -d text="$MSG" -d parse_mode="HTML" >/dev/null || true
    fi 
}

# --- EXTRACTION & IPSET (v11.7) ---
smart_extract() {
    local f="$1"
    if gzip -t "$f" 2>/dev/null; then zcat "$f"
    elif unzip -t "$f" 2>/dev/null; then unzip -p "$f"
    else cat "$f"; fi
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
    ipset create "$setname" hash:net family "$family" hashsize 4096 maxelem 2000000 -exist || true
    if [[ -s "$file" ]]; then
        ipset create "${setname}_tmp" hash:net family "$family" hashsize 4096 maxelem 2000000 -exist
        ipset flush "${setname}_tmp"
        sed "s/^/add ${setname}_tmp /" "$file" | ipset restore -! 2>/dev/null || true
        ipset swap "${setname}_tmp" "$setname"
        ipset destroy "${setname}_tmp" 2>/dev/null || true
    fi
}

# --- MAIN ---
mkdir -p "$CONFIG_DIR" /tmp/firewall-blocklists
TMPDIR="/tmp/firewall-blocklists"

if [[ -f "$KEYFILE" ]]; then set +u; set -a; source "$KEYFILE"; set +a; set -u; fi

check_connectivity
check_for_updates
manage_log_size
repair_environment

log "=== Start $SCRIPT_VERSION (Honeypot: ${HONEYPOT_MODE:-false}) ==="

# 1. Whitelists (v4 & v6)
: > "$TMPDIR/wl_raw.lst"
echo "1.1.1.1" >> "$TMPDIR/wl_raw.lst"
echo "10.0.0.0/8" >> "$TMPDIR/wl_raw.lst"
echo "172.16.0.0/12" >> "$TMPDIR/wl_raw.lst"
echo "192.168.0.0/16" >> "$TMPDIR/wl_raw.lst"
for c in ${WHITELIST_COUNTRIES:-}; do curl -sfL "https://iplists.firehol.org/files/geolite2_country/country_${c,,}.netset" >> "$TMPDIR/wl_raw.lst" || true; done
if [[ -n "${DYNDNS_HOST:-}" ]]; then dig +short "$DYNDNS_HOST" >> "$TMPDIR/wl_raw.lst" || true; fi

extract_ips "$TMPDIR/wl_raw.lst" "$TMPDIR/wl.v4" "inet"
extract_ips "$TMPDIR/wl_raw.lst" "$TMPDIR/wl.v6" "inet6"

# 2. Blocklists (v4 & v6)
: > "$TMPDIR/bl_raw.lst"
if [[ -f "$CONFIG_DIR/blocklist.sources" ]]; then
    while read -r url; do [[ "$url" =~ ^# || -z "$url" ]] && continue; curl -sfL -A "$USER_AGENT" "$url" >> "$TMPDIR/bl_raw.lst" || true; done < "$CONFIG_DIR/blocklist.sources"
fi
for c in ${BLOCKLIST_COUNTRIES:-}; do curl -sfL "https://iplists.firehol.org/files/geolite2_country/country_${c,,}.netset" >> "$TMPDIR/bl_raw.lst" || true; done

extract_ips "$TMPDIR/bl_raw.lst" "$TMPDIR/bl.v4" "inet"
extract_ips "$TMPDIR/bl_raw.lst" "$TMPDIR/bl.v6" "inet6"

# 3. Filtering
comm -23 <(sort -u "$TMPDIR/bl.v4") <(sort -u "$TMPDIR/wl.v4") > "$TMPDIR/bl_final.v4"
comm -23 <(sort -u "$TMPDIR/bl.v6") <(sort -u "$TMPDIR/wl.v6") > "$TMPDIR/bl_final.v6"

# 4. Apply IPSets
load_ipset "$TMPDIR/wl.v4" "allowed_whitelist" "inet"
load_ipset "$TMPDIR/bl_final.v4" "blocklist_all" "inet"
load_ipset "$TMPDIR/wl.v6" "allowed_whitelist_v6" "inet6"
load_ipset "$TMPDIR/bl_final.v6" "blocklist_all_v6" "inet6"

# 5. Iptables Enforcement
iptables -C INPUT -m set --match-set allowed_whitelist src -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -m set --match-set allowed_whitelist src -j ACCEPT

if [[ "${HONEYPOT_MODE:-false}" == "true" ]]; then
    iptables -C INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -p tcp --dport 2222 -j ACCEPT
fi

iptables -C INPUT -m set --match-set blocklist_all src -j DROP 2>/dev/null || iptables -A INPUT -m set --match-set blocklist_all src -j DROP

# IPv6 Support
if [[ -f /proc/net/if_inet6 ]]; then
    ip6tables -C INPUT -m set --match-set allowed_whitelist_v6 src -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -m set --match-set allowed_whitelist_v6 src -j ACCEPT
    ip6tables -C INPUT -m set --match-set blocklist_all_v6 src -j DROP 2>/dev/null || ip6tables -A INPUT -m set --match-set blocklist_all_v6 src -j DROP
fi

# Docker Support
if iptables -L DOCKER-USER >/dev/null 2>&1; then
    iptables -C DOCKER-USER -m set --match-set allowed_whitelist src -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -m set --match-set allowed_whitelist src -j ACCEPT
    iptables -C DOCKER-USER -m set --match-set blocklist_all src -j DROP 2>/dev/null || iptables -A DOCKER-USER -m set --match-set blocklist_all src -j DROP
fi

count=$(ipset list blocklist_all -t | grep "Number of entries" | cut -d: -f2 | tr -d ' ')
log "Finished. Blocked IPv4: $count"
[[ $count -lt 10000 ]] && send_telegram "⚠️ Warning: Low blocklist count ($count)"