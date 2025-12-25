#!/bin/bash
set -euo pipefail
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# --- VERSION CONTROL ---
SCRIPT_VERSION="v8.1"

#################################################
# Firewall Blocklist Updater (v8.1 - HoneyDB Purged)
# - REMOVED: All HoneyDB API references, keys & logic
# - CORE: Safe Config Loading & Browser User-Agent
# - FEAT: Full Sensor Suite (Endlessh + CrowdSec)
#################################################

# --- Constants ---
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="$BASE_DIR/firewall-blocklists"
KEYFILE="${KEYFILE:-$BASE_DIR/firewall-blocklist-keys.env}"
SOURCE_FILE="$CONFIG_DIR/blocklist.sources"
CUSTOM_WL_FILE="$CONFIG_DIR/whitelist.custom"
BACKUP_DIR="$BASE_DIR/backups"
SCRIPT_BIN="/usr/local/bin/update-firewall-blocklists.sh"
REPO_RAW_URL="https://raw.githubusercontent.com/gbzret4d/firewall-blocklist-updater/main/update-firewall-blocklists.sh"
LOCKFILE="/var/run/firewall-updater.lock"
LOGFILE="/var/log/firewall-blocklist-updater.log"
MAX_LOG_SIZE=$((5 * 1024 * 1024))
TIMER_FILE="/etc/systemd/system/firewall-blocklist-updater.timer"

# --- Globals ---
DRY_RUN=0
IPV6_ENABLED=1

# --- Lists (Fallback defaults) ---
RECOMMENDED_LISTS=(
    "Spamhaus DROP|https://www.spamhaus.org/drop/drop.txt"
    "Spamhaus EDROP|https://www.spamhaus.org/drop/edrop.txt"
    "DShield|https://feeds.dshield.org/block.txt"
    "Feodo Tracker|https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    "GreenSnow|https://blocklist.greensnow.co/greensnow.txt"
    "AbuseIPDB 100%|https://github.com/borestad/blocklist-abuseipdb/raw/refs/heads/main/abuseipdb-s100-7d.ipv4"
    "CINS Score|https://cinsscore.com/list/ci-badguys.txt"
)

# --- Logging ---
manage_log_size() {
    if [[ -f "$LOGFILE" ]]; then
        local size
        if command -v stat >/dev/null; then
            if [[ "$OSTYPE" == "linux-gnu"* ]]; then size=$(stat -c%s "$LOGFILE"); else size=$(stat -f%z "$LOGFILE"); fi
        else size=$(wc -c < "$LOGFILE"); fi
        if [[ $size -gt $MAX_LOG_SIZE ]]; then
            tail -n 2000 "$LOGFILE" > "${LOGFILE}.tmp" && mv "${LOGFILE}.tmp" "$LOGFILE"
        fi
    fi
}
log() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" | tee -a "$LOGFILE"; }
warn() { echo -e "\033[0;33m$(date '+%Y-%m-%d %H:%M:%S') [WARN] $*\033[0m" | tee -a "$LOGFILE"; }
dry() { echo -e "\033[0;36m[DRY-RUN] $*\033[0m"; }

cleanup() {
    rm -f "$LOCKFILE"
    rm -f /tmp/firewall-blocklists/*.lst /tmp/firewall-blocklists/*.v4 /tmp/firewall-blocklists/*.v6 /tmp/firewall-blocklists/*.ipset 
}
trap cleanup EXIT INT TERM

# --- Init ---
CURL_OPTS="-sfL --connect-timeout 20 --retry 2 -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'"
if curl --help | grep -q -- "--compressed"; then CURL_OPTS="$CURL_OPTS --compressed"; fi

HAS_FLOCK=0; if command -v flock >/dev/null; then HAS_FLOCK=1; fi
mkdir -p "$BASE_DIR" "$CONFIG_DIR" "$BACKUP_DIR"

check_dep() { if ! command -v "$1" &>/dev/null; then warn "Missing dependency: $1"; fi; }
for cmd in curl ipset iptables grep sort comm unzip file dig awk tr ip ss sed xargs; do check_dep "$cmd"; done

check_ipv6_stack() {
    if [[ ! -f /proc/net/if_inet6 ]]; then return 1; fi
    if ! ip -6 addr show scope global | grep -q "inet6"; then return 1; fi
    return 0
}

# --- Env Vars & Safe Loading ---
WHITELIST_COUNTRIES=""
BLOCKLIST_COUNTRIES=""
DYNDNS_HOST=""
ABUSEIPDB_API_KEY=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""

load_env_vars() {
  if [[ -f "$KEYFILE" ]]; then
    # Fix Windows line endings
    if command -v dos2unix >/dev/null; then dos2unix -q "$KEYFILE"; else tr -d '\r' < "$KEYFILE" > "${KEYFILE}.tmp" && mv "${KEYFILE}.tmp" "$KEYFILE"; fi
    
    # SAFE PARSER: Read line by line, ignore shell logic
    while IFS='=' read -r key val || [[ -n "$key" ]]; do
        [[ "$key" =~ ^# || -z "$key" ]] && continue
        [[ "$key" =~ ^(if|then|else|fi|case|esac|for|do|done|function) ]] && continue
        
        val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
        
        # Explicit Whitelist (HoneyDB completely removed)
        case "$key" in
            WHITELIST_COUNTRIES|BLOCKLIST_COUNTRIES|DYNDNS_HOST|ABUSEIPDB_API_KEY|TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID)
                printf -v "$key" "%s" "$val"
                ;;
        esac
    done < "$KEYFILE"
    
    # Sanitize Countries
    WHITELIST_COUNTRIES=$(echo "${WHITELIST_COUNTRIES:-}" | tr -cd 'A-Za-z ')
    BLOCKLIST_COUNTRIES=$(echo "${BLOCKLIST_COUNTRIES:-}" | tr -cd 'A-Za-z ')
  fi
}
load_env_vars

perform_auto_update() {
  if [[ "${1:-}" == "--post-update" ]]; then log "[AUTO-UPDATE] Update to $SCRIPT_VERSION successful."; return 0; fi
  if [[ $DRY_RUN -eq 1 ]]; then return 0; fi
  local tmp="/tmp/update-fw.sh.new"
  if curl -sfL -o "$tmp" "${REPO_RAW_URL}?t=$(date +%s)" || true; then
     if [[ -s "$tmp" ]]; then
         local remote_ver
         remote_ver=$(grep -oE 'SCRIPT_VERSION="v[0-9.]+"' "$tmp" | head -n1 | cut -d'"' -f2 || echo "unknown")
         if [[ "$remote_ver" != "unknown" && "$remote_ver" != "$SCRIPT_VERSION" ]]; then
            log "[AUTO-UPDATE] New version found ($remote_ver). Updating from $SCRIPT_VERSION..."
            cp "$tmp" "$SCRIPT_BIN" && chmod +x "$SCRIPT_BIN"
            rm -f "$tmp"
            exec "$SCRIPT_BIN" "--post-update"
         else rm -f "$tmp"; fi
     else rm -f "$tmp"; fi
  fi
}

check_connectivity() {
    if ! curl -s --head --request GET https://1.1.1.1 > /dev/null; then
        warn "No internet connection. Skipping update."
        exit 0
    fi
}

send_telegram() {
    local msg="$1"
    if [[ $DRY_RUN -eq 1 ]]; then dry "Telegram would send: $msg"; return; fi
    if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" \
            -d text="$msg" \
            -d parse_mode="HTML" >/dev/null || true
    fi
}

# --- SENSOR SETUP ---
check_port_free() {
    local port="$1"
    if command -v ss >/dev/null; then if ss -tuln | grep -q ":$port "; then return 1; fi
    elif command -v netstat >/dev/null; then if netstat -tuln | grep -q ":$port "; then return 1; fi; fi
    return 0
}

install_sensors() {
    echo ">>> Installing Sensors (Endlessh & Port-Scan Detection)..."
    if ! check_port_free 2222; then
        if ! pgrep -x "endlessh" >/dev/null; then
             echo "❌ Error: Port 2222 is already in use!"; return 1
        fi
    fi

    if ! command -v endlessh >/dev/null; then
        echo " -> Installing Endlessh package..."
        if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y endlessh
        elif command -v dnf >/dev/null; then dnf install -y endlessh
        elif command -v yum >/dev/null; then yum install -y endlessh
        elif command -v zypper >/dev/null; then zypper install -y endlessh
        else echo "❌ OS not supported. Install 'endlessh' manually."; return 1; fi
    fi

    mkdir -p /etc/endlessh
    if [[ -d /etc/endlessh ]]; then
        echo " -> Configuring Endlessh on Port 2222..."
        cat <<EOF > /etc/endlessh/config
Port 2222
Delay 10000
MaxLineLength 32
MSL 0
LogLevel 1
BindFamily 0
EOF
        systemctl enable --now endlessh; systemctl restart endlessh
    fi

    if command -v cscli >/dev/null; then
        echo " -> Installing CrowdSec Collections..."
        cscli collections install crowdsecurity/endlessh --force >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/iptables --force >/dev/null 2>&1 || true
        if ! grep -q "type: endlessh" /etc/crowdsec/acquis.yaml 2>/dev/null; then
            echo " -> Adding Endlessh & IPTables logs to CrowdSec..."
            cat <<YAML >> /etc/crowdsec/acquis.yaml

filenames:
  - /var/log/syslog
  - /var/log/kern.log
  - /var/log/messages
labels:
  type: iptables
---
filenames:
  - /var/log/syslog
  - /var/log/messages
labels:
  type: endlessh
YAML
            systemctl restart crowdsec; echo "✅ CrowdSec configured."
        fi
    fi
}

# --- MENUS ---
update_env_var() {
    local key="$1"; local val="$2"
    [[ ! -f "$KEYFILE" ]] && touch "$KEYFILE"
    if grep -q "^$key=" "$KEYFILE"; then sed -i "s|^$key=.*|$key=\"$val\"|" "$KEYFILE"; else echo "$key=\"$val\"" >> "$KEYFILE"; fi
    export "$key"="$val"
}

ask_user() {
    local prompt="$1"; local var_name="$2"; local current_val="${!var_name:-}"
    read -p "$prompt [Current: ${current_val:-None}] (Type 'none' to clear): " input
    if [[ "$input" == "none" ]]; then update_env_var "$var_name" ""; echo " -> Cleared."
    elif [[ -n "$input" ]]; then update_env_var "$var_name" "$input"; fi
}

menu_geo() {
    echo -e "\n--- 🌍 Geo-Blocking Settings ---"
    ask_user "Whitelist Countries (e.g. DE AT)" "WHITELIST_COUNTRIES"
    ask_user "Blocklist Countries (e.g. CN RU)" "BLOCKLIST_COUNTRIES"
}

menu_keys() {
    echo -e "\n--- 🔑 API Keys & CrowdSec ---"
    ask_user "AbuseIPDB API Key" "ABUSEIPDB_API_KEY"
    update_crowdsec_abuseipdb "$ABUSEIPDB_API_KEY"
    ask_user "DynDNS Hostname" "DYNDNS_HOST"
}

menu_telegram() {
    echo -e "\n--- 📢 Telegram Notifications ---"
    ask_user "Telegram Bot Token" "TELEGRAM_BOT_TOKEN"
    ask_user "Telegram Chat ID" "TELEGRAM_CHAT_ID"
    load_env_vars
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        echo " -> Sending test message..."; send_telegram "🔔 <b>Test</b> from $(hostname)"; echo " -> Check Telegram!"
    fi
}

menu_lists() {
    echo -e "\n--- 📋 Manage Blocklist Sources ---"
    [[ ! -f "$SOURCE_FILE" ]] && touch "$SOURCE_FILE"
    local current_content; current_content=$(cat "$SOURCE_FILE")
    local new_content=""
    echo "Select lists to ENABLE (y) or DISABLE (n/Enter):"
    for entry in "${RECOMMENDED_LISTS[@]}"; do
        local name="${entry%%|*}"; local url="${entry#*|}"
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

menu_timer() {
    echo -e "\n--- ⏲️ Update Interval ---"
    if [[ ! -f "$TIMER_FILE" ]]; then echo "Error: Timer file missing."; return; fi
    read -p "New Interval (e.g. 'hourly', 'daily'): " new_val
    if [[ -n "$new_val" ]]; then
        sed -i "s|^OnCalendar=.*|OnCalendar=$new_val|" "$TIMER_FILE"
        systemctl daemon-reload; systemctl restart firewall-blocklist-updater.timer
        echo "✅ Timer updated."
    fi
}

update_crowdsec_abuseipdb() {
    local key="$1"
    if ! command -v crowdsec >/dev/null; then return 0; fi
    echo " -> Updating CrowdSec config..."
    if [[ -z "$key" ]]; then
        [[ -f /etc/crowdsec/profiles.yaml ]] && sed -i '/- abuseipdb/d' /etc/crowdsec/profiles.yaml
    else
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
    "key": "$key"
  }
url: https://api.abuseipdb.com/api/v2/report
method: POST
headers:
  Content-Type: application/json
  Accept: application/json
NOTIFY
        if ! grep -q "abuseipdb" /etc/crowdsec/profiles.yaml 2>/dev/null; then
             if grep -q "notifications:" /etc/crowdsec/profiles.yaml; then sed -i '/notifications:/a \ - abuseipdb' /etc/crowdsec/profiles.yaml
             else echo -e "notifications:\n - abuseipdb" >> /etc/crowdsec/profiles.yaml; fi
        fi
    fi
    systemctl restart crowdsec
}

interactive_menu() {
    set +e 
    while true; do
        clear
        local sensor_status="[\033[0;31mNOT INSTALLED\033[0m]"
        if command -v endlessh >/dev/null && grep -q "type: endlessh" /etc/crowdsec/acquis.yaml 2>/dev/null; then sensor_status="[\033[1;32mACTIVE\033[0m]"; fi
        echo "==============================================="
        echo "   Firewall Admin Menu ($SCRIPT_VERSION)       "
        echo "==============================================="
        echo "1) 🌍 Geo-Blocking"
        echo "2) 📋 Blocklists"
        echo "3) 🔑 API Keys"
        echo "4) 📢 Telegram"
        echo "5) ⏲️ Timer"
        echo -e "6) 🪤 Sensors $sensor_status"
        echo "7) 🔄 Update NOW"
        echo "0) Exit"
        echo "-----------------------------------------------"
        read -p "Select: " opt
        case $opt in
            1) menu_geo ;; 2) menu_lists ;; 3) menu_keys ;; 4) menu_telegram ;; 5) menu_timer ;;
            6) install_sensors; read -p "Press Enter..." ;;
            7) main ;; 0) exit 0 ;; *) echo "Invalid" ;;
        esac
    done
    set -e
}

# --- Core Logic ---
TMPDIR="/tmp/firewall-blocklists"; mkdir -p "$TMPDIR"
IPSET_WL="allowed_whitelist"; IPSET_BL="blocklist_all"
IPSET_HASH_SIZE=4096; IPSET_MAX_ELEM=2000000

get_set_count() {
    ipset list "$1" -t 2>/dev/null | grep "Number of entries" | cut -d: -f2 | tr -d ' ' || echo 0
}

smart_extract() {
    local f="$1"; local m=""; command -v file >/dev/null && m=$(file --mime-type -b "$f")
    case "$m" in
        application/zip) unzip -p "$f" || true ;;
        application/gzip|application/x-gzip) gunzip -c "$f" || true ;;
        *) cat "$f" ;;
    esac
}

download_parallel() {
  local out="$1"; shift; local srcs=("$@")
  : > "$TMPDIR/merge.lst"
  [[ ${#srcs[@]} -eq 0 ]] && touch "$out" && return 0
  export -f smart_extract
  export TMPDIR CURL_OPTS
  
  printf '%s\n' "${srcs[@]}" | xargs -P4 -I{} bash -c '
    u="{}"; f=$(basename "$u" | sed "s/[^a-zA-Z0-9._-]/_/g")
    if curl '"$CURL_OPTS"' "$u" -o "$TMPDIR/$f" || true; then
        if [[ -s "$TMPDIR/$f" ]]; then
            # HTML Check
            if head -n 1 "$TMPDIR/$f" | grep -qiE "<!DOCTYPE|<html"; then
                echo "[WARNING] Download dropped (HTML detected): $u" >&2
                rm "$TMPDIR/$f"
            else
                tr -d "\r" < "$TMPDIR/$f" > "$TMPDIR/$f.clean" && mv "$TMPDIR/$f.clean" "$TMPDIR/$f"
                smart_extract "$TMPDIR/$f" >> "$TMPDIR/merge.lst" || true
                echo "" >> "$TMPDIR/merge.lst"
            fi
        else
            echo "[WARNING] Download empty or failed for: $u" >&2
        fi
    fi'
  sed -i 's/[#;].*//g' "$TMPDIR/merge.lst"
  sort -u "$TMPDIR/merge.lst" > "$out"
}

extract_ips() {
    local input="$1"; local output="$2"; local family="$3"
    [[ ! -f "$input" ]] && touch "$output" && return 0
    if [[ "$family" == "inet" ]]; then
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$input" > "$input.tmp" || true
        awk -F'[./]' '{valid=1; for(i=1;i<=4;i++)if($i>255)valid=0; if(NF>4&&$NF>32)valid=0; if(valid)print $0}' "$input.tmp" > "$output"
        rm -f "$input.tmp"
    else
        if [[ $IPV6_ENABLED -eq 1 ]]; then
            grep -v "http" "$input" | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?' | grep -E '[0-9a-fA-F]' | grep -vE "^::1$" > "$output" || true
        else touch "$output"; fi
    fi
}

backup_sets() {
    local setname="$1"
    if [[ $DRY_RUN -eq 1 ]]; then dry "Would backup set $setname"; return; fi
    if ipset list "$setname" >/dev/null 2>&1; then ipset save "$setname" > "$BACKUP_DIR/$setname.save" 2>/dev/null || true; fi
}

restore_backup() {
    local setname="$1"
    if [[ -f "$BACKUP_DIR/$setname.save" ]]; then warn "Restoring backup for $setname..."; ipset restore -! < "$BACKUP_DIR/$setname.save" || warn "Restore failed!"; fi
}

load_ipset() {
  local file="$1"; local setname="$2"; local family="$3"
  if [[ ! -s "$file" ]]; then return 0; fi
  if [[ "$family" == "inet6" && $IPV6_ENABLED -eq 0 ]]; then return 0; fi
  if [[ $DRY_RUN -eq 1 ]]; then local cnt; cnt=$(wc -l < "$file"); dry "Load $setname ($family): $cnt entries."; return 0; fi

  backup_sets "$setname"
  local tmp_set="${setname}_tmp"
  ipset create $setname hash:net family $family hashsize $IPSET_HASH_SIZE maxelem $IPSET_MAX_ELEM -exist 2>/dev/null || true

  echo "destroy $tmp_set" > "$TMPDIR/rst.ipset"
  echo "create $tmp_set hash:net family $family hashsize $IPSET_HASH_SIZE maxelem $IPSET_MAX_ELEM -exist" >> "$TMPDIR/rst.ipset"
  echo "flush $tmp_set" >> "$TMPDIR/rst.ipset"
  sed "s/^/add $tmp_set /" "$file" >> "$TMPDIR/rst.ipset"
  echo "swap $tmp_set $setname" >> "$TMPDIR/rst.ipset"
  echo "destroy $tmp_set" >> "$TMPDIR/rst.ipset"
  
  if ! ipset restore -! < "$TMPDIR/rst.ipset"; then
      warn "Failed to load set $setname. Attempting rollback..."
      restore_backup "$setname"
  fi
}

update_dyndns() {
  [[ -z "$DYNDNS_HOST" ]] && return 0
  if [[ $DRY_RUN -eq 1 ]]; then dry "Update DynDNS: $DYNDNS_HOST"; return; fi
  local ip=""
  if command -v dig >/dev/null; then ip=$(dig +short "$DYNDNS_HOST" | head -n1 || true)
  elif command -v host >/dev/null; then ip=$(host "$DYNDNS_HOST" | awk '/has address/{print $4}' | head -n1 || true)
  elif command -v getent >/dev/null; then ip=$(getent hosts "$DYNDNS_HOST" | awk '{print $1}' | head -n1 || true); fi
  
  if [[ -n "$ip" ]]; then
     local t="$IPSET_WL"; [[ "$ip" =~ : ]] && t="${IPSET_WL}_v6"
     if [[ "$t" == "${IPSET_WL}_v6" && $IPV6_ENABLED -eq 0 ]]; then return; fi
     ipset add "$t" "$ip" -exist 2>/dev/null || true
  fi
}

ensure_sensor_logging() {
    if [[ $DRY_RUN -eq 1 ]]; then return; fi
    if command -v crowdsec >/dev/null; then
        if ! iptables -C INPUT -m limit --limit 10/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4 2>/dev/null; then
            iptables -A INPUT -m limit --limit 10/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4 2>/dev/null || true
        fi
    fi
}

main() {
  if [[ "${1:-}" == "--dry-run" ]]; then DRY_RUN=1; echo "⚠️ DRY-RUN MODE"; fi
  if [[ "${1:-}" == "--setup-sensors" ]]; then install_sensors; exit 0; fi

  rm -rf "$TMPDIR"; mkdir -p "$TMPDIR"
  [[ "${1:-}" != "--post-update" && "${1:-}" != "--configure" && $DRY_RUN -eq 0 ]] && perform_auto_update "${1:-}"
  manage_log_size
  log "=== Update Start $SCRIPT_VERSION ==="
  
  if [[ $HAS_FLOCK -eq 1 && $DRY_RUN -eq 0 ]]; then 
      exec 9>"$LOCKFILE"
      if ! flock -n 9; then echo "[ERROR] Script running."; exit 1; fi
  fi
  
  check_connectivity
  if check_ipv6_stack; then IPV6_ENABLED=1; else log "Smart IPv6: Disabled."; IPV6_ENABLED=0; fi
  
  local cnt_old_v4; cnt_old_v4=$(get_set_count "$IPSET_BL")
  local cnt_old_v6; cnt_old_v6=$(get_set_count "${IPSET_BL}_v6")

  log "Processing Whitelists..."
  : > "$TMPDIR/wl_raw.lst"
  local wl=(); [[ -f "$CONFIG_DIR/whitelist.sources" ]] && mapfile -t wl < <(grep -vE '^\s*#' "$CONFIG_DIR/whitelist.sources" || true)
  
  for c in $WHITELIST_COUNTRIES; do 
      if [[ "$c" =~ ^[a-zA-Z]{2}$ ]]; then
          wl+=("https://iplists.firehol.org/files/geolite2_country/country_${c,,}.netset")
      fi
  done
  download_parallel "$TMPDIR/wl_raw.lst" "${wl[@]}"
  
  [[ -f "$CUSTOM_WL_FILE" ]] && cat "$CUSTOM_WL_FILE" >> "$TMPDIR/wl_raw.lst"
  if [[ -n "${SSH_CLIENT:-}" ]]; then echo "$SSH_CLIENT" | awk '{print $1}' >> "$TMPDIR/wl_raw.lst"; fi
  extract_ips "$TMPDIR/wl_raw.lst" "$TMPDIR/wl.v4" "inet"
  extract_ips "$TMPDIR/wl_raw.lst" "$TMPDIR/wl.v6" "inet6"

  log "Processing Blocklists..."
  local bl=(); [[ -f "$CONFIG_DIR/blocklist.sources" ]] && mapfile -t bl < <(grep -vE '^\s*#' "$CONFIG_DIR/blocklist.sources" || true)
  
  for c in $BLOCKLIST_COUNTRIES; do 
      if [[ "$c" =~ ^[a-zA-Z]{2}$ ]]; then
          bl+=("https://iplists.firehol.org/files/geolite2_country/country_${c,,}.netset")
      fi
  done
  download_parallel "$TMPDIR/bl_raw.lst" "${bl[@]}"

  extract_ips "$TMPDIR/bl_raw.lst" "$TMPDIR/bl.v4" "inet"
  extract_ips "$TMPDIR/bl_raw.lst" "$TMPDIR/bl.v6" "inet6"

  log "Filtering & Merging Lists..."
  grep -vE "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)" "$TMPDIR/bl.v4" > "$TMPDIR/bl.v4.tmp" || true
  mv "$TMPDIR/bl.v4.tmp" "$TMPDIR/bl.v4"
  sort -u "$TMPDIR/bl.v4" | comm -23 - <(sort -u "$TMPDIR/wl.v4") > "$TMPDIR/bl_final.v4"
  sort -u "$TMPDIR/bl.v6" | comm -23 - <(sort -u "$TMPDIR/wl.v6") > "$TMPDIR/bl_final.v6"

  log "Applying Firewall Rules..."
  load_ipset "$TMPDIR/wl.v4" "$IPSET_WL" "inet"
  load_ipset "$TMPDIR/bl_final.v4" "$IPSET_BL" "inet"
  load_ipset "$TMPDIR/wl.v6" "${IPSET_WL}_v6" "inet6"
  load_ipset "$TMPDIR/bl_final.v6" "${IPSET_BL}_v6" "inet6"

  if [[ $DRY_RUN -eq 0 ]]; then
      log "Updating IPTables..."
      iptables -C INPUT -m set --match-set "$IPSET_BL" src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set "$IPSET_BL" src -j DROP
      if [[ $IPV6_ENABLED -eq 1 ]]; then
          command -v ip6tables >/dev/null && { ip6tables -C INPUT -m set --match-set "${IPSET_BL}_v6" src -j DROP 2>/dev/null || ip6tables -I INPUT -m set --match-set "${IPSET_BL}_v6" src -j DROP; }
      fi
      ensure_sensor_logging
  else dry "Rules simulated."; fi
  
  update_dyndns

  local cnt_new_v4; cnt_new_v4=$(get_set_count "$IPSET_BL")
  local cnt_new_v6; cnt_new_v6=$(get_set_count "${IPSET_BL}_v6")
  if [[ $DRY_RUN -eq 1 ]]; then cnt_new_v4=$(wc -l < "$TMPDIR/bl_final.v4" || echo 0); cnt_new_v6=$(wc -l < "$TMPDIR/bl_final.v6" || echo 0); fi
  
  local diff_v4=$((cnt_new_v4 - cnt_old_v4)); local diff_v6=$((cnt_new_v6 - cnt_old_v6))
  local s_v4=""; [[ $diff_v4 -ge 0 ]] && s_v4="+"
  local s_v6=""; [[ $diff_v6 -ge 0 ]] && s_v6="+"

  local report="📊 Update Summary ($SCRIPT_VERSION)%0AIPv4 Blocked: $cnt_new_v4 ($s_v4$diff_v4)%0AIPv6 Blocked: $cnt_new_v6 ($s_v6$diff_v6)"
  [[ $IPV6_ENABLED -eq 0 ]] && report="$report (IPv6 Disabled)"
  [[ $DRY_RUN -eq 1 ]] && report="⚠️ DRY-RUN REPORT%0A$report"

  echo "------------------------------------------------"
  echo -e "${report//%0A/\\n}"
  echo "------------------------------------------------"

  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
      report="🛡️ <b>Firewall Update: $(hostname)</b>%0A$report"
      send_telegram "$report"
  fi
  log "=== Finished [IPv4: $cnt_new_v4, IPv6: $cnt_new_v6] ==="
}

# --- ENTRY POINT ---
[[ "${1:-}" == "--configure" || "${1:-}" == "-i" ]] && interactive_menu
main "${1:-}"