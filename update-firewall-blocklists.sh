#!/bin/bash
set -euo pipefail
export LC_ALL=C 

# --- VERSION CONTROL ---
SCRIPT_VERSION="v6.7"

#################################################
# Firewall Blocklist Updater (v6.7 - Final Hardened)
# - HARDENING: Stale Lock File Removal
# - HARDENING: Input Validation for Custom Whitelists
# - HARDENING: Zero-Byte File Protection
# - FEAT: Smart IPv6, Self-Healing, Dry-Run
# - FEAT: Telegram, SSH-Safety, Atomic Swap
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
    rm -f "$LOCKFILE" /tmp/firewall-blocklists/*.lst /tmp/firewall-blocklists/*.v4 /tmp/firewall-blocklists/*.v6 /tmp/firewall-blocklists/*.ipset 2>/dev/null || true
}
trap cleanup EXIT

# --- Init ---
CURL_OPTS="-sfL --connect-timeout 20 --retry 2"
if curl --help | grep -q -- "--compressed"; then CURL_OPTS="$CURL_OPTS --compressed"; fi
HAS_FLOCK=0; if command -v flock >/dev/null; then HAS_FLOCK=1; fi
mkdir -p "$BASE_DIR" "$CONFIG_DIR" "$BACKUP_DIR"

check_dep() { if ! command -v "$1" &>/dev/null; then warn "Missing dependency: $1"; fi; }
for cmd in curl ipset iptables grep sort comm unzip file dig awk tr ip; do check_dep "$cmd"; done

# --- Smart IPv6 Check ---
check_ipv6_stack() {
    if [[ ! -f /proc/net/if_inet6 ]]; then return 1; fi
    # Check for global scope address (ignoring Link-Local)
    if ! ip -6 addr show scope global | grep -q "inet6"; then return 1; fi
    return 0
}

# --- Env Vars ---
WHITELIST_COUNTRIES=""; BLOCKLIST_COUNTRIES=""; DYNDNS_HOST=""
ABUSEIPDB_API_KEY=""; HONEYDB_API_ID=""; HONEYDB_API_KEY=""
TELEGRAM_BOT_TOKEN=""; TELEGRAM_CHAT_ID=""

load_env_vars() {
  if [[ -f "$KEYFILE" ]]; then
    chmod 600 "$KEYFILE"
    while IFS='=' read -r key val || [[ -n "$key" ]]; do
       [[ "$key" =~ ^# || -z "$key" ]] && continue
       key="${key//export /}"; key="${key// /}"; val="${val%\"}"; val="${val#\"}"
       [[ -n "$key" ]] && printf -v "$key" "%s" "$val"
    done < "$KEYFILE"
  fi
}
load_env_vars

perform_auto_update() {
  if [[ "${1:-}" == "--post-update" ]]; then 
      log "[AUTO-UPDATE] Update to $SCRIPT_VERSION successful."; 
      return 0
  fi
  if [[ $DRY_RUN -eq 1 ]]; then return 0; fi
  
  local tmp="/tmp/update-fw.sh.new"
  if curl $CURL_OPTS -o "$tmp" "${REPO_RAW_URL}?t=$(date +%s)" || true; then
     if [[ -s "$tmp" ]]; then
         local remote_ver
         remote_ver=$(grep -oE 'SCRIPT_VERSION="v[0-9.]+"' "$tmp" | head -n1 | cut -d'"' -f2 || echo "unknown")
         if [[ "$remote_ver" != "unknown" && "$remote_ver" != "$SCRIPT_VERSION" ]]; then
            log "[AUTO-UPDATE] New version found ($remote_ver). Updating from $SCRIPT_VERSION..."
            cp "$tmp" "$SCRIPT_BIN" && chmod +x "$SCRIPT_BIN"
            rm -f "$tmp"
            exec "$SCRIPT_BIN" "--post-update"
         else
            rm -f "$tmp"
         fi
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

# --- MENUS ---
update_env_var() {
    local key="$1"; local val="$2"
    [[ ! -f "$KEYFILE" ]] && touch "$KEYFILE"
    if grep -q "^$key=" "$KEYFILE" || true; then 
        if grep -q "^$key=" "$KEYFILE"; then
            sed -i "s|^$key=.*|$key=\"$val\"|" "$KEYFILE"
        else
            echo "$key=\"$val\"" >> "$KEYFILE"
        fi
    else 
        echo "$key=\"$val\"" >> "$KEYFILE"
    fi
    printf -v "$key" "%s" "$val"
}

ask_user() {
    local prompt="$1"; local var_name="$2"; local current_val="${!var_name:-}"
    read -p "$prompt [Current: ${current_val:-None}] (Type 'none' to clear): " input
    if [[ "$input" == "none" ]]; then
        update_env_var "$var_name" ""
        echo " -> Cleared."
    elif [[ -n "$input" ]]; then
        update_env_var "$var_name" "$input"
    fi
}

menu_geo() {
    echo -e "\n--- 🌍 Geo-Blocking Settings ---"
    ask_user "Whitelist Countries (Space separated, e.g. DE AT)" "WHITELIST_COUNTRIES"
    ask_user "Blocklist Countries (Space separated, e.g. CN RU)" "BLOCKLIST_COUNTRIES"
}

menu_keys() {
    echo -e "\n--- 🔑 API Keys & CrowdSec ---"
    ask_user "AbuseIPDB API Key" "ABUSEIPDB_API_KEY"
    update_crowdsec_abuseipdb "$ABUSEIPDB_API_KEY"
    ask_user "HoneyDB API ID" "HONEYDB_API_ID"
    ask_user "HoneyDB API Key" "HONEYDB_API_KEY"
    ask_user "DynDNS Hostname" "DYNDNS_HOST"
}

menu_telegram() {
    echo -e "\n--- 📢 Telegram Notifications ---"
    echo "To get these values: Create a bot with @BotFather, then get your user ID from @userinfobot."
    ask_user "Telegram Bot Token" "TELEGRAM_BOT_TOKEN"
    ask_user "Telegram Chat ID" "TELEGRAM_CHAT_ID"
    load_env_vars
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        echo " -> Sending test message..."
        send_telegram "🔔 <b>Test Message</b> from Firewall Updater on $(hostname)"
        echo " -> Check your Telegram!"
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
        local status="[ ]"
        if echo "$current_content" | grep -Fq "$url"; then
            status="[\033[1;32mx\033[0m]" # Green X
            read -p "$(echo -e "$status $name") - Keep? (Y/n): " yn
            if [[ ! "$yn" =~ ^[Nn]$ ]]; then new_content+="$url"$'\n'; fi
        else
            read -p "$(echo -e "$status $name") - Enable? (y/N): " yn
            if [[ "$yn" =~ ^[Yy]$ ]]; then new_content+="$url"$'\n'; fi
        fi
    done
    echo "$new_content" > "$SOURCE_FILE"
    echo "✅ Selection saved."
}

menu_timer() {
    echo -e "\n--- ⏲️ Update Interval (Systemd Timer) ---"
    if [[ ! -f "$TIMER_FILE" ]]; then echo "Error: Timer file not found."; return; fi
    local current_timer
    current_timer=$(grep "OnCalendar" "$TIMER_FILE" | cut -d= -f2 || echo "Unknown")
    echo "Current Interval: $current_timer"
    echo "Examples: 'hourly', 'daily', '*-*-* 04:00:00'"
    read -p "New Interval (Enter to keep): " new_val
    if [[ -n "$new_val" ]]; then
        if command -v systemd-analyze >/dev/null; then
             if ! systemd-analyze calendar "$new_val" >/dev/null 2>&1; then
                 echo "❌ Invalid Systemd calendar format. Aborted."
                 return
             fi
        fi
        sed -i "s|^OnCalendar=.*|OnCalendar=$new_val|" "$TIMER_FILE"
        systemctl daemon-reload
        systemctl restart firewall-blocklist-updater.timer
        echo "✅ Timer updated to: $new_val (Active)"
    else
        echo " -> No change."
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
             if grep -q "notifications:" /etc/crowdsec/profiles.yaml; then
                 sed -i '/notifications:/a \ - abuseipdb' /etc/crowdsec/profiles.yaml
             else
                 echo "notifications:" >> /etc/crowdsec/profiles.yaml
                 echo " - abuseipdb" >> /etc/crowdsec/profiles.yaml
             fi
        fi
    fi
    systemctl restart crowdsec
}

interactive_menu() {
    set +e 
    while true; do
        clear
        echo "==============================================="
        echo "   Firewall Admin Menu ($SCRIPT_VERSION)       "
        echo "==============================================="
        echo "1) 🌍 Configure Geo-Blocking"
        echo "2) 📋 Select Blocklists"
        echo "3) 🔑 Configure API Keys (AbuseIPDB, HoneyDB)"
        echo "4) 📢 Configure Telegram Notifications"
        echo "5) ⏲️ Change Update Interval"
        echo "6) 🔄 Run Update NOW"
        echo "0) Exit"
        echo "-----------------------------------------------"
        read -p "Select option: " opt
        case $opt in
            1) menu_geo ;;
            2) menu_lists ;;
            3) menu_keys ;;
            4) menu_telegram ;;
            5) menu_timer ;;
            6) main ;;
            0) exit 0 ;;
            *) echo "Invalid option" ;;
        esac
        echo ""
        read -p "Press Enter to return to menu..."
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
    if curl '"$CURL_OPTS"' -A "fw-updater" "$u" -o "$TMPDIR/$f"; then
        if [[ -s "$TMPDIR/$f" ]]; then
            tr -d "\r" < "$TMPDIR/$f" > "$TMPDIR/$f.clean" && mv "$TMPDIR/$f.clean" "$TMPDIR/$f"
            smart_extract "$TMPDIR/$f" >> "$TMPDIR/merge.lst" || true
            echo "" >> "$TMPDIR/merge.lst"
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
        awk -F'[./]' '{
            valid = 1
            for(i=1; i<=4; i++) { if($i > 255) valid = 0 }
            if(NF > 4 && $NF > 32) valid = 0
            if(valid) print $0
        }' "$input.tmp" > "$output"
        rm -f "$input.tmp"
    else
        # Only process IPv6 if enabled
        if [[ $IPV6_ENABLED -eq 1 ]]; then
            grep -v "http" "$input" | \
            grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?' | \
            grep -E '[0-9a-fA-F]' | \
            grep -vE "^::1$" > "$output" || true
        else
             touch "$output"
        fi
    fi
}

backup_sets() {
    local setname="$1"
    if [[ $DRY_RUN -eq 1 ]]; then dry "Would backup set $setname"; return; fi
    # Save current set if it exists
    if ipset list "$setname" >/dev/null 2>&1; then
        ipset save "$setname" > "$BACKUP_DIR/$setname.save" 2>/dev/null || true
    fi
}

restore_backup() {
    local setname="$1"
    if [[ -f "$BACKUP_DIR/$setname.save" ]]; then
        warn "Restoring backup for $setname due to failure..."
        ipset restore -! < "$BACKUP_DIR/$setname.save" || warn "Backup restore failed!"
    fi
}

load_ipset() {
  local file="$1"; local setname="$2"; local family="$3"
  [[ ! -s "$file" ]] && return 0
  
  if [[ "$family" == "inet6" && $IPV6_ENABLED -eq 0 ]]; then return 0; fi

  if [[ $DRY_RUN -eq 1 ]]; then
      local cnt; cnt=$(wc -l < "$file")
      dry "Load IPSet $setname ($family): $cnt entries found. Skipping apply."
      return 0
  fi

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
  if [[ $DRY_RUN -eq 1 ]]; then dry "Would update DynDNS for $DYNDNS_HOST"; return; fi
  
  local ip=""; 
  if command -v dig >/dev/null; then ip=$(dig +short "$DYNDNS_HOST" | head -n1 || true); 
  elif command -v host >/dev/null; then ip=$(host "$DYNDNS_HOST" | awk '/has address/ { print $4 }' | head -n1 || true); fi
  if [[ -n "$ip" ]]; then
     local t="$IPSET_WL"; [[ "$ip" =~ : ]] && t="${IPSET_WL}_v6"
     if [[ "$t" == "${IPSET_WL}_v6" && $IPV6_ENABLED -eq 0 ]]; then return; fi
     ipset add "$t" "$ip" -exist 2>/dev/null || true
  fi
}

main() {
  if [[ "${1:-}" == "--dry-run" ]]; then DRY_RUN=1; echo "⚠️ DRY-RUN MODE: No changes will be applied."; fi

  rm -rf "$TMPDIR"
  mkdir -p "$TMPDIR"

  [[ "${1:-}" != "--post-update" && "${1:-}" != "--configure" && $DRY_RUN -eq 0 ]] && perform_auto_update "${1:-}"
  manage_log_size
  log "=== Update Start $SCRIPT_VERSION ==="
  
  if [[ $HAS_FLOCK -eq 1 && $DRY_RUN -eq 0 ]]; then 
      # Hardening: Check for stale locks
      if [[ -f "$LOCKFILE" ]]; then
          if ! kill -0 $(fuser "$LOCKFILE" 2>/dev/null) 2>/dev/null; then
               # Lock exists but process is dead -> remove it
               rm -f "$LOCKFILE"
          fi
      fi
      exec 9>"$LOCKFILE"
      if ! flock -n 9; then echo "[ERROR] Script running."; exit 1; fi
  fi
  
  check_connectivity
  
  if check_ipv6_stack; then
      IPV6_ENABLED=1
  else
      log "Smart IPv6: No global IPv6 address detected. Disabling IPv6 processing."
      IPV6_ENABLED=0
  fi
  
  local cnt_old_v4; cnt_old_v4=$(get_set_count "$IPSET_BL")
  local cnt_old_v6; cnt_old_v6=$(get_set_count "${IPSET_BL}_v6")

  # --- WHITELIST PROCESSING ---
  : > "$TMPDIR/wl_raw.lst" # Reset
  local wl=(); [[ -f "$CONFIG_DIR/whitelist.sources" ]] && mapfile -t wl < <(grep -vE '^\s*#' "$CONFIG_DIR/whitelist.sources" || true)
  for c in $WHITELIST_COUNTRIES; do wl+=("https://iplists.firehol.org/files/geolite2_country/country_${c,,}.netset"); done
  download_parallel "$TMPDIR/wl_raw.lst" "${wl[@]}"
  
  if [[ -f "$CUSTOM_WL_FILE" ]]; then
      log "Adding custom whitelist entries from $CUSTOM_WL_FILE"
      cat "$CUSTOM_WL_FILE" >> "$TMPDIR/wl_raw.lst"
      echo "" >> "$TMPDIR/wl_raw.lst"
  fi
  
  if [[ -n "${SSH_CLIENT:-}" ]]; then
      local ssh_ip; ssh_ip=$(echo "$SSH_CLIENT" | awk '{ print $1 }')
      log "Safety: Whitelisting current SSH Session IP ($ssh_ip)"
      echo "$ssh_ip" >> "$TMPDIR/wl_raw.lst"
      echo "" >> "$TMPDIR/wl_raw.lst"
  fi
  
  # Clean and Extract IPs from Whitelist first to ensure validity
  extract_ips "$TMPDIR/wl_raw.lst" "$TMPDIR/wl.v4" "inet"
  extract_ips "$TMPDIR/wl_raw.lst" "$TMPDIR/wl.v6" "inet6"

  # --- BLOCKLIST PROCESSING ---
  local bl=(); [[ -f "$CONFIG_DIR/blocklist.sources" ]] && mapfile -t bl < <(grep -vE '^\s*#' "$CONFIG_DIR/blocklist.sources" || true)
  for c in $BLOCKLIST_COUNTRIES; do bl+=("https://iplists.firehol.org/files/geolite2_country/country_${c,,}.netset"); done
  download_parallel "$TMPDIR/bl_raw.lst" "${bl[@]}"

  if [[ -n "${HONEYDB_API_ID:-}" && -n "${HONEYDB_API_KEY:-}" ]]; then
      curl $CURL_OPTS -H "X-HoneyDb-ApiId: $HONEYDB_API_ID" -H "X-HoneyDb-ApiKey: $HONEYDB_API_KEY" "https://honeydb.io/api/bad-hosts" -o "$TMPDIR/h.lst"
      if [[ -s "$TMPDIR/h.lst" ]]; then
          cat "$TMPDIR/h.lst" >> "$TMPDIR/bl_raw.lst"
          echo "" >> "$TMPDIR/bl_raw.lst"
      fi
  fi

  extract_ips "$TMPDIR/bl_raw.lst" "$TMPDIR/bl.v4" "inet"
  extract_ips "$TMPDIR/bl_raw.lst" "$TMPDIR/bl.v6" "inet6"

  # Exclude Private Ranges
  grep -vE "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)" "$TMPDIR/bl.v4" > "$TMPDIR/bl.v4.tmp" && mv "$TMPDIR/bl.v4.tmp" "$TMPDIR/bl.v4"

  # Apply Whitelist Filter
  sort -u "$TMPDIR/bl.v4" | comm -23 - <(sort -u "$TMPDIR/wl.v4") > "$TMPDIR/bl_final.v4"
  sort -u "$TMPDIR/bl.v6" | comm -23 - <(sort -u "$TMPDIR/wl.v6") > "$TMPDIR/bl_final.v6"

  # Load Sets
  load_ipset "$TMPDIR/wl.v4" "$IPSET_WL" "inet"
  load_ipset "$TMPDIR/bl_final.v4" "$IPSET_BL" "inet"
  load_ipset "$TMPDIR/wl.v6" "${IPSET_WL}_v6" "inet6"
  load_ipset "$TMPDIR/bl_final.v6" "${IPSET_BL}_v6" "inet6"

  if [[ $DRY_RUN -eq 0 ]]; then
      iptables -C INPUT -m set --match-set "$IPSET_BL" src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set "$IPSET_BL" src -j DROP
      if [[ $IPV6_ENABLED -eq 1 ]]; then
          command -v ip6tables >/dev/null && { ip6tables -C INPUT -m set --match-set "${IPSET_BL}_v6" src -j DROP 2>/dev/null || ip6tables -I INPUT -m set --match-set "${IPSET_BL}_v6" src -j DROP; }
      fi
  else
      dry "Would insert IPTables rules now."
  fi
  
  update_dyndns

  # --- POST-STATS ---
  local cnt_new_v4; cnt_new_v4=$(get_set_count "$IPSET_BL")
  local cnt_new_v6; cnt_new_v6=$(get_set_count "${IPSET_BL}_v6")
  
  if [[ $DRY_RUN -eq 1 ]]; then
      cnt_new_v4=$(wc -l < "$TMPDIR/bl_final.v4" || echo 0)
      cnt_new_v6=$(wc -l < "$TMPDIR/bl_final.v6" || echo 0)
  fi
  
  local diff_v4=$((cnt_new_v4 - cnt_old_v4))
  local diff_v6=$((cnt_new_v6 - cnt_old_v6))
  local s_v4=""; [[ $diff_v4 -ge 0 ]] && s_v4="+"
  local s_v6=""; [[ $diff_v6 -ge 0 ]] && s_v6="+"

  local report="📊 Update Summary ($SCRIPT_VERSION)%0AIPv4 Blocked: $cnt_new_v4 ($s_v4$diff_v4)%0AIPv6 Blocked: $cnt_new_v6 ($s_v6$diff_v6)"
  if [[ $IPV6_ENABLED -eq 0 ]]; then report="$report (IPv6 Disabled)"; fi
  if [[ $DRY_RUN -eq 1 ]]; then report="⚠️ DRY-RUN REPORT%0A$report"; fi

  echo "------------------------------------------------"
  echo -e "${report//%0A/\n}"
  echo "------------------------------------------------"

  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
      report="🛡️ <b>Firewall Update: $(hostname)</b>%0A$report"
      send_telegram "$report"
  fi

  log "=== Finished [IPv4: $cnt_new_v4 ($s_v4$diff_v4), IPv6: $cnt_new_v6 ($s_v6$diff_v6)] ==="
}

# --- ENTRY POINT ---
[[ "${1:-}" == "--configure" || "${1:-}" == "-i" ]] && interactive_menu
main "${1:-}"