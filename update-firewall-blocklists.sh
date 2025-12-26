#!/bin/bash
set -euo pipefail
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# --- VERSION CONTROL ---
SCRIPT_VERSION="v10.1"

#################################################
# Firewall Blocklist Updater (v10.1 - Self Healing)
# - FIX: Aggressive Plugin Cleanup inside Updater (Fixes persistent crash)
# - FIX: Enforced Newline in YAML generation
# - FEAT: Dynamic Port Scanner
# - LISTS: Full 32 Sources
#################################################

# --- Constants ---
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

# --- Globals ---
DRY_RUN=0
IPV6_ENABLED=1
USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# --- Lists (Full Sync) ---
RECOMMENDED_LISTS=(
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
    if ! ip -6 addr show scope global | grep -q "inet6"; then return 1; fi
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
  local tmp="/tmp/update-fw.sh.new"
  if curl -sfL -A "$USER_AGENT" -o "$tmp" "${REPO_RAW_URL}?t=$(date +%s)" || true; then
     if [[ -s "$tmp" ]]; then
         local remote_ver=$(grep -oE 'SCRIPT_VERSION="v[0-9.]+"' "$tmp" | head -n1 | cut -d'"' -f2 || echo "unknown")
         if [[ "$remote_ver" != "unknown" && "$remote_ver" != "$SCRIPT_VERSION" ]]; then
            log "[AUTO-UPDATE] New version found ($remote_ver). Updating..."
            cp "$tmp" "/usr/local/bin/update-firewall-blocklists.sh" && chmod +x "/usr/local/bin/update-firewall-blocklists.sh"
            exec "/usr/local/bin/update-firewall-blocklists.sh" "--post-update"
         fi
     fi
  fi
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

install_sensors() {
    echo ">>> Installing Sensors..."
    
    local EL_PORT=0
    
    # --- DYNAMIC PORT SCAN (2222 -> 2232) ---
    for (( p=2222; p<=2232; p++ )); do
        if ! ss -tuln | grep -q ":$p "; then
            EL_PORT=$p
            break
        else
            local PID=$(ss -lptn "sport = :$p" | grep -o 'pid=[0-9]*' | cut -d= -f2 | head -n1 || true)
            local PNAME=""
            if [[ -n "$PID" ]]; then PNAME=$(ps -p "$PID" -o comm= 2>/dev/null || echo "unknown"); fi
            
            if [[ "$PNAME" == "endlessh" ]]; then
                log "Port $p occupied by old endlessh (PID $PID). Reusing..."
                kill "$PID" 2>/dev/null || true; sleep 1
                EL_PORT=$p
                break
            else
                warn "Port $p busy by '$PNAME'. Trying next..."
            fi
        fi
    done

    if [[ $EL_PORT -eq 0 ]]; then
        warn "❌ ERROR: No free ports found between 2222-2232 for Endlessh!"
        return 1
    fi

    if ! command -v endlessh >/dev/null; then
        if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y endlessh
        elif command -v yum >/dev/null; then yum install -y endlessh; fi
    fi

    mkdir -p /etc/endlessh
    if [[ -d /etc/endlessh ]]; then
        echo "Port $EL_PORT" > /etc/endlessh/config
        echo "Delay 10000" >> /etc/endlessh/config
        echo "LogLevel 1" >> /etc/endlessh/config
        echo "BindFamily 0" >> /etc/endlessh/config
        
        local SVC="/lib/systemd/system/endlessh.service"
        if [[ -f "$SVC" ]]; then
            if ! grep -q "AmbientCapabilities" "$SVC"; then
                sed -i '/\[Service\]/a AmbientCapabilities=CAP_NET_BIND_SERVICE' "$SVC"
                systemctl daemon-reload
            fi
        fi
        
        if ! systemctl enable --now endlessh; then
            warn "Endlessh failed to start on port $EL_PORT."
        else
            systemctl restart endlessh
            log "✅ Endlessh running on port $EL_PORT"
        fi
    fi

    if command -v cscli >/dev/null; then
        cscli collections install crowdsecurity/endlessh --force >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/iptables --force >/dev/null 2>&1 || true
        
        if ! grep -q "type: endlessh" /etc/crowdsec/acquis.yaml 2>/dev/null; then
            echo " -> Adding Sensor config to CrowdSec..."
            cp /etc/crowdsec/acquis.yaml /etc/crowdsec/acquis.yaml.bak 2>/dev/null || true
            
            # FIX v10.1: Ensure Newline before separator to prevent YAML breakage
            echo "" >> /etc/crowdsec/acquis.yaml
            if [[ -s /etc/crowdsec/acquis.yaml ]]; then echo "---" >> /etc/crowdsec/acquis.yaml; fi
            
            cat <<YAML >> /etc/crowdsec/acquis.yaml
filenames:
  - /var/log/syslog
  - /var/log/messages
labels:
  type: endlessh
YAML
            
            # --- CRITICAL FIX v10.1: CLEANUP PLUGINS BEFORE RESTART ---
            # Even if install.sh missed it, we scrub the folder to ensure valid startup.
            if [[ -d "/usr/lib/crowdsec/plugins" ]]; then
                rm -f /usr/lib/crowdsec/plugins/dummy 2>/dev/null || true
                rm -f /usr/lib/crowdsec/plugins/*.sh 2>/dev/null || true
                rm -f /usr/lib/crowdsec/plugins/*.html 2>/dev/null || true
            fi

            # Validate & Restart
            if crowdsec -c /etc/crowdsec/config.yaml -t >/dev/null 2>&1; then
                systemctl restart crowdsec
                echo "✅ Sensors Configured."
            else
                echo "❌ Config invalid. Rolling back..."
                mv /etc/crowdsec/acquis.yaml.bak /etc/crowdsec/acquis.yaml 2>/dev/null || true
                
                # Cleanup again before fallback restart
                if [[ -d "/usr/lib/crowdsec/plugins" ]]; then
                    rm -f /usr/lib/crowdsec/plugins/*.sh 2>/dev/null || true
                fi
                systemctl restart crowdsec
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

# --- ROBUST EXTRACTION ---
smart_extract() {
    local f="$1"
    if gzip -t "$f" 2>/dev/null; then zcat "$f"; elif unzip -t "$f" 2>/dev/null; then unzip -p "$f"; else cat "$f"; fi
}

download_lists() {
  local out="$1"; shift; local srcs=("$@")
  : > "$TMPDIR/merge.lst"
  [[ ${#srcs[@]} -eq 0 ]] && touch "$out" && return 0
  export -f smart_extract; export TMPDIR

  for u in "${srcs[@]}"; do
      local f=$(basename "$u" | sed "s/[^a-zA-Z0-9._-]/_/g")
      if [[ $DRY_RUN -eq 0 ]]; then echo -n "."; fi 
      
      if curl -sfL --connect-timeout 10 --retry 1 -A "$USER_AGENT" "$u" -o "$TMPDIR/$f"; then
          if [[ -s "$TMPDIR/$f" ]]; then
              tr -d "\r" < "$TMPDIR/$f" > "$TMPDIR/$f.tmp" && mv "$TMPDIR/$f.tmp" "$TMPDIR/$f"
              if ! head -n 1 "$TMPDIR/$f" | grep -qiE "<!DOCTYPE|<html"; then
                   smart_extract "$TMPDIR/$f" >> "$TMPDIR/merge.lst" || true
                   echo "" >> "$TMPDIR/merge.lst"
              fi
          fi
      fi
  done
  if [[ $DRY_RUN -eq 0 ]]; then echo ""; fi

  sed -i 's/[#;].*//g' "$TMPDIR/merge.lst"
  sort -u "$TMPDIR/merge.lst" > "$out"
}

extract_ips() {
    local input="$1"; local output="$2"; local family="$3"
    [[ ! -f "$input" ]] && touch "$output" && return 0
    if [[ "$family" == "inet" ]]; then
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$input" | awk -F'[./]' '{valid=1; for(i=1;i<=4;i++)if($i>255)valid=0; if(NF>4&&$NF>32)valid=0; if(valid)print $0}' | grep -vE "^0\.0\.0\.0$" > "$output" || true
    else
        if [[ $IPV6_ENABLED -eq 1 ]]; then
            grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?' "$input" | grep -vE "^::" > "$output" || true
        else touch "$output"; fi
    fi
}

load_ipset() {
  local file="$1"; local setname="$2"; local family="$3"
  if [[ "$family" == "inet6" && $IPV6_ENABLED -eq 0 ]]; then return 0; fi
  ipset create $setname hash:net family $family hashsize $IPSET_HASH_SIZE maxelem $IPSET_MAX_ELEM -exist 2>/dev/null || true
  
  if [[ ! -s "$file" ]]; then
      ipset flush $setname 2>/dev/null || true
      return 0
  fi
  
  ipset flush "${setname}_tmp" 2>/dev/null || ipset create "${setname}_tmp" hash:net family $family hashsize $IPSET_HASH_SIZE maxelem $IPSET_MAX_ELEM -exist
  
  if ! sed "s/^/add ${setname}_tmp /" "$file" | ipset restore -! 2>/dev/null; then
      warn "Some IPs in $file were invalid and skipped by ipset (non-fatal)."
  fi
  
  ipset swap "${setname}_tmp" "$setname"
  ipset destroy "${setname}_tmp" 2>/dev/null || true
}

update_dyndns() {
  [[ -z "$DYNDNS_HOST" ]] && return 0
  if [[ $DRY_RUN -eq 1 ]]; then dry "DynDNS Update: $DYNDNS_HOST"; return; fi
  local ip=$(dig +short "$DYNDNS_HOST" | head -n1 || true)
  if [[ -n "$ip" ]]; then
     local t="$IPSET_WL"; [[ "$ip" =~ : ]] && t="${IPSET_WL}_v6"
     [[ "$t" == "${IPSET_WL}_v6" && $IPV6_ENABLED -eq 0 ]] && return
     ipset add "$t" "$ip" -exist 2>/dev/null || true
  fi
}

main() {
  if [[ "${1:-}" == "--dry-run" ]]; then DRY_RUN=1; echo "⚠️ DRY-RUN"; fi
  if [[ "${1:-}" == "--setup-sensors" ]]; then install_sensors; exit 0; fi

  [[ "${1:-}" != "--post-update" && "${1:-}" != "--configure" && $DRY_RUN -eq 0 ]] && perform_auto_update "${1:-}"
  manage_log_size
  log "=== Update Start $SCRIPT_VERSION ==="
  
  if [[ $HAS_FLOCK -eq 1 && $DRY_RUN -eq 0 ]]; then 
      exec 9>"$LOCKFILE"
      if ! flock -n 9; then echo "[ERROR] Locked."; exit 1; fi
  fi
  
  check_connectivity
  if check_ipv6_stack; then IPV6_ENABLED=1; else IPV6_ENABLED=0; fi
  
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
      if [[ $IPV6_ENABLED -eq 1 ]]; then
          command -v ip6tables >/dev/null && { ip6tables -C INPUT -m set --match-set "${IPSET_BL}_v6" src -j DROP 2>/dev/null || ip6tables -I INPUT -m set --match-set "${IPSET_BL}_v6" src -j DROP; }
      fi
      if command -v crowdsec >/dev/null; then
          iptables -C INPUT -m limit --limit 10/min -j LOG --log-prefix "IPTables-Dropped: " 2>/dev/null || \
          iptables -A INPUT -m limit --limit 10/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
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