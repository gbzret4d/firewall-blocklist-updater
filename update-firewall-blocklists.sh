#!/bin/bash
set -euo pipefail

#################################################
# Firewall Blocklist Update Script (Fixed & Optimized)
# - IPv4 and IPv6 support (Fixed: added ip6tables rules)
# - Parallel source download (Fixed: var exports)
# - Secure API key file permissions
# - Container compatible
# - Dynamic DynDNS IP whitelist management
#################################################

# Base directories
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="$BASE_DIR/firewall-blocklists"
KEYFILE="${KEYFILE:-$BASE_DIR/firewall-blocklist-keys.env}"
SCRIPT_BIN="/usr/local/bin/update-firewall-blocklists.sh"
REPO_URL="https://github.com/gbzret4d/firewall-blocklist-updater.git"

# Ensure base directories exist
mkdir -p "$BASE_DIR" "$CONFIG_DIR"

# ---- Auto-update from git repo ----
# Only run git operations if git is installed and we are in a git repo or empty dir
if command -v git &>/dev/null; then
  if [[ ! -d "$BASE_DIR/.git" ]]; then
    if [[ -z "$(ls -A "$BASE_DIR")" ]]; then
      echo "[INFO] Cloning repository to $BASE_DIR ..."
      git clone --depth=1 "$REPO_URL" "$BASE_DIR" || echo "[WARN] Git clone failed."
    fi
  else
    echo "[INFO] Updating repository in $BASE_DIR ..."
    (
      cd "$BASE_DIR"
      git fetch origin main || true
      git reset --hard origin/main || true
    )
  fi
  
  # Update script in /usr/local/bin if source exists
  if [[ -f "$BASE_DIR/update-firewall-blocklists.sh" ]]; then
     # Check if diff exists to avoid unnecessary writes
     if ! cmp -s "$BASE_DIR/update-firewall-blocklists.sh" "$SCRIPT_BIN"; then
         echo "[INFO] Installing/updating script to $SCRIPT_BIN ..."
         cp "$BASE_DIR/update-firewall-blocklists.sh" "$SCRIPT_BIN"
         chmod +x "$SCRIPT_BIN"
     fi
  fi
fi

# ---- Load API keys and configuration ----
load_env_vars() {
  if [[ -f "$KEYFILE" ]]; then
    # Only chmod if we own the file to avoid errors in containers
    if [[ -O "$KEYFILE" ]]; then chmod 600 "$KEYFILE"; fi
    
    while IFS='=' read -r var val || [[ -n "$var" ]]; do
      [[ "$var" =~ ^[[:space:]]*# ]] && continue
      [[ -z "$var" ]] && continue
      var="${var#export }"
      var="${var//[[:space:]]/}"
      if [[ -z "${!var-}" ]]; then
        val="${val%\"}"
        val="${val#\"}"
        export "$var=$val"
      fi
    done < "$KEYFILE"
    echo "[INFO] Loaded API keys and configuration from $KEYFILE"
  else
    echo "[WARN] Key file $KEYFILE not found. API, Telegram and DYNDNS features disabled."
  fi
}
load_env_vars

# ---- Color variables and logging ----
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  YELLOW='\033[0;33m'
  GREEN='\033[0;32m'
  BLUE='\033[0;34m'
  NC='\033[0m'
else
  RED='' YELLOW='' GREEN='' BLUE='' NC=''
fi

# Export colors so they are available in subshells (xargs)
export RED YELLOW GREEN BLUE NC

log() {
  local lvl="$1"; shift
  local color="$RED"
  case "$lvl" in
    INFO) color="$GREEN" ;;
    WARN) color="$YELLOW" ;;
    DEBUG) color="$BLUE" ;;
  esac
  echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${color}[$lvl]${NC} $*"
}

send_telegram() {
  if [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]]; then
    return 0
  fi
  local message="$1"
  curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d text="$message" >/dev/null 2>&1 || log WARN "Failed to send telegram notification."
}

error_handler() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    local host
    host="$(hostname)"
    local msg="🚨 Firewall blocklist update FAILED with exit code $exit_code on $host at $(date '+%Y-%m-%d %H:%M:%S')"
    send_telegram "$msg"
  fi
  exit $exit_code
}
trap error_handler ERR SIGINT SIGTERM

# ---- Package management ----
install_pkg() {
  # Don't try to install if not root
  if [[ $EUID -ne 0 ]]; then
    log WARN "Not running as root, cannot install missing package: $1"
    return 1
  fi

  local pkg="$1"
  if command -v apk &>/dev/null; then
    apk add --no-cache "$pkg"
  elif command -v apt-get &>/dev/null; then
    apt-get update && apt-get install -y "$pkg"
  elif command -v dnf &>/dev/null; then
    dnf install -y "$pkg"
  elif command -v yum &>/dev/null; then
    yum install -y "$pkg"
  else
    log WARN "No known package manager found to install $pkg"
  fi
}

check_install() {
  local binary="$1"
  if ! command -v "$binary" &>/dev/null; then
    log WARN "Missing $binary, trying to install..."
    install_pkg "$binary" || true
  fi
}

for cmd in curl ipset iptables python3 jq grep comm sort dig; do
  check_install "$cmd"
done

# ---- Variables ----
TMPDIR="${TMPDIR:-/tmp/firewall-blocklists}"
BACKUPDIR="$TMPDIR/backup"
mkdir -p "$TMPDIR" "$BACKUPDIR"

IPSET_WHITELIST="allowed_whitelist"
IPSET_BLOCKLIST="blocklist_all"
IPSET_WHITELIST6="allowed_whitelist_v6"
IPSET_BLOCKLIST6="blocklist_all_v6"

IPTABLES_CHAIN="INPUT"
IPTABLES_CHAIN6="INPUT"

IPSET_HASH_SIZE=2048
IPSET_MAX_ELEM=200000  # Increased size as blocklists can be large

ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
HONEYDB_API_ID="${HONEYDB_API_ID:-}"
HONEYDB_API_KEY="${HONEYDB_API_KEY:-}"
HONEYDB_URL="https://honeydb.io/api/bad-hosts"

WHITELIST_SOURCES_FILE="${WHITELIST_SOURCES_FILE:-$CONFIG_DIR/whitelist.sources}"
BLOCKLIST_SOURCES_FILE="${BLOCKLIST_SOURCES_FILE:-$CONFIG_DIR/blocklist.sources}"

# ---- Functions ----

read_sources() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    log WARN "Sources file $file does not exist."
    return 0
  fi
  # Use || true to prevent exit on no match
  grep -E '^\s*[^#[:space:]]' "$file" || true
}

download_with_backup() {
  local url="$1" output="$2" backup="$3"
  log INFO "Downloading $url"
  if curl -sfL --connect-timeout 20 -A "firewall-blocklist-updater" "$url" -o "$output"; then
    if [[ -s "$output" ]]; then
      cp "$output" "$backup"
      return 0
    else
      log WARN "Downloaded file is empty: $output"
    fi
  else
    log WARN "Failed to download $url"
  fi
  
  if [[ -s "$backup" ]]; then
    cp "$backup" "$output"
    log WARN "Used backup for $url"
    return 0
  fi
  log WARN "No backup available for $url"
  return 0
}

download_and_merge_parallel() {
  local outfile="$1"
  shift
  local sources=("$@")

  if [[ ${#sources[@]} -eq 0 ]]; then
      log WARN "No sources provided for $outfile"
      touch "$outfile"
      return 0
  fi

  : > "$TMPDIR/tmpmerge.lst"

  export -f download_with_backup log
  export TMPDIR BACKUPDIR
  # Note: Colors are already exported globally above

  printf '%s\n' "${sources[@]}" | xargs -P6 -I{} bash -c '
    url="{}"
    fname=$(basename "$url")
    if ! [[ "$fname" =~ \. ]]; then
      fname=$(echo "$url" | sed "s|https\?://||; s|[/:]|_|g")
    fi
    filepath="$TMPDIR/$fname"
    backup="$BACKUPDIR/$fname.bak"
    # Added || true to grep to prevent subshell failure on empty files
    if download_with_backup "$url" "$filepath" "$backup"; then
        grep -Ev "^\s*(#|\$)" "$filepath" >> "$TMPDIR/tmpmerge.lst" || true
    fi
  '

  sort -u "$TMPDIR/tmpmerge.lst" > "$outfile"
  log INFO "Merged $(wc -l < "$outfile") unique entries into $outfile"
}

download_abuseipdb() {
  local outfile="$1" bakfile="$2"
  if [[ -z "$ABUSEIPDB_API_KEY" ]]; then return 0; fi
  
  log INFO "Downloading AbuseIPDB blacklist"
  if curl -sfG "https://api.abuseipdb.com/api/v2/blacklist" \
    -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: text/plain" \
    -A "firewall-blocklist-updater" -o "$outfile"; then
    if [[ -s "$outfile" ]]; then
      cp "$outfile" "$bakfile"
      # Process directly
      grep -Eo '([0-9a-fA-F:.]+(/[0-9]+)?)' "$outfile" | sort -u > "${outfile}.tmp" && mv "${outfile}.tmp" "$outfile"
      log INFO "AbuseIPDB processed"
      return 0
    fi
  fi
  
  if [[ -s "$bakfile" ]]; then
    cp "$bakfile" "$outfile"
    log WARN "Using backup for AbuseIPDB"
  fi
}

download_honeydb() {
  local outfile="$1" bakfile="$2"
  if [[ -z "$HONEYDB_API_ID" || -z "$HONEYDB_API_KEY" ]]; then return 0; fi
  
  log INFO "Downloading HoneyDB blacklist"
  if curl -sfL "$HONEYDB_URL" \
    -H "X-HoneyDb-ApiId: $HONEYDB_API_ID" \
    -H "X-HoneyDb-ApiKey: $HONEYDB_API_KEY" \
    -A "firewall-blocklist-updater" -o "$outfile"; then
    if [[ -s "$outfile" ]]; then
      cp "$outfile" "$bakfile"
      if command -v jq &>/dev/null; then
        jq -r '.[].remote_host' "$outfile" | sort -u > "${outfile}.tmp" && mv "${outfile}.tmp" "$outfile"
      else
        grep -Eo '([0-9a-fA-F:.]+)' "$outfile" | sort -u > "${outfile}.tmp" && mv "${outfile}.tmp" "$outfile"
      fi
      log INFO "HoneyDB processed"
      return 0
    fi
  fi
  
  if [[ -s "$bakfile" ]]; then
    cp "$bakfile" "$outfile"
    log WARN "Using backup for HoneyDB"
  fi
}

filter_private_ips() {
  local infile="$1"
  local outfile="$2"
  if ! command -v python3 >/dev/null; then
    log WARN "python3 not found; skipping private IP filtering"
    cp "$infile" "$outfile"
    return 0
  fi

  # Filter script: Handles IPv4 and IPv6 private/reserved ranges
  python3 -c '
import ipaddress
import sys

ips = set()
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    try:
        if "/" in line:
            ipobj = ipaddress.ip_network(line, strict=False)
        else:
            ipobj = ipaddress.ip_address(line)
            
        if not (ipobj.is_private or ipobj.is_loopback or ipobj.is_reserved or ipobj.is_multicast):
            ips.add(str(ipobj))
    except ValueError:
        pass
    except Exception:
        pass

for ip in sorted(ips):
    print(ip)
' < "$infile" > "$outfile"
  log INFO "Filtered private/local IPs: $outfile"
}

create_or_flush_ipset() {
  local set=$1
  local type="hash:net"
  local family="inet"
  
  if [[ "$set" == *"_v6" ]]; then
    family="inet6"
    type="hash:net family inet6"
  fi
  
  if ipset list "$set" &>/dev/null; then
    ipset flush "$set"
    log INFO "Flushed ipset $set"
  else
    ipset create "$set" $type hashsize "$IPSET_HASH_SIZE" maxelem "$IPSET_MAX_ELEM"
    log INFO "Created ipset $set ($type)"
  fi
}

load_ips_to_ipset() {
  local file="$1" set="$2"
  local cnt=0
  
  # Determine IP version for grep regex
  local is_v6=0
  [[ "$set" == *"_v6" ]] && is_v6=1
  
  log INFO "Loading IPs from $file into $set"
  
  # Restore logic: read file line by line
  # Optimized: use ipset restore for speed if possible, but line-by-line is safer for mixed garbage
  while IFS= read -r ip; do
    ip="${ip//[[:space:]]/}"
    if [[ $is_v6 -eq 0 ]]; then
        # IPv4 Check
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?$ ]]; then
            ipset add "$set" "$ip" -exist 2>/dev/null || true
            ((cnt++))
        fi
    else
        # IPv6 Check
        if [[ "$ip" =~ : ]]; then
            ipset add "$set" "$ip" -exist 2>/dev/null || true
            ((cnt++))
        fi
    fi
  done < "$file"
  
  log INFO "Loaded $cnt IPs into $set"
}

cleanup_old_iptables_rules() {
  local current_sets=("$IPSET_BLOCKLIST" "$IPSET_WHITELIST" "$IPSET_BLOCKLIST6" "$IPSET_WHITELIST6")
  
  # Clean IPv4
  if command -v iptables &>/dev/null; then
      mapfile -t rules < <(iptables -S "$IPTABLES_CHAIN" | grep -- "-m set --match-set" || true)
      for rule in "${rules[@]}"; do
        if [[ "$rule" =~ --match-set[[:space:]]+([^[:space:]]+) ]]; then
          local setname="${BASH_REMATCH[1]}"
          # Check if setname corresponds to one of ours (simple check: contains blocklist or whitelist)
          if [[ "$setname" == *"blocklist"* || "$setname" == *"whitelist"* ]]; then
              if ! [[ " ${current_sets[*]} " =~ " ${setname} " ]]; then
                local delrule="${rule/-A/-D}"
                iptables $delrule || true
                log INFO "Removed obsolete IPv4 rule referencing $setname"
              fi
          fi
        fi
      done
  fi

  # Clean IPv6
  if command -v ip6tables &>/dev/null; then
      mapfile -t rules6 < <(ip6tables -S "$IPTABLES_CHAIN6" | grep -- "-m set --match-set" || true)
      for rule in "${rules6[@]}"; do
        if [[ "$rule" =~ --match-set[[:space:]]+([^[:space:]]+) ]]; then
          local setname="${BASH_REMATCH[1]}"
          if [[ "$setname" == *"blocklist"* || "$setname" == *"whitelist"* ]]; then
              if ! [[ " ${current_sets[*]} " =~ " ${setname} " ]]; then
                local delrule="${rule/-A/-D}"
                ip6tables $delrule || true
                log INFO "Removed obsolete IPv6 rule referencing $setname"
              fi
          fi
        fi
      done
  fi
}

ensure_iptables_rule() {
  # IPv4
  if command -v iptables &>/dev/null; then
      if ! iptables -C "$IPTABLES_CHAIN" -m set --match-set "$IPSET_BLOCKLIST" src -j DROP &>/dev/null; then
        iptables -I "$IPTABLES_CHAIN" -m set --match-set "$IPSET_BLOCKLIST" src -j DROP
        log INFO "Added IPv4 rule for $IPSET_BLOCKLIST"
      fi
  fi
  
  # IPv6
  if command -v ip6tables &>/dev/null; then
      if ! ip6tables -C "$IPTABLES_CHAIN6" -m set --match-set "$IPSET_BLOCKLIST6" src -j DROP &>/dev/null; then
        ip6tables -I "$IPTABLES_CHAIN6" -m set --match-set "$IPSET_BLOCKLIST6" src -j DROP
        log INFO "Added IPv6 rule for $IPSET_BLOCKLIST6"
      fi
  fi
}

cleanup_old_dynamic_dns_ips() {
  if [[ -z "${DYNDNS_HOST:-}" ]]; then return 0; fi
  local dnsname="$DYNDNS_HOST"
  local current_ip
  
  current_ip=$(dig +short "$dnsname" | head -n1 || true)
  if [[ -z "$current_ip" ]]; then return 0; fi

  # Only check IPv4 whitelist for now as dig returns A record primarily
  local members
  members=$(ipset list "$IPSET_WHITELIST" | grep -v "Header:" | grep -v "Members:" | grep -v "Name:" | grep -v "Type:" || true)
  
  for ip in $members; do
    # Assuming the whitelist only contains static IPs and the one DynDNS IP
    # This logic is risky if you have other dynamic IPs. 
    # Use with caution: here we compare if it LOOKS like a residential IP vs the current DynDNS
    # For safety: we only remove if it explicitly DOES NOT match current IP but was added by this script logic previously.
    # Since we don't track state, we skip complex removal to avoid banning valid static IPs.
    # A proper implementation requires a state file for the old DynDNS IP.
    : # Placeholder
  done
}

update_dynamic_dns_whitelist() {
  if [[ -z "${DYNDNS_HOST:-}" ]]; then return 0; fi
  local dnsname="$DYNDNS_HOST"
  local ip
  
  # Resolve IP (try both A and AAAA later if needed, mostly A for now)
  ip=$(dig +short "$dnsname" | head -n1 || true)

  if [[ -z "$ip" ]]; then
    log DEBUG "Failed to resolve $dnsname"
    return 0
  fi

  # Determine if IPv4 or IPv6
  local target_set="$IPSET_WHITELIST"
  if [[ "$ip" =~ : ]]; then
      target_set="$IPSET_WHITELIST6"
  fi

  if ipset test "$target_set" "$ip" &>/dev/null; then
    log DEBUG "Dynamic DNS IP $ip already in $target_set"
  else
    ipset add "$target_set" "$ip"
    log INFO "Added Dynamic DNS IP $ip to $target_set"
    
    # Simple cleanup: Save current IP to file, if file differs, remove old IP
    local state_file="$TMPDIR/dyndns_last_ip"
    if [[ -f "$state_file" ]]; then
        local old_ip
        old_ip=$(cat "$state_file")
        if [[ "$old_ip" != "$ip" && -n "$old_ip" ]]; then
            ipset del "$target_set" "$old_ip" 2>/dev/null || true
            log INFO "Removed old DynDNS IP $old_ip"
        fi
    fi
    echo "$ip" > "$state_file"
  fi
}

# --- Main execution ---
log INFO "=== Starting firewall blocklist update ==="

cleanup_old_iptables_rules
update_dynamic_dns_whitelist || true

# Sources
wl_sources=$(read_sources "$WHITELIST_SOURCES_FILE")
bl_sources=$(read_sources "$BLOCKLIST_SOURCES_FILE")

# Processing Whitelist
wl_file="$TMPDIR/whitelist.lst"
download_and_merge_parallel "$wl_file" $wl_sources

# Processing Blocklist
bl_file_raw="$TMPDIR/blocklist_raw.lst"
download_and_merge_parallel "$bl_file_raw" $bl_sources

# Add APIs
abuseipdb_file="$TMPDIR/abuseipdb.lst"
download_abuseipdb "$abuseipdb_file" "$BACKUPDIR/abuseipdb.bak"
cat "$abuseipdb_file" >> "$bl_file_raw" 2>/dev/null || true

honeydb_file="$TMPDIR/honeydb.lst"
download_honeydb "$honeydb_file" "$BACKUPDIR/honeydb.bak"
cat "$honeydb_file" >> "$bl_file_raw" 2>/dev/null || true

# Filter Private IPs
filter_private_ips "$bl_file_raw" "$TMPDIR/blocklist_filtered.lst"

# Subtract Whitelist from Blocklist
bl_file_filtered="$TMPDIR/blocklist_filtered.lst"
bl_file_final="$TMPDIR/blocklist_final.lst"

# comm requires sorted files
sort -u "$bl_file_filtered" -o "$bl_file_filtered"
sort -u "$wl_file" -o "$wl_file"

comm -23 "$bl_file_filtered" "$wl_file" > "$bl_file_final"

log INFO "$(wc -l < "$bl_file_final") IPs remain after applying whitelist"

# --- Load into IPsets ---

# IPv4
create_or_flush_ipset "$IPSET_WHITELIST"
load_ips_to_ipset "$wl_file" "$IPSET_WHITELIST"

create_or_flush_ipset "$IPSET_BLOCKLIST"
load_ips_to_ipset "$bl_file_final" "$IPSET_BLOCKLIST"

# IPv6
create_or_flush_ipset "$IPSET_WHITELIST6"
load_ips_to_ipset "$wl_file" "$IPSET_WHITELIST6"

create_or_flush_ipset "$IPSET_BLOCKLIST6"
load_ips_to_ipset "$bl_file_final" "$IPSET_BLOCKLIST6"

# Apply iptables rules
ensure_iptables_rule

# Stats
count_wl=$(ipset list "$IPSET_WHITELIST" 2>/dev/null | grep "Number of entries" | awk '{print $4}' || echo 0)
count_bl=$(ipset list "$IPSET_BLOCKLIST" 2>/dev/null | grep "Number of entries" | awk '{print $4}' || echo 0)
log INFO "IPv4 Whitelist: $count_wl | IPv4 Blocklist: $count_bl"

count_wl6=$(ipset list "$IPSET_WHITELIST6" 2>/dev/null | grep "Number of entries" | awk '{print $4}' || echo 0)
count_bl6=$(ipset list "$IPSET_BLOCKLIST6" 2>/dev/null | grep "Number of entries" | awk '{print $4}' || echo 0)
log INFO "IPv6 Whitelist: $count_wl6 | IPv6 Blocklist: $count_bl6"

log INFO "=== Firewall blocklist update finished ==="
exit 0