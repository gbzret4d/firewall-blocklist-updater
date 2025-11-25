#!/bin/bash
set -euo pipefail

#################################################
# Firewall Blocklist Update Script (extended)
# - IPv4 and IPv6 support
# - Parallel source download
# - Secure API key file permissions
# - Container compatible (no sudo required)
# - Dynamic DynDNS IP whitelist management added
# - Auto-update script from GitHub repo (/usr/local/etc/)
#
# Enhanced to accept environment variables passed in a one-liner:
# Variables set before script invocation override .env file values.
#################################################

# Base directories
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="$BASE_DIR/firewall-blocklists"
KEYFILE="${KEYFILE:-$BASE_DIR/firewall-blocklist-keys.env}"
SCRIPT_BIN="/usr/local/bin/update-firewall-blocklists.sh"
REPO_URL="https://github.com/gbzret4d/firewall-blocklist-updater.git"

# Ensure base directories exist
mkdir -p "$BASE_DIR" "$CONFIG_DIR"

# Auto-update from git repo
if [[ ! -d "$BASE_DIR/.git" ]]; then
  echo "[INFO] Cloning repository to $BASE_DIR ..."
  git clone --depth=1 "$REPO_URL" "$BASE_DIR"
else
  echo "[INFO] Updating repository in $BASE_DIR ..."
  (
    cd "$BASE_DIR"
    git fetch origin main || true
    git reset --hard origin/main || true
  )
fi

# Install/update script in /usr/local/bin
echo "[INFO] Installing/updating script to $SCRIPT_BIN ..."
cp "$BASE_DIR/update-firewall-blocklists.sh" "$SCRIPT_BIN"
chmod +x "$SCRIPT_BIN"

# Load API keys and configuration only if not already set by environment
load_env_vars() {
  if [[ -f "$KEYFILE" ]]; then
    chmod 600 "$KEYFILE"
    # Read each line and export variable only if not set already
    while IFS='=' read -r var val || [[ -n "$var" ]]; do
      # Skip empty lines or comments
      [[ "$var" =~ ^\s*# ]] && continue
      [[ -z "$var" ]] && continue
      # Remove export keyword if present
      var="${var#export }"
      # Trim spaces
      var="${var//[[:space:]]/}"
      if [[ -z "${!var-}" ]]; then
        # Remove possible quotes around value
        val="${val%\"}"
        val="${val#\"}"
        export "$var=$val"
      fi
    done < "$KEYFILE"
    echo "[INFO] Loaded API keys and configuration from $KEYFILE"
  else
    echo "[WARN] Key file $KEYFILE not found. API, Telegram and DYNDNS_HOST features disabled."
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
    log DEBUG "Telegram token or chat ID missing; skipping telegram notification."
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
    log WARN "Missing $binary, trying to install"
    install_pkg "$binary"
  else
    log DEBUG "$binary found"
  fi
}

for cmd in curl git ipset iptables python3 jq grep comm sort dig; do
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
IPTABLES_CHAIN6="INPUT"   # Adjust if ip6tables is used
IPSET_HASH_SIZE=2048
IPSET_MAX_ELEM=65536

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
  grep -E '^\s*[^#[:space:]]' "$file" || true
}

download_with_backup() {
  local url="$1" output="$2" backup="$3"
  log INFO "Downloading $url"
  if curl -sfL --connect-timeout 20 -A "firewall-blocklist-updater" "$url" -o "$output"; then
    if [[ -s "$output" ]]; then
      cp "$output" "$backup"
      log INFO "Downloaded and backed up $url"
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
  : > "$TMPDIR/tmpmerge.lst"

  export -f download_with_backup log
  export TMPDIR BACKUPDIR

  printf '%s\n' "${sources[@]}" | xargs -P6 -I{} bash -c '
    url="{}"
    fname=$(basename "$url")
    if ! [[ "$fname" =~ \. ]]; then
      fname=$(echo "$url" | sed "s|https\?://||; s|[/:]|_|g")
    fi
    filepath="$TMPDIR/$fname"
    backup="$BACKUPDIR/$fname.bak"
    download_with_backup "$url" "$filepath" "$backup" && grep -Ev "^\s*(#|\$)" "$filepath" >> "$TMPDIR/tmpmerge.lst"
  '

  sort -u "$TMPDIR/tmpmerge.lst" > "$outfile"
  log INFO "Merged $(wc -l < "$outfile") unique entries into $outfile"
}

download_abuseipdb() {
  local outfile="$1" bakfile="$2"
  if [[ -z "$ABUSEIPDB_API_KEY" ]]; then
    log DEBUG "AbuseIPDB API key missing or empty; skipping AbuseIPDB."
    return 0
  fi
  log INFO "Downloading AbuseIPDB blacklist"
  if curl -sfG "https://api.abuseipdb.com/api/v2/blacklist" \
    -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: text/plain" \
    -A "firewall-blocklist-updater" -o "$outfile"; then
    if [[ -s "$outfile" ]]; then
      cp "$outfile" "$bakfile"
      grep -Eo '([0-9a-fA-F:.]+(/[0-9]+)?)' "$outfile" | sort -u > "${outfile}.ips"
      mv "${outfile}.ips" "$outfile"
      log INFO "AbuseIPDB blacklist downloaded and processed"
      return 0
    else
      log WARN "AbuseIPDB response empty"
    fi
  else
    log WARN "Failed to download AbuseIPDB blacklist"
  fi
  if [[ -s "$bakfile" ]]; then
    cp "$bakfile" "$outfile"
    log WARN "Using backup for AbuseIPDB blacklist"
    return 0
  fi
  log WARN "No AbuseIPDB backup available"
  return 0
}

download_honeydb() {
  local outfile="$1" bakfile="$2"
  if [[ -z "$HONEYDB_API_ID" || -z "$HONEYDB_API_KEY" ]]; then
    log DEBUG "HoneyDB API ID or KEY not set or empty; skipping HoneyDB."
    return 0
  fi
  log INFO "Downloading HoneyDB blacklist"
  if curl -sfL "$HONEYDB_URL" \
    -H "X-HoneyDb-ApiId: $HONEYDB_API_ID" \
    -H "X-HoneyDb-ApiKey: $HONEYDB_API_KEY" \
    -A "firewall-blocklist-updater" -o "$outfile"; then
    if [[ -s "$outfile" ]]; then
      cp "$outfile" "$bakfile"
      if command -v jq &>/dev/null; then
        jq -r '.[].remote_host' "$outfile" | sort -u > "${outfile}.ips"
      else
        grep -Eo '([0-9a-fA-F:.]+)' "$outfile" | sort -u > "${outfile}.ips"
        log WARN "jq not found; fallback JSON parse used"
      fi
      mv "${outfile}.ips" "$outfile"
      log INFO "HoneyDB blacklist downloaded and processed"
      return 0
    else
      log WARN "HoneyDB response empty"
    fi
  else
    log WARN "Failed to download HoneyDB blacklist"
  fi
  if [[ -s "$bakfile" ]]; then
    cp "$bakfile" "$outfile"
    log WARN "Using backup for HoneyDB blacklist"
    return 0
  fi
  log WARN "No HoneyDB backup available"
  return 0
}

filter_private_ips() {
  local infile="$1" outfile="$2"
  if ! command -v python3 &>/dev/null; then
    log WARN "python3 not found; skipping private IP filtering"
    cp "$infile" "$outfile"
    return 0
  fi

  python3 <<EOF < "$infile" > "$outfile"
import ipaddress, sys
ips = set()
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    try:
        ipobj = None
        if "/" in line:
            ipobj = ipaddress.ip_network(line, strict=False)
        else:
            ipobj = ipaddress.ip_address(line)
        if ipobj.version == 4:
            if not (ipobj.is_private or ipobj.is_loopback or ipobj.is_reserved or ipobj.is_multicast):
                ips.add(str(ipobj))
        elif ipobj.version == 6:
            if not (ipobj.is_private or ipobj.is_loopback or ipobj.is_reserved or ipobj.is_multicast):
                ips.add(str(ipobj))
    except:
        pass
for ip in sorted(ips):
    print(ip)
EOF

  log INFO "Filtered private/local IPs (IPv4+IPv6): $infile -> $outfile"
}

  python3 -c "$(cat <<EOF
import ipaddress, sys
ips = set()
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    try:
        ipobj = None
        if "/" in line:
            ipobj = ipaddress.ip_network(line, strict=False)
        else:
            ipobj = ipaddress.ip_address(line)
        if ipobj.version == 4:
            if not (ipobj.is_private or ipobj.is_loopback or ipobj.is_reserved or ipobj.is_multicast):
                ips.add(str(ipobj))
        elif ipobj.version == 6:
            if not (ipobj.is_private or ipobj.is_loopback or ipobj.is_reserved or ipobj.is_multicast):
                ips.add(str(ipobj))
    except:
        pass

with open('${outfile}', 'w') as f:
    for ip in sorted(ips):
        f.write(ip + "\\n")
EOF
)" < "$infile"

  log INFO "Filtered private/local IPs (IPv4+IPv6): $infile -> $outfile"
}

create_or_flush_ipset() {
  local set=$1
  local type="hash:net"
  if [[ "$set" == *"_v6" ]]; then
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
  log INFO "Loading IPs from $file into $set"
  while IFS= read -r ip; do
    ip="${ip//[[:space:]]/}"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?$ ]] && [[ "$set" != *_v6 ]]; then
      ipset add "$set" "$ip" 2>/dev/null || true
      ((cnt++))
    elif [[ "$ip" =~ ^([0-9a-fA-F:]+(/[0-9]+)?)$ ]] && [[ "$set" == *_v6 ]]; then
      ipset add "$set" "$ip" 2>/dev/null || true
      ((cnt++))
    fi
  done < <(grep -Ev '^\s*($|#)' "$file" || true)
  log INFO "Loaded $cnt IPs into $set"
}

cleanup_old_iptables_rules() {
  local current_sets=("$IPSET_BLOCKLIST" "$IPSET_WHITELIST" "$IPSET_BLOCKLIST6" "$IPSET_WHITELIST6")
  mapfile -t rules < <(iptables -S "$IPTABLES_CHAIN" | grep -- "-m set --match-set" || true)
  for rule in "${rules[@]}"; do
    if [[ "$rule" =~ --match-set[[:space:]]+([^[:space:]]+) ]]; then
      local setname="${BASH_REMATCH[1]}"
      if ! [[ " ${current_sets[*]} " =~ " ${setname} " ]]; then
        local delrule="${rule/-A/-D}"
        iptables $delrule || true
        log INFO "Removed obsolete iptables rule referencing $setname"
      fi
    fi
  done
}

ensure_iptables_rule() {
  if ! iptables -C "$IPTABLES_CHAIN" -m set --match-set "$IPSET_BLOCKLIST" src -j DROP &>/dev/null; then
    iptables -I "$IPTABLES_CHAIN" -m set --match-set "$IPSET_BLOCKLIST" src -j DROP
    log INFO "Added iptables rule to drop IPs in $IPSET_BLOCKLIST"
  else
    log INFO "iptables rule for $IPSET_BLOCKLIST already exists"
  fi
}

cleanup_old_dynamic_dns_ips() {
  if [[ -z "${DYNDNS_HOST:-}" ]]; then
    log DEBUG "DYNDNS_HOST not set. Skipping dynamic DNS whitelist cleanup."
    return 0
  fi
  local dnsname="$DYNDNS_HOST"
  local current_ip new_ips ip

  current_ip=$(dig +short "$dnsname" | head -n1 || true)
  if [[ -z "$current_ip" ]]; then
    log DEBUG "Failed to resolve $dnsname; skipping cleanup of old DynDNS IPs."
    return 0
  fi

  mapfile -t new_ips < <(ipset list "$IPSET_WHITELIST" | awk '/^Members:$/ {flag=1;next} flag && NF {print $1}' || true)

  for ip in "${new_ips[@]}"; do
    if [[ "$ip" != "$current_ip" ]]; then
      ipset del "$IPSET_WHITELIST" "$ip" 2>/dev/null && log INFO "Removed old DynDNS IP $ip from whitelist"
    fi
  done
  return 0
}

update_dynamic_dns_whitelist() {
  if [[ -z "${DYNDNS_HOST:-}" ]]; then
    log DEBUG "DYNDNS_HOST not set. Skipping dynamic DNS whitelist update."
    return 0
  fi
  local dnsname="$DYNDNS_HOST"
  local ip
  ip=$(dig +short "$dnsname" | head -n1 || true)

  if [[ -z "$ip" ]]; then
    log DEBUG "Failed to resolve $dnsname; whitelist entry unchanged."
    return 0
  fi

  if ipset test "$IPSET_WHITELIST" "$ip" &>/dev/null; then
    log INFO "Dynamic DNS IP $ip already in whitelist"
  else
    ipset add "$IPSET_WHITELIST" "$ip"
    log INFO "Added dynamic DNS IP $ip to whitelist"
  fi

  cleanup_old_dynamic_dns_ips || true
  return 0
}

# --- Main execution ---
log INFO "=== Starting firewall blocklist update ==="

cleanup_old_iptables_rules

update_dynamic_dns_whitelist || true

wl_file="$TMPDIR/whitelist.lst"
download_and_merge_parallel "$wl_file" $(read_sources "$WHITELIST_SOURCES_FILE")

bl_file_raw="$TMPDIR/blocklist_raw.lst"
download_and_merge_parallel "$bl_file_raw" $(read_sources "$BLOCKLIST_SOURCES_FILE")

abuseipdb_file="$TMPDIR/abuseipdb.lst"
download_abuseipdb "$abuseipdb_file" "$BACKUPDIR/abuseipdb.bak"
cat "$abuseipdb_file" >> "$bl_file_raw" 2>/dev/null || true

honeydb_file="$TMPDIR/honeydb.lst"
download_honeydb "$honeydb_file" "$BACKUPDIR/honeydb.bak"
cat "$honeydb_file" >> "$bl_file_raw" 2>/dev/null || true

filter_private_ips "$bl_file_raw" "$TMPDIR/blocklist_filtered.lst"

bl_file_filtered="$TMPDIR/blocklist_filtered.lst"
bl_file_final="$TMPDIR/blocklist_final.lst"
comm -23 <(sort "$bl_file_filtered") <(sort "$wl_file") > "$bl_file_final"

log INFO "$(wc -l < "$bl_file_final") IPs remain after applying whitelist"

create_or_flush_ipset "$IPSET_WHITELIST"
load_ips_to_ipset "$wl_file" "$IPSET_WHITELIST"

create_or_flush_ipset "$IPSET_BLOCKLIST"
load_ips_to_ipset "$bl_file_final" "$IPSET_BLOCKLIST"

create_or_flush_ipset "$IPSET_WHITELIST6"
load_ips_to_ipset "$wl_file" "$IPSET_WHITELIST6"

create_or_flush_ipset "$IPSET_BLOCKLIST6"
load_ips_to_ipset "$bl_file_final" "$IPSET_BLOCKLIST6"

ensure_iptables_rule

count_wl=$(ipset list "$IPSET_WHITELIST" 2>/dev/null | awk '/Number of entries:/ {print $4}' || echo 0)
count_bl=$(ipset list "$IPSET_BLOCKLIST" 2>/dev/null | awk '/Number of entries:/ {print $4}' || echo 0)
log INFO "Whitelist contains: $count_wl IPs"
log INFO "Blocklist contains: $count_bl IPs"

log INFO "=== Firewall blocklist update finished ==="
exit 0
