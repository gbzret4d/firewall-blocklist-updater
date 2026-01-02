#!/bin/bash
set -e
set -o pipefail

# --- FIREWALL & CROWDSEC INSTALLER (v17.16 - COMPATIBILITY MODE) ---
# - FIX: Replaced 'curl --dns-servers' (incompatible with old OS) with system-level /etc/resolv.conf override.
# - FIX: Ensures blocklists can be downloaded even if local DNS is broken.
# - LOGIC: Auto-Update + Idempotent + Silent.
# - COMPAT: Universal (Works on old Debian/Ubuntu).

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a 
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
INSTALLER_VERSION="v17.16"

# --- 0. PRE-FLIGHT: FIREWALL FLUSH ---
# Clear everything to ensure we can reach the internet/DNS
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
if command -v ipset >/dev/null; then ipset flush 2>/dev/null || true; fi

# --- 0.1 HARD DNS REPAIR (The Fix for 'host not found') ---
# If we can't resolve Google, we force Google DNS into the system configuration
if ! getent hosts google.com >/dev/null 2>&1; then
    echo "⚠️ System DNS is broken. Forcing Google DNS (8.8.8.8) into /etc/resolv.conf..."
    # Backup existing
    cp /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null || true
    # Overwrite
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    sleep 2
    echo "✅ DNS patched."
fi

# --- 1. KEY LOADING ---
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

handle_error() {
    local line=$1
    echo "❌ CRITICAL ERROR at line $line"
    local LOG_TAIL=""; if command -v journalctl >/dev/null; then LOG_TAIL=$(journalctl -u crowdsec -n 10 --no-pager 2>/dev/null | tail -n 10); fi
    get_server_identity
    local OS_NAME="Unknown"; if [ -f /etc/os-release ]; then OS_NAME=$(grep -E '^(ID|PRETTY_NAME)=' /etc/os-release | head -n 1 | cut -d= -f2 | tr -d '"'); fi
    send_msg "🚨 <b>INSTALL CRASHED</b>%0A%0A<b>Host:</b> $(hostname)%0A<b>IP:</b> $SERVER_IP ($SERVER_CC)%0A<b>OS:</b> $OS_NAME%0A<b>Line:</b> $line%0A%0A<b>Log Context:</b>%0A<pre>$LOG_TAIL</pre>"
}
trap 'handle_error $LINENO' ERR

echo "============================================="
echo "   FIREWALL & CROWDSEC INSTALLER ($INSTALLER_VERSION) "
echo "============================================="

# --- OS & DEPENDENCIES ---
if command -v dpkg >/dev/null; then dpkg --configure -a || true; fi

if command -v apt-get >/dev/null; then
    PM="apt-get"
    # Try update, if DNS fails, it will fail but we patched resolv.conf above so it should work
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

# --- CLEANUP ---
mkdir -p /etc/systemd/journald.conf.d
echo -e "[Journal]\nSystemMaxUse=500M\nSystemMaxFileSize=100M\nMaxRetentionSec=2weeks" > /etc/systemd/journald.conf.d/00-limit-size.conf
systemctl restart systemd-journald || true

cat <<EOF > /usr/local/bin/daily-system-cleanup.sh
#!/bin/bash
journalctl --vacuum-size=500M >/dev/null 2>&1
if command -v apt-get >/dev/null; then apt-get clean; elif command -v dnf >/dev/null; then dnf clean all; fi
EOF
chmod +x /usr/local/bin/daily-system-cleanup.sh

cat <<SERV > /etc/systemd/system/daily-system-cleanup.service
[Unit]
Description=Daily System Cleanup
[Service]
Type=oneshot
ExecStart=/usr/local/bin/daily-system-cleanup.sh
SERV
cat <<TIME > /etc/systemd/system/daily-system-cleanup.timer
[Unit]
Description=Run Daily Cleanup
[Timer]
OnCalendar=daily
RandomizedDelaySec=300
Persistent=true
[Install]
WantedBy=timers.target
TIME
systemctl daemon-reload
systemctl enable --now daily-system-cleanup.timer

# --- CROWDSEC SETUP ---
CS_INSTALLED=false
if command -v crowdsec >/dev/null; then CS_INSTALLED=true; fi

harden_crowdsec_service() {
    cat <<SERVICE > /lib/systemd/system/crowdsec.service
[Unit]
Description=Crowdsec agent
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=notify
Environment=LC_ALL=C LANG=C
PIDFile=/var/run/crowdsec.pid
ExecStartPre=/usr/bin/crowdsec -c /etc/crowdsec/config.yaml -t
ExecStart=/usr/bin/crowdsec -c /etc/crowdsec/config.yaml
Restart=always
RestartSec=5s
StartLimitInterval=0
ExecStartPre=-/usr/bin/pkill -9 -f "crowdsec -c"

[Install]
WantedBy=multi-user.target
SERVICE
    systemctl daemon-reload
}

synthesize_configs() {
    mkdir -p /etc/crowdsec
    if [[ ! -s /etc/crowdsec/acquis.yaml ]]; then
        echo -e "filenames:\n  - /var/log/syslog\n  - /var/log/auth.log\n  - /var/log/messages\nlabels:\n  type: syslog\n---" > /etc/crowdsec/acquis.yaml
    fi
}

purge_crowdsec() {
    echo "☢️ PURGING CrowdSec (Clean Slate)..."
    systemctl stop crowdsec || true
    purge_pkg crowdsec crowdsec-firewall-bouncer-iptables
    rm -rf /etc/crowdsec /var/lib/crowdsec /var/log/crowdsec
    CS_INSTALLED=false
}

configure_and_start_crowdsec() {
    # SMART CHECK
    if systemctl is-active --quiet crowdsec; then
        local CUR_PORT=$(grep "listen_uri:" /etc/crowdsec/config.yaml | awk -F':' '{print $3}' | tr -d ' ' || echo "8080")
        if [[ "$CUR_PORT" -ge 42000 && "$CUR_PORT" -le 42100 ]]; then
            if cscli lapi status >/dev/null 2>&1; then
                echo "✅ CrowdSec is already running healthy on port $CUR_PORT. Skipping setup."
                return 0
            fi
        fi
    fi

    harden_crowdsec_service
    synthesize_configs
    systemctl stop crowdsec || true
    pkill -9 crowdsec || true
    sleep 2

    local CONFIG_FILE="/etc/crowdsec/config.yaml"
    local ATTEMPT=0
    local MAX_ATTEMPTS=6
    local START_PORT=42000
    
    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        local TEST_PORT=$((START_PORT + ATTEMPT))
        echo "🔧 Config Attempt on Port: $TEST_PORT ($((ATTEMPT+1))/$MAX_ATTEMPTS)"
        if [[ ! -f "$CONFIG_FILE" ]]; then install_pkg crowdsec; harden_crowdsec_service; synthesize_configs; fi
        sed -i -E "s/127\.0\.0\.1:[0-9]+/127.0.0.1:$TEST_PORT/g" /etc/crowdsec/config.yaml 2>/dev/null || true
        sed -i -E "s/127\.0\.0\.1:[0-9]+/127.0.0.1:$TEST_PORT/g" /etc/crowdsec/local_api_credentials.yaml 2>/dev/null || true
        find /etc/crowdsec/bouncers/ -name "*.yaml" -exec sed -i -E "s/127\.0\.0\.1:[0-9]+/127.0.0.1:$TEST_PORT/g" {} + 2>/dev/null || true
        
        if systemctl start crowdsec; then
            sleep 5
            if systemctl is-active --quiet crowdsec; then
                if cscli lapi status >/dev/null 2>&1; then
                    echo "✅ CrowdSec LIVE on port $TEST_PORT."
                    return 0
                fi
            fi
        fi
        echo "⚠️ Start failed on $TEST_PORT. Rotating..."
        systemctl stop crowdsec || true
        pkill -9 crowdsec || true
        ATTEMPT=$((ATTEMPT + 1))
    done
    return 1
}

if [[ -n "$CS_ENROLL" ]] || [[ "$CS_INSTALLED" == "false" ]]; then
    if [[ "$CS_INSTALLED" == "false" ]]; then
        if [[ "$PM" == "apt-get" ]]; then curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash 2>/dev/null
        else curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash 2>/dev/null; fi
        install_pkg crowdsec
    fi
    
    if ! configure_and_start_crowdsec; then
        echo "❌ First pass failed. Initiating NUCLEAR RESET..."
        purge_crowdsec
        install_pkg crowdsec
        if ! configure_and_start_crowdsec; then
            echo "❌ CRITICAL: Even fresh install failed."
            exit 1
        fi
    fi
    
    for i in {1..20}; do if cscli lapi status >/dev/null 2>&1; then break; fi; sleep 2; done

    if ! command -v crowdsec-firewall-bouncer >/dev/null; then
        install_pkg crowdsec-firewall-bouncer-iptables
        configure_and_start_crowdsec
    fi

    rm -f /usr/lib/crowdsec/plugins/{dummy,install.sh,update-firewall-blocklists.sh} 2>/dev/null || true

    if command -v cscli >/dev/null; then
        cscli hub update >/dev/null 2>&1 || true
        cscli notifications update >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/whitelist-good-actors --force >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/linux --force >/dev/null 2>&1 || true
        cscli collections install crowdsecurity/sshd --force >/dev/null 2>&1 || true
        if command -v docker >/dev/null; then cscli collections install crowdsecurity/docker --force >/dev/null 2>&1 || true; fi
    fi

    if [[ -n "$CS_ENROLL" ]]; then 
        if [[ -f "/etc/crowdsec/online_api_credentials.yaml" ]]; then
            echo "✅ Agent is already enrolled. Skipping."
        else
            echo "🔑 Enrolling Agent..."
            if cscli console enroll "$CS_ENROLL" --overwrite; then systemctl reload crowdsec || systemctl restart crowdsec; fi
        fi
    fi

    if [[ -n "$ABUSE_KEY" ]]; then
        mkdir -p /etc/crowdsec/notifications
        cat <<YAML > /etc/crowdsec/notifications/abuseipdb.yaml
type: http
name: abuseipdb
log_level: info
format: |
  {
    "ip": "{{range . -}}{{.Source.IP}}{{end}}",
    "categories": "18,22",
    "comment": "Blocked by CrowdSec. Scenario: {{range . -}}{{.Scenario}}{{end}}",
    "key": "$ABUSE_KEY"
  }
url: https://api.abuseipdb.com/api/v2/report
method: POST
headers:
  Content-Type: application/json
  Accept: application/json
YAML
        if ! grep -q "abuseipdb" /etc/crowdsec/profiles.yaml 2>/dev/null; then
            cat <<YAML > /etc/crowdsec/profiles.yaml
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
YAML
        fi
    fi
fi

INSTALL_DIR="/usr/local/bin"
CONF_DIR="/usr/local/etc/firewall-blocklist-updater"
mkdir -p "$CONF_DIR/firewall-blocklists" "$CONF_DIR/backups"

# --- WRITE UPDATER WITH SYSTEM DNS FIX ---
cat << EOF_UPDATER > "$INSTALL_DIR/update-firewall-blocklists.sh"
#!/bin/bash
set -euo pipefail
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SCRIPT_VERSION="v11.16"
BASE_DIR="/usr/local/etc/firewall-blocklist-updater"
CONFIG_DIR="\$BASE_DIR/firewall-blocklists"
KEYFILE="\${KEYFILE:-\$BASE_DIR/firewall-blocklist-keys.env}"
SOURCE_FILE="\$CONFIG_DIR/blocklist.sources"
CUSTOM_WL_FILE="\$CONFIG_DIR/whitelist.custom"
LOCKFILE="/var/run/firewall-updater.lock"
LOGFILE="/var/log/firewall-blocklist-updater.log"
MAX_LOG_SIZE=$((5 * 1024 * 1024))
DRY_RUN=0
REPO_URL="$REPO_URL"

manage_log_size() {
    if [[ -f "\$LOGFILE" ]]; then
        local size=\$(stat -c%s "\$LOGFILE" 2>/dev/null || stat -f%z "\$LOGFILE" 2>/dev/null || echo 0)
        if [[ \$size -gt \$MAX_LOG_SIZE ]]; then tail -n 2000 "\$LOGFILE" > "\$LOGFILE.tmp" && mv "\$LOGFILE.tmp" "\$LOGFILE"; fi
    fi
}
log() { echo -e "\$(date '+%Y-%m-%d %H:%M:%S') [INFO] \$*" | tee -a "\$LOGFILE"; }
cleanup() { rm -f "\$LOCKFILE" /tmp/firewall-blocklists/* 2>/dev/null || true; }
trap cleanup EXIT INT TERM
HAS_FLOCK=0; if command -v flock >/dev/null; then HAS_FLOCK=1; fi
mkdir -p "\$BASE_DIR" "\$CONFIG_DIR" /tmp/firewall-blocklists

# --- FORCE DNS REPAIR IN UPDATER TOO ---
fix_dns() {
    if ! getent hosts google.com >/dev/null 2>&1; then
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
    fi
}

check_ipv6_stack() { if [[ ! -f /proc/net/if_inet6 ]]; then return 1; fi; if ! command -v ip6tables >/dev/null; then return 1; fi; return 0; }
load_env_vars() { if [[ -f "\$KEYFILE" ]]; then set +u; set -a; source "\$KEYFILE"; set +a; set -u; fi; }

perform_auto_update() {
    fix_dns
    local TMP_INSTALLER="/tmp/install_latest.sh"
    # No --dns-servers flag here, because we fixed /etc/resolv.conf directly
    if curl -sL --max-time 10 "\$REPO_URL/install.sh" -o "\$TMP_INSTALLER"; then
        local NEW_UPDATER_VER=\$(grep -oE 'SCRIPT_VERSION="v[0-9]+\.[0-9]+"' "\$TMP_INSTALLER" | head -n1 | cut -d'"' -f2 || echo "")
        if [[ -n "\$NEW_UPDATER_VER" && "\$NEW_UPDATER_VER" != "\$SCRIPT_VERSION" ]]; then
            log "Update found: Installer carries \$NEW_UPDATER_VER (Local: \$SCRIPT_VERSION). Upgrading..."
            bash "\$TMP_INSTALLER"
            rm -f "\$TMP_INSTALLER"
            exit 0
        fi
        rm -f "\$TMP_INSTALLER"
    fi
    return 0
}

check_connectivity() { if ! curl -s --head --request GET https://1.1.1.1 > /dev/null; then echo "No internet."; exit 0; fi; }
repair_environment() { local HN=\$(hostname); if ! grep -q "127.0.1.1 \$HN" /etc/hosts; then echo "127.0.1.1 \$HN" >> /etc/hosts; fi; }

get_identity() {
    HN=\$(hostname)
    IP=\$(curl -s --max-time 2 http://ip-api.com/csv/?fields=query | cut -d',' -f1 || echo "Unknown-IP")
}

send_telegram() { 
    if [[ -n "\${TELEGRAM_BOT_TOKEN:-}" && -n "\${TELEGRAM_CHAT_ID:-}" ]]; then 
        get_identity
        local MSG="<b>[\$HN] (\$IP)</b>%0A\$1"
        curl -s -X POST "https://api.telegram.org/bot\$TELEGRAM_BOT_TOKEN/sendMessage" -d chat_id="\$TELEGRAM_CHAT_ID" -d text="\$MSG" -d parse_mode="HTML" >/dev/null || true; 
    fi 
}

TMPDIR="/tmp/firewall-blocklists"
IPSET_WL="allowed_whitelist"; IPSET_BL="blocklist_all"
get_set_count() { ipset list "\$1" -t 2>/dev/null | grep "Number of entries" | cut -d: -f2 | tr -d ' ' || echo 0; }
smart_extract() { local f="\$1"; if gzip -t "\$f" 2>/dev/null; then zcat "\$f"; elif unzip -t "\$f" 2>/dev/null; then unzip -p "\$f"; else cat "\$f"; fi; }
download_lists() {
  fix_dns
  local out="\$1"; shift; local srcs=("\$@"); : > "\$TMPDIR/merge.lst"
  for u in "\${srcs[@]}"; do
      local f=\$(basename "\$u" | sed "s/[^a-zA-Z0-9._-]/_/g")
      if curl -sfL --connect-timeout 10 --retry 1 -A "$USER_AGENT" "\$u" -o "\$TMPDIR/\$f"; then
          if [[ -s "\$TMPDIR/\$f" ]]; then smart_extract "\$TMPDIR/\$f" >> "\$TMPDIR/merge.lst" || true; echo "" >> "\$TMPDIR/merge.lst"; fi
      fi
  done
  sed -i 's/[#;].*//g' "\$TMPDIR/merge.lst"; sort -u "\$TMPDIR/merge.lst" > "\$out"
}
extract_ips() {
    local input="\$1"; local output="\$2"; local family="\$3"
    [[ ! -f "\$input" ]] && touch "\$output" && return 0
    if [[ "\$family" == "inet" ]]; then grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "\$input" | grep -vE "^0\.0\.0\.0$" > "\$output" || true
    else grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?' "\$input" | grep -vE "^::" > "\$output" || true; fi
}
load_ipset() {
  local file="\$1"; local setname="\$2"; local family="\$3"
  if [[ "\$family" == "inet6" && \$IPV6_ENABLED -eq 0 ]]; then return 0; fi
  ipset create \$setname hash:net family \$family hashsize 4096 maxelem 2000000 -exist 2>/dev/null || true
  if [[ ! -s "\$file" ]]; then ipset flush \$setname 2>/dev/null || true; return 0; fi
  ipset flush "\${setname}_tmp" 2>/dev/null || ipset create "\${setname}_tmp" hash:net family \$family hashsize 4096 maxelem 2000000 -exist
  if ! sed "s/^/add \${setname}_tmp /" "\$file" | ipset restore -! 2>/dev/null; then echo "Partial ipset restore"; fi
  ipset swap "\${setname}_tmp" "\$setname"; ipset destroy "\${setname}_tmp" 2>/dev/null || true
}
update_dyndns() {
  fix_dns
  [[ -z "\$DYNDNS_HOST" ]] && return 0
  local ip=""
  if ! ip=\$(dig +short "\$DYNDNS_HOST" | head -n1); then
      ip=\$(dig +short @8.8.8.8 "\$DYNDNS_HOST" | head -n1 || true)
  fi
  if [[ -n "\$ip" ]]; then local t="\$IPSET_WL"; [[ "\$ip" =~ : ]] && t="\${IPSET_WL}_v6"; ipset add "\$t" "\$ip" -exist 2>/dev/null || true; fi
}
main() {
  [[ "\${1:-}" != "--post-update" && \$DRY_RUN -eq 0 ]] && perform_auto_update
  manage_log_size; log "=== Update Start \$SCRIPT_VERSION ==="; repair_environment
  
  if [[ \$HAS_FLOCK -eq 1 && \$DRY_RUN -eq 0 ]]; then exec 9>"\$LOCKFILE"; if ! flock -n 9; then echo "[ERROR] Locked (Previous job running). Exiting."; exit 1; fi; fi
  
  check_connectivity; load_env_vars
  if check_ipv6_stack; then IPV6_ENABLED=1; log "IPv6: Yes"; else IPV6_ENABLED=0; log "IPv6: No"; fi
  local cnt_old_v4=\$(get_set_count "\$IPSET_BL")
  log "Processing..."
  : > "\$TMPDIR/wl_raw.lst"; local wl=(); 
  
  # RESCUE: LOAD COUNTRY WHITELISTS
  for c in \${WHITELIST_COUNTRIES:-}; do wl+=("https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset"); done
  download_lists "\$TMPDIR/wl_raw.lst" "\${wl[@]}"
  
  [[ -f "\$CUSTOM_WL_FILE" ]] && cat "\$CUSTOM_WL_FILE" >> "\$TMPDIR/wl_raw.lst"
  extract_ips "\$TMPDIR/wl_raw.lst" "\$TMPDIR/wl.v4" "inet"; extract_ips "\$TMPDIR/wl_raw.lst" "\$TMPDIR/wl.v6" "inet6"

  local bl=(); [[ -f "\$CONFIG_DIR/blocklist.sources" ]] && mapfile -t bl < <(grep -vE '^\s*#' "\$CONFIG_DIR/blocklist.sources" || true)
  for c in \${BLOCKLIST_COUNTRIES:-}; do bl+=("https://iplists.firehol.org/files/geolite2_country/country_\${c,,}.netset"); done
  download_lists "\$TMPDIR/bl_raw.lst" "\${bl[@]}"
  local line_count=\$(wc -l < "\$TMPDIR/bl_raw.lst" || echo 0)
  if [[ \$line_count -lt 5000 ]]; then send_telegram "⚠️ Too few IPs (\$line_count). Skipping."; exit 0; fi
  
  extract_ips "\$TMPDIR/bl_raw.lst" "\$TMPDIR/bl.v4" "inet"; extract_ips "\$TMPDIR/bl_raw.lst" "\$TMPDIR/bl.v6" "inet6"
  grep -vE "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)" "\$TMPDIR/bl.v4" | sort -u | comm -23 - <(sort -u "\$TMPDIR/wl.v4") > "\$TMPDIR/bl_final.v4" || true
  sort -u "\$TMPDIR/bl.v6" | comm -23 - <(sort -u "\$TMPDIR/wl.v6") > "\$TMPDIR/bl_final.v6" || true

  load_ipset "\$TMPDIR/wl.v4" "\$IPSET_WL" "inet"; load_ipset "\$TMPDIR/bl_final.v4" "\$IPSET_BL" "inet"
  load_ipset "\$TMPDIR/wl.v6" "\${IPSET_WL}_v6" "inet6"; load_ipset "\$TMPDIR/bl_final.v6" "\${IPSET_BL}_v6" "inet6"

  if [[ \$DRY_RUN -eq 0 ]]; then
      iptables -D INPUT -m set --match-set "\$IPSET_BL" src -j DROP 2>/dev/null || true
      iptables -D INPUT -m set --match-set "\$IPSET_WL" src -j ACCEPT 2>/dev/null || true
      
      iptables -I INPUT 1 -p udp --sport 53 -j ACCEPT
      iptables -I INPUT 2 -p tcp --sport 53 -j ACCEPT
      iptables -I INPUT 3 -m set --match-set "\$IPSET_WL" src -j ACCEPT
      iptables -A INPUT -m set --match-set "\$IPSET_BL" src -j DROP
      
      if iptables -L DOCKER-USER >/dev/null 2>&1; then 
          iptables -D DOCKER-USER -m set --match-set "\$IPSET_BL" src -j DROP 2>/dev/null || true
          iptables -D DOCKER-USER -m set --match-set "\$IPSET_WL" src -j ACCEPT 2>/dev/null || true
          iptables -I DOCKER-USER 1 -m set --match-set "\$IPSET_WL" src -j ACCEPT
          iptables -A DOCKER-USER -m set --match-set "\$IPSET_BL" src -j DROP
      fi
      
      if [[ \$IPV6_ENABLED -eq 1 ]]; then 
          if command -v ip6tables >/dev/null; then
             ip6tables -D INPUT -m set --match-set "\${IPSET_BL}_v6" src -j DROP 2>/dev/null || true
             ip6tables -D INPUT -m set --match-set "\${IPSET_WL}_v6" src -j ACCEPT 2>/dev/null || true
             ip6tables -I INPUT 1 -m set --match-set "\${IPSET_WL}_v6" src -j ACCEPT
             ip6tables -A INPUT -m set --match-set "\${IPSET_BL}_v6" src -j DROP
          fi
      fi
      if command -v crowdsec >/dev/null; then iptables -C INPUT -m limit --limit 10/min -j LOG --log-prefix "IPTables-Dropped: " 2>/dev/null || iptables -A INPUT -m limit --limit 10/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4; fi
  fi
  update_dyndns
  local cnt_new_v4=\$(get_set_count "\$IPSET_BL"); local diff_v4=\$((cnt_new_v4 - cnt_old_v4))
  log "Finished [IPv4: \$cnt_new_v4 (\$diff_v4)]"
}
main "\${1:-}"
EOF_UPDATER
chmod +x "$INSTALL_DIR/update-firewall-blocklists.sh"

# --- REMOVE STALE LOCKFILE BEFORE STARTING ---
rm -f /var/run/firewall-updater.lock

CURRENT_TASK="Running Initial Update"
$INSTALL_DIR/update-firewall-blocklists.sh

CURRENT_TASK="Final Diagnostics"
FAILED_SERVICES=""
get_status() { systemctl is-active --quiet $1 && echo "Active" || echo "Failed"; }

[[ "$(get_status crowdsec)" == "Active" ]] && echo "✅ CrowdSec: OK" || { echo "❌ CrowdSec: FAIL"; FAILED_SERVICES+="- CrowdSec%0A"; }
[[ "$(get_status endlessh)" == "Active" ]] && echo "✅ Endlessh: OK" || { echo "❌ Endlessh: FAIL"; FAILED_SERVICES+="- Endlessh%0A"; }
[[ "$(get_status daily-system-cleanup.timer)" == "Active" ]] && echo "✅ Cleanup: OK" || { echo "❌ Cleanup: FAIL"; FAILED_SERVICES+="- Cleanup Timer%0A"; }

if command -v iptables >/dev/null && iptables -L DOCKER-USER >/dev/null 2>&1; then
    if iptables -C DOCKER-USER -m set --match-set blocklist_all src -j DROP 2>/dev/null; then echo "✅ Docker Protection: OK"; else echo "⚠️ Docker Protection: Rule Missing"; fi
fi

if [[ -n "$FAILED_SERVICES" ]]; then
    get_server_identity
    OS_NAME="Unknown"
    if [ -f /etc/os-release ]; then OS_NAME=$(grep -E '^(ID|PRETTY_NAME)=' /etc/os-release | head -n 1 | cut -d= -f2 | tr -d '"'); fi
    send_msg "⚠️ <b>INSTALL WARNING</b>%0A%0A<b>Host:</b> $(hostname)%0A<b>IP:</b> $SERVER_IP ($SERVER_CC)%0A<b>OS:</b> $OS_NAME%0A%0AThe following services failed:%0A$FAILED_SERVICES"
else
    echo "✅ INSTALLATION COMPLETE!"
fi