#!/usr/bin/env bash
# Configure this host to forward locally processed rsyslog messages to a
# central syslog receiver hosted on the user-supplied DB server.
# Cron monitors the forwarding service; rsyslog itself sends continuously.
set -Eeuo pipefail
umask 077

readonly CONFIG=/etc/rsyslog.d/90-central-db-forward.conf
readonly HEALTH=/usr/local/sbin/central-rsyslog-forward-health
readonly CRON=/etc/cron.d/central-rsyslog-forward-health
readonly SYSLOG_PORT=514  # Default TCP syslog port; receiver must listen here.

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

usage() {
  printf 'Usage: sudo bash %s [--db-ip IPv4]\n' "${0##*/}"
  printf 'The DB host must already accept TCP syslog. This does not insert into SQL.\n'
}

valid_ipv4() {
  local ip=$1 octet
  local -a octets
  [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || return 1
  done
  (( 10#${octets[0]} >= 1 && 10#${octets[0]} <= 223 )) || return 1
  [[ ${octets[0]} != 127 ]] || return 1
}

db_ip=''
while (( $# > 0 )); do
  case $1 in
    --db-ip)
      (( $# >= 2 )) || die '--db-ip requires an IPv4 address'
      db_ip=$2
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "Unknown argument: $1" ;;
  esac
done

(( EUID == 0 )) || die 'Run as root (sudo).'
for command_name in rsyslogd systemctl install mktemp cmp cp logger timeout bash; do
  command -v "$command_name" >/dev/null 2>&1 || die "Missing command: $command_name"
done
[[ -f /etc/rsyslog.conf ]] || die 'Missing /etc/rsyslog.conf'
[[ -d /etc/rsyslog.d ]] || die 'Missing /etc/rsyslog.d'

if [[ -z $db_ip ]]; then
  [[ -t 0 ]] || die 'Provide --db-ip IPv4 in noninteractive mode.'
  read -r -p 'Central DB/syslog receiver IPv4 address: ' db_ip
fi
valid_ipv4 "$db_ip" || die "Invalid receiver IPv4 address: $db_ip"

if command -v ip >/dev/null 2>&1 && ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$db_ip"; then
  die 'The receiver address belongs to this host; refusing to create a forwarding loop.'
fi

tmp_config=$(mktemp /etc/rsyslog.d/.central-db-forward.XXXXXXXX)
tmp_health=$(mktemp /usr/local/sbin/.central-rsyslog-health.XXXXXXXX)
tmp_cron=$(mktemp /etc/cron.d/.central-rsyslog-health.XXXXXXXX)
backup=''
had_config=0
changed_config=0

cleanup() {
  rm -f -- "$tmp_config" "$tmp_health" "$tmp_cron"
}
trap cleanup EXIT

install -d -m 0750 /var/lib/rsyslog
cat > "$tmp_config" <<EOF
# Managed by central-rsyslog-forward.sh. Local logging remains unchanged.
# Requires a central TCP syslog receiver at ${db_ip}.
if (\$inputname != "imtcp" and \$inputname != "imudp") then {
action(
  type="omfwd"
  target="${db_ip}"
  port="${SYSLOG_PORT}"
  protocol="tcp"
  template="RSYSLOG_SyslogProtocol23Format"
  queue.type="LinkedList"
  queue.filename="central_db_fwd"
  queue.spoolDirectory="/var/lib/rsyslog"
  queue.size="10000"
  queue.maxDiskSpace="1g"
  queue.saveOnShutdown="on"
  action.resumeRetryCount="-1"
)
}
EOF

rollback_config() {
  if (( changed_config )); then
    if (( had_config )); then
      cp -p -- "$backup" "$CONFIG"
    else
      rm -f -- "$CONFIG"
    fi
    rsyslogd -N1 >/dev/null 2>&1 || true
    systemctl restart rsyslog >/dev/null 2>&1 || true
  fi
}

if [[ -f $CONFIG ]]; then
  had_config=1
fi

if ! [[ -f $CONFIG ]] || ! cmp -s "$tmp_config" "$CONFIG"; then
  if (( had_config )); then
    backup=$(mktemp "${CONFIG}.bak.XXXXXXXX")
    cp -p -- "$CONFIG" "$backup"
    info "Existing forwarding config backed up to $backup"
  fi
  install -o root -g root -m 0644 "$tmp_config" "$CONFIG"
  changed_config=1
  if ! rsyslogd -N1; then
    rollback_config
    die 'Rsyslog syntax check failed; previous config restored.'
  fi
  if ! systemctl restart rsyslog || ! systemctl is-active --quiet rsyslog; then
    rollback_config
    die 'Rsyslog did not restart successfully; previous config restored.'
  fi
else
  rsyslogd -N1 || die 'Existing rsyslog configuration is invalid.'
  systemctl is-active --quiet rsyslog || die 'Rsyslog is not active.'
  info 'Forwarding config already matches; no rsyslog restart needed.'
fi

cat > "$tmp_health" <<EOF
#!/usr/bin/env bash
# Cron health check; rsyslog itself forwards messages continuously.
set -Eeuo pipefail
if ! rsyslogd -N1 >/dev/null 2>&1; then
  logger -p daemon.err -t central-rsyslog-forward 'Invalid rsyslog configuration; refusing automatic restart'
  exit 1
fi
if ! systemctl is-active --quiet rsyslog; then
  if ! systemctl restart rsyslog; then
    logger -p daemon.err -t central-rsyslog-forward 'Failed to restart inactive rsyslog service'
    exit 1
  fi
fi
if ! timeout 3 bash -c 'exec 3<>/dev/tcp/${db_ip}/${SYSLOG_PORT}' 2>/dev/null; then
  logger -p daemon.warning -t central-rsyslog-forward 'Central syslog receiver ${db_ip} is unreachable; rsyslog will retry from its queue'
  exit 1
fi
EOF
install -o root -g root -m 0750 "$tmp_health" "$HEALTH"

cat > "$tmp_cron" <<EOF
SHELL=/bin/bash
PATH=/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * root ${HEALTH} >/dev/null 2>&1
EOF
install -o root -g root -m 0644 "$tmp_cron" "$CRON"

if systemctl list-unit-files crond.service --no-legend 2>/dev/null | grep -q '^crond.service'; then
  systemctl enable --now crond >/dev/null
elif systemctl list-unit-files cron.service --no-legend 2>/dev/null | grep -q '^cron.service'; then
  systemctl enable --now cron >/dev/null
else
  info 'Warning: cron daemon not found; rsyslog forwarding works, but health cron will not run.'
fi

logger -t central-rsyslog-forward "forwarding-test host=$(hostname -s) receiver=${db_ip}"
info "Configured rsyslog forwarding to ${db_ip} (default TCP syslog)."
info "Cron health check installed at ${CRON}; rsyslog sends continuously."
info 'Check the central receiver for the forwarding-test message to confirm delivery.'
info 'Traffic is unencrypted TCP syslog; use TLS before forwarding across untrusted networks.'
