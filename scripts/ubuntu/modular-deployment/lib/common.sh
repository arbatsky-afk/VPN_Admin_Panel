#!/usr/bin/env bash
# Shared helpers for the modular deployment bundle. This file is sourced by
# component installers; the dispatcher itself owns shell options.

readonly MODULAR_DEPLOYMENT_SCHEMA_VERSION='1'
readonly PACKAGE_MANAGER_BUSY_MESSAGE='The system package manager is currently busy with another operation. Try this deployment again later.'

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '%s\n' "$*"
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"
}

run_package_manager_command() {
  local error_file status
  error_file=$(mktemp) || die 'Could not create temporary package-manager diagnostics.'
  if "$@" 2>"$error_file"; then
    status=0
  else
    status=$?
  fi

  if (( status == 0 )); then
    if [[ -s "$error_file" ]]; then
      cat "$error_file" >&2
    fi
    rm -f -- "$error_file"
    return 0
  fi

  if grep -Eiq 'Could not get lock .*(apt|dpkg)|Unable to acquire (the )?(dpkg|apt).*lock|frontend lock was locked by another process' "$error_file"; then
    rm -f -- "$error_file"
    die "$PACKAGE_MANAGER_BUSY_MESSAGE"
  fi

  cat "$error_file" >&2
  rm -f -- "$error_file"
  return "$status"
}

valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

valid_port_range() {
  valid_port "$1" && valid_port "$2" && (( 10#$1 <= 10#$2 ))
}

allocate_component_port() {
  local root_dir=$1 protocol=$2 range_start=$3 range_end=$4 ssh_port=$5
  need python3
  python3 "$root_dir/lib/port_contract.py" allocate \
    --protocol "$protocol" \
    --range-start "$range_start" \
    --range-end "$range_end" \
    --ssh-port "$ssh_port"
}

verify_component_port() {
  local root_dir=$1 protocol=$2 port=$3 config_port=$4 recovery_port=$5 fragment=$6
  python3 "$root_dir/lib/port_contract.py" verify \
    --protocol "$protocol" \
    --port "$port" \
    --config-port "$config_port" \
    --recovery-port "$recovery_port" \
    --fragment "$fragment"
}

emit_deployment_result() {
  local component=$1 protocol=$2 port=$3
  case "$component" in xray|hysteria2|mieru) ;; *) die 'Invalid deployment result component.' ;; esac
  case "$protocol" in tcp|udp) ;; *) die 'Invalid deployment result protocol.' ;; esac
  valid_port "$port" || die 'Invalid deployment result port.'
  printf 'VPN_ADMIN_DEPLOY_RESULT={"component":"%s","protocol":"%s","port":%s}\n' \
    "$component" "$protocol" "$port"
}

valid_hostname() {
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$1" != *..* ]]
}

valid_ipv4() {
  local address=$1 octet
  local -a octets
  [[ "$address" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  local IFS=.
  read -r -a octets <<< "$address"
  for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || return 1
  done
}

valid_hysteria_user_name() {
  [[ "$1" =~ ^[A-Za-z0-9-]+$ ]]
}

valid_mieru_user_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$ ]]
}

valid_hysteria_bandwidth() {
  [[ "$1" =~ ^[1-9][0-9]*[[:space:]]+[kKmMgGtT]?[bB][pP][sS]$ ]]
}

valid_certificate_days() {
  [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 36500 ))
}

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die 'Run as root.'
}

require_ubuntu_24_amd64() {
  [[ -r /etc/os-release ]] || die 'Could not identify the operating system.'
  # shellcheck source=/dev/null
  . /etc/os-release
  [[ ${ID:-} == 'ubuntu' && ${VERSION_ID:-} == '24.04' ]] || die 'Only Ubuntu 24.04 is supported.'
  [[ $(dpkg --print-architecture) == 'amd64' ]] || die 'Only amd64 is supported.'
}

require_config_file() {
  local config_file=$1
  [[ -f "$config_file" ]] || die "Configuration file is missing: $config_file"
}

load_trusted_config() {
  local config_file=$1
  require_config_file "$config_file"
  # The file is created from validated local operator input by the launcher.
  # shellcheck source=/dev/null
  source "$config_file"
}
