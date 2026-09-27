#!/usr/bin/env bash

readonly HYSTERIA_VERSION='2.9.2'
readonly HYSTERIA_ASSET="hysteria2/hysteria-linux-amd64-v$HYSTERIA_VERSION"
readonly HYSTERIA_CONFIG='/etc/hysteria/config.yaml'
readonly HYSTERIA_SECRETS='/opt/vpn/recovery/hysteria2-secrets.env'
readonly HYSTERIA_CERTIFICATE='/etc/hysteria/server.crt'
readonly HYSTERIA_PRIVATE_KEY='/etc/hysteria/server.key'

escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

render_hysteria_config() {
  local template=$1 destination=$2
  local bandwidth_up bandwidth_down initial_user initial_password masquerade_host obfs_password
  bandwidth_up=$(escape_sed_replacement "$HYSTERIA_BANDWIDTH_UP")
  bandwidth_down=$(escape_sed_replacement "$HYSTERIA_BANDWIDTH_DOWN")
  initial_user=$(escape_sed_replacement "$HYSTERIA_INITIAL_USER")
  initial_password=$(escape_sed_replacement "$HYSTERIA_INITIAL_PASSWORD")
  masquerade_host=$(escape_sed_replacement "$HYSTERIA_MASQUERADE_HOST")
  obfs_password=$(escape_sed_replacement "$HYSTERIA_OBFS_PASSWORD")
  sed \
    -e "s|__HYSTERIA_PORT__|$HYSTERIA_PORT|g" \
    -e "s|__HYSTERIA_BANDWIDTH_UP__|$bandwidth_up|g" \
    -e "s|__HYSTERIA_BANDWIDTH_DOWN__|$bandwidth_down|g" \
    -e "s|__HYSTERIA_INITIAL_USER__|$initial_user|g" \
    -e "s|__HYSTERIA_INITIAL_PASSWORD__|$initial_password|g" \
    -e "s|__HYSTERIA_MASQUERADE_HOST__|$masquerade_host|g" \
    -e "s|__HYSTERIA_OBFS_PASSWORD__|$obfs_password|g" \
    "$template" > "$destination"
}

create_hysteria2_secrets() {
  local candidate
  HYSTERIA_INITIAL_PASSWORD=$(openssl rand -hex 24)
  HYSTERIA_OBFS_PASSWORD=$(openssl rand -hex 24)
  [[ -n "$HYSTERIA_INITIAL_PASSWORD" && -n "$HYSTERIA_OBFS_PASSWORD" ]] \
    || die 'Could not generate Hysteria2 secrets.'

  candidate=$(mktemp /opt/vpn/recovery/.hysteria2-secrets.XXXXXX)
  cat > "$candidate" <<EOF
HYSTERIA_INITIAL_PASSWORD='$HYSTERIA_INITIAL_PASSWORD'
HYSTERIA_OBFS_PASSWORD='$HYSTERIA_OBFS_PASSWORD'
DEPLOYED_HYSTERIA_PORT='$HYSTERIA_PORT'
DEPLOYED_HYSTERIA_INITIAL_USER='$HYSTERIA_INITIAL_USER'
DEPLOYED_HYSTERIA_CERTIFICATE_DAYS='$HYSTERIA_CERTIFICATE_DAYS'
DEPLOYED_HYSTERIA_BANDWIDTH_UP='$HYSTERIA_BANDWIDTH_UP'
DEPLOYED_HYSTERIA_BANDWIDTH_DOWN='$HYSTERIA_BANDWIDTH_DOWN'
DEPLOYED_HYSTERIA_MASQUERADE_HOST='$HYSTERIA_MASQUERADE_HOST'
DEPLOYED_HYSTERIA_SERVER_ADDRESS='$SERVER_ADDRESS'
EOF
  chmod 0600 "$candidate"
  mv -f "$candidate" "$HYSTERIA_SECRETS"
}

load_or_create_hysteria2_secrets() {
  if [[ -f "$HYSTERIA_SECRETS" ]]; then
    # shellcheck source=/dev/null
    source "$HYSTERIA_SECRETS"
    [[ -n ${HYSTERIA_INITIAL_PASSWORD:-} && -n ${HYSTERIA_OBFS_PASSWORD:-} ]] \
      || die 'Existing Hysteria2 secrets are incomplete.'
    return
  fi
  create_hysteria2_secrets
}

create_hysteria2_certificate() {
  local certificate_candidate key_candidate
  if [[ -e "$HYSTERIA_CERTIFICATE" || -e "$HYSTERIA_PRIVATE_KEY" ]]; then
    [[ -f "$HYSTERIA_CERTIFICATE" && -f "$HYSTERIA_PRIVATE_KEY" ]] \
      || die 'Existing Hysteria2 certificate files are incomplete.'
    return
  fi

  certificate_candidate=$(mktemp /etc/hysteria/.server-crt.XXXXXX)
  key_candidate=$(mktemp /etc/hysteria/.server-key.XXXXXX)
  openssl req -x509 -nodes -newkey rsa:3072 -days "$HYSTERIA_CERTIFICATE_DAYS" \
    -keyout "$key_candidate" -out "$certificate_candidate" -subj "/CN=$SERVER_ADDRESS"
  chmod 0600 "$key_candidate"
  chmod 0644 "$certificate_candidate"
  mv -f "$key_candidate" "$HYSTERIA_PRIVATE_KEY"
  mv -f "$certificate_candidate" "$HYSTERIA_CERTIFICATE"
}

install_hysteria2() {
  local root_dir=$1 config_file=$2 candidate fragment asset_checksum existing_ssh_port
  local config_port recovery_port

  require_root
  load_trusted_config "$config_file"
  [[ ${TARGET_OS:-} == 'ubuntu-24.04' ]] || die 'TARGET_OS must be ubuntu-24.04.'
  [[ ${TARGET_ARCH:-} == 'amd64' ]] || die 'TARGET_ARCH must be amd64.'
  valid_ipv4 "${SERVER_ADDRESS:-}" || die 'SERVER_ADDRESS must be a valid IPv4 address.'
  valid_port_range "${HYSTERIA_PORT_RANGE_START:-}" "${HYSTERIA_PORT_RANGE_END:-}" \
    || die 'HYSTERIA_PORT_RANGE_START/END must define a valid UDP port range.'
  valid_hysteria_user_name "${HYSTERIA_INITIAL_USER:-}" || die 'HYSTERIA_INITIAL_USER contains unsupported characters.'
  valid_certificate_days "${HYSTERIA_CERTIFICATE_DAYS:-}" || die 'HYSTERIA_CERTIFICATE_DAYS must be between 1 and 36500.'
  valid_hysteria_bandwidth "${HYSTERIA_BANDWIDTH_UP:-}" || die 'HYSTERIA_BANDWIDTH_UP has an unsupported format.'
  valid_hysteria_bandwidth "${HYSTERIA_BANDWIDTH_DOWN:-}" || die 'HYSTERIA_BANDWIDTH_DOWN has an unsupported format.'
  valid_hostname "${HYSTERIA_MASQUERADE_HOST:-}" || die 'HYSTERIA_MASQUERADE_HOST must be a valid hostname.'
  require_ubuntu_24_amd64
  require_base_security_ready
  existing_ssh_port=$(base_security_ssh_port)
  if [[ -f "$HYSTERIA_SECRETS" ]]; then
    # Existing deployments inherit their parameters from recovery; defaults apply only to the first installation.
    # shellcheck source=/dev/null
    source "$HYSTERIA_SECRETS"
    HYSTERIA_PORT=${DEPLOYED_HYSTERIA_PORT:-}
    HYSTERIA_INITIAL_USER=${DEPLOYED_HYSTERIA_INITIAL_USER:-}
    HYSTERIA_CERTIFICATE_DAYS=${DEPLOYED_HYSTERIA_CERTIFICATE_DAYS:-}
    HYSTERIA_BANDWIDTH_UP=${DEPLOYED_HYSTERIA_BANDWIDTH_UP:-}
    HYSTERIA_BANDWIDTH_DOWN=${DEPLOYED_HYSTERIA_BANDWIDTH_DOWN:-}
    HYSTERIA_MASQUERADE_HOST=${DEPLOYED_HYSTERIA_MASQUERADE_HOST:-}
    SERVER_ADDRESS=${DEPLOYED_HYSTERIA_SERVER_ADDRESS:-}
  else
    HYSTERIA_PORT=$(allocate_component_port \
      "$root_dir" udp "$HYSTERIA_PORT_RANGE_START" "$HYSTERIA_PORT_RANGE_END" "$existing_ssh_port") \
      || die 'Could not allocate a Hysteria2 port.'
  fi
  valid_port "${HYSTERIA_PORT:-}" || die 'Hysteria2 recovery contains an invalid UDP port.'
  [[ "$HYSTERIA_PORT" != "$existing_ssh_port" ]] || die 'HYSTERIA_PORT must differ from the Base + Security SSH port.'
  valid_ipv4 "${SERVER_ADDRESS:-}" || die 'Hysteria2 recovery contains an invalid server address.'
  valid_hysteria_user_name "${HYSTERIA_INITIAL_USER:-}" || die 'Hysteria2 recovery contains an invalid initial user.'
  valid_certificate_days "${HYSTERIA_CERTIFICATE_DAYS:-}" || die 'Hysteria2 recovery contains invalid certificate days.'
  valid_hysteria_bandwidth "${HYSTERIA_BANDWIDTH_UP:-}" || die 'Hysteria2 recovery contains invalid upload bandwidth.'
  valid_hysteria_bandwidth "${HYSTERIA_BANDWIDTH_DOWN:-}" || die 'Hysteria2 recovery contains invalid download bandwidth.'
  valid_hostname "${HYSTERIA_MASQUERADE_HOST:-}" || die 'Hysteria2 recovery contains an invalid masquerade host.'

  [[ ! -e "$HYSTERIA_CONFIG" || -f "$HYSTERIA_SECRETS" ]] \
    || die 'Existing Hysteria2 configuration detected without modular Hysteria2 secrets.'
  [[ ! -e /etc/systemd/system/hysteria-server.service || -f "$HYSTERIA_SECRETS" ]] \
    || die 'Existing Hysteria2 service detected without modular Hysteria2 secrets.'

  umask 077
  if ! getent group hysteria >/dev/null; then
    groupadd --system hysteria
  fi
  if ! id -u hysteria >/dev/null 2>&1; then
    useradd --system --gid hysteria --home-dir /nonexistent --shell /usr/sbin/nologin hysteria
  fi
  install -d -m 0755 /opt/vpn/recovery
  install -d -o hysteria -g hysteria -m 0750 /etc/hysteria
  asset_checksum=$(awk -v filename="$HYSTERIA_ASSET" '$2 == filename {print; count++} END {exit count != 1}' "$root_dir/assets/SHA256SUMS") \
    || die 'Hysteria2 archive checksum is missing or ambiguous.'
  (
    cd "$root_dir/assets"
    printf '%s\n' "$asset_checksum" | sha256sum -c --strict -
  ) || die 'Hysteria2 archive checksum verification failed.'
  candidate=$(mktemp /usr/local/bin/.hysteria.XXXXXX)
  install -m 0755 "$root_dir/assets/$HYSTERIA_ASSET" "$candidate"
  mv -f "$candidate" /usr/local/bin/hysteria
  hysteria version >/dev/null

  load_or_create_hysteria2_secrets
  if [[ ! -f "$HYSTERIA_CONFIG" ]]; then
    candidate=$(mktemp --suffix=.yaml /etc/hysteria/.config.XXXXXX)
    render_hysteria_config "$root_dir/templates/hysteria-config.yaml.tmpl" "$candidate"
    python3 "$root_dir/lib/hysteria2_config.py" "$candidate" \
      || die 'Hysteria2 configuration validation failed.'
    install -o hysteria -g hysteria -m 0640 "$candidate" "$HYSTERIA_CONFIG"
    rm -f "$candidate"
  else
    python3 "$root_dir/lib/hysteria2_config.py" "$HYSTERIA_CONFIG" \
      || die 'Existing Hysteria2 configuration validation failed.'
  fi
  chown hysteria:hysteria "$HYSTERIA_CONFIG"
  chmod 0640 "$HYSTERIA_CONFIG"

  create_hysteria2_certificate
  chown hysteria:hysteria "$HYSTERIA_PRIVATE_KEY" "$HYSTERIA_CERTIFICATE"
  chmod 0600 "$HYSTERIA_PRIVATE_KEY"
  chmod 0644 "$HYSTERIA_CERTIFICATE"
  openssl pkey -in "$HYSTERIA_PRIVATE_KEY" -noout
  openssl x509 -in "$HYSTERIA_CERTIFICATE" -noout

  install -m 0644 "$root_dir/templates/hysteria-server.service.tmpl" /etc/systemd/system/hysteria-server.service
  fragment=$(component_firewall_fragment hysteria2)
  sed "s|__HYSTERIA_PORT__|$HYSTERIA_PORT|g" "$root_dir/templates/30-hysteria2.nft.tmpl" > "$fragment"
  chmod 0644 "$fragment"
  apply_firewall
  systemctl daemon-reload
  systemctl enable --now hysteria-server.service
  systemctl is-active --quiet hysteria-server.service
  config_port=$(PYTHONPATH="$root_dir/lib" python3 -c 'import sys; from hysteria2_config import hysteria2_connection_details; print(hysteria2_connection_details(open(sys.argv[1], encoding="utf-8").read())[0])' "$HYSTERIA_CONFIG") \
    || die 'Could not read the Hysteria2 config port.'
  # shellcheck source=/dev/null
  source "$HYSTERIA_SECRETS"
  recovery_port=${DEPLOYED_HYSTERIA_PORT:-}
  verify_component_port "$root_dir" udp "$HYSTERIA_PORT" "$config_port" "$recovery_port" "$fragment" \
    || die 'Hysteria2 port verification failed.'
  install_hysteria2_declaration "$root_dir"
  register_hysteria2_component

  emit_deployment_result hysteria2 udp "$HYSTERIA_PORT"
  log 'Hysteria2 deployment complete.'
}
