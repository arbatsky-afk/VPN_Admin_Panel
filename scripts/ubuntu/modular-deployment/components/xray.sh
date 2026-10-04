#!/usr/bin/env bash

readonly XRAY_VERSION='26.6.27'
readonly XRAY_ARCHIVE="xray/Xray-linux-64-v$XRAY_VERSION.zip"
readonly XRAY_CONFIG='/usr/local/etc/xray/config.json'
readonly XRAY_SECRETS='/opt/vpn/recovery/xray-secrets.env'

render_xray_config() {
  local template=$1 destination=$2
  local private_key short_id uuid host
  private_key=$(printf '%s' "$XRAY_PRIVATE_KEY" | sed -e 's/[\\&|]/\\&/g')
  short_id=$(printf '%s' "$XRAY_SHORT_ID" | sed -e 's/[\\&|]/\\&/g')
  uuid=$(printf '%s' "$XRAY_UUID" | sed -e 's/[\\&|]/\\&/g')
  host=$(printf '%s' "$MASQUERADE_HOST" | sed -e 's/[\\&|]/\\&/g')
  sed \
    -e "s|__XRAY_PORT__|$XRAY_PORT|g" \
    -e "s|__MASQUERADE_HOST__|$host|g" \
    -e "s|__XRAY_UUID__|$uuid|g" \
    -e "s|__XRAY_PRIVATE_KEY__|$private_key|g" \
    -e "s|__XRAY_SHORT_ID__|$short_id|g" \
    "$template" > "$destination"
}

create_xray_secrets() {
  local key_output candidate
  key_output=$(xray x25519)
  XRAY_PRIVATE_KEY=$(awk -F': *' 'tolower($1) ~ /private.*key/ {print $2; exit}' <<<"$key_output")
  XRAY_PUBLIC_KEY=$(awk -F': *' 'tolower($1) ~ /public.*key/ {print $2; exit}' <<<"$key_output")
  XRAY_UUID=$(xray uuid)
  XRAY_SHORT_ID=$(openssl rand -hex 8)
  [[ -n "$XRAY_PRIVATE_KEY" && -n "$XRAY_PUBLIC_KEY" && -n "$XRAY_UUID" && -n "$XRAY_SHORT_ID" ]] \
    || die 'Could not generate Xray secrets.'

  candidate=$(mktemp /opt/vpn/recovery/.xray-secrets.XXXXXX)
  cat > "$candidate" <<EOF
XRAY_PRIVATE_KEY='$XRAY_PRIVATE_KEY'
XRAY_PUBLIC_KEY='$XRAY_PUBLIC_KEY'
XRAY_UUID='$XRAY_UUID'
XRAY_SHORT_ID='$XRAY_SHORT_ID'
DEPLOYED_XRAY_PORT='$XRAY_PORT'
DEPLOYED_MASQUERADE_HOST='$MASQUERADE_HOST'
EOF
  chmod 0600 "$candidate"
  mv -f "$candidate" "$XRAY_SECRETS"
}

load_or_create_xray_secrets() {
  if [[ -f "$XRAY_SECRETS" ]]; then
    # shellcheck source=/dev/null
    source "$XRAY_SECRETS"
    [[ -n ${XRAY_PRIVATE_KEY:-} && -n ${XRAY_PUBLIC_KEY:-} && -n ${XRAY_UUID:-} && -n ${XRAY_SHORT_ID:-} ]] \
      || die 'Existing Xray secrets are incomplete.'
    return
  fi
  create_xray_secrets
}

install_xray() {
  local root_dir=$1 config_file=$2 existing_ssh_port candidate fragment asset_checksum
  local config_port recovery_port

  require_root
  load_trusted_config "$config_file"
  [[ ${TARGET_OS:-} == 'ubuntu-24.04' ]] || die 'TARGET_OS must be ubuntu-24.04.'
  [[ ${TARGET_ARCH:-} == 'amd64' ]] || die 'TARGET_ARCH must be amd64.'
  valid_port_range "${XRAY_PORT_RANGE_START:-}" "${XRAY_PORT_RANGE_END:-}" \
    || die 'XRAY_PORT_RANGE_START/END must define a valid TCP port range.'
  valid_hostname "${MASQUERADE_HOST:-}" || die 'MASQUERADE_HOST must be a valid hostname.'
  require_ubuntu_24_amd64
  require_base_security_ready
  existing_ssh_port=$(base_security_ssh_port)
  if [[ -f "$XRAY_SECRETS" ]]; then
    # Existing deployments inherit their parameters from recovery; defaults apply only to the first installation.
    # shellcheck source=/dev/null
    source "$XRAY_SECRETS"
    XRAY_PORT=${DEPLOYED_XRAY_PORT:-}
    MASQUERADE_HOST=${DEPLOYED_MASQUERADE_HOST:-}
  else
    XRAY_PORT=$(allocate_component_port \
      "$root_dir" tcp "$XRAY_PORT_RANGE_START" "$XRAY_PORT_RANGE_END" "$existing_ssh_port") \
      || die 'Could not allocate an Xray port.'
  fi
  valid_port "${XRAY_PORT:-}" || die 'Xray recovery contains an invalid TCP port.'
  valid_hostname "${MASQUERADE_HOST:-}" || die 'Xray recovery contains an invalid masquerade host.'
  [[ "$XRAY_PORT" != "$existing_ssh_port" ]] || die 'XRAY_PORT must differ from the Base + Security SSH port.'

  [[ ! -e "$XRAY_CONFIG" || -f "$XRAY_SECRETS" ]] \
    || die 'Existing Xray configuration detected without modular Xray secrets.'
  [[ ! -e /etc/systemd/system/xray.service || -f "$XRAY_SECRETS" ]] \
    || die 'Existing Xray service detected without modular Xray secrets.'

  umask 077
  install -d -m 0755 /usr/local/etc/xray /usr/local/share/xray /opt/vpn/recovery
  asset_checksum=$(awk -v filename="$XRAY_ARCHIVE" '$2 == filename {print; count++} END {exit count != 1}' "$root_dir/assets/SHA256SUMS") \
    || die 'Xray archive checksum is missing or ambiguous.'
  (
    cd "$root_dir/assets"
    printf '%s\n' "$asset_checksum" | sha256sum -c --strict -
  ) || die 'Xray archive checksum verification failed.'
  candidate=$(mktemp /usr/local/bin/.xray.XXXXXX)
  unzip -p "$root_dir/assets/$XRAY_ARCHIVE" xray > "$candidate"
  chmod 0755 "$candidate"
  mv -f "$candidate" /usr/local/bin/xray
  unzip -p "$root_dir/assets/$XRAY_ARCHIVE" geoip.dat > /usr/local/share/xray/geoip.dat
  unzip -p "$root_dir/assets/$XRAY_ARCHIVE" geosite.dat > /usr/local/share/xray/geosite.dat

  load_or_create_xray_secrets
  if [[ ! -f "$XRAY_CONFIG" ]]; then
    candidate=$(mktemp --suffix=.json /usr/local/etc/xray/.config.XXXXXX)
    render_xray_config "$root_dir/templates/xray-config.json.tmpl" "$candidate"
    xray run -test -config "$candidate"
    install -m 0600 "$candidate" "$XRAY_CONFIG"
    rm -f "$candidate"
  fi
  chown root:root "$XRAY_CONFIG"
  chmod 0600 "$XRAY_CONFIG"
  xray run -test -config "$XRAY_CONFIG"

  install -m 0644 "$root_dir/templates/xray.service.tmpl" /etc/systemd/system/xray.service
  fragment=$(component_firewall_fragment xray)
  sed "s|__XRAY_PORT__|$XRAY_PORT|g" "$root_dir/templates/20-xray.nft.tmpl" > "$fragment"
  chmod 0644 "$fragment"
  apply_firewall
  systemctl daemon-reload
  systemctl enable --now xray.service
  systemctl is-active --quiet xray.service
  config_port=$(python3 -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8"))["inbounds"][0]["port"]; assert type(value) is int and 1 <= value <= 65535; print(value)' "$XRAY_CONFIG") \
    || die 'Could not read the Xray config port.'
  # shellcheck source=/dev/null
  source "$XRAY_SECRETS"
  recovery_port=${DEPLOYED_XRAY_PORT:-}
  verify_component_port "$root_dir" tcp "$XRAY_PORT" "$config_port" "$recovery_port" "$fragment" \
    || die 'Xray port verification failed.'
  install_xray_declaration "$root_dir"
  register_xray_component

  emit_deployment_result xray tcp "$XRAY_PORT"
  log 'Xray deployment complete.'
}
