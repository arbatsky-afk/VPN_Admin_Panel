#!/usr/bin/env bash

readonly MIERU_VERSION='3.35.0'
readonly MIERU_ASSET="mita/mita_${MIERU_VERSION}_amd64.deb"
readonly MIERU_CONFIG='/etc/mita/server.conf.pb'
readonly MIERU_RECOVERY='/opt/vpn/recovery/mieru-secrets.json'

install_mieru_package() {
  local package_path=$1 package_version
  package_version=$(dpkg-query -W -f='${Version}' mita 2>/dev/null || true)
  if [[ -n "$package_version" && "$package_version" != "$MIERU_VERSION" ]]; then
    die "A different Mita package version is installed: $package_version."
  fi
  if [[ -z "$package_version" ]]; then
    run_package_manager_command dpkg -i -- "$package_path"
  fi
  [[ $(dpkg-query -W -f='${Version}' mita 2>/dev/null) == "$MIERU_VERSION" ]] \
    || die 'Installed Mita package version does not match the bundle.'
}

install_mieru() {
  local root_dir=$1 config_file=$2 existing_ssh_port asset_checksum
  local recovery_candidate config_candidate fragment runtime_status
  local server_settings described_config config_port recovery_port

  require_root
  load_trusted_config "$config_file"
  [[ ${TARGET_OS:-} == 'ubuntu-24.04' ]] || die 'TARGET_OS must be ubuntu-24.04.'
  [[ ${TARGET_ARCH:-} == 'amd64' ]] || die 'TARGET_ARCH must be amd64.'
  valid_port_range "${MIERU_PORT_RANGE_START:-}" "${MIERU_PORT_RANGE_END:-}" \
    || die 'MIERU_PORT_RANGE_START/END must define a valid port range.'
  [[ ${MIERU_PROTOCOL:-} == 'TCP' || ${MIERU_PROTOCOL:-} == 'UDP' ]] || die 'MIERU_PROTOCOL must be TCP or UDP.'
  [[ ${MIERU_MTU:-} =~ ^[0-9]+$ ]] && (( 10#$MIERU_MTU >= 1280 && 10#$MIERU_MTU <= 9000 )) \
    || die 'MIERU_MTU must be between 1280 and 9000.'
  valid_mieru_user_name "${MIERU_INITIAL_USER:-}" || die 'MIERU_INITIAL_USER contains unsupported characters.'
  require_ubuntu_24_amd64
  require_base_security_ready
  existing_ssh_port=$(base_security_ssh_port)
  if [[ -f "$MIERU_RECOVERY" ]]; then
    server_settings=$(python3 "$root_dir/lib/mieru_config.py" show-server "$MIERU_RECOVERY") \
      || die 'Could not read existing Mieru server settings.'
    MIERU_PORT=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["port"])' "$server_settings")
    MIERU_PROTOCOL=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["protocol"])' "$server_settings")
    MIERU_MTU=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["mtu"])' "$server_settings")
  else
    MIERU_PORT=$(allocate_component_port \
      "$root_dir" "${MIERU_PROTOCOL,,}" "$MIERU_PORT_RANGE_START" "$MIERU_PORT_RANGE_END" "$existing_ssh_port") \
      || die 'Could not allocate a Mieru port.'
  fi
  valid_port "${MIERU_PORT:-}" || die 'Mieru recovery contains an invalid port.'
  (( 10#$MIERU_PORT >= 1025 )) || die 'MIERU_PORT must be between 1025 and 65535.'
  [[ ${MIERU_PROTOCOL:-} == 'TCP' || ${MIERU_PROTOCOL:-} == 'UDP' ]] || die 'Mieru recovery contains an invalid protocol.'
  [[ ${MIERU_MTU:-} =~ ^[0-9]+$ ]] && (( 10#$MIERU_MTU >= 1280 && 10#$MIERU_MTU <= 9000 )) \
    || die 'Mieru recovery contains an invalid MTU.'
  [[ "$MIERU_PORT" != "$existing_ssh_port" ]] || die 'MIERU_PORT must differ from the Base + Security SSH port.'

  [[ ! -e "$MIERU_CONFIG" || -f "$MIERU_RECOVERY" ]] \
    || die 'Existing Mita configuration detected without panel recovery metadata.'
  [[ ! -e /lib/systemd/system/mita.service || -f "$MIERU_RECOVERY" ]] \
    || die 'Existing Mita service detected without panel recovery metadata.'

  need python3
  need dpkg
  need sha256sum
  umask 077
  install -d -m 0700 /opt/vpn/recovery
  recovery_candidate=$(mktemp /opt/vpn/recovery/.mieru-secrets.XXXXXX)
  config_candidate=$(mktemp /opt/vpn/recovery/.mita-config.XXXXXX)
  rm -f -- "$recovery_candidate" "$config_candidate"
  trap "rm -f -- $(printf '%q' "$recovery_candidate") $(printf '%q' "$config_candidate")" EXIT
  python3 "$root_dir/lib/mieru_config.py" prepare \
    --recovery "$MIERU_RECOVERY" \
    --recovery-candidate "$recovery_candidate" \
    --config-candidate "$config_candidate" \
    --port "$MIERU_PORT" \
    --protocol "$MIERU_PROTOCOL" \
    --mtu "$MIERU_MTU" \
    --user "$MIERU_INITIAL_USER" \
    || die 'Could not prepare Mieru recovery and Mita configuration candidates.'

  asset_checksum=$(awk -v filename="$MIERU_ASSET" '$2 == filename {print; count++} END {exit count != 1}' "$root_dir/assets/SHA256SUMS") \
    || die 'Mita package checksum is missing or ambiguous.'
  (
    cd "$root_dir/assets"
    printf '%s\n' "$asset_checksum" | sha256sum -c --strict -
  ) || die 'Mita package checksum verification failed.'

  install_mieru_package "$root_dir/assets/$MIERU_ASSET"
  systemctl enable --now mita.service
  systemctl is-active --quiet mita.service || die 'Mita daemon did not start after package installation.'

  install -d -o mita -g mita -m 0750 /etc/mita /var/lib/mita /var/run/mita
  find /etc/mita /var/lib/mita -xdev -type d -exec chmod 0750 {} +
  find /etc/mita /var/lib/mita -xdev -type f -exec chmod 0600 {} +
  chown -R mita:mita /etc/mita /var/lib/mita /var/run/mita

  mita apply config "$config_candidate"
  [[ -f "$MIERU_CONFIG" ]] || die 'Mita did not create its protobuf configuration.'
  chown mita:mita "$MIERU_CONFIG"
  chmod 0600 "$MIERU_CONFIG"
  mita describe config >/dev/null
  python3 "$root_dir/lib/mieru_config.py" commit \
    --candidate "$recovery_candidate" --destination "$MIERU_RECOVERY" \
    || die 'Could not commit Mieru recovery metadata.'
  chown root:root "$MIERU_RECOVERY"
  chmod 0600 "$MIERU_RECOVERY"

  fragment=$(component_firewall_fragment mieru)
  sed -e "s|__MIERU_PORT__|$MIERU_PORT|g" -e "s|__MIERU_PROTOCOL__|${MIERU_PROTOCOL,,}|g" \
    "$root_dir/templates/40-mieru.nft.tmpl" > "$fragment"
  chmod 0644 "$fragment"
  apply_firewall

  runtime_status=$(mita status 2>&1 || true)
  if [[ "$runtime_status" != *'"RUNNING"'* ]]; then
    mita start
  fi
  mita status 2>&1 | grep -Fq '"RUNNING"' || die 'Mita proxy runtime is not RUNNING.'
  systemctl is-active --quiet mita.service || die 'Mita daemon is not active after deployment.'
  described_config=$(mita describe config) || die 'Could not describe the active Mita configuration.'
  config_port=$(python3 -c 'import json,sys; data=json.loads(sys.argv[1]); bindings=data.get("portBindings"); assert isinstance(bindings,list) and len(bindings)==1; binding=bindings[0]; assert isinstance(binding,dict) and binding.get("protocol")==sys.argv[2]; port=binding.get("port"); assert type(port) is int and 1025 <= port <= 65535; print(port)' "$described_config" "$MIERU_PROTOCOL") \
    || die 'The active Mita configuration has an invalid port binding.'
  server_settings=$(python3 "$root_dir/lib/mieru_config.py" show-server "$MIERU_RECOVERY") \
    || die 'Could not verify committed Mieru recovery metadata.'
  recovery_port=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["port"])' "$server_settings")
  verify_component_port "$root_dir" "${MIERU_PROTOCOL,,}" "$MIERU_PORT" "$config_port" "$recovery_port" "$fragment" \
    || die 'Mieru port verification failed.'
  install_mieru_declaration "$root_dir"
  register_mieru_component

  rm -f -- "$recovery_candidate" "$config_candidate"
  trap - EXIT
  emit_deployment_result mieru "${MIERU_PROTOCOL,,}" "$MIERU_PORT"
  log 'Mieru deployment complete.'
}
