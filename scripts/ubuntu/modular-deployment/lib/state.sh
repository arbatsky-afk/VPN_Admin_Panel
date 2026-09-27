#!/usr/bin/env bash
# Non-secret state markers for modular deployment dependencies.

readonly VPN_ADMIN_STATE_DIRECTORY='/etc/vpn-admin/state'
readonly BASE_SECURITY_STATE_FILE="$VPN_ADMIN_STATE_DIRECTORY/base-security.json"
readonly COMPONENT_STATE_DIRECTORY='/opt/vpn/state'
readonly COMPONENT_STATE_REGISTRY_FILE="$COMPONENT_STATE_DIRECTORY/components.json"
readonly COMPONENT_DECLARATION_DIRECTORY='/opt/vpn/components'
readonly STATE_LIBRARY_DIRECTORY=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly COMPONENT_REGISTRY_HELPER="$STATE_LIBRARY_DIRECTORY/component_registry.py"

component_registry() {
  need python3
  [[ -f "$COMPONENT_REGISTRY_HELPER" ]] || die 'Component registry helper is missing from the deployment bundle.'
  python3 "$COMPONENT_REGISTRY_HELPER" "$@"
}

base_security_registry_exists() {
  [[ -e "$COMPONENT_STATE_REGISTRY_FILE" ]] || return 1
  component_registry base-security-present --registry "$COMPONENT_STATE_REGISTRY_FILE"
}

component_registered() {
  local component=$1
  [[ -e "$COMPONENT_STATE_REGISTRY_FILE" ]] || return 1
  component_registry component-present \
    --registry "$COMPONENT_STATE_REGISTRY_FILE" \
    --component "$component"
}

base_security_marker_exists() {
  if [[ -e "$COMPONENT_STATE_REGISTRY_FILE" ]]; then
    if base_security_registry_exists; then
      return 0
    else
      local registry_status=$?
      [[ $registry_status -eq 1 ]] || die 'Component state registry is invalid.'
    fi
  fi
  [[ -s "$BASE_SECURITY_STATE_FILE" ]]
}

require_base_security_marker() {
  base_security_marker_exists || die 'Base + Security is not installed on this server.'
}

base_security_ssh_port() {
  require_base_security_marker
  local ssh_port
  if [[ -e "$COMPONENT_STATE_REGISTRY_FILE" ]]; then
    if ssh_port=$(component_registry base-security-ssh-port --registry "$COMPONENT_STATE_REGISTRY_FILE"); then
      valid_port "$ssh_port" || die 'Base + Security registry has an invalid SSH port.'
      printf '%s\n' "$ssh_port"
      return
    else
      local registry_status=$?
      [[ $registry_status -eq 1 ]] || die 'Component state registry is invalid.'
    fi
  fi
  ssh_port=$(sed -nE 's/^[[:space:]]*"ssh_port"[[:space:]]*:[[:space:]]*([0-9]+),?$/\1/p' "$BASE_SECURITY_STATE_FILE" | head -n 1)
  valid_port "$ssh_port" || die 'Base + Security state has an invalid SSH port.'
  printf '%s\n' "$ssh_port"
}


base_security_legacy_applied_at() {
  [[ -s "$BASE_SECURITY_STATE_FILE" ]] || return 1
  sed -nE 's/^[[:space:]]*"applied_at"[[:space:]]*:[[:space:]]*"([^"]+)",?$/\1/p' "$BASE_SECURITY_STATE_FILE" | head -n 1
}

require_base_security_ready() {
  require_base_security_marker
  need nft
  require_modular_firewall_layout
  nft -c -f "$NFTABLES_MAIN_CONFIG"
  systemctl is-active --quiet nftables.service || die 'Base + Security nftables service is not active.'
  systemctl is-active --quiet fail2ban.service || die 'Base + Security Fail2Ban service is not active.'
}

write_base_security_state() {
  local ssh_port=$1
  valid_port "$ssh_port" || die "Invalid SSH port for Base + Security state: $ssh_port"

  install -d -m 0700 "$VPN_ADMIN_STATE_DIRECTORY"
  local candidate
  candidate=$(mktemp "$VPN_ADMIN_STATE_DIRECTORY/.base-security.XXXXXX")
  printf '{\n  "schema_version": %s,\n  "ssh_port": %s,\n  "applied_at": "%s"\n}\n' \
    "$MODULAR_DEPLOYMENT_SCHEMA_VERSION" "$ssh_port" "$(date --iso-8601=seconds)" > "$candidate"
  chmod 0600 "$candidate"
  mv -f "$candidate" "$BASE_SECURITY_STATE_FILE"
}


install_component_declaration() {
  local root_dir=$1 component=$2
  local asset_directory="$root_dir/assets/declarations"
  local source="$asset_directory/$component.json"
  local destination_directory="$COMPONENT_DECLARATION_DIRECTORY/$component"
  local destination="$destination_directory/declaration.json"
  local checksum_entry
  [[ -f "$source" ]] || die "Component declaration asset is missing: $component."
  [[ -f "$asset_directory/SHA256SUMS" ]] || die 'Component declaration checksum manifest is missing.'
  checksum_entry=$(awk -v filename="$component.json" '$2 == filename {print; found=1} END {exit !found}' "$asset_directory/SHA256SUMS") \
    || die "Component declaration checksum is missing: $component."
  (
    cd "$asset_directory"
    printf '%s\n' "$checksum_entry" | sha256sum -c --strict -
  ) || die 'Component declaration asset checksum verification failed.'

  install -d -m 0755 "$destination_directory"
  local candidate
  candidate=$(mktemp "$destination_directory/.declaration.XXXXXX")
  install -m 0644 "$source" "$candidate"
  if ! component_registry validate-declaration "$candidate" "$component"; then
    rm -f "$candidate"
    die "Component declaration asset is invalid: $component."
  fi
  mv -f "$candidate" "$destination"
}


install_base_security_declaration() {
  install_component_declaration "$1" base-security
}


install_xray_declaration() {
  install_component_declaration "$1" xray
}


install_hysteria2_declaration() {
  install_component_declaration "$1" hysteria2
}


install_mieru_declaration() {
  install_component_declaration "$1" mieru
}


install_docker_declaration() {
  install_component_declaration "$1" docker
}


install_nginx_declaration() {
  install_component_declaration "$1" nginx
}


register_base_security_component() {
  local ssh_port=$1
  local legacy_applied_at=${2:-}
  local declaration_directory="$COMPONENT_DECLARATION_DIRECTORY/base-security"
  local declaration="$declaration_directory/declaration.json"
  component_registry register-base-security \
    --registry "$COMPONENT_STATE_REGISTRY_FILE" \
    --declaration "$declaration" \
    --component-directory "$declaration_directory" \
    --ssh-port "$ssh_port" \
    --legacy-installed-at "$legacy_applied_at" \
    || die 'Could not update the Base + Security component state registry.'
}


register_xray_component() {
  local declaration_directory="$COMPONENT_DECLARATION_DIRECTORY/xray"
  local declaration="$declaration_directory/declaration.json"
  component_registry register-component \
    --registry "$COMPONENT_STATE_REGISTRY_FILE" \
    --declaration "$declaration" \
    --component-directory "$declaration_directory" \
    --component xray \
    || die 'Could not update the Xray component state registry.'
}


register_hysteria2_component() {
  local declaration_directory="$COMPONENT_DECLARATION_DIRECTORY/hysteria2"
  local declaration="$declaration_directory/declaration.json"
  component_registry register-component \
    --registry "$COMPONENT_STATE_REGISTRY_FILE" \
    --declaration "$declaration" \
    --component-directory "$declaration_directory" \
    --component hysteria2 \
    || die 'Could not update the Hysteria2 component state registry.'
}


register_mieru_component() {
  local declaration_directory="$COMPONENT_DECLARATION_DIRECTORY/mieru"
  local declaration="$declaration_directory/declaration.json"
  component_registry register-component \
    --registry "$COMPONENT_STATE_REGISTRY_FILE" \
    --declaration "$declaration" \
    --component-directory "$declaration_directory" \
    --component mieru \
    || die 'Could not update the Mieru component state registry.'
}


register_docker_component() {
  local declaration_directory="$COMPONENT_DECLARATION_DIRECTORY/docker"
  local declaration="$declaration_directory/declaration.json"
  component_registry register-component \
    --registry "$COMPONENT_STATE_REGISTRY_FILE" \
    --declaration "$declaration" \
    --component-directory "$declaration_directory" \
    --component docker \
    || die 'Could not update the Docker component state registry.'
}


register_nginx_component() {
  local declaration_directory="$COMPONENT_DECLARATION_DIRECTORY/nginx"
  local declaration="$declaration_directory/declaration.json"
  component_registry register-component \
    --registry "$COMPONENT_STATE_REGISTRY_FILE" \
    --declaration "$declaration" \
    --component-directory "$declaration_directory" \
    --component nginx \
    || die 'Could not update the Nginx component state registry.'
}


register_netdata_component() {
  local declaration_directory="$COMPONENT_DECLARATION_DIRECTORY/netdata"
  local declaration="$declaration_directory/declaration.json"
  component_registry register-component \
    --registry "$COMPONENT_STATE_REGISTRY_FILE" \
    --declaration "$declaration" \
    --component-directory "$declaration_directory" \
    --component netdata \
    || die 'Could not update the Netdata component state registry.'
}
