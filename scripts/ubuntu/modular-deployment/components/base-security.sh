#!/usr/bin/env bash

install_base_security_packages() {
  run_package_manager_command apt-get update
  run_package_manager_command apt-get install -y ca-certificates curl fail2ban gnupg mc nftables openssl unzip
}

install_base_security() {
  local root_dir=$1 config_file=$2
  local legacy_applied_at=''

  require_root
  load_trusted_config "$config_file"
  [[ ${TARGET_OS:-} == 'ubuntu-24.04' ]] || die 'TARGET_OS must be ubuntu-24.04.'
  [[ ${TARGET_ARCH:-} == 'amd64' ]] || die 'TARGET_ARCH must be amd64.'
  valid_port "${SSH_PORT:-}" || die 'SSH_PORT must be a valid TCP port.'
  require_ubuntu_24_amd64

  if base_security_marker_exists; then
    local existing_ssh_port
    existing_ssh_port=$(base_security_ssh_port)
    [[ "$existing_ssh_port" == "$SSH_PORT" ]] || die 'Base + Security is already installed with a different SSH port.'
    legacy_applied_at=$(base_security_legacy_applied_at || true)
  fi

  export DEBIAN_FRONTEND=noninteractive
  install_base_security_packages

  install -d -m 0755 "$NFTABLES_FRAGMENT_DIRECTORY"
  install -m 0644 "$root_dir/templates/nftables.conf.tmpl" "$NFTABLES_MAIN_CONFIG"
  sed "s|__SSH_PORT__|$SSH_PORT|g" "$root_dir/templates/10-base.nft.tmpl" > "$NFTABLES_FRAGMENT_DIRECTORY/10-base.nft"
  chmod 0644 "$NFTABLES_FRAGMENT_DIRECTORY/10-base.nft"
  install -m 0644 "$root_dir/templates/fail2ban-jail.local.tmpl" /etc/fail2ban/jail.local

  apply_firewall
  systemctl enable --now fail2ban.service
  systemctl is-active --quiet nftables.service
  systemctl is-active --quiet fail2ban.service
  write_base_security_state "$SSH_PORT"
  install_base_security_declaration "$root_dir"
  register_base_security_component "$SSH_PORT" "$legacy_applied_at"

  log 'Base + Security deployment complete.'
}
