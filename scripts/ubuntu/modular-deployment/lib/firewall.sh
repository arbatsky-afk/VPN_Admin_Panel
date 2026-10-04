#!/usr/bin/env bash
# The modular deployment owns only the vpn_filter table. Docker and Fail2Ban
# keep their runtime rules outside this table.

readonly NFTABLES_MAIN_CONFIG='/etc/nftables.conf'
readonly NFTABLES_FRAGMENT_DIRECTORY='/etc/nftables.d'
readonly VPN_FILTER_TABLE='vpn_filter'

require_modular_firewall_layout() {
  [[ -f "$NFTABLES_MAIN_CONFIG" ]] || die "Firewall configuration is missing: $NFTABLES_MAIN_CONFIG"
  [[ -d "$NFTABLES_FRAGMENT_DIRECTORY" ]] || die "Firewall fragment directory is missing: $NFTABLES_FRAGMENT_DIRECTORY"
}

apply_firewall() {
  need nft
  require_modular_firewall_layout
  nft -c -f "$NFTABLES_MAIN_CONFIG"
  systemctl enable nftables.service
  if systemctl is-active --quiet nftables.service; then
    systemctl reload nftables.service
  else
    systemctl start nftables.service
  fi
  systemctl is-active --quiet nftables.service
}

component_firewall_fragment() {
  case "$1" in
    xray) printf '%s\n' "$NFTABLES_FRAGMENT_DIRECTORY/20-xray.nft" ;;
    hysteria2) printf '%s\n' "$NFTABLES_FRAGMENT_DIRECTORY/30-hysteria2.nft" ;;
    mieru) printf '%s\n' "$NFTABLES_FRAGMENT_DIRECTORY/40-mieru.nft" ;;
    *) die "Unknown firewall component: $1" ;;
  esac
}
