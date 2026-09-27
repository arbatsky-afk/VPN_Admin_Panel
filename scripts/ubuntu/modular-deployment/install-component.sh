#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
COMPONENT=${1:-}
CONFIG_FILE=${2:-"$ROOT_DIR/config.env"}

[[ -n "$COMPONENT" ]] || { echo 'Usage: install-component.sh <component> [config-file]' >&2; exit 2; }

# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/state.sh
source "$ROOT_DIR/lib/state.sh"
# shellcheck source=lib/firewall.sh
source "$ROOT_DIR/lib/firewall.sh"

case "$COMPONENT" in
  base-security)
    # shellcheck source=components/base-security.sh
    source "$ROOT_DIR/components/base-security.sh"
    install_base_security "$ROOT_DIR" "$CONFIG_FILE"
    ;;
  xray)
    # shellcheck source=components/xray.sh
    source "$ROOT_DIR/components/xray.sh"
    install_xray "$ROOT_DIR" "$CONFIG_FILE"
    ;;
  hysteria2)
    # shellcheck source=components/hysteria2.sh
    source "$ROOT_DIR/components/hysteria2.sh"
    install_hysteria2 "$ROOT_DIR" "$CONFIG_FILE"
    ;;
  mieru)
    # shellcheck source=components/mieru.sh
    source "$ROOT_DIR/components/mieru.sh"
    install_mieru "$ROOT_DIR" "$CONFIG_FILE"
    ;;
  docker)
    # shellcheck source=components/docker.sh
    source "$ROOT_DIR/components/docker.sh"
    install_docker "$ROOT_DIR" "$CONFIG_FILE"
    ;;
  nginx)
    # shellcheck source=components/nginx.sh
    source "$ROOT_DIR/components/nginx.sh"
    install_nginx "$ROOT_DIR" "$CONFIG_FILE"
    ;;
  netdata)
    # shellcheck source=components/netdata.sh
    source "$ROOT_DIR/components/netdata.sh"
    install_netdata "$ROOT_DIR" "$CONFIG_FILE"
    ;;
  *)
    die "Unsupported modular deployment component: $COMPONENT"
    ;;
esac
