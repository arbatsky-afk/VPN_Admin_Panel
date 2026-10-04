#!/usr/bin/env bash

readonly DOCKER_KEYRING_DIRECTORY='/etc/apt/keyrings'
readonly DOCKER_KEYRING="$DOCKER_KEYRING_DIRECTORY/docker.asc"
readonly DOCKER_SOURCES='/etc/apt/sources.list.d/docker.sources'

require_no_conflicting_docker_packages() {
  local package
  local -a conflicting_packages=(
    docker.io
    docker-doc
    docker-compose
    docker-compose-v2
    podman-docker
    containerd
    runc
  )

  for package in "${conflicting_packages[@]}"; do
    if dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null | grep -qx 'installed'; then
      die "Conflicting package is installed: $package. Remove it manually before installing Docker Engine from the official repository."
    fi
  done
}

install_docker_repository() {
  local docker_codename
  install -d -m 0755 "$DOCKER_KEYRING_DIRECTORY"
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$DOCKER_KEYRING"
  chmod a+r "$DOCKER_KEYRING"

  # shellcheck source=/dev/null
  . /etc/os-release
  docker_codename=${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}
  [[ -n "$docker_codename" ]] || die 'Could not determine the Ubuntu codename for the Docker repository.'
  cat > "$DOCKER_SOURCES" <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $docker_codename
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: $DOCKER_KEYRING
EOF
}

install_docker_packages() {
  run_package_manager_command apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin
}

install_docker() {
  local root_dir=$1 config_file=$2
  # The component receives the shared config to enforce the same trusted input
  # boundary as every modular operation; Docker has no component-specific input.
  : "$root_dir"

  require_root
  load_trusted_config "$config_file"
  [[ ${TARGET_OS:-} == 'ubuntu-24.04' ]] || die 'TARGET_OS must be ubuntu-24.04.'
  [[ ${TARGET_ARCH:-} == 'amd64' ]] || die 'TARGET_ARCH must be amd64.'
  require_ubuntu_24_amd64
  require_base_security_ready
  require_no_conflicting_docker_packages

  export DEBIAN_FRONTEND=noninteractive
  install_docker_repository
  run_package_manager_command apt-get update
  install_docker_packages

  systemctl enable --now docker.service
  systemctl is-active --quiet docker.service
  docker compose version >/dev/null
  nft -c -f "$NFTABLES_MAIN_CONFIG"
  install_docker_declaration "$root_dir"
  register_docker_component

  log 'Docker deployment complete.'
}
