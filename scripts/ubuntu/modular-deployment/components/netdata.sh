#!/usr/bin/env bash

readonly NETDATA_PORT=19999
readonly NETDATA_CONFIG='/etc/netdata/netdata.conf'
readonly NETDATA_NGINX_LOCATION='/etc/nginx/vpn-admin-locations/netdata.conf'
readonly NETDATA_LEGACY_AUTH_FILE='/etc/nginx/vpn-admin-auth/netdata.htpasswd'
readonly NETDATA_CLAIM_CONFIG='/etc/netdata/claim.conf'
readonly NETDATA_DECLARATION='/opt/vpn/components/netdata/declaration.json'
readonly NETDATA_NGINX_DECLARATION='/opt/vpn/components/nginx/declaration.json'
readonly NETDATA_NGINX_CONFIG='/etc/nginx/conf.d/vpn-admin-site.conf'
readonly NETDATA_NGINX_CONTRACT='/usr/local/lib/vpn-admin/nginx_contract.py'
readonly NETDATA_KICKSTART_URL='https://get.netdata.cloud/kickstart.sh'
readonly NETDATA_CLOUD_URL='https://app.netdata.cloud'

NETDATA_ROLLBACK_ARMED=0
NETDATA_ROLLBACK_DIRECTORY=''
NETDATA_ROLLBACK_REGISTERED=0
NETDATA_ROLLBACK_SERVICE_ACTIVE=0
NETDATA_ROLLBACK_SERVICE_ENABLED=0
NETDATA_ROLLBACK_CONFIG_PRESENT=0
NETDATA_ROLLBACK_LOCATION_PRESENT=0
NETDATA_ROLLBACK_DECLARATION_PRESENT=0


valid_netdata_claim_token() {
  [[ ${#1} -ge 20 && ${#1} -le 1024 && "$1" =~ ^[A-Za-z0-9_-]+$ ]]
}


valid_netdata_claim_rooms() {
  local uuid='[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'
  [[ -z "$1" || "$1" =~ ^${uuid}(,${uuid})*$ ]]
}


_netdata_path_has_no_symlink_components() {
  local path=$1 current='/' component
  local -a components
  [[ "$path" == /* ]] || return 1
  local IFS=/
  read -r -a components <<< "$path"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    [[ "$component" != . && "$component" != .. ]] || return 1
    if [[ "$current" == / ]]; then current="/$component"; else current="$current/$component"; fi
    [[ ! -L "$current" ]] || return 1
  done
}


_netdata_install_file_atomically() {
  local source=$1 destination=$2 mode=$3 candidate directory
  directory=$(dirname -- "$destination")
  [[ -f "$source" && ! -L "$source" ]] || return 1
  install -d -m 0755 -- "$directory" || return 1
  _netdata_path_has_no_symlink_components "$directory" || return 1
  candidate=$(mktemp "$directory/.vpn-admin-netdata.XXXXXX") || return 1
  if ! install -m "$mode" -- "$source" "$candidate" || ! mv -f -- "$candidate" "$destination"; then
    rm -f -- "$candidate"
    return 1
  fi
}


_netdata_package_installed() {
  dpkg-query -W -f='${Status}\n' netdata 2>/dev/null | grep -Fqx 'install ok installed'
}


_netdata_stock_config() {
  local path=$1 owner_entry package_owner conffiles registered_md5 current_md5
  [[ -f "$path" && ! -L "$path" ]] || return 1
  owner_entry=$(dpkg-query -S "$path" 2>/dev/null) || return 1
  package_owner=${owner_entry%%:*}
  [[ -n "$package_owner" && ${owner_entry#*: } == "$path" ]] || return 1
  conffiles=$(dpkg-query -W -f='${Conffiles}\n' "$package_owner" 2>/dev/null) || return 1
  registered_md5=$(awk -v path="$path" '
    $1 == path { value=$2; count++ }
    END { if (count != 1 || value !~ /^[0-9a-fA-F]{32}$/) exit 1; print tolower(value) }
  ' <<<"$conffiles") || return 1
  current_md5=$(md5sum -- "$path") || return 1
  current_md5=${current_md5%% *}
  [[ "$current_md5" == "$registered_md5" ]]
}


_netdata_listener_is_owned_or_absent() {
  local output line local_address port found=0
  output=$(ss -H -lntp 2>/dev/null) || return 1
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -r _ _ _ local_address _ _ <<<"$line"
    port=${local_address##*:}
    [[ "$port" == "$NETDATA_PORT" ]] || continue
    [[ "$line" == *'"netdata"'* ]] || return 1
    found=1
  done <<<"$output"
  NETDATA_EXISTING_LISTENER=$found
}


require_netdata_nginx_ready() {
  local root_dir=$1 registry_status
  if component_registered nginx; then
    :
  else
    registry_status=$?
    if [[ $registry_status -eq 1 ]]; then
      die 'Netdata requires Nginx. Install Nginx from Deploy first.'
    fi
    die 'Component state registry is invalid.'
  fi
  component_registry validate-declaration "$NETDATA_NGINX_DECLARATION" nginx \
    || die 'Netdata requires a valid managed Nginx declaration. Redeploy Nginx first.'
  grep -Eq '^[[:space:]]*"contract_version"[[:space:]]*:[[:space:]]*"5"[[:space:]]*,?[[:space:]]*$' \
    "$NETDATA_NGINX_DECLARATION" \
    || die 'Netdata requires the current Nginx contract. Redeploy Nginx first.'
  [[ -f "$NETDATA_NGINX_CONTRACT" && ! -L "$NETDATA_NGINX_CONTRACT" ]] \
    || die 'Netdata requires the current managed Nginx contract helper. Redeploy Nginx first.'
  python3 "$NETDATA_NGINX_CONTRACT" verify-owned \
    || die 'Netdata requires the current managed Nginx configuration. Redeploy Nginx first.'
  systemctl is-active --quiet nginx.service \
    || die 'Netdata requires active Nginx. Start or redeploy Nginx first.'
  nginx -t >/dev/null 2>&1 \
    || die 'Netdata requires a valid Nginx configuration. Repair Nginx first.'
}


require_no_foreign_netdata_state() {
  local registered=$1 root_dir=$2 package_installed=0
  _netdata_package_installed && package_installed=1
  _netdata_listener_is_owned_or_absent || return 1
  [[ ! -e "$NETDATA_LEGACY_AUTH_FILE" && ! -L "$NETDATA_LEGACY_AUTH_FILE" ]] || return 1
  [[ ! -e "$NETDATA_CLAIM_CONFIG" && ! -L "$NETDATA_CLAIM_CONFIG" ]] || return 1
  if (( registered == 1 )); then
    (( package_installed == 1 )) || return 1
    cmp -s -- "$NETDATA_CONFIG" "$root_dir/templates/netdata.conf.tmpl" || return 1
    cmp -s -- "$NETDATA_NGINX_LOCATION" "$root_dir/templates/netdata-location.conf.tmpl" || return 1
  else
    [[ ! -e "$NETDATA_NGINX_LOCATION" && ! -L "$NETDATA_NGINX_LOCATION" ]] || return 1
    [[ ! -e "$NETDATA_DECLARATION" && ! -L "$NETDATA_DECLARATION" ]] || return 1
    if [[ -e "$NETDATA_CONFIG" || -L "$NETDATA_CONFIG" ]]; then
      (( package_installed == 1 )) && _netdata_stock_config "$NETDATA_CONFIG" || return 1
    fi
    (( NETDATA_EXISTING_LISTENER == 0 || package_installed == 1 )) || return 1
  fi
}


_netdata_capture_file() {
  local source=$1 backup_name=$2 present_variable=$3
  if [[ -e "$source" || -L "$source" ]]; then
    [[ -f "$source" && ! -L "$source" ]] || return 1
    cp -p -- "$source" "$NETDATA_ROLLBACK_DIRECTORY/$backup_name" || return 1
    printf -v "$present_variable" '%s' 1
  fi
}


_netdata_restore_file() {
  local destination=$1 backup_name=$2 was_present=$3
  if (( was_present == 1 )); then
    install -d -m 0755 -- "$(dirname -- "$destination")"
    cp -p -- "$NETDATA_ROLLBACK_DIRECTORY/$backup_name" "$destination"
  else
    rm -f -- "$destination"
  fi
}


_rollback_netdata_install() {
  (( NETDATA_ROLLBACK_ARMED == 1 )) || return 0
  set +e
  _netdata_restore_file "$NETDATA_CONFIG" config "$NETDATA_ROLLBACK_CONFIG_PRESENT"
  _netdata_restore_file "$NETDATA_NGINX_LOCATION" location "$NETDATA_ROLLBACK_LOCATION_PRESENT"
  _netdata_restore_file "$NETDATA_DECLARATION" declaration "$NETDATA_ROLLBACK_DECLARATION_PRESENT"
  rm -f -- "$NETDATA_CLAIM_CONFIG"
  nginx -t >/dev/null 2>&1 && systemctl reload nginx.service >/dev/null 2>&1
  if (( NETDATA_ROLLBACK_REGISTERED == 0 )); then
    systemctl stop netdata.service >/dev/null 2>&1
    systemctl disable netdata.service >/dev/null 2>&1
  else
    if (( NETDATA_ROLLBACK_SERVICE_ENABLED == 1 )); then
      systemctl enable netdata.service >/dev/null 2>&1
    else
      systemctl disable netdata.service >/dev/null 2>&1
    fi
    if (( NETDATA_ROLLBACK_SERVICE_ACTIVE == 1 )); then
      systemctl restart netdata.service >/dev/null 2>&1
    else
      systemctl stop netdata.service >/dev/null 2>&1
    fi
  fi
  rm -rf -- "$NETDATA_ROLLBACK_DIRECTORY"
}


_arm_netdata_rollback() {
  NETDATA_ROLLBACK_DIRECTORY=$(mktemp -d) || die 'Could not create Netdata rollback state.'
  systemctl is-active --quiet netdata.service && NETDATA_ROLLBACK_SERVICE_ACTIVE=1
  systemctl is-enabled --quiet netdata.service && NETDATA_ROLLBACK_SERVICE_ENABLED=1
  _netdata_capture_file "$NETDATA_CONFIG" config NETDATA_ROLLBACK_CONFIG_PRESENT \
    || die 'Could not capture the existing Netdata configuration.'
  _netdata_capture_file "$NETDATA_NGINX_LOCATION" location NETDATA_ROLLBACK_LOCATION_PRESENT \
    || die 'Could not capture the existing Netdata Nginx location.'
  _netdata_capture_file "$NETDATA_DECLARATION" declaration NETDATA_ROLLBACK_DECLARATION_PRESENT \
    || die 'Could not capture the existing Netdata declaration.'
  NETDATA_ROLLBACK_ARMED=1
  trap '_rollback_netdata_install' EXIT
}


_netdata_download_kickstart() {
  local destination=$1
  curl --fail --silent --show-error --location --output "$destination" "$NETDATA_KICKSTART_URL" \
    || return 1
  [[ -s "$destination" && ! -L "$destination" ]] || return 1
  chmod 0700 "$destination"
}


_netdata_claim() {
  local kickstart=$1 token=$2 rooms=$3 private_log
  private_log=$(mktemp "$NETDATA_ROLLBACK_DIRECTORY/claim.XXXXXX") || return 1
  chmod 0600 "$private_log" || { rm -f -- "$private_log"; return 1; }
  # Current kickstart claim-only exits non-zero after running the claim path.
  # Cloud online verification below is the authoritative success criterion.
  NETDATA_CLAIM_TOKEN="$token" NETDATA_CLAIM_ROOMS="$rooms" NETDATA_CLAIM_URL="$NETDATA_CLOUD_URL" \
    sh "$kickstart" --claim-only --non-interactive --disable-telemetry >"$private_log" 2>&1 || :
  rm -f -- "$private_log"
}


_netdata_cloud_online() {
  local state
  state=$(netdatacli aclk-state 2>/dev/null) || return 1
  [[ $(grep -Fxc 'Claimed: Yes' <<<"$state") -eq 1 ]] || return 1
  [[ $(grep -Fxc 'Online: Yes' <<<"$state") -eq 1 ]]
}


verify_netdata_runtime() {
  local listener_output public_code protected_code attempt cloud_ready=0
  systemctl is-active --quiet netdata.service \
    || { log 'Netdata verification failed: service is not active.'; return 1; }
  systemctl is-enabled --quiet netdata.service \
    || { log 'Netdata verification failed: service is not enabled.'; return 1; }
  systemctl is-enabled --quiet netdata-updater.timer \
    || { log 'Netdata verification failed: stable auto-update timer is not enabled.'; return 1; }
  systemctl is-active --quiet netdata-updater.timer \
    || { log 'Netdata verification failed: stable auto-update timer is not active.'; return 1; }
  cmp -s -- "$NETDATA_CONFIG" "$NETDATA_TEMPLATE" \
    || { log 'Netdata verification failed: managed configuration differs.'; return 1; }
  cmp -s -- "$NETDATA_NGINX_LOCATION" "$NETDATA_LOCATION_TEMPLATE" \
    || { log 'Netdata verification failed: managed Nginx location differs.'; return 1; }
  [[ ! -e "$NETDATA_LEGACY_AUTH_FILE" && ! -L "$NETDATA_LEGACY_AUTH_FILE" ]] \
    || { log 'Netdata verification failed: legacy Basic Auth state exists.'; return 1; }
  nginx -t >/dev/null 2>&1 \
    || { log 'Netdata verification failed: nginx -t rejected the configuration.'; return 1; }
  for attempt in {1..120}; do
    if curl --fail --silent --show-error --output /dev/null --max-time 3 \
      http://127.0.0.1:19999/api/v3/info \
      && _netdata_cloud_online; then
      cloud_ready=1
      break
    fi
    sleep 1
  done
  [[ "$cloud_ready" == 1 ]] \
    || { log 'Netdata verification failed: Agent is not online in Netdata Cloud after 120 seconds.'; return 1; }
  rm -f -- "$NETDATA_CLAIM_CONFIG"
  [[ ! -e "$NETDATA_CLAIM_CONFIG" && ! -L "$NETDATA_CLAIM_CONFIG" ]] \
    || { log 'Netdata verification failed: temporary claim configuration was not removed.'; return 1; }

  listener_output=$(ss -H -lntp 2>/dev/null) \
    || { log 'Netdata verification failed: listeners could not be inspected.'; return 1; }
  [[ $(grep -Ec '127\.0\.0\.1:19999([[:space:]]|$).*["(]netdata[",)]' <<<"$listener_output") -ge 1 ]] \
    || { log 'Netdata verification failed: owned localhost listener was not found.'; return 1; }
  [[ $(grep -Ec '(^|[[:space:]])(0\.0\.0\.0|\[::\]|\*):19999([[:space:]]|$)' <<<"$listener_output") -eq 0 ]] \
    || { log 'Netdata verification failed: a public port 19999 listener exists.'; return 1; }

  public_code=$(curl --silent --show-error --insecure --output /dev/null \
    --write-out '%{http_code}' --max-time 5 https://127.0.0.1/netdata/api/v3/info) \
    || { log 'Netdata verification failed: HTTPS proxy is unavailable.'; return 1; }
  [[ "$public_code" == 200 ]] \
    || { log 'Netdata verification failed: HTTPS proxy public bootstrap API is unavailable.'; return 1; }
  protected_code=$(curl --silent --show-error --insecure --output /dev/null \
    --write-out '%{http_code}' --max-time 5 https://127.0.0.1/netdata/api/v3/nodes) \
    || { log 'Netdata verification failed: HTTPS bearer protection probe failed.'; return 1; }
  [[ "$protected_code" == 412 ]] \
    || { log 'Netdata verification failed: HTTPS proxy did not enforce Bearer Token Protection.'; return 1; }
}


install_netdata() {
  local root_dir=$1 config_file=$2 registered=0 registry_status allow_listener='' kickstart
  NETDATA_TEMPLATE="$root_dir/templates/netdata.conf.tmpl"
  NETDATA_LOCATION_TEMPLATE="$root_dir/templates/netdata-location.conf.tmpl"

  require_root
  [[ -d "$root_dir" && ! -L "$root_dir" ]] || die 'The deployment bundle root is invalid.'
  load_trusted_config "$config_file"
  [[ ${TARGET_OS:-} == 'ubuntu-24.04' ]] || die 'TARGET_OS must be ubuntu-24.04.'
  [[ ${TARGET_ARCH:-} == 'amd64' ]] || die 'TARGET_ARCH must be amd64.'
  valid_port "${SSH_PORT:-}" || die 'SSH_PORT must be a valid port.'
  valid_ipv4 "${SERVER_ADDRESS:-}" || die 'SERVER_ADDRESS must be a valid IPv4 address.'
  valid_netdata_claim_token "${NETDATA_CLAIM_TOKEN:-}" || die 'NETDATA_CLAIM_TOKEN is invalid.'
  valid_netdata_claim_rooms "${NETDATA_CLAIM_ROOMS:-}" || die 'NETDATA_CLAIM_ROOMS is invalid.'
  require_ubuntu_24_amd64
  require_base_security_ready
  require_netdata_nginx_ready "$root_dir"
  if component_registered netdata; then
    registered=1
  else
    registry_status=$?
    [[ $registry_status -eq 1 ]] || die 'Component state registry is invalid.'
  fi
  NETDATA_ROLLBACK_REGISTERED=$registered
  require_no_foreign_netdata_state "$registered" "$root_dir" \
    || die 'Foreign or incomplete Netdata state conflicts with this deployment.'
  (( NETDATA_EXISTING_LISTENER == 1 )) && allow_listener='--allow-listener tcp'
  # shellcheck disable=SC2086
  python3 "$root_dir/lib/port_contract.py" check-fixed --port "$NETDATA_PORT" \
    --ssh-port "$SSH_PORT" $allow_listener \
    || die 'Netdata port 19999 conflicts with existing server state.'

  _arm_netdata_rollback
  need curl
  need python3
  kickstart="$NETDATA_ROLLBACK_DIRECTORY/kickstart.sh"
  _netdata_download_kickstart "$kickstart" || die 'Could not download the official Netdata installer.'
  sh "$kickstart" --stable-channel --native-only --non-interactive --auto-update \
    --auto-update-type systemd --disable-telemetry \
    || die 'The official Netdata installer failed.'
  _netdata_package_installed || die 'The official installer did not install the native Netdata package.'
  systemctl stop netdata.service
  _netdata_install_file_atomically "$NETDATA_TEMPLATE" "$NETDATA_CONFIG" 0644 \
    || die 'Could not install the Netdata configuration.'
  _netdata_install_file_atomically "$NETDATA_LOCATION_TEMPLATE" "$NETDATA_NGINX_LOCATION" 0644 \
    || die 'Could not install the Netdata Nginx location.'
  nginx -t >/dev/null 2>&1 || die 'The Nginx configuration is invalid with Netdata.'
  systemctl enable --now netdata.service
  systemctl reload nginx.service
  _netdata_claim "$kickstart" "$NETDATA_CLAIM_TOKEN" "${NETDATA_CLAIM_ROOMS:-}" \
    || die 'Netdata Cloud claim failed.'
  systemctl restart netdata.service
  rm -f -- "$kickstart"
  verify_netdata_runtime || die 'Netdata runtime verification failed.'
  install_component_declaration "$root_dir" netdata
  register_netdata_component

  NETDATA_ROLLBACK_ARMED=0
  trap - EXIT
  rm -rf -- "$NETDATA_ROLLBACK_DIRECTORY"
  log 'Netdata deployment complete: stable auto-updates, Cloud claim and Bearer Token Protection are active.'
}
