#!/usr/bin/env bash

readonly NGINX_COMPONENT_SCRIPT_DIRECTORY=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly NGINX_TEMPLATE_DIRECTORY=$(cd -- "$NGINX_COMPONENT_SCRIPT_DIRECTORY/../templates" && pwd)
readonly NGINX_SITE_TEMPLATE="$NGINX_TEMPLATE_DIRECTORY/nginx-site.conf.tmpl"
readonly NGINX_LETSENCRYPT_SITE_TEMPLATE="$NGINX_TEMPLATE_DIRECTORY/nginx-letsencrypt-site.conf.tmpl"
readonly NGINX_SUBSCRIPTIONS_LOCATION_TEMPLATE="$NGINX_TEMPLATE_DIRECTORY/nginx-subscriptions-location.conf.tmpl"
readonly NGINX_FIREWALL_TEMPLATE="$NGINX_TEMPLATE_DIRECTORY/50-nginx.nft.tmpl"
readonly NGINX_RENEW_TEMPLATE="$NGINX_TEMPLATE_DIRECTORY/nginx-renew.sh.tmpl"
readonly NGINX_RENEW_SERVICE_TEMPLATE="$NGINX_TEMPLATE_DIRECTORY/vpn-admin-nginx-renew.service.tmpl"
readonly NGINX_RENEW_TIMER_TEMPLATE="$NGINX_TEMPLATE_DIRECTORY/vpn-admin-nginx-renew.timer.tmpl"
readonly NGINX_CONTRACT_SOURCE="$NGINX_COMPONENT_SCRIPT_DIRECTORY/../lib/nginx_contract.py"
readonly NGINX_CONFIG='/etc/nginx/conf.d/vpn-admin-site.conf'
readonly NGINX_SUBSCRIPTIONS_LOCATION='/etc/nginx/vpn-admin-locations/subscriptions.conf'
readonly NGINX_SITE_ROOT='/var/www/vpn-admin-site'
readonly NGINX_INDEX="$NGINX_SITE_ROOT/index.html"
readonly NGINX_TLS_DIRECTORY='/etc/nginx/vpn-admin-tls'
readonly NGINX_CERTIFICATE="$NGINX_TLS_DIRECTORY/server.crt"
readonly NGINX_PRIVATE_KEY="$NGINX_TLS_DIRECTORY/server.key"
readonly NGINX_TLS_STATE="$NGINX_TLS_DIRECTORY/state"
readonly NGINX_RUNTIME_DIRECTORY='/usr/local/lib/vpn-admin'
readonly NGINX_CONTRACT="$NGINX_RUNTIME_DIRECTORY/nginx_contract.py"
readonly NGINX_RENEW_SCRIPT="$NGINX_RUNTIME_DIRECTORY/nginx-renew"
readonly NGINX_RENEW_HOOK='/etc/letsencrypt/renewal-hooks/deploy/vpn-admin-nginx'
readonly NGINX_RENEW_SERVICE='/etc/systemd/system/vpn-admin-nginx-renew.service'
readonly NGINX_RENEW_TIMER='/etc/systemd/system/vpn-admin-nginx-renew.timer'
readonly NGINX_RENEW_TIMER_UNIT='vpn-admin-nginx-renew.timer'
readonly NGINX_NATIVE_CERTBOT_TIMER_UNIT='certbot.timer'
readonly NGINX_FIREWALL_FRAGMENT='/etc/nftables.d/50-nginx.nft'
readonly NGINX_DEFAULT_ENABLED='/etc/nginx/sites-enabled/default'
readonly NGINX_DEFAULT_AVAILABLE='/etc/nginx/sites-available/default'
readonly NGINX_V1_SITE_SHA256='948cdfd4c3189fd26fae7d9220f42f15a162fa8213d758598abef1c7913ec22a'

NGINX_ROLLBACK_ARMED=0
NGINX_ROLLBACK_DIRECTORY=''
NGINX_ROLLBACK_REGISTERED=0
NGINX_ROLLBACK_PACKAGE_INSTALLED=0
NGINX_ROLLBACK_CERTBOT_PACKAGE_INSTALLED=0
NGINX_ROLLBACK_SERVICE_ACTIVE=0
NGINX_ROLLBACK_SERVICE_ENABLED=0
NGINX_ROLLBACK_DEFAULT_PRESENT=0
NGINX_ROLLBACK_DEFAULT_TARGET=''
NGINX_ROLLBACK_CONFIG_PRESENT=0
NGINX_ROLLBACK_FIREWALL_PRESENT=0
NGINX_ROLLBACK_DECLARATION_PRESENT=0
NGINX_ROLLBACK_CERTIFICATE_PRESENT=0
NGINX_ROLLBACK_PRIVATE_KEY_PRESENT=0
NGINX_ROLLBACK_INDEX_PRESENT=0
NGINX_ROLLBACK_TLS_STATE_PRESENT=0
NGINX_ROLLBACK_CONTRACT_PRESENT=0
NGINX_ROLLBACK_RENEW_SCRIPT_PRESENT=0
NGINX_ROLLBACK_RENEW_HOOK_PRESENT=0
NGINX_ROLLBACK_RENEW_SERVICE_PRESENT=0
NGINX_ROLLBACK_RENEW_TIMER_PRESENT=0
NGINX_ROLLBACK_SUBSCRIPTIONS_LOCATION_PRESENT=0
NGINX_ROLLBACK_RENEW_TIMER_ACTIVE=0
NGINX_ROLLBACK_RENEW_TIMER_ENABLED=0

install_nginx_packages() {
  run_package_manager_command apt-get install -y nginx certbot
}


_nginx_target_directory_has_no_symlink_components() {
  local path=$1 current='/' component
  local -a components

  [[ "$path" == /* ]] || return 1
  local IFS=/
  read -r -a components <<< "$path"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    [[ "$component" != . && "$component" != .. ]] || return 1
    if [[ "$current" == / ]]; then
      current="/$component"
    else
      current="$current/$component"
    fi
    [[ ! -L "$current" ]] || return 1
  done
}


ensure_nginx_index() {
  local site_root=$1 index_path=$2 template=$3
  [[ "$(dirname -- "$index_path")" == "$site_root" ]] || return 1
  _nginx_target_directory_has_no_symlink_components "$site_root" || return 1
  [[ -f "$template" && ! -L "$template" ]] || return 1

  if [[ -e "$index_path" || -L "$index_path" ]]; then
    [[ -f "$index_path" && ! -L "$index_path" ]] || return 1
    chmod 0644 "$index_path"
    return
  fi

  mkdir -p -- "$site_root" || return 1
  chmod 0755 "$site_root" || return 1
  cp -- "$template" "$index_path" || return 1
  chmod 0644 "$index_path"
}


validate_nginx_certificate() {
  local certificate=$1 private_key=$2 server_address=$3
  local certificate_public_key private_public_key

  valid_ipv4 "$server_address" || return 1
  [[ -f "$certificate" && ! -L "$certificate" ]] || return 1
  [[ -f "$private_key" && ! -L "$private_key" ]] || return 1
  openssl pkey -in "$private_key" -noout >/dev/null 2>&1 || return 1
  openssl x509 -in "$certificate" -noout -checkend 0 >/dev/null 2>&1 || return 1
  openssl x509 -in "$certificate" -noout -checkip "$server_address" >/dev/null 2>&1 || return 1
  certificate_public_key=$(
    openssl x509 -in "$certificate" -pubkey -noout 2>/dev/null \
      | openssl pkey -pubin -outform DER 2>/dev/null \
      | sha256sum
  ) || return 1
  private_public_key=$(
    openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null \
      | sha256sum
  ) || return 1
  [[ "$certificate_public_key" == "$private_public_key" ]]
}


ensure_nginx_certificate() {
  local tls_directory=$1 certificate=$2 private_key=$3 server_address=$4
  local replace_existing=${5:-0}
  local certificate_candidate private_key_candidate

  valid_ipv4 "$server_address" || return 1
  [[ "$replace_existing" == 0 || "$replace_existing" == 1 ]] || return 1
  [[ "$(dirname -- "$certificate")" == "$tls_directory" ]] || return 1
  [[ "$(dirname -- "$private_key")" == "$tls_directory" ]] || return 1
  _nginx_target_directory_has_no_symlink_components "$tls_directory" || return 1

  if [[ "$replace_existing" == 0 \
    && ( -e "$certificate" || -L "$certificate" || -e "$private_key" || -L "$private_key" ) ]]; then
    [[ -f "$certificate" && ! -L "$certificate" ]] || return 1
    [[ -f "$private_key" && ! -L "$private_key" ]] || return 1
    validate_nginx_certificate "$certificate" "$private_key" "$server_address" || return 1
    chown root:root "$tls_directory" || return 1
    chown root:root "$private_key" || return 1
    chown root:root "$certificate" || return 1
    chmod 0700 "$tls_directory" || return 1
    chmod 0600 "$private_key" || return 1
    chmod 0644 "$certificate" || return 1
    return
  fi

  mkdir -p -- "$tls_directory" || return 1
  chmod 0700 "$tls_directory" || return 1
  chown root:root "$tls_directory" || return 1
  private_key_candidate=$(mktemp "$tls_directory/.server.key.XXXXXX") || return 1
  certificate_candidate=$(mktemp "$tls_directory/.server.crt.XXXXXX") || {
    rm -f -- "$private_key_candidate"
    return 1
  }

  if ! openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 365 \
    -keyout "$private_key_candidate" \
    -out "$certificate_candidate" \
    -subj "/CN=$server_address" \
    -addext "subjectAltName=IP:$server_address" >/dev/null 2>&1; then
    rm -f -- "$private_key_candidate" "$certificate_candidate"
    return 1
  fi
  if ! validate_nginx_certificate "$certificate_candidate" "$private_key_candidate" "$server_address"; then
    rm -f -- "$private_key_candidate" "$certificate_candidate"
    return 1
  fi

  chmod 0600 "$private_key_candidate" || {
    rm -f -- "$private_key_candidate" "$certificate_candidate"
    return 1
  }
  chmod 0644 "$certificate_candidate" || {
    rm -f -- "$private_key_candidate" "$certificate_candidate"
    return 1
  }
  chown root:root "$private_key_candidate" || {
    rm -f -- "$private_key_candidate" "$certificate_candidate"
    return 1
  }
  chown root:root "$certificate_candidate" || {
    rm -f -- "$private_key_candidate" "$certificate_candidate"
    return 1
  }
  mv -f -- "$private_key_candidate" "$private_key" || {
    rm -f -- "$private_key_candidate" "$certificate_candidate"
    return 1
  }
  mv -f -- "$certificate_candidate" "$certificate" || {
    rm -f -- "$certificate_candidate"
    return 1
  }
}


valid_nginx_domain() {
  local value=$1
  (( ${#value} <= 253 )) || return 1
  [[ "$value" == *[a-z]* ]] || return 1
  [[ "$value" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]
}


_render_nginx_site() {
  local mode=$1 server_name=$2 destination=$3
  [[ "$mode" == self_signed || "$mode" == letsencrypt ]] || return 1
  [[ -n "$destination" ]] || return 1
  if [[ "$mode" == self_signed ]]; then
    cp -- "$NGINX_SITE_TEMPLATE" "$destination"
    return
  fi
  valid_nginx_domain "$server_name" || return 1
  sed "s/__SERVER_NAME__/$server_name/g" "$NGINX_LETSENCRYPT_SITE_TEMPLATE" > "$destination"
}


_write_nginx_tls_state() {
  local mode=$1 server_name=$2 server_address=$3 destination=$4
  local destination_directory candidate

  [[ "$mode" == self_signed || "$mode" == letsencrypt ]] || return 1
  valid_ipv4 "$server_address" || return 1
  if [[ "$mode" == self_signed ]]; then
    [[ "$server_name" == "$server_address" ]] || return 1
  else
    valid_nginx_domain "$server_name" || return 1
  fi
  destination_directory=$(dirname -- "$destination")
  [[ -d "$destination_directory" ]] || return 1
  _nginx_target_directory_has_no_symlink_components "$destination_directory" || return 1
  candidate=$(mktemp "$destination_directory/.state.XXXXXX") || return 1
  if ! printf 'version=1\ntls_mode=%s\nserver_name=%s\nserver_address=%s\n' \
    "$mode" "$server_name" "$server_address" > "$candidate" \
    || ! chmod 0644 "$candidate" \
    || ! chown root:root "$candidate" \
    || ! mv -f -- "$candidate" "$destination"; then
    rm -f -- "$candidate"
    return 1
  fi
}


_install_nginx_file_atomically() {
  local source=$1 destination=$2 mode=$3 candidate destination_directory
  destination_directory=$(dirname -- "$destination")
  [[ -f "$source" && ! -L "$source" ]] || return 1
  mkdir -p -- "$destination_directory" || return 1
  _nginx_target_directory_has_no_symlink_components "$destination_directory" || return 1
  candidate=$(mktemp "$destination_directory/.vpn-admin-nginx.XXXXXX") || return 1
  if ! install -m "$mode" -- "$source" "$candidate" \
    || ! chown root:root "$candidate" \
    || ! mv -f -- "$candidate" "$destination"; then
    rm -f -- "$candidate"
    return 1
  fi
}


install_nginx_runtime_assets() {
  local mode=$1 server_name=$2 server_address=$3
  _install_nginx_file_atomically "$NGINX_CONTRACT_SOURCE" "$NGINX_CONTRACT" 0755 || return 1
  _install_nginx_file_atomically "$NGINX_RENEW_TEMPLATE" "$NGINX_RENEW_SCRIPT" 0755 || return 1
  _install_nginx_file_atomically "$NGINX_RENEW_TEMPLATE" "$NGINX_RENEW_HOOK" 0755 || return 1
  _install_nginx_file_atomically "$NGINX_RENEW_SERVICE_TEMPLATE" "$NGINX_RENEW_SERVICE" 0644 || return 1
  _install_nginx_file_atomically "$NGINX_RENEW_TIMER_TEMPLATE" "$NGINX_RENEW_TIMER" 0644 || return 1
  _write_nginx_tls_state "$mode" "$server_name" "$server_address" "$NGINX_TLS_STATE" || return 1
  systemctl daemon-reload || return 1
  systemctl enable --now "$NGINX_RENEW_TIMER_UNIT"
}


_read_installed_nginx_tls_state() {
  [[ -f "$NGINX_CONTRACT_SOURCE" && ! -L "$NGINX_CONTRACT_SOURCE" ]] || return 1
  python3 "$NGINX_CONTRACT_SOURCE" state
}


_validate_stock_nginx_site() {
  local enabled_path=$1 available_path=$2 enabled_directory package_owner owner_entry
  local conffiles registered_md5 current_md5
  local -a enabled_entries

  enabled_directory=$(dirname -- "$enabled_path")
  shopt -s nullglob
  enabled_entries=("$enabled_directory"/*)
  shopt -u nullglob
  (( ${#enabled_entries[@]} == 1 )) || return 1
  [[ "${enabled_entries[0]}" == "$enabled_path" ]] || return 1
  [[ -L "$enabled_path" ]] || return 1
  [[ -f "$available_path" && ! -L "$available_path" ]] || return 1
  [[ "$(readlink -f -- "$enabled_path")" == "$(readlink -f -- "$available_path")" ]] || return 1

  owner_entry=$(dpkg-query -S "$available_path" 2>/dev/null) || return 1
  package_owner=${owner_entry%%:*}
  [[ -n "$package_owner" && ${owner_entry#*: } == "$available_path" ]] || return 1
  conffiles=$(dpkg-query -W -f='${Conffiles}\n' "$package_owner" 2>/dev/null) || return 1
  registered_md5=$(awk -v path="$available_path" '
    $1 == path { value=$2; count++ }
    END { if (count != 1 || value !~ /^[0-9a-fA-F]{32}$/) exit 1; print tolower(value) }
  ' <<<"$conffiles") || return 1
  current_md5=$(md5sum -- "$available_path") || return 1
  current_md5=${current_md5%% *}
  [[ "$current_md5" == "$registered_md5" ]]
}


disable_stock_nginx_site() {
  local enabled_path=$1 available_path=$2 enabled_directory
  local -a enabled_entries

  enabled_directory=$(dirname -- "$enabled_path")
  shopt -s nullglob
  enabled_entries=("$enabled_directory"/*)
  shopt -u nullglob
  if (( ${#enabled_entries[@]} == 0 )); then
    return 0
  fi
  _validate_stock_nginx_site "$enabled_path" "$available_path" || return 1
  rm -- "$enabled_path"
}


_nginx_owned_state_is_complete() {
  local owned_vhost=$1 certificate=$2 private_key=$3 index_path=$4 firewall_fragment=$5 server_address=$6
  local registered=${7:-0} subscriptions_location=${8:-$NGINX_SUBSCRIPTIONS_LOCATION} current_sha256

  [[ -f "$owned_vhost" && ! -L "$owned_vhost" ]] || return 1
  [[ -f "$index_path" && ! -L "$index_path" ]] || return 1
  [[ -f "$firewall_fragment" && ! -L "$firewall_fragment" ]] || return 1
  cmp -s -- "$firewall_fragment" "$NGINX_FIREWALL_TEMPLATE" || return 1
  if [[ -e "$subscriptions_location" || -L "$subscriptions_location" ]]; then
    [[ -f "$subscriptions_location" && ! -L "$subscriptions_location" ]] || return 1
    cmp -s -- "$subscriptions_location" "$NGINX_SUBSCRIPTIONS_LOCATION_TEMPLATE" || return 1
  fi
  if [[ "$owned_vhost" == "$NGINX_CONFIG" && ( -e "$NGINX_TLS_STATE" || -L "$NGINX_TLS_STATE" ) ]]; then
    [[ -f "$NGINX_TLS_STATE" && ! -L "$NGINX_TLS_STATE" ]] || return 1
    [[ -f "$NGINX_CONTRACT" && ! -L "$NGINX_CONTRACT" ]] || return 1
    [[ -f "$NGINX_RENEW_SCRIPT" && ! -L "$NGINX_RENEW_SCRIPT" ]] || return 1
    [[ -f "$NGINX_RENEW_HOOK" && ! -L "$NGINX_RENEW_HOOK" ]] || return 1
    [[ -f "$NGINX_RENEW_SERVICE" && ! -L "$NGINX_RENEW_SERVICE" ]] || return 1
    [[ -f "$NGINX_RENEW_TIMER" && ! -L "$NGINX_RENEW_TIMER" ]] || return 1
    python3 "$NGINX_CONTRACT_SOURCE" verify-owned --allow-expired --allow-legacy-v4 || return 1
    return 0
  fi
  if [[ "$owned_vhost" == "$NGINX_CONFIG" ]]; then
    local managed_path
    for managed_path in \
      "$NGINX_CONTRACT" "$NGINX_RENEW_SCRIPT" "$NGINX_RENEW_HOOK" \
      "$NGINX_RENEW_SERVICE" "$NGINX_RENEW_TIMER" "$NGINX_SUBSCRIPTIONS_LOCATION"; do
      [[ ! -e "$managed_path" && ! -L "$managed_path" ]] || return 1
    done
  fi
  if ! cmp -s -- "$owned_vhost" "$NGINX_SITE_TEMPLATE"; then
    (( registered == 1 )) || return 1
    current_sha256=$(sha256sum -- "$owned_vhost") || return 1
    current_sha256=${current_sha256%% *}
    [[ "$current_sha256" == "$NGINX_V1_SITE_SHA256" ]] || return 1
  fi
  validate_nginx_certificate "$certificate" "$private_key" "$server_address"
}


_nginx_running_uses_owned_vhost() {
  local owned_vhost=$1 nginx_binary=$2 nginx_dump candidate status

  [[ -x "$nginx_binary" && ! -L "$nginx_binary" ]] || return 1
  nginx_dump=$("$nginx_binary" -T 2>&1) || return 1
  candidate=$(mktemp) || return 1
  if ! awk -v marker="# configuration file $owned_vhost:" '
    $0 == marker {
      count++
      if (count > 1) exit 1
      capture=1
      next
    }
    capture && /^# configuration file .*:$/ { capture=0 }
    capture { print }
    END { if (count != 1) exit 1 }
  ' <<<"$nginx_dump" | sed '${/^$/d;}' > "$candidate"; then
    rm -f -- "$candidate"
    return 1
  fi
  if cmp -s -- "$candidate" "$owned_vhost"; then
    status=0
  else
    status=1
  fi
  rm -f -- "$candidate"
  return "$status"
}


_nginx_live_endpoint_uses_owned_vhost() {
  local curl_binary=$1 url=$2
  shift 2
  local headers

  [[ -x "$curl_binary" && ! -L "$curl_binary" ]] || return 1
  headers=$("$curl_binary" \
    --silent --show-error --fail --max-time 5 \
    --output /dev/null --dump-header - "$@" "$url" 2>/dev/null) || return 1
  tr -d '\r' <<<"$headers" | grep -Fqx 'X-VPN-Admin-Component: nginx/1'
}


require_no_foreign_nginx_state() {
  local registered=$1
  local conf_directory=${2:-/etc/nginx/conf.d}
  local sites_enabled_directory=${3:-/etc/nginx/sites-enabled}
  local owned_vhost=${4:-/etc/nginx/conf.d/vpn-admin-site.conf}
  local stock_enabled=${5:-/etc/nginx/sites-enabled/default}
  local stock_available=${6:-/etc/nginx/sites-available/default}
  local certificate=${7:-/etc/nginx/vpn-admin-tls/server.crt}
  local private_key=${8:-/etc/nginx/vpn-admin-tls/server.key}
  local index_path=${9:-/var/www/vpn-admin-site/index.html}
  local firewall_fragment=${10:-/etc/nftables.d/50-nginx.nft}
  local server_address=${11:-${SERVER_IPV4:-}}
  local nginx_binary=${12:-/usr/sbin/nginx}
  local curl_binary=${13:-/usr/bin/curl}
  local subscriptions_location=${14:-$NGINX_SUBSCRIPTIONS_LOCATION}
  local owned_complete=0 owned_present=0 nginx_listener_found=0
  local http_listener_found=0 https_listener_found=0
  local listener_output line local_address listener_port
  local -a conf_entries enabled_entries

  [[ "$registered" == 0 || "$registered" == 1 ]] || return 1
  valid_ipv4 "$server_address" || return 1

  if _nginx_owned_state_is_complete \
    "$owned_vhost" "$certificate" "$private_key" "$index_path" "$firewall_fragment" "$server_address" \
    "$registered" "$subscriptions_location"; then
    owned_complete=1
  fi
  local owned_path
  for owned_path in \
    "$owned_vhost" "$certificate" "$private_key" "$index_path" "$firewall_fragment" \
    "$NGINX_TLS_STATE" "$NGINX_CONTRACT" "$NGINX_RENEW_SCRIPT" "$NGINX_RENEW_HOOK" \
    "$NGINX_RENEW_SERVICE" "$NGINX_RENEW_TIMER" "$subscriptions_location"; do
    if [[ -e "$owned_path" || -L "$owned_path" ]]; then
      owned_present=1
    fi
  done
  (( owned_present == 0 || owned_complete == 1 )) || return 1
  (( registered == 0 || owned_complete == 1 )) || return 1

  shopt -s nullglob
  conf_entries=("$conf_directory"/*.conf)
  enabled_entries=("$sites_enabled_directory"/*)
  shopt -u nullglob
  local entry
  for entry in "${conf_entries[@]}"; do
    [[ "$entry" == "$owned_vhost" && $owned_complete -eq 1 ]] || return 1
  done
  if (( ${#enabled_entries[@]} > 0 )); then
    (( registered == 0 && ${#enabled_entries[@]} == 1 )) || return 1
    _validate_stock_nginx_site "$stock_enabled" "$stock_available" || return 1
  fi

  listener_output=$(ss -H -lntp 2>/dev/null) || return 1
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -r _ _ _ local_address _ _ <<<"$line"
    listener_port=${local_address##*:}
    case "$listener_port" in
      80|443)
        (( registered == 1 && owned_complete == 1 )) || return 1
        [[ "$line" == *'"nginx"'* ]] || return 1
        nginx_listener_found=1
        if [[ "$listener_port" == 80 ]]; then
          http_listener_found=1
        else
          https_listener_found=1
        fi
        ;;
    esac
  done <<<"$listener_output"
  if (( nginx_listener_found == 1 )); then
    _nginx_running_uses_owned_vhost "$owned_vhost" "$nginx_binary" || return 1
    (( http_listener_found == 1 && https_listener_found == 1 )) || return 1
    _nginx_live_endpoint_uses_owned_vhost "$curl_binary" http://127.0.0.1/ || return 1
    _nginx_live_endpoint_uses_owned_vhost "$curl_binary" https://127.0.0.1/ --insecure || return 1
  fi
}


_install_nginx_template_atomically() {
  local template=$1 destination=$2 candidate destination_directory
  destination_directory=$(dirname -- "$destination")
  [[ -f "$template" && ! -L "$template" ]] || return 1
  [[ -d "$destination_directory" ]] || return 1
  _nginx_target_directory_has_no_symlink_components "$destination_directory" || return 1
  candidate=$(mktemp "$destination_directory/.vpn-admin-nginx.XXXXXX") || return 1
  if ! install -m 0644 -- "$template" "$candidate" || ! mv -f -- "$candidate" "$destination"; then
    rm -f -- "$candidate"
    return 1
  fi
}


install_nginx_subscriptions_location() {
  local template=$1 destination=$2 directory
  directory=$(dirname -- "$destination")
  [[ -f "$template" && ! -L "$template" ]] || return 1
  _nginx_target_directory_has_no_symlink_components "$directory" || return 1
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -f "$destination" && ! -L "$destination" ]] || return 1
  fi
  install -d -m 0755 -- "$directory" || return 1
  _nginx_target_directory_has_no_symlink_components "$directory" || return 1
  _install_nginx_template_atomically "$template" "$destination"
}


_nginx_capture_file() {
  local source=$1 backup_name=$2 present_variable=$3
  if [[ -e "$source" || -L "$source" ]]; then
    [[ -f "$source" && ! -L "$source" ]] || return 1
    cp -p -- "$source" "$NGINX_ROLLBACK_DIRECTORY/$backup_name" || return 1
    printf -v "$present_variable" '%s' 1
  fi
}


_nginx_restore_file() {
  local destination=$1 backup_name=$2 was_present=$3
  if (( was_present == 1 )); then
    cp -p -- "$NGINX_ROLLBACK_DIRECTORY/$backup_name" "$destination"
  else
    rm -f -- "$destination"
  fi
}


_rollback_nginx_install() {
  local declaration="$COMPONENT_DECLARATION_DIRECTORY/nginx/declaration.json"
  (( NGINX_ROLLBACK_ARMED == 1 )) || return 0
  set +e

  _nginx_restore_file "$NGINX_CONFIG" config "$NGINX_ROLLBACK_CONFIG_PRESENT"
  _nginx_restore_file "$NGINX_INDEX" index "$NGINX_ROLLBACK_INDEX_PRESENT"
  _nginx_restore_file "$NGINX_FIREWALL_FRAGMENT" firewall "$NGINX_ROLLBACK_FIREWALL_PRESENT"
  _nginx_restore_file "$declaration" declaration "$NGINX_ROLLBACK_DECLARATION_PRESENT"
  _nginx_restore_file "$NGINX_TLS_STATE" tls-state "$NGINX_ROLLBACK_TLS_STATE_PRESENT"
  _nginx_restore_file "$NGINX_CONTRACT" contract "$NGINX_ROLLBACK_CONTRACT_PRESENT"
  _nginx_restore_file "$NGINX_RENEW_SCRIPT" renew-script "$NGINX_ROLLBACK_RENEW_SCRIPT_PRESENT"
  _nginx_restore_file "$NGINX_RENEW_HOOK" renew-hook "$NGINX_ROLLBACK_RENEW_HOOK_PRESENT"
  _nginx_restore_file "$NGINX_RENEW_SERVICE" renew-service "$NGINX_ROLLBACK_RENEW_SERVICE_PRESENT"
  _nginx_restore_file "$NGINX_RENEW_TIMER" renew-timer "$NGINX_ROLLBACK_RENEW_TIMER_PRESENT"
  _nginx_restore_file "$NGINX_SUBSCRIPTIONS_LOCATION" subscriptions-location \
    "$NGINX_ROLLBACK_SUBSCRIPTIONS_LOCATION_PRESENT"
  _nginx_restore_file "$NGINX_CERTIFICATE" certificate "$NGINX_ROLLBACK_CERTIFICATE_PRESENT"
  _nginx_restore_file "$NGINX_PRIVATE_KEY" private-key "$NGINX_ROLLBACK_PRIVATE_KEY_PRESENT"
  systemctl disable --now "$NGINX_RENEW_TIMER_UNIT" >/dev/null 2>&1
  systemctl daemon-reload >/dev/null 2>&1
  if (( NGINX_ROLLBACK_RENEW_TIMER_ENABLED == 1 )); then
    systemctl enable "$NGINX_RENEW_TIMER_UNIT" >/dev/null 2>&1
  fi
  if (( NGINX_ROLLBACK_RENEW_TIMER_ACTIVE == 1 )); then
    systemctl start "$NGINX_RENEW_TIMER_UNIT" >/dev/null 2>&1
  fi
  rm -f -- "$NGINX_DEFAULT_ENABLED"
  if (( NGINX_ROLLBACK_DEFAULT_PRESENT == 1 )); then
    ln -s -- "$NGINX_ROLLBACK_DEFAULT_TARGET" "$NGINX_DEFAULT_ENABLED"
  fi

  if nft -c -f "$NFTABLES_MAIN_CONFIG" >/dev/null 2>&1; then
    apply_firewall >/dev/null 2>&1
  fi

  if (( NGINX_ROLLBACK_REGISTERED == 0 )); then
    systemctl stop nginx.service >/dev/null 2>&1
    systemctl disable nginx.service >/dev/null 2>&1
  else
    if (( NGINX_ROLLBACK_SERVICE_ENABLED == 1 )); then
      systemctl enable nginx.service >/dev/null 2>&1
    else
      systemctl disable nginx.service >/dev/null 2>&1
    fi
    if (( NGINX_ROLLBACK_SERVICE_ACTIVE == 1 )); then
      nginx -t >/dev/null 2>&1 && systemctl restart nginx.service >/dev/null 2>&1
    else
      systemctl stop nginx.service >/dev/null 2>&1
    fi
  fi
  rm -rf -- "$NGINX_ROLLBACK_DIRECTORY"
}


_arm_nginx_rollback() {
  local declaration="$COMPONENT_DECLARATION_DIRECTORY/nginx/declaration.json"
  NGINX_ROLLBACK_DIRECTORY=$(mktemp -d) || die 'Could not create Nginx rollback state.'
  NGINX_ROLLBACK_PACKAGE_INSTALLED=0
  NGINX_ROLLBACK_CERTBOT_PACKAGE_INSTALLED=0
  NGINX_ROLLBACK_SERVICE_ACTIVE=0
  NGINX_ROLLBACK_SERVICE_ENABLED=0
  NGINX_ROLLBACK_DEFAULT_PRESENT=0
  NGINX_ROLLBACK_DEFAULT_TARGET=''
  NGINX_ROLLBACK_CONFIG_PRESENT=0
  NGINX_ROLLBACK_FIREWALL_PRESENT=0
  NGINX_ROLLBACK_DECLARATION_PRESENT=0
  NGINX_ROLLBACK_CERTIFICATE_PRESENT=0
  NGINX_ROLLBACK_PRIVATE_KEY_PRESENT=0
  NGINX_ROLLBACK_INDEX_PRESENT=0
  NGINX_ROLLBACK_TLS_STATE_PRESENT=0
  NGINX_ROLLBACK_CONTRACT_PRESENT=0
  NGINX_ROLLBACK_RENEW_SCRIPT_PRESENT=0
  NGINX_ROLLBACK_RENEW_HOOK_PRESENT=0
  NGINX_ROLLBACK_RENEW_SERVICE_PRESENT=0
  NGINX_ROLLBACK_RENEW_TIMER_PRESENT=0
  NGINX_ROLLBACK_SUBSCRIPTIONS_LOCATION_PRESENT=0
  NGINX_ROLLBACK_RENEW_TIMER_ACTIVE=0
  NGINX_ROLLBACK_RENEW_TIMER_ENABLED=0
  if dpkg-query -W -f='${Status}\n' nginx 2>/dev/null \
    | grep -Fqx 'install ok installed'; then
    NGINX_ROLLBACK_PACKAGE_INSTALLED=1
  fi
  if dpkg-query -W -f='${Status}\n' certbot 2>/dev/null \
    | grep -Fqx 'install ok installed'; then
    NGINX_ROLLBACK_CERTBOT_PACKAGE_INSTALLED=1
  fi
  systemctl is-active --quiet nginx.service && NGINX_ROLLBACK_SERVICE_ACTIVE=1
  systemctl is-enabled --quiet nginx.service && NGINX_ROLLBACK_SERVICE_ENABLED=1
  systemctl is-active --quiet "$NGINX_RENEW_TIMER_UNIT" && NGINX_ROLLBACK_RENEW_TIMER_ACTIVE=1
  systemctl is-enabled --quiet "$NGINX_RENEW_TIMER_UNIT" && NGINX_ROLLBACK_RENEW_TIMER_ENABLED=1
  if [[ -e "$NGINX_DEFAULT_ENABLED" || -L "$NGINX_DEFAULT_ENABLED" ]]; then
    [[ -L "$NGINX_DEFAULT_ENABLED" ]] || die 'The enabled Nginx default site is not a symlink.'
    NGINX_ROLLBACK_DEFAULT_PRESENT=1
    NGINX_ROLLBACK_DEFAULT_TARGET=$(readlink -- "$NGINX_DEFAULT_ENABLED") || die 'Could not capture the Nginx default site.'
  fi
  _nginx_capture_file "$NGINX_CONFIG" config NGINX_ROLLBACK_CONFIG_PRESENT \
    || die 'Could not capture the existing Nginx site configuration.'
  _nginx_capture_file "$NGINX_FIREWALL_FRAGMENT" firewall NGINX_ROLLBACK_FIREWALL_PRESENT \
    || die 'Could not capture the existing Nginx firewall fragment.'
  _nginx_capture_file "$declaration" declaration NGINX_ROLLBACK_DECLARATION_PRESENT \
    || die 'Could not capture the existing Nginx declaration.'
  _nginx_capture_file "$NGINX_CERTIFICATE" certificate NGINX_ROLLBACK_CERTIFICATE_PRESENT \
    || die 'Could not capture the existing Nginx certificate.'
  _nginx_capture_file "$NGINX_PRIVATE_KEY" private-key NGINX_ROLLBACK_PRIVATE_KEY_PRESENT \
    || die 'Could not capture the existing Nginx private key.'
  _nginx_capture_file "$NGINX_INDEX" index NGINX_ROLLBACK_INDEX_PRESENT \
    || die 'Could not capture the existing Nginx index.'
  _nginx_capture_file "$NGINX_TLS_STATE" tls-state NGINX_ROLLBACK_TLS_STATE_PRESENT \
    || die 'Could not capture the existing Nginx TLS state.'
  _nginx_capture_file "$NGINX_CONTRACT" contract NGINX_ROLLBACK_CONTRACT_PRESENT \
    || die 'Could not capture the existing Nginx contract helper.'
  _nginx_capture_file "$NGINX_RENEW_SCRIPT" renew-script NGINX_ROLLBACK_RENEW_SCRIPT_PRESENT \
    || die 'Could not capture the existing Nginx renewal script.'
  _nginx_capture_file "$NGINX_RENEW_HOOK" renew-hook NGINX_ROLLBACK_RENEW_HOOK_PRESENT \
    || die 'Could not capture the existing Nginx renewal hook.'
  _nginx_capture_file "$NGINX_RENEW_SERVICE" renew-service NGINX_ROLLBACK_RENEW_SERVICE_PRESENT \
    || die 'Could not capture the existing Nginx renewal service.'
  _nginx_capture_file "$NGINX_RENEW_TIMER" renew-timer NGINX_ROLLBACK_RENEW_TIMER_PRESENT \
    || die 'Could not capture the existing Nginx renewal timer.'
  _nginx_capture_file "$NGINX_SUBSCRIPTIONS_LOCATION" subscriptions-location \
    NGINX_ROLLBACK_SUBSCRIPTIONS_LOCATION_PRESENT \
    || die 'Could not capture the existing Nginx subscriptions location.'
  NGINX_ROLLBACK_ARMED=1
  trap '_rollback_nginx_install' EXIT
}


_capture_package_created_nginx_default() {
  (( NGINX_ROLLBACK_PACKAGE_INSTALLED == 0 )) || return 0
  (( NGINX_ROLLBACK_DEFAULT_PRESENT == 0 )) || return 0
  [[ -e "$NGINX_DEFAULT_ENABLED" || -L "$NGINX_DEFAULT_ENABLED" ]] || return 0
  _validate_stock_nginx_site "$NGINX_DEFAULT_ENABLED" "$NGINX_DEFAULT_AVAILABLE" || return 1
  NGINX_ROLLBACK_DEFAULT_TARGET=$(readlink -- "$NGINX_DEFAULT_ENABLED") || return 1
  NGINX_ROLLBACK_DEFAULT_PRESENT=1
}


_nginx_listeners_are_owned() {
  local output line local_address port
  local http_seen=0 https_seen=0
  output=$(ss -H -lntp 2>/dev/null) || return 1
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -r _ _ _ local_address _ _ <<<"$line"
    port=${local_address##*:}
    case "$port" in
      80)
        [[ "$line" == *'"nginx"'* ]] || return 1
        http_seen=1
        ;;
      443)
        [[ "$line" == *'"nginx"'* ]] || return 1
        https_seen=1
        ;;
    esac
  done <<<"$output"
  (( http_seen == 1 && https_seen == 1 ))
}


_nginx_active_firewall_is_exact() {
  local rules
  cmp -s -- "$NGINX_FIREWALL_FRAGMENT" "$NGINX_FIREWALL_TEMPLATE" || return 1
  rules=$(nft list table inet vpn_filter 2>/dev/null) || return 1
  [[ $(grep -Ec 'tcp dport 80 accept' <<<"$rules") -eq 1 ]] || return 1
  [[ $(grep -Ec 'tcp dport 443 accept' <<<"$rules") -eq 1 ]]
}


verify_nginx_runtime() {
  local mode=$1 server_name=$2 server_address=$3
  systemctl is-active --quiet nginx.service || return 1
  systemctl is-enabled --quiet nginx.service || return 1
  systemctl is-active --quiet "$NGINX_RENEW_TIMER_UNIT" || return 1
  systemctl is-enabled --quiet "$NGINX_RENEW_TIMER_UNIT" || return 1
  nginx -t >/dev/null 2>&1 || return 1
  python3 "$NGINX_CONTRACT" verify-owned || return 1
  cmp -s -- "$NGINX_SUBSCRIPTIONS_LOCATION" "$NGINX_SUBSCRIPTIONS_LOCATION_TEMPLATE" || return 1
  _nginx_running_uses_owned_vhost "$NGINX_CONFIG" /usr/sbin/nginx || return 1
  _nginx_live_endpoint_uses_owned_vhost /usr/bin/curl http://127.0.0.1/ || return 1
  _nginx_live_endpoint_uses_owned_vhost /usr/bin/curl https://127.0.0.1/ --insecure || return 1
  if [[ "$mode" == letsencrypt ]]; then
    _nginx_live_endpoint_uses_owned_vhost \
      /usr/bin/curl "https://$server_name/" --resolve "$server_name:443:127.0.0.1" || return 1
  else
    [[ "$server_name" == "$server_address" ]] || return 1
  fi
  _nginx_listeners_are_owned || return 1
  _nginx_active_firewall_is_exact
}


install_nginx() {
  local root_dir=$1 config_file=$2 registered=0 registry_status
  local requested_mode requested_name existing_mode='' existing_name='' existing_address=''
  local rendered_site bootstrap_required=1

  require_root
  [[ -d "$root_dir" && ! -L "$root_dir" ]] || die 'The deployment bundle root is invalid.'
  load_trusted_config "$config_file"
  [[ ${TARGET_OS:-} == 'ubuntu-24.04' ]] || die 'TARGET_OS must be ubuntu-24.04.'
  [[ ${TARGET_ARCH:-} == 'amd64' ]] || die 'TARGET_ARCH must be amd64.'
  valid_ipv4 "${SERVER_ADDRESS:-}" || die 'SERVER_ADDRESS must be a valid IPv4 address.'
  requested_mode=${NGINX_TLS_MODE:-self_signed}
  requested_name=${NGINX_SERVER_NAME:-}
  [[ "$requested_mode" == self_signed || "$requested_mode" == letsencrypt ]] \
    || die 'NGINX_TLS_MODE must be self_signed or letsencrypt.'
  if [[ "$requested_mode" == letsencrypt ]]; then
    valid_nginx_domain "$requested_name" || die 'NGINX_SERVER_NAME must be a valid lowercase domain.'
  else
    [[ -z "$requested_name" ]] || die 'NGINX_SERVER_NAME is only supported with letsencrypt.'
  fi
  require_ubuntu_24_amd64
  require_base_security_ready
  if component_registered nginx; then
    registered=1
  else
    registry_status=$?
    [[ $registry_status -eq 1 ]] || die 'Component state registry is invalid.'
  fi
  NGINX_ROLLBACK_REGISTERED=$registered
  require_no_foreign_nginx_state "$registered" \
    /etc/nginx/conf.d /etc/nginx/sites-enabled "$NGINX_CONFIG" \
    "$NGINX_DEFAULT_ENABLED" "$NGINX_DEFAULT_AVAILABLE" \
    "$NGINX_CERTIFICATE" "$NGINX_PRIVATE_KEY" "$NGINX_INDEX" \
    "$NGINX_FIREWALL_FRAGMENT" "$SERVER_ADDRESS" /usr/sbin/nginx /usr/bin/curl \
    || die 'Foreign or incomplete Nginx state conflicts with this deployment.'

  if [[ -f "$NGINX_TLS_STATE" && ! -L "$NGINX_TLS_STATE" ]]; then
    read -r existing_mode existing_name existing_address < <(_read_installed_nginx_tls_state) \
      || die 'Could not read the existing managed Nginx TLS state.'
    [[ "$existing_address" == "$SERVER_ADDRESS" ]] \
      || die 'The existing managed Nginx TLS state belongs to another server address.'
  elif (( registered == 1 )); then
    existing_mode=self_signed
    existing_name=$SERVER_ADDRESS
    existing_address=$SERVER_ADDRESS
  fi
  if [[ -n "$existing_mode" ]]; then
    bootstrap_required=0
  fi

  _arm_nginx_rollback
  export DEBIAN_FRONTEND=noninteractive
  run_package_manager_command apt-get update
  install_nginx_packages
  if (( NGINX_ROLLBACK_CERTBOT_PACKAGE_INSTALLED == 0 )); then
    systemctl disable --now "$NGINX_NATIVE_CERTBOT_TIMER_UNIT" \
      || die 'Could not disable the redundant native Certbot timer.'
  fi
  _capture_package_created_nginx_default \
    || die 'Could not capture the package-created Nginx default site.'
  disable_stock_nginx_site "$NGINX_DEFAULT_ENABLED" "$NGINX_DEFAULT_AVAILABLE"
  ensure_nginx_index "$NGINX_SITE_ROOT" "$NGINX_INDEX" "$root_dir/templates/nginx-index.html.tmpl"
  install_nginx_subscriptions_location \
    "$root_dir/templates/nginx-subscriptions-location.conf.tmpl" "$NGINX_SUBSCRIPTIONS_LOCATION" \
    || die 'Could not install the managed Nginx subscriptions location.'
  if (( bootstrap_required == 1 )); then
    ensure_nginx_certificate \
      "$NGINX_TLS_DIRECTORY" "$NGINX_CERTIFICATE" "$NGINX_PRIVATE_KEY" "$SERVER_ADDRESS"
    _install_nginx_template_atomically "$root_dir/templates/nginx-site.conf.tmpl" "$NGINX_CONFIG" \
      || die 'Could not install the bootstrap Nginx site configuration.'
  fi
  _install_nginx_template_atomically "$root_dir/templates/50-nginx.nft.tmpl" "$NGINX_FIREWALL_FRAGMENT" \
    || die 'Could not install the Nginx firewall fragment.'
  nginx -t >/dev/null 2>&1 || die 'The bootstrap Nginx configuration is invalid.'
  nft -c -f "$NFTABLES_MAIN_CONFIG" || die 'The firewall configuration is invalid with the Nginx fragment.'
  apply_firewall
  systemctl enable --now nginx.service
  systemctl reload nginx.service

  if [[ "$requested_mode" == self_signed && $bootstrap_required -eq 0 ]]; then
    if [[ "$existing_mode" == self_signed ]]; then
      ensure_nginx_certificate \
        "$NGINX_TLS_DIRECTORY" "$NGINX_CERTIFICATE" "$NGINX_PRIVATE_KEY" "$SERVER_ADDRESS" \
        || die 'Could not validate the existing self-signed Nginx certificate.'
    else
      ensure_nginx_certificate \
        "$NGINX_TLS_DIRECTORY" "$NGINX_CERTIFICATE" "$NGINX_PRIVATE_KEY" "$SERVER_ADDRESS" 1 \
        || die 'Could not install the requested self-signed Nginx certificate.'
    fi
  fi

  install_nginx_runtime_assets "$requested_mode" \
    "${requested_name:-$SERVER_ADDRESS}" "$SERVER_ADDRESS" \
    || die 'Could not install the managed Nginx TLS runtime.'
  if [[ "$requested_mode" == letsencrypt ]]; then
    "$NGINX_RENEW_SCRIPT" || die 'Could not obtain or install the trusted Nginx certificate.'
  fi
  rendered_site=$(mktemp) || die 'Could not create the rendered Nginx site candidate.'
  _render_nginx_site "$requested_mode" "${requested_name:-$SERVER_ADDRESS}" "$rendered_site" \
    || { rm -f -- "$rendered_site"; die 'Could not render the Nginx site configuration.'; }
  _install_nginx_template_atomically "$rendered_site" "$NGINX_CONFIG" \
    || { rm -f -- "$rendered_site"; die 'Could not install the Nginx site configuration.'; }
  rm -f -- "$rendered_site"
  nginx -t >/dev/null 2>&1 || die 'The Nginx configuration is invalid.'
  systemctl reload nginx.service
  verify_nginx_runtime "$requested_mode" "${requested_name:-$SERVER_ADDRESS}" "$SERVER_ADDRESS" \
    || die 'Nginx runtime verification failed.'
  install_nginx_declaration "$root_dir"
  register_nginx_component

  NGINX_ROLLBACK_ARMED=0
  trap - EXIT
  rm -rf -- "$NGINX_ROLLBACK_DIRECTORY"
  log 'Nginx deployment complete.'
}
