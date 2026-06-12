#!/bin/sh
set -eu

# Fill these in if you want non-interactive defaults. Leave empty to prompt.
DOCKER_IMAGE_REPOSITORY="${DOCKER_IMAGE_REPOSITORY:-}"
DOCKER_IMAGE="${DOCKER_IMAGE:-}"

DEFAULT_CONFIG_DIR="/etc/uscf"
DEFAULT_MASQUE_CONTAINER="uscf"
DEFAULT_WG_CONTAINER="uscf-wg"

say() {
    printf '%s\n' "$*"
}

die() {
    say "error: $*" >&2
    exit 1
}

trim() {
    # shellcheck disable=SC2001
    printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

prompt() {
    label=$1
    default=${2:-}
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$label" "$default" >&2
    else
        printf '%s: ' "$label" >&2
    fi
    IFS= read -r value || value=""
    value=$(trim "$value")
    if [ -z "$value" ]; then
        value=$default
    fi
    printf '%s' "$value"
}

prompt_required() {
    label=$1
    default=${2:-}
    while :; do
        value=$(prompt "$label" "$default")
        if [ -n "$value" ]; then
            printf '%s' "$value"
            return
        fi
        say "This value is required." >&2
    done
}

prompt_yes_no() {
    label=$1
    default=${2:-n}
    while :; do
        answer=$(prompt "$label (y/n)" "$default")
        case "$answer" in
            y|Y|yes|YES|Yes) return 0 ;;
            n|N|no|NO|No) return 1 ;;
            *) say "Please enter y or n." >&2 ;;
        esac
    done
}

prompt_port() {
    label=$1
    default=$2
    while :; do
        port=$(prompt "$label" "$default")
        case "$port" in
            ''|*[!0-9]*)
                say "Port must be a number between 1 and 65535." >&2
                ;;
            *)
                if [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
                    printf '%s' "$port"
                    return
                fi
                say "Port must be a number between 1 and 65535." >&2
                ;;
        esac
    done
}

choose_mode() {
    say "Select deployment mode:" >&2
    say "  1) MASQUE/usque" >&2
    say "  2) WireGuard" >&2
    while :; do
        choice=$(prompt "Mode" "1")
        case "$choice" in
            1|masque|MASQUE|usque|USQUE) printf '%s' "masque"; return ;;
            2|wg|WG|wireguard|WireGuard) printf '%s' "wg"; return ;;
            *) say "Please choose 1 or 2." >&2 ;;
        esac
    done
}

choose_account_mode() {
    say "Select account mode:" >&2
    say "  1) Free account" >&2
    say "  2) Premium team account with JWT" >&2
    say "  3) Premium personal account with WARP+ key" >&2
    while :; do
        choice=$(prompt "Account mode" "1")
        case "$choice" in
            1|free|FREE) printf '%s' "free"; return ;;
            2|team|TEAM|jwt|JWT) printf '%s' "team"; return ;;
            3|premium|PREMIUM|key|KEY|license|LICENSE) printf '%s' "premium"; return ;;
            *) say "Please choose 1, 2, or 3." >&2 ;;
        esac
    done
}

choose_image_tag() {
    mode=$1

    if [ "$mode" = "masque" ]; then
        stable_tag="latest"
        dev_tag="dev"
    else
        stable_tag="wg-latest"
        dev_tag="wg-dev"
    fi

    say "Select Docker image tag:" >&2
    say "  1) ${stable_tag} (stable)" >&2
    say "  2) ${dev_tag} (testing)" >&2
    say "  3) custom tag" >&2
    while :; do
        choice=$(prompt "Image tag" "1")
        case "$choice" in
            1|stable|STABLE|latest|wg-latest) printf '%s' "$stable_tag"; return ;;
            2|dev|DEV|testing|TESTING|wg-dev) printf '%s' "$dev_tag"; return ;;
            3|custom|CUSTOM)
                custom_tag=$(prompt_required "Custom tag")
                printf '%s' "$custom_tag"
                return
                ;;
            *)
                if [ -n "$choice" ]; then
                    printf '%s' "$choice"
                    return
                fi
                say "Please choose 1, 2, 3, or enter a tag." >&2
                ;;
        esac
    done
}

resolve_image() {
    mode=$1

    if [ -n "$DOCKER_IMAGE" ]; then
        say "Using full Docker image from DOCKER_IMAGE: ${DOCKER_IMAGE}" >&2
        printf '%s' "$DOCKER_IMAGE"
        return
    fi

    repository=$(prompt_required "Docker image repository, without tag" "$DOCKER_IMAGE_REPOSITORY")
    tag=$(choose_image_tag "$mode")
    printf '%s:%s' "$repository" "$tag"
}

require_docker() {
    command -v docker >/dev/null 2>&1 || die "docker is not installed or not in PATH"
}

write_config() {
    config_dir=$1
    bind_address=$2
    port=$3
    username=$4
    password=$5
    use_ipv6=$6
    include_use_ipv6=$7

    mkdir -p "$config_dir"
    config_file="${config_dir}/config.json"

    if [ -f "$config_file" ]; then
        if ! prompt_yes_no "config.json already exists. Overwrite SOCKS settings" "n"; then
            say "Keeping existing ${config_file}."
            return
        fi
    fi

    bind_json=$(json_escape "$bind_address")
    port_json=$(json_escape "$port")
    username_json=$(json_escape "$username")
    password_json=$(json_escape "$password")

    umask 077
    if [ "$include_use_ipv6" = "true" ]; then
        cat > "$config_file" <<EOF
{
  "socks": {
    "bind_address": "${bind_json}",
    "port": "${port_json}",
    "username": "${username_json}",
    "password": "${password_json}",
    "use_ipv6": ${use_ipv6}
  },
  "logging": {
    "level": "info",
    "format": "text",
    "socks_verbose": false
  },
  "registration": {
    "device_name": "uscf"
  }
}
EOF
    else
        cat > "$config_file" <<EOF
{
  "socks": {
    "bind_address": "${bind_json}",
    "port": "${port_json}",
    "username": "${username_json}",
    "password": "${password_json}"
  },
  "logging": {
    "level": "info",
    "format": "text",
    "socks_verbose": false
  }
}
EOF
    fi
    say "Wrote ${config_file}."
}

remove_existing_container() {
    container_name=$1
    if docker ps -a --format '{{.Names}}' | grep -Fx "$container_name" >/dev/null 2>&1; then
        if prompt_yes_no "Container ${container_name} already exists. Remove and recreate it" "y"; then
            docker rm -f "$container_name" >/dev/null
        else
            die "container ${container_name} already exists"
        fi
    fi
}

run_helper() {
    image=$1
    config_dir=$2
    shift 2
    docker run --rm \
        -v "${config_dir}:/app/etc" \
        --entrypoint /bin/uscf \
        "$image" "$@"
}

prepare_wg_state() {
    image=$1
    config_dir=$2
    account_mode=$3
    account_secret=$4

    account_path="${config_dir}/wg-account.json"
    profile_path="${config_dir}/wgcf.conf"
    mkdir -p "$config_dir"

    if [ "$account_mode" = "premium" ]; then
        if [ -f "$account_path" ]; then
            say "Updating existing WireGuard account with WARP+ key..."
            run_helper "$image" "$config_dir" wg update \
                --wg-account /app/etc/wg-account.json \
                --license "$account_secret"
        else
            say "Registering WireGuard account with WARP+ key..."
            run_helper "$image" "$config_dir" wg register \
                --accept-tos \
                --wg-account /app/etc/wg-account.json \
                --license "$account_secret"
        fi

        say "Generating WireGuard profile..."
        run_helper "$image" "$config_dir" wg generate \
            --wg-account /app/etc/wg-account.json \
            --profile /app/etc/wgcf.conf

        [ -f "$profile_path" ] || die "failed to generate ${profile_path}"
        return
    fi

    if [ -f "$profile_path" ]; then
        if [ "$account_mode" = "team" ]; then
            say "Existing WireGuard profile found; Team JWT is only used when registering new WireGuard state."
        fi
        return
    fi

    if [ ! -f "$account_path" ]; then
        if [ "$account_mode" = "team" ]; then
            say "Registering WireGuard team account..."
            run_helper "$image" "$config_dir" wg register \
                --accept-tos \
                --wg-account /app/etc/wg-account.json \
                --jwt "$account_secret"
        else
            say "Registering WireGuard free account..."
            run_helper "$image" "$config_dir" wg register \
                --accept-tos \
                --wg-account /app/etc/wg-account.json
        fi
    fi

    say "Generating WireGuard profile..."
    run_helper "$image" "$config_dir" wg generate \
        --wg-account /app/etc/wg-account.json \
        --profile /app/etc/wgcf.conf

    [ -f "$profile_path" ] || die "failed to generate ${profile_path}"
}

run_masque_container() {
    image=$1
    container_name=$2
    config_dir=$3
    account_mode=$4
    account_secret=$5

    remove_existing_container "$container_name"

    set -- docker run -d \
        --name "$container_name" \
        --network=host \
        -v "${config_dir}:/app/etc" \
        --log-driver json-file \
        --log-opt max-size=3m \
        --restart unless-stopped \
        "$image"

    case "$account_mode" in
        team) set -- "$@" --jwt "$account_secret" ;;
        premium) set -- "$@" --license "$account_secret" ;;
    esac

    "$@"
}

run_wg_container() {
    image=$1
    container_name=$2
    config_dir=$3
    port=$4
    account_mode=$5
    account_secret=$6
    enable_ipv6=$7

    remove_existing_container "$container_name"

    set -- docker run -d \
        --name "$container_name" \
        --privileged \
        -p "${port}:${port}" \
        -v "${config_dir}:/app/etc" \
        --restart unless-stopped

    if [ "$enable_ipv6" = "true" ]; then
        set -- "$@" \
            --sysctl net.ipv6.conf.all.disable_ipv6=0 \
            --sysctl net.ipv6.conf.default.disable_ipv6=0
    fi

    if [ "$account_mode" = "team" ]; then
        set -- "$@" -e "WG_TEAM_JWT=${account_secret}"
    fi

    set -- "$@" "$image"
    "$@"
}

main() {
    require_docker

    say "USCF interactive Docker deployment"
    say "This script writes config.json and starts a Docker container."
    say ""

    mode=$(choose_mode)
    account_mode=$(choose_account_mode)
    account_secret=""
    case "$account_mode" in
        team) account_secret=$(prompt_required "Team JWT") ;;
        premium) account_secret=$(prompt_required "WARP+ license key") ;;
    esac

    if [ "$mode" = "masque" ]; then
        say "Image repository example: ghcr.io/hynor/uscf"
        default_container=$DEFAULT_MASQUE_CONTAINER
        include_use_ipv6=true
    else
        say "Image repository example: ghcr.io/hynor/uscf"
        default_container=$DEFAULT_WG_CONTAINER
        include_use_ipv6=false
    fi

    image=$(resolve_image "$mode")
    config_dir=$(prompt_required "Host config directory" "$DEFAULT_CONFIG_DIR")
    container_name=$(prompt_required "Container name" "$default_container")
    bind_address=$(prompt "SOCKS5 bind address" "0.0.0.0")
    port=$(prompt_port "SOCKS5 port" "1080")
    username=$(prompt "SOCKS5 username, empty disables auth" "")
    password=""
    if [ -n "$username" ]; then
        password=$(prompt_required "SOCKS5 password")
    else
        password=$(prompt "SOCKS5 password, empty disables auth" "")
    fi

    use_ipv6=false
    if [ "$mode" = "masque" ]; then
        if prompt_yes_no "Use IPv6 endpoint for MASQUE connection (socks.use_ipv6)" "n"; then
            use_ipv6=true
        fi
    else
        if prompt_yes_no "Enable IPv6 inside the WireGuard container" "y"; then
            use_ipv6=true
        fi
    fi

    say ""
    say "Summary:"
    say "  mode: ${mode}"
    say "  account: ${account_mode}"
    say "  image: ${image}"
    say "  config dir: ${config_dir}"
    say "  container: ${container_name}"
    say "  socks: ${bind_address}:${port}"
    if [ "$mode" = "masque" ]; then
        say "  socks.use_ipv6: ${use_ipv6}"
    else
        say "  container ipv6 sysctl: ${use_ipv6}"
    fi
    say ""

    if ! prompt_yes_no "Continue and deploy" "y"; then
        die "deployment cancelled"
    fi

    if [ "$mode" = "wg" ]; then
        prepare_wg_state "$image" "$config_dir" "$account_mode" "$account_secret"
    fi

    write_config "$config_dir" "$bind_address" "$port" "$username" "$password" "$use_ipv6" "$include_use_ipv6"

    if [ "$mode" = "masque" ]; then
        container_id=$(run_masque_container "$image" "$container_name" "$config_dir" "$account_mode" "$account_secret")
    else
        container_id=$(run_wg_container "$image" "$container_name" "$config_dir" "$port" "$account_mode" "$account_secret" "$use_ipv6")
    fi

    say "Started container ${container_name}: ${container_id}"
    say "View logs with: docker logs -f ${container_name}"
}

main "$@"
