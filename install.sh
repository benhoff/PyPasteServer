#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

PROJECT_DIRECTORY=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ENVIRONMENT_FILE="$PROJECT_DIRECTORY/.env"

START_SERVER=1
BUILD_IMAGE=1
RECONFIGURE=0
CONFIG_OVERRIDDEN=0
SERVER_BIND_OVERRIDE=""
SERVER_PORT_OVERRIDE=""
DATA_DIRECTORY_OVERRIDE=""

info() {
    printf '==> %s\n' "$*"
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./install.sh [OPTIONS]

Configure, build, and start PyPasteServer with Docker Compose.

Options:
  --listen ADDRESS  Host address to publish (default: 127.0.0.1)
  --port PORT       Host port to publish (default: 8001)
  --data-dir PATH   Persistent database directory
                    (default: $XDG_DATA_HOME/pypasteserver or
                    $HOME/.local/share/pypasteserver)
  --reconfigure     Rewrite the installer-managed .env file. The existing JWT
                    secret is preserved.
  --no-build        Reuse the existing server image
  --no-start        Configure and build without starting the stack
  -h, --help        Show this help

Examples:
  ./install.sh
  ./install.sh --listen 0.0.0.0
  ./install.sh --reconfigure --port 9000

Binding to 0.0.0.0 exposes the development HTTP/WebSocket service to the local
network. Use a TLS reverse proxy and wss:// for an Internet-facing deployment.
EOF
}

require_value() {
    local option=$1
    local count=$2
    ((count >= 2)) || fail "$option requires a value"
}

while (($# > 0)); do
    case "$1" in
        --listen)
            require_value "$1" "$#"
            SERVER_BIND_OVERRIDE=$2
            CONFIG_OVERRIDDEN=1
            shift 2
            ;;
        --port)
            require_value "$1" "$#"
            SERVER_PORT_OVERRIDE=$2
            CONFIG_OVERRIDDEN=1
            shift 2
            ;;
        --data-dir)
            require_value "$1" "$#"
            DATA_DIRECTORY_OVERRIDE=$2
            CONFIG_OVERRIDDEN=1
            shift 2
            ;;
        --reconfigure)
            RECONFIGURE=1
            shift
            ;;
        --no-build)
            BUILD_IMAGE=0
            shift
            ;;
        --no-start)
            START_SERVER=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

read_setting() {
    local key=$1
    [[ -f "$ENVIRONMENT_FILE" ]] || return 1
    awk -v key="$key" '
        index($0, key "=") == 1 {
            value = substr($0, length(key) + 2)
        }
        END {
            if (value != "") {
                print value
            } else {
                exit 1
            }
        }
    ' "$ENVIRONMENT_FILE"
}

default_data_directory() {
    if [[ -n "${XDG_DATA_HOME:-}" ]]; then
        printf '%s/pypasteserver\n' "$XDG_DATA_HOME"
    elif [[ -n "${HOME:-}" ]]; then
        printf '%s/.local/share/pypasteserver\n' "$HOME"
    else
        fail "HOME and XDG_DATA_HOME are unavailable; pass --data-dir"
    fi
}

generate_secret() {
    command -v od >/dev/null 2>&1 || fail "od is required to generate JWT_SECRET"
    command -v tr >/dev/null 2>&1 || fail "tr is required to generate JWT_SECRET"
    LC_ALL=C od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

existing_bind=$(read_setting PYP_SERVER_BIND_ADDRESS || true)
existing_port=$(read_setting PYP_SERVER_PORT || true)
existing_data=$(read_setting PYP_SERVER_DATA_DIRECTORY || true)
existing_secret=$(read_setting JWT_SECRET || true)

if [[ -f "$ENVIRONMENT_FILE" && "$CONFIG_OVERRIDDEN" == 1 && "$RECONFIGURE" == 0 ]]; then
    fail "configuration already exists at $ENVIRONMENT_FILE; use --reconfigure to change it"
fi

SERVER_BIND_ADDRESS=${SERVER_BIND_OVERRIDE:-${existing_bind:-127.0.0.1}}
SERVER_PORT=${SERVER_PORT_OVERRIDE:-${existing_port:-8001}}
DATA_DIRECTORY=${DATA_DIRECTORY_OVERRIDE:-${existing_data:-$(default_data_directory)}}
JWT_SECRET_VALUE=${existing_secret:-$(generate_secret)}

[[ -n "$SERVER_BIND_ADDRESS" ]] || fail "listen address must not be empty"
[[ "$SERVER_BIND_ADDRESS" != *[[:space:]/]* ]] || fail "listen address is invalid"
[[ "$SERVER_PORT" =~ ^[0-9]+$ ]] || fail "port must be an integer"
((SERVER_PORT >= 1 && SERVER_PORT <= 65535)) || \
    fail "port must be between 1 and 65535"
[[ -n "$DATA_DIRECTORY" ]] || fail "data directory must not be empty"
[[ "$DATA_DIRECTORY" != *$'\n'* && "$DATA_DIRECTORY" != *$'\r'* ]] || \
    fail "data directory must not contain a newline"
[[ ${#JWT_SECRET_VALUE} -ge 32 ]] || \
    fail "JWT_SECRET must contain at least 32 characters"

if [[ "$DATA_DIRECTORY" != /* ]]; then
    DATA_DIRECTORY="$PROJECT_DIRECTORY/$DATA_DIRECTORY"
fi

write_configuration() {
    local temporary_file
    temporary_file=$(mktemp "$PROJECT_DIRECTORY/.env.XXXXXX")
    {
        printf '# Managed by ./install.sh. Keep this file private.\n'
        printf 'PYP_SERVER_BIND_ADDRESS=%s\n' "$SERVER_BIND_ADDRESS"
        printf 'PYP_SERVER_PORT=%s\n' "$SERVER_PORT"
        printf 'PYP_SERVER_DATA_DIRECTORY=%s\n' "$DATA_DIRECTORY"
        printf 'JWT_SECRET=%s\n' "$JWT_SECRET_VALUE"
        printf 'APP_ENV=development\n'
        printf 'SYNC_REQUIRE_TLS=0\n'
    } >"$temporary_file"
    chmod 600 "$temporary_file"
    mv "$temporary_file" "$ENVIRONMENT_FILE"
}

if [[ ! -f "$ENVIRONMENT_FILE" || "$RECONFIGURE" == 1 ]]; then
    write_configuration
    info "Wrote private configuration to $ENVIRONMENT_FILE"
else
    if [[ -z "$existing_bind" || -z "$existing_port" || \
        -z "$existing_data" || -z "$existing_secret" ]]; then
        fail "$ENVIRONMENT_FILE is not installer-managed or is incomplete; rerun with --reconfigure"
    fi
    info "Using existing configuration from $ENVIRONMENT_FILE"
fi

mkdir -p -- "$DATA_DIRECTORY"
chmod 700 "$DATA_DIRECTORY"

command -v docker >/dev/null 2>&1 || \
    fail "Docker is required; install Docker Engine and its Compose plugin"
docker compose version >/dev/null 2>&1 || \
    fail "the Docker Compose plugin is required (docker compose)"
docker info >/dev/null 2>&1 || \
    fail "cannot access the Docker daemon; start Docker or fix your user permissions"

cd "$PROJECT_DIRECTORY"
docker compose config >/dev/null

if [[ "$BUILD_IMAGE" == 1 ]]; then
    info "Building the PyPasteServer image"
    docker compose build app
fi

if [[ "$START_SERVER" == 1 ]]; then
    info "Starting PyPasteServer and Redis"
    docker compose up -d app
    docker compose ps app
else
    info "Installation configured without starting the server"
    printf 'Start it later with: cd %q && docker compose up -d app\n' "$PROJECT_DIRECTORY"
fi

display_host=$SERVER_BIND_ADDRESS
if [[ "$display_host" == "0.0.0.0" || "$display_host" == "[::]" ]]; then
    display_host="<server-address>"
fi

printf '\nPyPasteServer configuration is ready.\n'
printf '  API:   http://%s:%s\n' "$display_host" "$SERVER_PORT"
printf '  Relay: ws://%s:%s/sync/v1\n' "$display_host" "$SERVER_PORT"
printf '  Data:  %s\n' "$DATA_DIRECTORY"
printf '\nConfigure kclip with that relay URL and allow_insecure_transport=true.\n'
