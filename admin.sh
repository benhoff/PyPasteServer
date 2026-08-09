#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

PROJECT_DIRECTORY=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ENVIRONMENT_FILE="$PROJECT_DIRECTORY/.env"
PROMPT_VALUE=""
SELECTED_ACCOUNT=""
SELECTED_RELAY_URL=""

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./admin.sh [COMMAND]

Run without a command for an interactive menu.

Commands:
  device add [USERNAME] [DEVICE_NAME]
  device list [USERNAME]
  device revoke [PAIRING_ID] [--yes]
  diagnose
  account list
  account create [USERNAME]
  help

Examples:
  ./admin.sh
  ./admin.sh device add
  ./admin.sh device add hoff princess
  ./admin.sh device list hoff
  ./admin.sh diagnose
  ./admin.sh account create hoff
EOF
}

prompt_required() {
    local label=$1
    local value=""
    while [[ -z "$value" ]]; do
        read -r -p "${label}: " value || return 1
    done
    PROMPT_VALUE=$value
}

require_server() {
    command -v docker >/dev/null 2>&1 || fail "Docker is not installed"
    docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is unavailable"
    docker info >/dev/null 2>&1 || fail "cannot access the Docker daemon"

    local container_id running
    container_id=$(docker compose ps -q app 2>/dev/null || true)
    [[ -n "$container_id" ]] || fail \
        "PyPasteServer is not running; start it with ./install.sh"
    running=$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)
    [[ "$running" == "true" ]] || fail \
        "the PyPasteServer app container is not running; inspect docker compose logs app"
}

run_admin() {
    (
        cd "$PROJECT_DIRECTORY"
        docker compose exec -T app python -m server_app.admin "$@"
    )
}

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

resolve_relay_url() {
    local configured bind port
    configured=$(read_setting PYP_SERVER_PUBLIC_RELAY_URL || true)
    if [[ -n "$configured" ]]; then
        printf '%s\n' "$configured"
        return 0
    fi

    bind=$(read_setting PYP_SERVER_BIND_ADDRESS || true)
    port=$(read_setting PYP_SERVER_PORT || true)
    bind=${bind:-0.0.0.0}
    port=${port:-8001}
    case "$bind" in
        0.0.0.0|'[::]') return 1 ;;
        *) printf 'ws://%s:%s/sync/v1\n' "$bind" "$port" ;;
    esac
}

valid_relay_url() {
    local value=$1
    [[ "$value" =~ ^wss?://[^/[:space:]]+/sync/v1$ ]]
}

select_relay_url() {
    local relay
    relay=$(resolve_relay_url || true)
    if [[ -n "$relay" ]]; then
        SELECTED_RELAY_URL=$relay
        return 0
    fi

    if [[ ! -t 0 ]]; then
        fail "the client-facing relay URL is unknown; configure it with ./install.sh --reconfigure --relay-url URL"
    fi

    printf '%s\n' \
        "The server listens on all interfaces, so its client-facing address cannot be inferred." \
        "Enter the address clients will use, including /sync/v1."
    while true; do
        prompt_required "Relay URL (ws:// or wss://)" || return 1
        relay=$PROMPT_VALUE
        if valid_relay_url "$relay"; then
            SELECTED_RELAY_URL=$relay
            return 0
        fi
        printf 'Use a URL such as ws://clipboard.home:8001/sync/v1.\n'
    done
}

list_accounts() {
    run_admin account list
}

create_account() {
    local username=${1:-}
    if [[ -z "$username" ]]; then
        prompt_required "Account username" || return 1
        username=$PROMPT_VALUE
    fi
    run_admin account create --username "$username"
}

create_account_for_device() {
    local username
    prompt_required "New account username" || return 1
    username=$PROMPT_VALUE
    create_account "$username" || return 1
    SELECTED_ACCOUNT=$username
}

select_account() {
    local listing choice line index username active total
    local -a rows=()
    listing=$(run_admin account list) || return 1

    if [[ "$listing" == "No accounts" ]]; then
        printf 'No accounts exist yet. Create the first account for this device.\n\n'
        create_account_for_device || return 1
        return 0
    fi

    while IFS= read -r line; do
        [[ -n "$line" && "$line" != USERNAME$'\t'* ]] && rows+=("$line")
    done <<<"$listing"
    ((${#rows[@]} > 0)) || fail "could not read the account list"

    printf 'Choose the account this device belongs to:\n'
    for index in "${!rows[@]}"; do
        IFS=$'\t' read -r username active total <<<"${rows[$index]}"
        printf '  %d) %s (%s active device(s))\n' \
            "$((index + 1))" "$username" "$active"
    done
    printf '  %d) Create a new account\n' "$((${#rows[@]} + 1))"

    while true; do
        read -r -p "Choose an account [1-$((${#rows[@]} + 1))]: " choice || return 1
        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#rows[@]})); then
            line=${rows[$((choice - 1))]}
            SELECTED_ACCOUNT=${line%%$'\t'*}
            return 0
        fi
        if [[ "$choice" == "$((${#rows[@]} + 1))" ]]; then
            create_account_for_device || return 1
            return 0
        fi
        printf 'Please choose a number from 1 through %d.\n' "$((${#rows[@]} + 1))"
    done
}

show_client_handoff() {
    cat <<'EOF'

Next steps on the client device
  1. Run:  kclip sync setup
  2. Paste the client setup code shown above into the hidden prompt.

The setup code configures the relay and authenticates this device. It does not
contain the separate account encryption key shared between client devices.
EOF
}

connect_device() {
    local username=${1:-}
    local device_name=${2:-}
    select_relay_url || return 1
    if [[ -z "$username" ]]; then
        select_account || return 1
        username=$SELECTED_ACCOUNT
    fi
    if [[ -z "$device_name" ]]; then
        prompt_required "Device name (for example, office-laptop)" || return 1
        device_name=$PROMPT_VALUE
    fi

    printf '\nCreating a credential for %s on account %s...\n\n' "$device_name" "$username"
    run_admin device add \
        --username "$username" \
        --device-name "$device_name" \
        --relay-url "$SELECTED_RELAY_URL" || return 1
    show_client_handoff
}

list_devices() {
    local username=${1:-}
    if [[ -z "$username" ]]; then
        select_account || return 1
        username=$SELECTED_ACCOUNT
    fi
    run_admin device list --username "$username"
}

review_devices() {
    local username=${1:-}
    local listing line id state name last_used
    if [[ -z "$username" ]]; then
        select_account || return 1
        username=$SELECTED_ACCOUNT
    fi
    printf '\nDevices for %s:\n' "$username"
    listing=$(list_devices "$username") || return 1
    if [[ "$listing" == "No devices" ]]; then
        printf '  No devices have been added.\n'
        return 0
    fi
    while IFS= read -r line; do
        IFS=$'\t' read -r id state name last_used <<<"$line"
        printf '  %s — %s — %s\n' "$name" "$state" "$last_used"
        printf '    ID: %s\n' "$id"
    done <<<"$listing"
}

revoke_device() {
    local pairing_id=${1:-}
    local confirmed=${2:-}
    [[ -n "$pairing_id" ]] || fail "device revoke requires a pairing ID"
    if [[ "$confirmed" != "--yes" ]]; then
        local answer
        read -r -p "Revoke device ${pairing_id}? [y/N] " answer || return 1
        case "$answer" in
            y|Y|yes|YES) ;;
            *)
                printf 'Revocation cancelled.\n'
                return 0
                ;;
        esac
    fi
    run_admin device revoke --pairing-id "$pairing_id"
}

select_and_revoke_device() {
    local username=${1:-}
    local listing line choice index id state name last_used
    local -a ids=() labels=()
    if [[ -z "$username" ]]; then
        select_account || return 1
        username=$SELECTED_ACCOUNT
    fi
    listing=$(run_admin device list --username "$username") || return 1
    if [[ "$listing" == "No devices" ]]; then
        printf 'No devices have been added for %s.\n' "$username"
        return 0
    fi

    while IFS= read -r line; do
        IFS=$'\t' read -r id state name last_used <<<"$line"
        if [[ "$state" == "active" ]]; then
            ids+=("$id")
            labels+=("$name ($last_used)")
        fi
    done <<<"$listing"
    if ((${#ids[@]} == 0)); then
        printf 'No active devices remain for %s.\n' "$username"
        return 0
    fi

    printf 'Choose a device to revoke from %s:\n' "$username"
    for index in "${!ids[@]}"; do
        printf '  %d) %s\n' "$((index + 1))" "${labels[$index]}"
    done
    while true; do
        read -r -p "Choose a device [1-${#ids[@]}]: " choice || return 1
        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#ids[@]})); then
            revoke_device "${ids[$((choice - 1))]}"
            return 0
        fi
        printf 'Please choose a number from 1 through %d.\n' "${#ids[@]}"
    done
}

show_diagnosis() {
    local relay bind
    docker compose ps app redis
    printf '\nServer configuration:\n'
    bind=$(read_setting PYP_SERVER_BIND_ADDRESS || true)
    printf '  Listen address: %s:%s\n' "${bind:-unknown}" "$(read_setting PYP_SERVER_PORT || printf 'unknown')"
    relay=$(resolve_relay_url || true)
    if [[ -n "$relay" ]]; then
        printf '  Client relay:  %s\n' "$relay"
    else
        printf '  Client relay:  not configured\n'
        printf '  Next action:   ./install.sh --reconfigure --relay-url ws://HOST:PORT/sync/v1\n'
    fi
    printf '\nAccounts:\n'
    list_accounts
}

manage_accounts_menu() {
    while true; do
        cat <<'EOF'

Account management
  1) List accounts
  2) Create account
  3) Back
EOF
        local choice
        read -r -p "Choose an action [1-3]: " choice || return 0
        case "$choice" in
            1) list_accounts || true ;;
            2) create_account || true ;;
            3) return 0 ;;
            *) printf 'Please choose a number from 1 through 3.\n' ;;
        esac
    done
}

interactive_menu() {
    while true; do
        cat <<'EOF'

PyPasteServer administration
  1) Connect a new device
  2) Review devices
  3) Revoke a device
  4) Manage accounts
  5) Diagnose server
  6) Exit
EOF
        local choice
        read -r -p "Choose an action [1-6]: " choice || return 0
        case "$choice" in
            1) connect_device || true ;;
            2) review_devices || true ;;
            3) select_and_revoke_device || true ;;
            4) manage_accounts_menu || true ;;
            5) show_diagnosis || true ;;
            6) return 0 ;;
            *) printf 'Please choose a number from 1 through 6.\n' ;;
        esac
    done
}

cd "$PROJECT_DIRECTORY"
case ${1:-} in
    help|-h|--help)
        usage
        exit 0
        ;;
esac
require_server

case ${1:-} in
    "") interactive_menu ;;
    account)
        case ${2:-} in
            list) list_accounts ;;
            create) create_account "${3:-}" ;;
            *) fail "use: ./admin.sh account {list|create}" ;;
        esac
        ;;
    device)
        case ${2:-} in
            add) connect_device "${3:-}" "${4:-}" ;;
            list) review_devices "${3:-}" ;;
            revoke)
                if [[ -n ${3:-} ]]; then
                    revoke_device "${3:-}" "${4:-}"
                else
                    select_and_revoke_device
                fi
                ;;
            *) fail "use: ./admin.sh device {add|list|revoke}" ;;
        esac
        ;;
    diagnose) show_diagnosis ;;
    *)
        usage >&2
        fail "unknown command: $1"
        ;;
esac
