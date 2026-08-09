#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

PROJECT_DIRECTORY=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROMPT_VALUE=""

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./admin.sh [COMMAND]

Run without a command for an interactive menu.

Commands:
  accounts
  account create [USERNAME] [EMAIL]
  pair create [USERNAME] [DEVICE_NAME]
  pair list [USERNAME]
  pair revoke [PAIRING_ID] [--yes]
  status
  help

Examples:
  ./admin.sh
  ./admin.sh accounts
  ./admin.sh account create hoff hoff@example.com
  ./admin.sh pair create hoff princess
  ./admin.sh pair list hoff
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

list_accounts() {
    run_admin list-accounts
}

create_account() {
    local username=${1:-}
    local email=${2:-}
    if [[ -z "$username" ]]; then
        prompt_required "Account username"
        username=$PROMPT_VALUE
    fi
    if [[ -z "$email" ]]; then
        prompt_required "Email address"
        email=$PROMPT_VALUE
    fi
    run_admin create-account --username "$username" --email "$email"
}

create_pairing() {
    local username=${1:-}
    local device_name=${2:-}
    if [[ -z "$username" ]]; then
        list_accounts
        printf '\n'
        prompt_required "Account username"
        username=$PROMPT_VALUE
    fi
    if [[ -z "$device_name" ]]; then
        prompt_required "Device name"
        device_name=$PROMPT_VALUE
    fi
    run_admin create-pairing --username "$username" --device-name "$device_name"
}

list_pairings() {
    local username=${1:-}
    if [[ -z "$username" ]]; then
        list_accounts
        printf '\n'
        prompt_required "Account username"
        username=$PROMPT_VALUE
    fi
    run_admin list-pairings --username "$username"
}

revoke_pairing() {
    local pairing_id=${1:-}
    local confirmed=${2:-}
    if [[ -z "$pairing_id" ]]; then
        list_pairings
        printf '\n'
        prompt_required "Pairing ID to revoke"
        pairing_id=$PROMPT_VALUE
    fi
    if [[ "$confirmed" != "--yes" ]]; then
        local answer
        read -r -p "Revoke pairing ${pairing_id}? [y/N] " answer || return 1
        case "$answer" in
            y|Y|yes|YES) ;;
            *)
                printf 'Revocation cancelled.\n'
                return 0
                ;;
        esac
    fi
    run_admin revoke-pairing --pairing-id "$pairing_id"
}

show_status() {
    docker compose ps app
    printf '\nAccounts:\n'
    list_accounts
}

interactive_menu() {
    while true; do
        cat <<'EOF'

PyPasteServer administration
  1) List accounts
  2) Create account
  3) Create device pairing
  4) List device pairings
  5) Revoke device pairing
  6) Server status
  7) Exit
EOF
        local choice
        read -r -p "Choose an action [1-7]: " choice || return 0
        case "$choice" in
            1) list_accounts || true ;;
            2) create_account || true ;;
            3) create_pairing || true ;;
            4) list_pairings || true ;;
            5) revoke_pairing || true ;;
            6) show_status || true ;;
            7) return 0 ;;
            *) printf 'Please choose a number from 1 through 7.\n' ;;
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
    accounts|list-accounts) list_accounts ;;
    account)
        [[ ${2:-} == "create" ]] || fail "use: ./admin.sh account create [USERNAME] [EMAIL]"
        create_account "${3:-}" "${4:-}"
        ;;
    pair)
        case ${2:-} in
            create) create_pairing "${3:-}" "${4:-}" ;;
            list) list_pairings "${3:-}" ;;
            revoke) revoke_pairing "${3:-}" "${4:-}" ;;
            *) fail "use: ./admin.sh pair {create|list|revoke}" ;;
        esac
        ;;
    status) show_status ;;
    *)
        usage >&2
        fail "unknown command: $1"
        ;;
esac
