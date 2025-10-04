import argparse
import os
import sys
from getpass import getpass
from pathlib import Path
from typing import Any

from .auth import login_user, logout_user, prompt_user_details, register_user
from .config import DEFAULT_CONFIG_PATH, create_default_config, load_config
from .mnemonic_utils import (
    generate_and_save_mnemonic,
    print_key,
    prompt_for_mnemonic,
    save_mnemonic_phrase,
)
from .storage import load_json_data, save_json_data
from .sync import sync_with_server


def _expand(path: Path) -> Path:
    return Path(os.path.expanduser(str(path)))


def register_command(args: Any) -> None:
    config_path = DEFAULT_CONFIG_PATH
    if not config_path.exists():
        print(f"Configuration file not found at {config_path}. Creating default configuration.")
        create_default_config(config_path)

    server_url = args.server
    token_file = _expand(args.token_file)
    key_file = _expand(args.key_file)

    user_data = prompt_user_details()

    try:
        print("\nRegistering user...")
        token = register_user(server_url, user_data)
        print("Registration successful.")
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except ConnectionError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"An unexpected error occurred: {exc}")
        sys.exit(1)

    try:
        generate_and_save_mnemonic(key_file)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Failed to handle mnemonic generation: {exc}")
        sys.exit(1)

    try:
        save_json_data({"access_token": token}, token_file)
    except IOError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    print("\nRegistration and key generation complete.")
    print(f"Access Token saved to: {token_file}")
    print(f"Byte-Based Key saved to: {key_file}")


def login_command(args: Any) -> None:
    print("=== User Login ===")
    username = input("Enter username: ").strip()
    while not username:
        print("Username cannot be empty.")
        username = input("Enter username: ").strip()

    password = getpass("Enter password: ").strip()
    while not password:
        print("Password cannot be empty.")
        password = getpass("Enter password: ").strip()

    server_url = args.server
    token_file = _expand(args.token_file)
    key_file = _expand(args.key_file)

    try:
        print("\nLogging in...")
        token = login_user(server_url, username, password)
        print("Login successful.")
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except ConnectionError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"An unexpected error occurred: {exc}")
        sys.exit(1)

    try:
        save_json_data({"access_token": token}, token_file)
    except IOError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    print(f"\nAccess Token saved to: {token_file}")

    print("\n=== Encryption Key Management ===")
    while True:
        choice = input("Do you want to provide an existing mnemonic? (yes/no): ").strip().lower()
        if choice in {"yes", "y"}:
            mnemonic = prompt_for_mnemonic()
            try:
                save_mnemonic_phrase(mnemonic, key_file)
            except SystemExit:
                raise
            except Exception as exc:
                print(f"Error saving the mnemonic: {exc}")
                sys.exit(1)
            break
        if choice in {"no", "n"}:
            generate_and_save_mnemonic(key_file)
            break
        print("Invalid input. Please enter 'yes' or 'no'.")

    print("\nLogin and key management complete.")
    print(f"Encryption Key saved to: {key_file}")


def logout_command(args: Any) -> None:
    token_file = _expand(args.token_file)
    try:
        logout_user(token_file)
        print("Logout successful.")
    except IOError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"An unexpected error occurred: {exc}")
        sys.exit(1)


def sync_command(args: Any) -> None:
    token_file = _expand(args.token_file)
    try:
        sync_with_server(args.server, token_file)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except ConnectionError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"An unexpected error occurred: {exc}")
        sys.exit(1)


def key_command(args: Any) -> None:
    key_file = _expand(args.key_file)
    try:
        print_key(key_file)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"An unexpected error occurred: {exc}")
        sys.exit(1)


def status_command(_: Any) -> None:
    config_path = DEFAULT_CONFIG_PATH
    config_exists = config_path.exists()
    config = load_config(create_if_missing=False)

    server_url = config.get("Server", "url", fallback="http://127.0.0.1:8001")
    token_path_raw = config.get("Paths", "token_file", fallback="~/.config/clipboard_app/token.json")
    key_path_raw = config.get("Paths", "enc_key_file", fallback="~/.config/clipboard_app/key")

    token_file = _expand(Path(token_path_raw))
    key_file = _expand(Path(key_path_raw))

    token_exists = token_file.exists()
    token_data = load_json_data(token_file) if token_exists else None
    token_present = bool(token_data and token_data.get("access_token"))

    key_exists = key_file.exists()
    key_has_data = False
    if key_exists:
        try:
            key_has_data = key_file.stat().st_size > 0
        except OSError:
            key_has_data = False

    print("=== CLI Status ===")
    print(f"Configuration file: {config_path} ({'present' if config_exists else 'missing'})")
    print(f"Server URL: {server_url}")
    print(f"Token file: {token_file} ({'present' if token_exists else 'missing'})")
    print(f"Access token stored: {'yes' if token_present else 'no'}")
    print(
        f"Key file: {key_file} ("
        f"{'present' if key_exists else 'missing'}"
        f"{' with data' if key_exists and key_has_data else ''}"
        f")"
    )


def help_command(args: Any, parser: argparse.ArgumentParser) -> None:
    if args.subcommand:
        subparsers = parser._subparsers._actions[1].choices  # type: ignore[attr-defined]
        if args.subcommand in subparsers:
            subparsers[args.subcommand].print_help()
        else:
            print(f"No help available for '{args.subcommand}'.")
    else:
        parser.print_help()
