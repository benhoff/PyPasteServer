import argparse
import os
import sys
from getpass import getpass
from pathlib import Path
from typing import Any

from .auth import login_user, logout_user, prompt_user_details, register_user
from .colors import color_text, style_text
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
        print(
            color_text(
                f"Configuration file not found at {config_path}. Creating default configuration.",
                "yellow",
            )
        )
        create_default_config(config_path)

    server_url = args.server
    token_file = _expand(args.token_file)
    key_file = _expand(args.key_file)

    user_data = prompt_user_details()

    try:
        print(style_text("\nRegistering user...", "bold"))
        token = register_user(server_url, user_data)
        print(color_text("Registration successful.", "green"))
    except ValueError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)
    except ConnectionError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)
    except Exception as exc:
        print(color_text(f"An unexpected error occurred: {exc}", "red"))
        sys.exit(1)

    try:
        generate_and_save_mnemonic(key_file)
    except SystemExit:
        raise
    except Exception as exc:
        print(color_text(f"Failed to handle mnemonic generation: {exc}", "red"))
        sys.exit(1)

    try:
        save_json_data({"access_token": token}, token_file)
    except IOError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)

    print(style_text("\nRegistration and key generation complete.", "bold", "green"))
    print(color_text(f"Access Token saved to: {token_file}", "cyan"))
    print(color_text(f"Byte-Based Key saved to: {key_file}", "cyan"))


def login_command(args: Any) -> None:
    print(style_text("=== User Login ===", "bold", "cyan"))
    username = input("Enter username: ").strip()
    while not username:
        print(color_text("Username cannot be empty.", "yellow"))
        username = input("Enter username: ").strip()

    password = getpass("Enter password: ").strip()
    while not password:
        print(color_text("Password cannot be empty.", "yellow"))
        password = getpass("Enter password: ").strip()

    server_url = args.server
    token_file = _expand(args.token_file)
    key_file = _expand(args.key_file)

    try:
        print(style_text("\nLogging in...", "bold"))
        token = login_user(server_url, username, password)
        print(color_text("Login successful.", "green"))
    except ValueError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)
    except ConnectionError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)
    except Exception as exc:
        print(color_text(f"An unexpected error occurred: {exc}", "red"))
        sys.exit(1)

    try:
        save_json_data({"access_token": token}, token_file)
    except IOError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)

    print(color_text(f"\nAccess Token saved to: {token_file}", "cyan"))

    print(style_text("\n=== Encryption Key Management ===", "bold", "cyan"))
    while True:
        choice = input("Do you want to provide an existing mnemonic? (yes/no): ").strip().lower()
        if choice in {"yes", "y"}:
            mnemonic = prompt_for_mnemonic()
            try:
                save_mnemonic_phrase(mnemonic, key_file)
            except SystemExit:
                raise
            except Exception as exc:
                print(color_text(f"Error saving the mnemonic: {exc}", "red"))
                sys.exit(1)
            break
        if choice in {"no", "n"}:
            generate_and_save_mnemonic(key_file)
            break
        print(color_text("Invalid input. Please enter 'yes' or 'no'.", "yellow"))

    print(style_text("\nLogin and key management complete.", "bold", "green"))
    print(color_text(f"Encryption Key saved to: {key_file}", "cyan"))


def logout_command(args: Any) -> None:
    token_file = _expand(args.token_file)
    try:
        logout_user(token_file)
        print(color_text("Logout successful.", "green"))
    except IOError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)
    except Exception as exc:
        print(color_text(f"An unexpected error occurred: {exc}", "red"))
        sys.exit(1)


def sync_command(args: Any) -> None:
    token_file = _expand(args.token_file)
    try:
        sync_with_server(args.server, token_file)
    except ValueError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)
    except ConnectionError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)
    except Exception as exc:
        print(color_text(f"An unexpected error occurred: {exc}", "red"))
        sys.exit(1)


def key_command(args: Any) -> None:
    key_file = _expand(args.key_file)
    try:
        print_key(key_file)
    except ValueError as exc:
        print(color_text(f"Error: {exc}", "red"))
        sys.exit(1)
    except Exception as exc:
        print(color_text(f"An unexpected error occurred: {exc}", "red"))
        sys.exit(1)


def init_command(args: Any) -> None:
    config_path = DEFAULT_CONFIG_PATH
    config_exists = config_path.exists()
    force_create = getattr(args, "force", False)

    if config_exists and not force_create:
        print(color_text(f"Configuration already exists at {config_path}.", "cyan"))
    else:
        if config_exists and force_create:
            print(color_text(f"Overwriting configuration at {config_path}.", "yellow"))
        else:
            print(color_text(f"Creating configuration at {config_path}.", "cyan"))
        create_default_config(config_path)
        print(color_text("Default configuration ready.", "green"))

    print(style_text("\nGetting Started", "bold", "cyan"))
    print(color_text("1. Review the current configuration details below.", "cyan"))
    print(color_text("2. Register a new account to receive your access token.", "cyan"))
    print(color_text("3. Use `cli.py sync` or `cli.py key` once authenticated.", "cyan"))

    status_command(args)

    if getattr(args, "register", False):
        print(style_text("\nStarting interactive registration...", "bold", "cyan"))
        register_command(args)
    else:
        print(
            color_text(
                "\nRun `cli.py register` when you're ready to create your account.",
                "yellow",
            )
        )


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

    def flag(value: bool, *, yes: str = "yes", no: str = "no") -> str:
        return color_text(yes, "green") if value else color_text(no, "red")

    print(style_text("=== CLI Status ===", "bold", "cyan"))
    config_state = flag(config_exists, yes="present", no="missing")
    print(
        f"Configuration file: {color_text(str(config_path), 'cyan')} ({config_state})"
    )
    print(f"Server URL: {color_text(server_url, 'cyan')}")
    token_state = flag(token_exists, yes="present", no="missing")
    print(f"Token file: {color_text(str(token_file), 'cyan')} ({token_state})")
    print(f"Access token stored: {flag(token_present)}")

    key_state = flag(key_exists, yes="present", no="missing")
    data_descriptor = color_text(" with data", "green") if key_exists and key_has_data else ""
    print(f"Key file: {color_text(str(key_file), 'cyan')} ({key_state}{data_descriptor})")


def help_command(args: Any, parser: argparse.ArgumentParser) -> None:
    if args.subcommand:
        subparsers = parser._subparsers._actions[1].choices  # type: ignore[attr-defined]
        if args.subcommand in subparsers:
            subparsers[args.subcommand].print_help()
        else:
            print(f"No help available for '{args.subcommand}'.")
    else:
        parser.print_help()
