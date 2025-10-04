import argparse
import os
from pathlib import Path
from typing import Any

from .commands import (
    help_command,
    key_command,
    login_command,
    logout_command,
    register_command,
    sync_command,
)


def _default_path(config: Any, section: str, option: str, fallback: str) -> Path:
    value = config.get(section, option, fallback=fallback)
    return Path(os.path.expanduser(value))


def build_parser(config: Any) -> argparse.ArgumentParser:
    server_url = config.get("Server", "url", fallback="http://127.0.0.1:8001")
    token_file = _default_path(config, "Paths", "token_file", "~/.config/clipboard_app/token.json")
    key_file = _default_path(config, "Paths", "enc_key_file", "~/.config/clipboard_app/key")

    parser = argparse.ArgumentParser(
        description="Command-Line Clipboard Application",
        usage="python cli.py <command> [<args>]",
    )
    subparsers = parser.add_subparsers(title="Commands", dest="command")

    parser_register = subparsers.add_parser("register", help="Register with the configured server")
    parser_register.add_argument(
        "--server",
        type=str,
        default=server_url,
        help=f"URL of the registration server (default: {server_url})",
    )
    parser_register.add_argument(
        "--token-file",
        type=Path,
        default=token_file,
        help=f"Path to save the access token (default: {token_file})",
    )
    parser_register.add_argument(
        "--key-file",
        type=Path,
        default=key_file,
        help=f"Path to save the byte-based key (default: {key_file})",
    )
    parser_register.set_defaults(func=register_command)

    parser_login = subparsers.add_parser("login", help="Login to the configured server")
    parser_login.add_argument(
        "--server",
        type=str,
        default=server_url,
        help=f"URL of the server (default: {server_url})",
    )
    parser_login.add_argument(
        "--token-file",
        type=Path,
        default=token_file,
        help=f"Path to save the access token (default: {token_file})",
    )
    parser_login.add_argument(
        "--key-file",
        type=Path,
        default=key_file,
        help=f"Path to save the byte-based key (default: {key_file})",
    )
    parser_login.set_defaults(func=login_command)

    parser_logout = subparsers.add_parser("logout", help="Log out")
    parser_logout.add_argument(
        "--token-file",
        type=Path,
        default=token_file,
        help=f"Path to the access token file (default: {token_file})",
    )
    parser_logout.add_argument(
        "--key-file",
        type=Path,
        default=key_file,
        help=f"Path to the byte-based key file (default: {key_file})",
    )
    parser_logout.set_defaults(func=logout_command)

    parser_sync = subparsers.add_parser("sync", help="Sync with the configured server")
    parser_sync.add_argument(
        "--server",
        type=str,
        default=server_url,
        help=f"URL of the server (default: {server_url})",
    )
    parser_sync.add_argument(
        "--token-file",
        type=Path,
        default=token_file,
        help=f"Path to the access token file (default: {token_file})",
    )
    parser_sync.set_defaults(func=sync_command)

    parser_key = subparsers.add_parser(
        "key", help="Print the encryption key for transfer to another machine"
    )
    parser_key.add_argument(
        "--key-file",
        type=Path,
        default=key_file,
        help=f"Path to the byte-based key file (default: {key_file})",
    )
    parser_key.set_defaults(func=key_command)

    parser_help = subparsers.add_parser(
        "help",
        help="Print this message or the help of the given subcommand(s)",
    )
    parser_help.add_argument("subcommand", nargs="?", help="Subcommand to get help for")
    parser_help.set_defaults(func=lambda args: help_command(args, parser))

    return parser
