import configparser
import os
import sys
from pathlib import Path

DEFAULT_CONFIG_CONTENT = """; This is a sample configuration file for the clipboard application

[Paths]
token_file = ~/.config/clipboard_app/token.json
enc_key_file = ~/.config/clipboard_app/key

[Server]
url = http://127.0.0.1:8001

[Encryption]
nonce_size = 24

[Logging]
log_level = INFO
"""

DEFAULT_CONFIG_PATH = Path(os.path.expanduser("~/.config/clipboard_app/config.ini"))


def create_default_config(config_path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Create a default configuration file at config_path."""
    try:
        config_dir = config_path.parent
        config_dir.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as config_file:
            config_file.write(DEFAULT_CONFIG_CONTENT)
        print(f"Default configuration file created at {config_path}.")
    except IOError as exc:
        print(f"Failed to create default configuration file: {exc}", file=sys.stderr)
        sys.exit(1)


def load_config(create_if_missing: bool = False, config_path: Path = DEFAULT_CONFIG_PATH) -> configparser.ConfigParser:
    """Load the application configuration."""
    config = configparser.ConfigParser()

    if not config_path.exists():
        if create_if_missing:
            print(f"Configuration file not found at {config_path}. Creating default configuration.")
            create_default_config(config_path)
            try:
                config.read(config_path)
            except configparser.Error as exc:
                print(f"Error parsing newly-created config: {exc}", file=sys.stderr)
        else:
            print(
                f"Configuration file not found at {config_path}. Using default configuration.",
                file=sys.stderr,
            )
            return config
    else:
        try:
            config.read(config_path)
        except configparser.Error as exc:
            print(f"Error parsing configuration file: {exc}", file=sys.stderr)
            print("Using default configuration values.", file=sys.stderr)
            return config

    return config
