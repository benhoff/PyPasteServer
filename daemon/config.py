import os
import configparser
from .constants import DEFAULT_CONFIG, APP_CONFIG_PATH


def strip_http_prefix(url: str) -> str:
    if url.startswith('http://'):
        return url[len('http://'):]
    if url.startswith('https://'):
        return url[len('https://'):]
    return url


def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_dict(DEFAULT_CONFIG)

    if os.path.exists(APP_CONFIG_PATH):
        try:
            cfg.read(APP_CONFIG_PATH)
            print(f"Configuration loaded from {APP_CONFIG_PATH}.")
        except configparser.Error as e:
            print(f"Error parsing configuration file: {e}")
            print("Using default configuration values.")
    else:
        print(f"Configuration file not found at {APP_CONFIG_PATH}. Using default configuration.")
    return cfg


cfg = load_config()
TOKEN_FILE = os.path.expanduser(cfg.get('Paths', 'token_file', fallback=DEFAULT_CONFIG['Paths']['token_file']))
ENC_KEY_FILE = os.path.expanduser(cfg.get('Paths', 'enc_key_file', fallback=DEFAULT_CONFIG['Paths']['enc_key_file']))
SERVER_URL = strip_http_prefix(cfg.get('Server', 'url', fallback=DEFAULT_CONFIG['Server']['url']))
NONCE_SIZE = cfg.getint('Encryption', 'nonce_size', fallback=int(DEFAULT_CONFIG['Encryption']['nonce_size']))
MAX_RETRIES = cfg.getint('Retry', 'max_retries', fallback=int(DEFAULT_CONFIG['Retry']['max_retries']))
