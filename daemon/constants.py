from pathlib import Path

DEFAULT_CONFIG = {
    'Paths': {
        'token_file': str(Path.home() / '.config/clipboard_app/token.json'),
        'enc_key_file': str(Path.home() / '.config/clipboard_app/key'),
    },
    'Server': {
        'url': 'https://default.server.com',
    },
    'Encryption': {
        'nonce_size': '24',
    },
    'Retry': {
        'max_retries': '5',
    },
}

APP_CONFIG_PATH = str(Path.home() / '.config/clipboard_app/config.ini')
