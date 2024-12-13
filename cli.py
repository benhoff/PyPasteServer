#!/usr/bin/env python3

import requests
import json
import os
import sys
from getpass import getpass
from pathlib import Path
from mnemonic import Mnemonic  # BIP39 library
import binascii
import argparse

# Constants for default file paths
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"
DEFAULT_TOKEN_FILE = Path.home() / ".clipboard_app" / "token.json"
DEFAULT_KEY_FILE = Path.home() / ".clipboard_app" / "key.json"

def prompt_user_details():
    """
    Prompt the user for username, email, and password.
    Returns a dictionary with the collected data.
    """
    print("=== User Registration ===")
    username = input("Enter username: ").strip()
    while not username:
        print("Username cannot be empty.")
        username = input("Enter username: ").strip()
    
    email = input("Enter email: ").strip()
    while not email:
        print("Email cannot be empty.")
        email = input("Enter email: ").strip()
    
    password = getpass("Enter password: ").strip()
    while not password:
        print("Password cannot be empty.")
        password = getpass("Enter password: ").strip()
    
    confirm_password = getpass("Confirm password: ").strip()
    while password != confirm_password:
        print("Passwords do not match. Please try again.")
        password = getpass("Enter password: ").strip()
        confirm_password = getpass("Confirm password: ").strip()
    
    return {
        "username": username,
        "email": email,
        "password": password
    }

def register_user(server_url, user_data):
    """
    Send a POST request to the /register endpoint with user_data.
    Returns the access token if successful.
    Raises exceptions for HTTP errors or connection issues.
    """
    register_endpoint = f"{server_url}/register"
    headers = {
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(register_endpoint, headers=headers, json=user_data)
        if response.status_code == 200:
            data = response.json()
            access_token = data.get("access_token")
            if not access_token:
                raise ValueError("Access token not found in the response.")
            return access_token
        elif response.status_code == 400:
            # Handle bad request, e.g., username or email already exists
            error_detail = response.json().get("detail", "Bad Request")
            raise ValueError(f"Registration failed: {error_detail}")
        else:
            # Handle other HTTP errors
            response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to connect to the server: {e}")

def login_user(server_url, username, password):
    """
    Send a POST request to the /login endpoint with username and password.
    Returns the access token if successful.
    Raises exceptions for HTTP errors or connection issues.
    """
    login_endpoint = f"{server_url}/login"
    data = {
        "username": username,
        "password": password
    }
    headers = {
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(login_endpoint, headers=headers, json=data)
        if response.status_code == 200:
            data = response.json()
            access_token = data.get("access_token")
            if not access_token:
                raise ValueError("Access token not found in the response.")
            return access_token
        elif response.status_code == 401:
            error_detail = response.json().get("detail", "Unauthorized")
            raise ValueError(f"Login failed: {error_detail}")
        else:
            response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to connect to the server: {e}")

def logout_user(token_file, key_file):
    """
    Log out the user by deleting the stored token and key files.
    """
    try:
        if token_file.exists():
            token_file.unlink()
            print(f"Access token '{token_file}' deleted successfully.")
        else:
            print(f"No access token found at '{token_file}'.")
        
    except Exception as e:
        raise IOError(f"Failed to delete files: {e}")

def generate_mnemonic():
    """
    Generate a BIP39 compliant mnemonic phrase.
    Returns the mnemonic as a string.
    """
    mnemo = Mnemonic("english")
    entropy = mnemo.generate(strength=256)  # 12-word mnemonic
    return entropy

def derive_seed(mnemonic, passphrase=''):
    """
    Derive a binary seed from the mnemonic and optional passphrase.
    Returns the seed as bytes.
    """
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic, passphrase)
    return seed

def convert_seed_to_hex(seed_bytes):
    """
    Convert seed bytes to a hexadecimal string.
    Returns the hex string.
    """
    return binascii.hexlify(seed_bytes).decode()

def save_data(data, filepath):
    """
    Save data to a specified file in JSON format.
    """
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Data saved to {filepath}")
    except IOError as e:
        raise IOError(f"Failed to write data to file: {e}")

def load_data(filepath):
    """
    Load data from a specified file.
    Returns the data as a dictionary.
    """
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None

def sync_with_server(server_url, token_file):
    """
    Sync with the server by fetching the user's clipboard content.
    """
    clipboard_endpoint = f"{server_url}/clipboard"
    token_data = load_data(token_file)
    if not token_data or not token_data.get("access_token"):
        raise ValueError("No access token found. Please login or register first.")
    
    access_token = token_data["access_token"]
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    try:
        response = requests.get(clipboard_endpoint, headers=headers)
        if response.status_code == 200:
            data = response.json()
            clipboard_text = data.get("text", "")
            print(f"Clipboard Content:\n{clipboard_text}")
        elif response.status_code == 401:
            error_detail = response.json().get("detail", "Unauthorized")
            raise ValueError(f"Sync failed: {error_detail}")
        else:
            response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to connect to the server: {e}")

import binascii
from mnemonic import Mnemonic
from getpass import getpass

def print_key(key_file):
    """
    Print the mnemonic phrase for transfer to another machine.
    If the mnemonic does not exist, generate a new one and store it.
    """
    key_data = load_data(key_file)
    make_key = False

    # Check if the mnemonic already exists
    if not key_data or not key_data.get("mnemonic"):
        make_key = True

    mnemo = Mnemonic("english")

    if make_key:
        try:
            # Generate a new mnemonic
            mnemonic = mnemo.generate(strength=256)  # 24-word mnemonic for better security
            print("Mnemonic generated successfully:")
            print(mnemonic)
        except Exception as e:
            print(f"Failed to generate mnemonic: {e}")
            sys.exit(1)

        seed = mnemo.to_seed(mnemonic, "")

        try:
            # Save the mnemonic to the key file
            save_data({"mnemonic": mnemonic}, key_file)
            print("Mnemonic saved successfully.")
        except IOError as ioe:
            print(f"Error saving the mnemonic: {ioe}")
            sys.exit(1)

        # Reload the key data to ensure it's saved
        key_data = load_data(key_file)

    # Retrieve the mnemonic
    mnemonic_stored = key_data.get("mnemonic")
    if not mnemonic_stored:
        print("Error: Mnemonic data is corrupted or missing.")
        sys.exit(1)

    print(mnemonic_stored)
    print("\nEnsure you transfer this mnemonic securely to another machine.")

def register_command(args):
    """
    Handle the register command.
    """
    user_data = prompt_user_details()
    
    # Register the user
    try:
        print("\nRegistering user...")
        token = register_user(args.server, user_data)
        print("Registration successful.")
    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except ConnectionError as ce:
        print(f"Error: {ce}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    
    # Generate mnemonic
    try:
        mnemonic = generate_mnemonic()
        print("Mnemonic generated successfully.")
    except Exception as e:
        print(f"Failed to generate mnemonic: {e}")
        sys.exit(1)
    
    # Derive seed from mnemonic
    try:
        seed = derive_seed(mnemonic, "")
        print("Seed derived successfully.")
    except Exception as e:
        print(f"Failed to derive seed: {e}")
        sys.exit(1)
    
    # Convert seed to hex string (or keep as bytes if preferred)
    seed_hex = convert_seed_to_hex(seed)
    
    # Save the token and seed_hex
    try:
        save_data({"access_token": token}, args.token_file)
        save_data({"key": seed_hex}, args.key_file)
    except IOError as ioe:
        print(f"Error: {ioe}")
        sys.exit(1)
    
    print("\nRegistration and key generation complete.")
    print(f"Access Token saved to: {args.token_file}")
    print(f"Byte-Based Key saved to: {args.key_file}")

def login_command(args):
    """
    Handle the login command.
    """
    print("=== User Login ===")
    username = input("Enter username: ").strip()
    while not username:
        print("Username cannot be empty.")
        username = input("Enter username: ").strip()
    
    password = getpass("Enter password: ").strip()
    while not password:
        print("Password cannot be empty.")
        password = getpass("Enter password: ").strip()
    
    # Login the user
    try:
        print("\nLogging in...")
        token = login_user(args.server, username, password)
        print("Login successful.")
    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except ConnectionError as ce:
        print(f"Error: {ce}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    
    # Save the token
    try:
        save_data({"access_token": token}, args.token_file)
    except IOError as ioe:
        print(f"Error: {ioe}")
        sys.exit(1)
    
    print(f"\nAccess Token saved to: {args.token_file}")

def logout_command(args):
    """
    Handle the logout command.
    """
    try:
        logout_user(args.token_file, args.key_file)
        print("Logout successful.")
    except IOError as ioe:
        print(f"Error: {ioe}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

def sync_command(args):
    """
    Handle the sync command.
    """
    try:
        sync_with_server(args.server, args.token_file)
    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except ConnectionError as ce:
        print(f"Error: {ce}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

def key_command(args):
    """
    Handle the key command.
    """
    try:
        print_key(args.key_file)
    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

def help_command(args, parser):
    """
    Handle the help command.
    """
    if args.subcommand:
        # Print help for the specific subcommand
        if args.subcommand in parser._subparsers._actions[1].choices:
            parser._subparsers._actions[1].choices[args.subcommand].print_help()
        else:
            print(f"No help available for '{args.subcommand}'.")
    else:
        # Print general help
        parser.print_help()

def main():
    """
    Main function to parse arguments and execute commands.
    """
    parser = argparse.ArgumentParser(
        description="Command-Line Clipboard Application",
        usage="python cli_app.py <command> [<args>]"
    )
    subparsers = parser.add_subparsers(title="Commands", dest="command")

    # Register Command
    parser_register = subparsers.add_parser("register", help="Register with the configured server")
    parser_register.add_argument('--server', type=str, default=DEFAULT_SERVER_URL,
                                 help=f"URL of the registration server (default: {DEFAULT_SERVER_URL})")
    parser_register.add_argument('--token-file', type=Path, default=DEFAULT_TOKEN_FILE,
                                 help=f"Path to save the access token (default: {DEFAULT_TOKEN_FILE})")
    parser_register.add_argument('--key-file', type=Path, default=DEFAULT_KEY_FILE,
                                 help=f"Path to save the byte-based key (default: {DEFAULT_KEY_FILE})")
    parser_register.set_defaults(func=register_command)

    # Login Command
    parser_login = subparsers.add_parser("login", help="Login to the configured server")
    parser_login.add_argument('--server', type=str, default=DEFAULT_SERVER_URL,
                              help=f"URL of the server (default: {DEFAULT_SERVER_URL})")
    parser_login.add_argument('--token-file', type=Path, default=DEFAULT_TOKEN_FILE,
                              help=f"Path to save the access token (default: {DEFAULT_TOKEN_FILE})")
    parser_login.set_defaults(func=login_command)

    # Logout Command
    parser_logout = subparsers.add_parser("logout", help="Log out")
    parser_logout.add_argument('--token-file', type=Path, default=DEFAULT_TOKEN_FILE,
                               help=f"Path to the access token file (default: {DEFAULT_TOKEN_FILE})")
    parser_logout.add_argument('--key-file', type=Path, default=DEFAULT_KEY_FILE,
                               help=f"Path to the byte-based key file (default: {DEFAULT_KEY_FILE})")
    parser_logout.set_defaults(func=logout_command)

    # Sync Command
    parser_sync = subparsers.add_parser("sync", help="Sync with the configured server")
    parser_sync.add_argument('--server', type=str, default=DEFAULT_SERVER_URL,
                             help=f"URL of the server (default: {DEFAULT_SERVER_URL})")
    parser_sync.add_argument('--token-file', type=Path, default=DEFAULT_TOKEN_FILE,
                             help=f"Path to the access token file (default: {DEFAULT_TOKEN_FILE})")
    parser_sync.set_defaults(func=sync_command)

    # Key Command
    parser_key = subparsers.add_parser("key", help="Print the encryption key for transfer to another machine")
    parser_key.add_argument('--key-file', type=Path, default=DEFAULT_KEY_FILE,
                            help=f"Path to the byte-based key file (default: {DEFAULT_KEY_FILE})")
    parser_key.set_defaults(func=key_command)

    # Help Command
    parser_help = subparsers.add_parser("help", help="Print this message or the help of the given subcommand(s)")
    parser_help.add_argument('subcommand', nargs='?', help="Subcommand to get help for")
    parser_help.set_defaults(func=lambda args: help_command(args, parser))

    # If no arguments are provided, print help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

