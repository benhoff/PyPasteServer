#!/usr/bin/env python3

import requests
import json
import os
import sys
from getpass import getpass
from pathlib import Path
from mnemonic import Mnemonic  # BIP39 library

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

def generate_mnemonic():
    """
    Generate a BIP39 compliant mnemonic phrase.
    Returns the mnemonic as a string.
    """
    mnemo = Mnemonic("english")
    entropy = mnemo.generate(strength=256)  # 24-word mnemonic
    return entropy

def save_data(data, filepath):
    """
    Save data to a specified file in JSON format.
    """
    try:
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

def main():
    """
    Main function to handle user registration, mnemonic generation, and data saving.
    """
    # Configuration
    DEFAULT_SERVER_URL = "http://127.0.0.1:8000"
    DEFAULT_TOKEN_FILE = "token.json"
    DEFAULT_KEY_FILE = "key.json"
    
    # Optional: Allow the user to specify the server URL, token file, and key file via command-line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Register a new user, generate a mnemonic, and save the access token.")
    parser.add_argument('--server', type=str, default=DEFAULT_SERVER_URL,
                        help=f"URL of the registration server (default: {DEFAULT_SERVER_URL})")
    parser.add_argument('--token-file', type=str, default=DEFAULT_TOKEN_FILE,
                        help=f"Path to save the access token (default: {DEFAULT_TOKEN_FILE})")
    parser.add_argument('--key-file', type=str, default=DEFAULT_KEY_FILE,
                        help=f"Path to save the mnemonic key (default: {DEFAULT_KEY_FILE})")
    args = parser.parse_args()
    
    server_url = args.server.rstrip('/')
    token_file = args.token_file
    key_file = args.key_file
    
    # Check if token file already exists
    token_path = Path(token_file)
    if token_path.exists():
        existing_token = load_data(token_file)
        if existing_token and existing_token.get("access_token"):
            print(f"An access token already exists at '{token_file}'.")
            overwrite = input("Do you want to overwrite it? (y/n): ").strip().lower()
            if overwrite != 'y':
                print("Registration aborted.")
                sys.exit(0)
    
    # Check if key file already exists
    key_path = Path(key_file)
    if key_path.exists():
        existing_key = load_data(key_file)
        if existing_key and existing_key.get("mnemonic"):
            print(f"A mnemonic key already exists at '{key_file}'.")
            overwrite = input("Do you want to overwrite it? (y/n): ").strip().lower()
            if overwrite != 'y':
                print("Registration aborted.")
                sys.exit(0)
    
    # Prompt user for details
    user_data = prompt_user_details()
    
    # Register the user
    try:
        print("\nRegistering user...")
        token = register_user(server_url, user_data)
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
    
    # Save the token and mnemonic
    try:
        save_data({"access_token": token}, token_file)
        save_data({"mnemonic": mnemonic}, key_file)
    except IOError as ioe:
        print(f"Error: {ioe}")
        sys.exit(1)

if __name__ == "__main__":
    main()

