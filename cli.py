#!/usr/bin/env python3

import requests
import json
import os
import sys
from getpass import getpass
from pathlib import Path

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

def save_token(token, filepath):
    """
    Save the access token to a specified file in JSON format.
    """
    data = {
        "access_token": token
    }
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f)
        print(f"Access token saved to {filepath}")
    except IOError as e:
        raise IOError(f"Failed to write token to file: {e}")

def load_token(filepath):
    """
    Load the access token from a specified file.
    Returns the token as a string.
    """
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            return data.get("access_token")
    except (IOError, json.JSONDecodeError):
        return None

def main():
    """
    Main function to handle user registration and token saving.
    """
    # Configuration
    DEFAULT_SERVER_URL = "http://127.0.0.1:8000"
    DEFAULT_TOKEN_FILE = "token.json"
    
    # Optional: Allow the user to specify the server URL and token file via command-line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Register a new user and save the access token.")
    parser.add_argument('--server', type=str, default=DEFAULT_SERVER_URL,
                        help=f"URL of the registration server (default: {DEFAULT_SERVER_URL})")
    parser.add_argument('--token-file', type=str, default=DEFAULT_TOKEN_FILE,
                        help=f"Path to save the access token (default: {DEFAULT_TOKEN_FILE})")
    args = parser.parse_args()
    
    server_url = args.server.rstrip('/')
    token_file = args.token_file
    
    # Check if token file already exists
    token_path = Path(token_file)
    if token_path.exists():
        existing_token = load_token(token_file)
        if existing_token:
            print(f"An access token already exists at '{token_file}'.")
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
        print(f"An unexpected e")
    
    # Save the token
    try:
        save_token(token, token_file)
    except IOError as ioe:
        print(f"Error: {ioe}")
        sys.exit(1)

if __name__ == "__main__":
    main()
