import sys
from getpass import getpass
from pathlib import Path
from typing import Dict

import requests


def prompt_user_details() -> Dict[str, str]:
    """Prompt the user for registration information."""
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

    return {"username": username, "email": email, "password": password}


def register_user(server_url: str, user_data: Dict[str, str]) -> str:
    """Send a registration request to the server and return the access token."""
    register_endpoint = f"{server_url}/register"
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(register_endpoint, headers=headers, json=user_data, timeout=10)
        if response.status_code == 200:
            data = response.json()
            access_token = data.get("access_token")
            if not access_token:
                raise ValueError("Access token not found in the response.")
            return access_token
        if response.status_code == 400:
            error_detail = response.json().get("detail", "Bad Request")
            raise ValueError(f"Registration failed: {error_detail}")
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise ConnectionError(f"Failed to connect to the server: {exc}") from exc
    raise RuntimeError("Unexpected registration response")


def login_user(server_url: str, username: str, password: str) -> str:
    """Send a login request and return the access token."""
    login_endpoint = f"{server_url}/login"
    data = {"username": username, "password": password}
    try:
        response = requests.post(login_endpoint, data=data, timeout=10)
        if response.status_code == 200:
            data = response.json()
            access_token = data.get("access_token")
            if not access_token:
                raise ValueError("Access token not found in the response.")
            return access_token
        if response.status_code == 401:
            error_detail = response.json().get("detail", "Unauthorized")
            raise ValueError(f"Login failed: {error_detail}")
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise ConnectionError(f"Failed to connect to the server: {exc}") from exc
    raise RuntimeError("Unexpected login response")


def logout_user(token_file: Path) -> None:
    """Remove the stored token file if it exists."""
    try:
        if token_file.exists():
            token_file.unlink()
            print(f"Access token '{token_file}' deleted successfully.")
        else:
            print(f"No access token found at '{token_file}'.")
    except Exception as exc:
        raise IOError(f"Failed to delete files: {exc}") from exc
