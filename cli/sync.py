from pathlib import Path

import requests

from .storage import load_json_data


def sync_with_server(server_url: str, token_file: Path) -> None:
    """Fetch the clipboard content from the server using the stored token."""
    clipboard_endpoint = f"{server_url}/clipboard"
    token_data = load_json_data(token_file)
    if not token_data or not token_data.get("access_token"):
        raise ValueError("No access token found. Please login or register first.")

    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        response = requests.get(clipboard_endpoint, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            clipboard_text = data.get("text", "")
            print(f"Clipboard Content:\n{clipboard_text}")
            return
        if response.status_code == 401:
            error_detail = response.json().get("detail", "Unauthorized")
            raise ValueError(f"Sync failed: {error_detail}")
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise ConnectionError(f"Failed to connect to the server: {exc}") from exc
