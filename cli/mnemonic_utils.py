import sys
from pathlib import Path

from mnemonic import Mnemonic


def _mnemonic_instance() -> Mnemonic:
    return Mnemonic("english")


def generate_mnemonic() -> str:
    """Generate a 24-word mnemonic phrase."""
    mnemo = _mnemonic_instance()
    return mnemo.generate(strength=256)


def print_key(key_file: Path) -> None:
    """Print the mnemonic phrase backing the stored key, generating it if absent."""
    make_key = False
    key_data = None
    mnemo = _mnemonic_instance()

    try:
        with open(key_file, "rb") as handle:
            key_data = handle.read()
    except IOError:
        make_key = True

    if make_key:
        try:
            mnemonic = generate_mnemonic()
            print("Mnemonic generated successfully:")
            print(mnemonic)
        except Exception as exc:
            print(f"Failed to generate mnemonic: {exc}")
            sys.exit(1)

        entropy = mnemo.to_entropy(mnemonic)

        try:
            with open(key_file, "wb") as handle:
                handle.write(entropy)
            print("Mnemonic saved successfully.")
        except IOError as exc:
            print(f"Error saving the mnemonic: {exc}")
            sys.exit(1)

        key_data = entropy

    if key_data:
        try:
            mnemonic = mnemo.to_mnemonic(key_data)
            print("\nYour Mnemonic Phrase:")
            print(mnemonic)
            print("\nEnsure you transfer this mnemonic securely to another machine.")
        except Exception as exc:
            print(f"Error converting key to mnemonic: {exc}")
            sys.exit(1)


def prompt_for_mnemonic() -> str:
    """Interactively request a valid mnemonic from the user."""
    mnemo = _mnemonic_instance()
    while True:
        mnemonic = input("Enter your 24-word mnemonic phrase: ").strip()
        if mnemo.check(mnemonic):
            return mnemonic
        print("Invalid mnemonic phrase. Please try again.")


def generate_and_save_mnemonic(key_file: Path) -> str:
    """Create a mnemonic, save its entropy, and return the phrase."""
    mnemonic = generate_mnemonic()
    print("\nGenerated Mnemonic Phrase:")
    print(mnemonic)

    mnemo = _mnemonic_instance()
    entropy = mnemo.to_entropy(mnemonic)

    try:
        key_file.parent.mkdir(parents=True, exist_ok=True)
        with open(key_file, "wb") as handle:
            handle.write(entropy)
        print("\nMnemonic saved successfully.")
    except IOError as exc:
        print(f"Error saving the mnemonic: {exc}")
        sys.exit(1)

    return mnemonic


def save_mnemonic_phrase(mnemonic: str, key_file: Path) -> None:
    """Persist an existing mnemonic phrase to key_file as entropy."""
    mnemo = _mnemonic_instance()
    entropy = mnemo.to_entropy(mnemonic)

    try:
        key_file.parent.mkdir(parents=True, exist_ok=True)
        with open(key_file, "wb") as handle:
            handle.write(entropy)
        print("Mnemonic saved successfully.")
    except IOError as exc:
        print(f"Error saving the mnemonic: {exc}")
        sys.exit(1)
