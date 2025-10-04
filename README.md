# PyPasteServer Daemon

  Clipboard daemon with optional cloud sync and KDE Klipper integration.

  ## System prerequisites

  The daemon relies on GI/GLib bindings. Install the system packages first (Ubuntu/Debian):

  ```bash
  sudo apt install python3-gi gir1.2-glib-2.0

  These stay outside the virtualenv; the daemon runs against them by inheriting system site packages.

  ## Installation

  Create the venv with access to system packages and install the project:

  python3 -m venv --system-site-packages venv
  source venv/bin/activate
  pip install .

  If you already have a venv, either recreate it as above or add the system GI path (for example /usr/lib/python3/dist-packages) to venv/lib/python3.11/site-packages/system.pth.

  ### Optional features

  - sync (pycryptodome, websocket-client) enables encrypted WebSocket syncing.
  - klipper (dbus-python) enables KDE Klipper integration.

  Install them as needed:

  pip install .[sync]
  pip install .[sync,klipper]

  ## Running

  Activate the venv and launch the daemon:

  source venv/bin/activate
  python -m daemon
