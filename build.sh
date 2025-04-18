# build.sh
#!/bin/bash
nuitka --onefile --standalone daemon.py --output-dir=bin --remove-output --plugin-enable=gi

