# tests/conftest.py
import os, sys

# Project root is one level up from tests/
root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root not in sys.path:
    sys.path.insert(0, root)

