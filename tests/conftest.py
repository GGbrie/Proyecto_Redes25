# tests/conftest.py
import os, sys
# Añade la carpeta raíz del proyecto al sys.path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
