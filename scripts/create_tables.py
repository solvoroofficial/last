"""Create SQLite tables for the app when not using Firebase.

Run from PowerShell with:
  python scripts/create_tables.py

This script checks the `USE_FIREBASE` flag from `app` and will not
attempt to create tables if Firebase is enabled.
"""
import os
import sys

# Ensure project root is on sys.path so `import app` works when this script
# is executed from the `scripts/` directory.
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(HERE, '..'))
if PROJECT_ROOT not in sys.path:
  sys.path.insert(0, PROJECT_ROOT)

from app import db, USE_FIREBASE, app


if USE_FIREBASE:
  print('USE_FIREBASE is enabled. Local SQLite tables will not be created.')
  print('Unset the USE_FIREBASE environment variable to create local tables.')
else:
  with app.app_context():
    db.create_all()
    print('SQLite tables created successfully.')
