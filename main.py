# Main Entry Point for File Encryption Web Application
# ===================================================
# This file serves as the entry point for the Flask application when run in production.
# It imports the Flask app instance from app.py, which contains all the route definitions
# and application logic.
#
# Usage:
#   - For development: Run `python app.py` directly
#   - For production: This file is used by WSGI servers like Gunicorn
#   - The gunicorn command references this file: `gunicorn main:app`
#
# The noqa comment tells linters to ignore the "imported but unused" warning,
# since we need to import the app for the WSGI server to find it.

from app import app  # noqa: F401
