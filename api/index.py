import sys
import os

# Add project root to path so imports work in serverless context
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app

# Vercel expects a handler function
handler = app
