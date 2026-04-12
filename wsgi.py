"""
WSGI entry point for production deployment with Gunicorn.
This file is used when running with: gunicorn --worker-class gevent wsgi:app
"""
from app import app, socketio, background_price_updater

# Start background task for production
socketio.start_background_task(background_price_updater)

# Export app for Gunicorn
application = app
