"""
Main Flask application - Refactored architecture.
"""
# Use gevent for WebSocket support (modern, actively maintained alternative to eventlet)
# Gevent provides proper async support without deprecation warnings
# IMPORTANT: Monkey patch must happen BEFORE any other imports that use sockets/threading
try:
    import gevent
    from gevent import monkey
    # Only patch what's necessary to avoid conflicts with Flask's debug reloader
    monkey.patch_all(thread=False, socket=True, time=True, select=True)
    USE_GEVENT = True
except ImportError:
    USE_GEVENT = False

from flask import Flask, render_template
from flask_pymysql import MySQL
from flask_socketio import SocketIO
from datetime import timedelta
import os
import logging

# Import configuration
from config import Config
from utils.logging_config import setup_logging

# Import routes
from routes.auth import init_auth_routes, limiter
from routes.trading import init_trading_routes
from routes.watchlist import init_watchlist_routes
from routes.holdings import init_holdings_routes
from routes.wallet import init_wallet_routes
from routes.health import init_health_routes

# Import WebSocket handlers
from handlers.websocket_handlers import init_websocket_handlers

# Initialize Flask app
app = Flask(__name__)

# Configure logging FIRST (before other operations)
logger = setup_logging(
    env=Config.FLASK_ENV,
    log_level=os.getenv('LOG_LEVEL')  # Can override with LOG_LEVEL env var
)

# Configure app
app.config.update(
    SECRET_KEY=Config.SECRET_KEY,
    SESSION_COOKIE_SECURE=Config.SESSION_COOKIE_SECURE,
    SESSION_COOKIE_HTTPONLY=Config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=Config.SESSION_COOKIE_SAMESITE,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15)
)

# Configure MySQL
mysql_config = Config.get_mysql_config()
app.config.update(mysql_config)

# Initialize MySQL
mysql = MySQL()
mysql.init_app(app)

# Initialize SocketIO with gevent async mode for WebSocket handling
# Gevent is actively maintained and handles WebSocket disconnections properly
if USE_GEVENT:
    async_mode = 'gevent'
    logger.info("Using gevent async mode for WebSocket support")
else:
    # Fallback to threading mode
    async_mode = 'threading'
    logger.warning("Using threading mode. Install gevent for better WebSocket support: pip install gevent gevent-websocket")

socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode=async_mode,
    logger=False, 
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25
)

# Google OAuth Configuration
if Config.FLASK_ENV == 'development' or Config.OAUTHLIB_INSECURE_TRANSPORT == '1':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

client_config = Config.get_google_oauth_config()

# Validate configuration
warnings = Config.validate_config()
for warning in warnings:
    logger.warning(warning)

auth_bp = init_auth_routes(mysql, client_config, Config.GOOGLE_CLIENT_ID, Config.GOOGLE_CLIENT_SECRET)

# Register the Rate Limiter specifically onto the main app context
limiter.init_app(app)

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('error.html', error_msg=f"BRUTE FORCE PROTECTION: {e.description}"), 429
trading_bp = init_trading_routes(mysql)
watchlist_bp = init_watchlist_routes(mysql)
holdings_bp = init_holdings_routes(mysql)
wallet_bp = init_wallet_routes(mysql)
health_bp = init_health_routes()

app.register_blueprint(auth_bp)
app.register_blueprint(trading_bp)
app.register_blueprint(watchlist_bp)
app.register_blueprint(holdings_bp)
app.register_blueprint(wallet_bp)
app.register_blueprint(health_bp)

# Initialize WebSocket handlers
background_price_updater = init_websocket_handlers(socketio, app, mysql)

# Make socketio, app, and background_price_updater available for WSGI
__all__ = ['app', 'socketio', 'background_price_updater']

if __name__ == '__main__':
    # Development mode - use Flask-SocketIO's built-in server
    # For production, use: gunicorn --worker-class gevent --workers 4 wsgi:app
    
    # Use environment-based configuration for production readiness
    debug_mode = Config.FLASK_ENV == 'development'
    
    if not USE_GEVENT:
        logger.warning("Gevent not installed. WebSocket disconnection errors may occur.")
        logger.info("Install with: pip install gevent gevent-websocket")
        logger.info("Or use production server: gunicorn --worker-class gevent wsgi:app")
    
    # Start background task
    logger.info("Initializing WebSocket server...")
    socketio.start_background_task(background_price_updater)
    
    # Use socketio.run for development
    logger.info("Starting server on http://127.0.0.1:5001")
    # Disable reloader when using gevent (gevent doesn't work well with Flask's reloader)
    use_reloader = debug_mode and not USE_GEVENT
    
    socketio.run(
        app, 
        host='127.0.0.1',
        port=5001, 
        debug=debug_mode, 
        allow_unsafe_werkzeug=debug_mode,  # Only allow unsafe werkzeug in development
        log_output=True,
        use_reloader=use_reloader
    )
