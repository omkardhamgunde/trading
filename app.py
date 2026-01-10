"""
Main Flask application - Refactored architecture.
"""
from flask import Flask
from flask_pymysql import MySQL
from flask_socketio import SocketIO
from datetime import timedelta
import os
import logging
from werkzeug.serving import WSGIRequestHandler

# Import configuration
from config import Config

# Import routes
from routes.auth import init_auth_routes
from routes.trading import init_trading_routes
from routes.watchlist import init_watchlist_routes
from routes.holdings import init_holdings_routes
from routes.wallet import init_wallet_routes

# Import WebSocket handlers
from websocket_handlers import init_websocket_handlers

# Initialize Flask app
app = Flask(__name__)

# Configure app
app.config.update(
    SECRET_KEY=Config.SECRET_KEY,
    SESSION_COOKIE_SECURE=Config.SESSION_COOKIE_SECURE,
    SESSION_COOKIE_HTTPONLY=Config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=Config.SESSION_COOKIE_SAMESITE,
    PERMANENT_SESSION_LIFETIME=timedelta(days=1)
)

# Configure MySQL
mysql_config = Config.get_mysql_config()
app.config.update(mysql_config)

# Initialize MySQL
mysql = MySQL()
mysql.init_app(app)

# Suppress Werkzeug connection errors (WebSocket disconnection warnings)
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# Custom request handler to suppress WebSocket disconnection errors
class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        # Suppress logging for WebSocket disconnection errors
        if code == 500 and 'socket.io' in self.path:
            return
        super().log_request(code, size)
    
    def log_error(self, *args, **kwargs):
        # Suppress AssertionError from WebSocket disconnections
        import sys
        exc_info = sys.exc_info()
        if exc_info[0] == AssertionError and 'write() before start_response' in str(exc_info[1]):
            # Silently handle WebSocket disconnection errors
            return
        super().log_error(*args, **kwargs)
    
    def handle_error(self, request, client_address):
        # Suppress AssertionError from WebSocket disconnections
        import sys
        exc_type, exc_value, exc_traceback = sys.exc_info()
        if exc_type == AssertionError and 'write() before start_response' in str(exc_value):
            # Silently handle WebSocket disconnection errors
            return
        super().handle_error(request, client_address)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=False, engineio_logger=False)

# Google OAuth Configuration
if Config.FLASK_ENV == 'development' or Config.OAUTHLIB_INSECURE_TRANSPORT == '1':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

client_config = Config.get_google_oauth_config()

# Validate configuration
warnings = Config.validate_config()
for warning in warnings:
    print(warning)

# Initialize and register blueprints
auth_bp = init_auth_routes(mysql, client_config, Config.GOOGLE_CLIENT_ID, Config.GOOGLE_CLIENT_SECRET)
trading_bp = init_trading_routes(mysql)
watchlist_bp = init_watchlist_routes(mysql)
holdings_bp = init_holdings_routes(mysql)
wallet_bp = init_wallet_routes(mysql)

app.register_blueprint(auth_bp)
app.register_blueprint(trading_bp)
app.register_blueprint(watchlist_bp)
app.register_blueprint(holdings_bp)
app.register_blueprint(wallet_bp)

# Initialize WebSocket handlers
background_price_updater = init_websocket_handlers(socketio, app, mysql)

# Suppress WebSocket disconnection errors using exception hook
import sys
import traceback

# Install exception hook to suppress WebSocket errors
_original_excepthook = sys.excepthook

def custom_excepthook(exc_type, exc_value, exc_traceback):
    """Custom exception hook to suppress WebSocket disconnection errors."""
    if exc_type == AssertionError and 'write() before start_response' in str(exc_value):
        # Check if it's from werkzeug.serving (WebSocket disconnection)
        if exc_traceback:
            tb_str = ''.join(traceback.format_tb(exc_traceback))
            if 'werkzeug' in tb_str.lower() and ('socket.io' in tb_str.lower() or 'serving.py' in tb_str.lower()):
                # Suppress this error - it's harmless WebSocket disconnection
                return
    # Call original exception hook for other errors
    _original_excepthook(exc_type, exc_value, exc_traceback)

sys.excepthook = custom_excepthook

# Patch werkzeug's error output directly
import werkzeug.serving
_original_log_error = werkzeug.serving.WSGIRequestHandler.log_error

def patched_log_error(self, *args, **kwargs):
    """Suppress WebSocket disconnection errors in werkzeug."""
    import sys
    exc_info = sys.exc_info()
    if exc_info[0] == AssertionError and 'write() before start_response' in str(exc_info[1]):
        # Suppress this error
        return
    _original_log_error(self, *args, **kwargs)

werkzeug.serving.WSGIRequestHandler.log_error = patched_log_error

if __name__ == '__main__':
    # Start background task
    print("Initializing WebSocket server...")
    socketio.start_background_task(background_price_updater)
    
    # Use socketio.run instead of app.run
    print("Starting server on http://127.0.0.1:5001")
    socketio.run(
        app, 
        debug=True, 
        port=5001, 
        allow_unsafe_werkzeug=True,
        request_handler=QuietWSGIRequestHandler,
        log_output=False
    )
