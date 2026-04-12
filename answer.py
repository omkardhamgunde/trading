"""
Interview Answers - Trading Platform Project
Format: 2 questions at a time. Answer below, then say "next" for the next 2.
"""

# =============================================================================
# SET 3 — Questions 5 & 6
# =============================================================================

# Q5: What design principles guided your project structure?
#     (e.g. separation of concerns, modularity, where config lives)
# Your Answer:
# i used separation of concerns means every function has its own file
# i used .env file for secret key and other configuration
# code reuseability means i used same code in multiple files
# (Small note: it's "each concern/module" per file — e.g. trade_service.py has many functions)


# Q6: How do you initialize the Flask app in this project?
#     What happens in app.py when the application starts?
# Your Answer:
# when application start flask app is created
# logging is set up (setup_logging), not "login page" — login is just a route when user visits /login
# mysql is created using configuration from .env / config.py
# websocket (SocketIO) is created for real-time price updates
# blueprints (routes) for auth, trading, watchlist, holdings, wallet, health are registered
# then WebSocket handlers are initialized; on startup, background task + socketio.run()


# =============================================================================
# SET 4 — Questions 7 & 8
# =============================================================================

# Q7: What are Flask Blueprints? Name the blueprints in your project and what each does.
# Your Answer:
# Flask blueprints are used to organize routes in a modular way.
# Blueprints in this project (from app.py):
#   auth_bp      — /, /login, /login/google, /logout (home, login, Google OAuth)
#   trading_bp   — /trade, /trade-log, /clear-trade-log (execute trade, view/clear log)
#   watchlist_bp — watchlist page, /search_stocks, add/remove stocks
#   holdings_bp  — /holdings (portfolio with P/L)
#   wallet_bp    — wallet page, add funds
#   health_bp    — /health, /metrics (health check, API metrics)


# Q8: How does your application connect to MySQL? Where is the config, and how do routes get DB access?
# Your Answer:
# Application connects to MySQL using flask_pymysql; config comes from .env (loaded in config.py).
# config.py has MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB; get_mysql_config() returns the dict.
# In app.py: mysql = MySQL(); mysql.init_app(app). Each blueprint gets mysql in init_*_routes(mysql)
# (e.g. trading_bp.mysql). Routes use trading_bp.mysql.connection.cursor() to run queries.


# =============================================================================
# SET 5 — Questions 9 & 10
# =============================================================================

# Q9: How do you manage user sessions? Where do you set session['user_id'], and how do you protect routes that require login?
# Your Answer:
# (Reference: session['user_id'] set in routes/auth.py on login. Protected routes: if 'user_id' not in session → redirect to login. Session config in app.py.)
# 


# Q10: When a user submits a trade (buy/sell), walk through the request–response cycle from button click to seeing the result.
# Your Answer:
# so when user place trade we check if user is logged in after that we fetch the current stock price from yfinance
# then we check if user has enough balance or stocks to place the trade
# if yes then we execute the trade and update the database
# (Good. Full order: session check → validate_trade → get_current_stock_price → check_wallet_balance if buy → execute_trade → flash → redirect to holdings.)


# =============================================================================
# SET 6 — Questions 11 & 12
# =============================================================================

# Q11: How does the WebSocket work in this project? (What connects, what subscribes, who pushes data?)
# Your Answer:
# so we initialize websocket using flask_socketio
# user subscribes to websocket (subscribe_watchlist / subscribe_holdings with user_id)
# then websocket pushes data to users who subscribed every 10 seconds (price_update / holdings_update)
# if user is disconnected then websocket removes user from active_connections
# (Good. Client: io() → emit subscribe_* with user_id. Server: stores in active_connections; background task fetches DB + prices, emits to each sid.)


# Q12: Why do we use app.app_context() inside the WebSocket background task?
# Your Answer:
# we use app.app_context() inside the WebSocket background task to access the database
# we use app.app_context() to access the database because the background task is not tied to an HTTP request
# so we use app.app_context() to access the database
# (Correct. Flask's mysql.connection and app context are request-scoped; the background loop runs outside requests, so we push the app context explicitly.)


# =============================================================================
# SET 7 — Questions 13 & 14
# =============================================================================

# Q13: When a trade fails (e.g. insufficient balance), how does the user see the error? (Where is the message set and how does it show on the page?)
# Your Answer:
# insufficient balance or insufficient stocks then we flash the error message and redirect to the watchlist page
# (Good. In routes/trading.py we do flash(error_msg, 'danger'); base template shows flash messages.)


# Q14: Where is the stock price data coming from? How do we fetch it and do we cache it?
# Your Answer:
# it's coming from Yahoo Finance API via the yfinance library; we fetch using yfinance, WebSocket refreshes every 10s
# we cache in an in-memory TTL cache (utils/cache.py, price_cache), not Redis — 10s TTL, reduces API calls
# (Redis is a separate in-memory store for caching across processes; this project uses in-memory cache in utils/cache.py.)



# =============================================================================
# SET 8 — Questions 15 & 16
# =============================================================================

# Q15: When we execute a trade (buy/sell), we update the wallet and insert into trade_log. What happens if one succeeds and the other fails? How do we keep data consistent?
# Your Answer:
# i think we use ACID transaction to keep data consistent
# (Correct. In trade_service.execute_trade: commit() on success, rollback() on exception.)
# 


# Q16: What is the purpose of the /health and /metrics endpoints? Who might use them?
# Your Answer:
# health check and metrics endpoints are used to check the health of the application and to get the metrics of the application
# (Good. /health = status, uptime; /metrics = API calls, cache stats. Used by load balancers, monitoring.)
# 


# =============================================================================
# SET 9 — Questions 17 & 18
# =============================================================================
#
# Q17: How does Google OAuth login work in this project? (High level: what the user clicks, where they go, and how we get the user_id.)
# Your Answer:
#
#
# Q18: Where are passwords stored for email/password login? Is that approach secure for production?
# Your Answer:
#
#
# --- When done, say "next" for the next 2 questions (Q19 & Q20) ---
