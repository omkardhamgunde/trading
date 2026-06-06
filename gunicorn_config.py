"""
Gunicorn configuration for production deployment.
Uses gevent workers for proper WebSocket support.
"""
import os

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '5001')}"
backlog = 2048

# Worker processes
# Keep one worker unless you add a Socket.IO message queue such as Redis.
workers = int(os.getenv("WEB_CONCURRENCY", "1"))
worker_class = "gevent"
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "trading_app"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (configure if using HTTPS)
# keyfile = None
# certfile = None
