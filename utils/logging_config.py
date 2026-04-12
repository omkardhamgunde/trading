"""
Logging configuration for the application.
Follows best practices for production-ready logging.
"""
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
import os


def setup_logging(env='development', log_level=None):
    """
    Configure application-wide logging.
    
    Args:
        env: Environment ('development' or 'production')
        log_level: Override log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Configured root logger
    """
    # Determine log level
    # Default to INFO even in development (DEBUG is too verbose)
    if log_level:
        level = getattr(logging, log_level.upper(), logging.INFO)
    else:
        level = logging.INFO  # INFO for both dev and prod (use LOG_LEVEL=DEBUG if needed)
    
    # Create logs directory if it doesn't exist
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Console handler (for development - shows all logs)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(simple_formatter if env == 'development' else detailed_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (for production - rotates logs)
    file_handler = RotatingFileHandler(
        log_dir / 'app.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.INFO)  # File always logs INFO and above
    file_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(file_handler)
    
    # Error file handler (only errors and above)
    error_handler = RotatingFileHandler(
        log_dir / 'errors.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(error_handler)
    
    # Suppress noisy third-party loggers (set to ERROR to minimize noise)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    logging.getLogger('gevent').setLevel(logging.ERROR)
    logging.getLogger('engineio').setLevel(logging.ERROR)
    logging.getLogger('socketio').setLevel(logging.ERROR)
    logging.getLogger('flask').setLevel(logging.WARNING)
    
    root_logger.info(f"Logging configured - Environment: {env}, Level: {logging.getLevelName(level)}")
    
    return root_logger
