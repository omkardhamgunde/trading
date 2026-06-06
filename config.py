"""
Application configuration module.
Loads configuration from environment variables.
"""
import os
import secrets
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Base configuration class."""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(16))
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # MySQL Configuration
    MYSQL_HOST = os.getenv('MYSQL_HOST', '127.0.0.1')
    MYSQL_PORT = int(os.getenv('MYSQL_PORT', '3306'))
    MYSQL_USER = os.getenv('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
    MYSQL_DB = os.getenv('MYSQL_DB', 'trading_website')
    MYSQL_SSL = os.getenv(
        'MYSQL_SSL',
        'True' if 'tidbcloud.com' in MYSQL_HOST else 'False'
    ).lower() == 'true'
    MYSQL_SSL_CA = os.getenv(
        'MYSQL_SSL_CA',
        '/etc/ssl/certs/ca-certificates.crt' if MYSQL_SSL else None
    )
    MYSQL_SSL_VERIFY_CERT = os.getenv('MYSQL_SSL_VERIFY_CERT', 'True').lower() == 'true'
    MYSQL_SSL_VERIFY_IDENTITY = os.getenv('MYSQL_SSL_VERIFY_IDENTITY', 'True').lower() == 'true'
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5001/login/google/authorized')
    GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    
    # OAuth Development Setting
    OAUTHLIB_INSECURE_TRANSPORT = os.getenv('OAUTHLIB_INSECURE_TRANSPORT', '1')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    
    @staticmethod
    def get_mysql_config():
        """Get MySQL configuration dictionary."""
        pymysql_kwargs = {
            'user': Config.MYSQL_USER,
            'password': Config.MYSQL_PASSWORD,
            'db': Config.MYSQL_DB,
            'host': Config.MYSQL_HOST,
            'port': Config.MYSQL_PORT
        }

        if Config.MYSQL_SSL:
            pymysql_kwargs.update({
                'ssl_verify_cert': Config.MYSQL_SSL_VERIFY_CERT,
                'ssl_verify_identity': Config.MYSQL_SSL_VERIFY_IDENTITY
            })
            if Config.MYSQL_SSL_CA:
                pymysql_kwargs['ssl_ca'] = Config.MYSQL_SSL_CA
            else:
                pymysql_kwargs['ssl'] = {}

        return {
            'MYSQL_HOST': Config.MYSQL_HOST,
            'MYSQL_PORT': Config.MYSQL_PORT,
            'MYSQL_USER': Config.MYSQL_USER,
            'MYSQL_PASSWORD': Config.MYSQL_PASSWORD,
            'MYSQL_DB': Config.MYSQL_DB,
            'pymysql_kwargs': pymysql_kwargs
        }
    
    @staticmethod
    def get_google_oauth_config():
        """Get Google OAuth configuration dictionary."""
        if not Config.GOOGLE_CLIENT_ID or not Config.GOOGLE_CLIENT_SECRET:
            return None
        
        return {
            "web": {
                "client_id": Config.GOOGLE_CLIENT_ID,
                "client_secret": Config.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [
                    "http://localhost:5001/login/google/authorized",
                    "http://127.0.0.1:5001/login/google/authorized",
                    Config.GOOGLE_REDIRECT_URI
                ]
            }
        }
    
    @staticmethod
    def validate_config():
        """Validate that required configuration is present."""
        warnings = []
        
        if not Config.GOOGLE_CLIENT_ID or not Config.GOOGLE_CLIENT_SECRET:
            warnings.append("⚠️  WARNING: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set.")
            warnings.append("   Google OAuth login will not work. Please set these in your .env file.")
        
        if not Config.MYSQL_PASSWORD:
            warnings.append("⚠️  WARNING: MYSQL_PASSWORD not set.")
            warnings.append("   Database connection will fail. Please set this in your .env file.")
        
        return warnings
