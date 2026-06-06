"""
Authentication routes (login, OAuth, logout).
"""
from flask import Blueprint, render_template, request, redirect, session, flash, url_for
from flask_pymysql import MySQL
from forms import LoginForm, SignupForm
from config import Config
import secrets
import logging
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests as google_requests
from werkzeug.security import check_password_hash, generate_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

# Initialize rate limiter for the auth module
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


def init_auth_routes(mysql, client_config, google_client_id, google_client_secret):
    """Initialize auth routes with dependencies."""
    auth_bp.mysql = mysql
    auth_bp.client_config = client_config
    auth_bp.google_client_id = google_client_id
    auth_bp.google_client_secret = google_client_secret
    return auth_bp


@auth_bp.route('/')
def home():
    """Home page."""
    return render_template('home.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Brute force blocked. Please try again after 1 minute.")
def login():
    """Email/password login."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        ip_addr = request.remote_addr
        user_agent = request.user_agent.string
        
        try:
            cursor = auth_bp.mysql.connection.cursor()
            # ONLY SELECT id and password hash for safety
            cursor.execute("SELECT id, password FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            # Verify using secure cryptographic hash check
            # Handle fallback for existing plain text passwords gracefully if migration hasn't run
            is_valid = False
            if user:
                db_pass = user[1]
                if db_pass and (db_pass.startswith('scrypt:') or db_pass.startswith('pbkdf2:')):
                    is_valid = check_password_hash(db_pass, password)
                else:
                    # Fallback plaintext check ONLY to prevent lockdown if migration fails
                    is_valid = (db_pass == password)
                    
            if is_valid:
                session['user_id'] = user[0]

                # Log successful login
                cursor.execute(
                    "INSERT INTO login_history (user_id, username, ip_address, user_agent, status) VALUES (%s, %s, %s, %s, %s)",
                    (user[0], username, ip_addr, user_agent, 'Success')
                )

                # Check if wallet exists for the user
                cursor.execute("SELECT * FROM wallet WHERE user_id = %s", [user[0]])
                wallet = cursor.fetchone()
                if not wallet:
                    # Create a new wallet entry for the user with a default balance
                    cursor.execute("INSERT INTO wallet (user_id, balance) VALUES (%s, %s)", (user[0], 10000))
                    
                auth_bp.mysql.connection.commit()

                flash('Login successful!', 'success')
                return redirect(url_for('watchlist.watchlist'))
            else:
                user_id = user[0] if user else None
                # Log failed login
                cursor.execute(
                    "INSERT INTO login_history (user_id, username, ip_address, user_agent, status) VALUES (%s, %s, %s, %s, %s)",
                    (user_id, username, ip_addr, user_agent, 'Failure')
                )
                auth_bp.mysql.connection.commit()
                flash('Invalid credentials', 'danger')
        except AttributeError:
            flash('Database connection failed. Please check your MySQL server and configuration.', 'danger')
    return render_template('login.html', form=form)


@auth_bp.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Too many signup attempts. Please try again after 1 minute.")
def signup():
    """Create a local email/password account."""
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password_hash = generate_password_hash(form.password.data)

        try:
            cursor = auth_bp.mysql.connection.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE username = %s OR email = %s",
                (username, email)
            )
            existing_user = cursor.fetchone()
            if existing_user:
                flash('Username or email is already registered.', 'danger')
                return render_template('signup.html', form=form)

            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, password_hash)
            )
            user_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO wallet (user_id, balance) VALUES (%s, %s)",
                (user_id, 10000)
            )
            auth_bp.mysql.connection.commit()

            session.permanent = True
            session['user_id'] = user_id

            flash('Account created successfully!', 'success')
            return redirect(url_for('watchlist.watchlist'))
        except AttributeError:
            flash('Database connection failed. Please check your MySQL server and configuration.', 'danger')
        except Exception as e:
            try:
                auth_bp.mysql.connection.rollback()
            except Exception:
                logger.warning("Signup rollback failed", exc_info=True)
            logger.error(f"Error during signup: {e}", exc_info=True)
            flash('Could not create your account. Please try again.', 'danger')

    return render_template('signup.html', form=form)


@auth_bp.route('/login/google')
def google_login():
    """Initiate Google OAuth login."""
    if not auth_bp.client_config or not auth_bp.google_client_id or not auth_bp.google_client_secret:
        flash('Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file.', 'danger')
        return redirect(url_for('auth.login'))
    
    # Generate a new state token for this request
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    session.modified = True
    
    # Create flow instance
    flow = Flow.from_client_config(
        auth_bp.client_config,
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
    )
    
    # Set the redirect URI
    flow.redirect_uri = Config.GOOGLE_REDIRECT_URI
    
    # Generate the authorization URL
    authorization_url, _ = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        state=state,
        prompt='select_account'
    )
    
    return redirect(authorization_url)


@auth_bp.route('/login/google/authorized')
def google_authorized():
    """Google OAuth callback handler."""
    if not auth_bp.client_config or not auth_bp.google_client_id or not auth_bp.google_client_secret:
        flash('Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file.', 'danger')
        return redirect(url_for('auth.login'))
    
    # OAuth callback received (no need to log details)
    
    # Get the state from the session and request
    session_state = session.pop('oauth_state', None)
    request_state = request.args.get('state')
    
    # Verify the state parameter to prevent CSRF
    if not session_state or not request_state or session_state != request_state:
        error_msg = f"Invalid state parameter. Session state: {session_state}, Request state: {request_state}"
        logger.warning(error_msg)
        flash('Invalid state parameter. Please try logging in again.', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get the authorization code from the response
    code = request.args.get('code')
    # Authorization code received (no need to log)
    
    # Exchange the authorization code for tokens
    try:
        flow = Flow.from_client_config(
            auth_bp.client_config,
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
        )
        
        flow.redirect_uri = Config.GOOGLE_REDIRECT_URI
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        idinfo = id_token.verify_oauth2_token(
            credentials._id_token,
            google_requests.Request(),
            auth_bp.google_client_id,
            clock_skew_in_seconds=5
        )
        
        # Get user info
        google_id = idinfo.get('sub')
        email = idinfo.get('email')
        name = idinfo.get('name')
        
        logger.info(f"OAuth login - Email: {email}, Name: {name}")
        
        if not email:
            error_msg = 'Could not get email from Google'
            logger.error(error_msg)
            flash(error_msg, 'danger')
            return redirect(url_for('auth.login'))
        
        cursor = auth_bp.mysql.connection.cursor()
        
        # Check if user exists by email or google_id
        cursor.execute("SELECT * FROM users WHERE email = %s OR google_id = %s", (email, google_id))
        user = cursor.fetchone()
        if not user:
            # Create new user
            username = email.split('@')[0]
            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = %s", [username])
            if cursor.fetchone():
                username = f"{username}_{secrets.token_hex(4)}"
            
            # Insert new user
            cursor.execute(
                "INSERT INTO users (username, email, google_id) VALUES (%s, %s, %s)",
                (username, email, google_id)
            )
            user_id = cursor.lastrowid
            logger.info(f"New user created - ID: {user_id}, Email: {email}")
            
            # Create wallet for new user
            cursor.execute(
                "INSERT INTO wallet (user_id, balance) VALUES (%s, %s)",
                (user_id, 10000)
            )
            auth_bp.mysql.connection.commit()
            
            flash('Account created successfully!', 'success')
        else:
            user_id = user[0]
            # Update Google ID if not set
            if not user[3]:
                cursor.execute("UPDATE users SET google_id = %s WHERE id = %s", (google_id, user_id))
                auth_bp.mysql.connection.commit()
        
        # Set user session
        session.permanent = True
        session['user_id'] = user_id
        session['google_token'] = credentials._id_token
        
        logger.info(f"User {user_id} logged in successfully")
        flash('Logged in with Google successfully!', 'success')
        return redirect(url_for('watchlist.watchlist'))
        
    except Exception as e:
        logger.error(f"Error during Google OAuth: {e}", exc_info=True)
        flash('Failed to log in with Google. Please try again.', 'danger')
        return redirect(url_for('auth.login'))


@auth_bp.route('/logout')
def logout():
    """Logout user."""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))
