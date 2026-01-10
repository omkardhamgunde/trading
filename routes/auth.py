"""
Authentication routes (login, OAuth, logout).
"""
from flask import Blueprint, render_template, request, redirect, session, flash, url_for
from flask_pymysql import MySQL
from forms import LoginForm
from config import Config
import secrets
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests as google_requests

auth_bp = Blueprint('auth', __name__)


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
def login():
    """Email/password login."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        try:
            cursor = auth_bp.mysql.connection.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
            user = cursor.fetchone()
            if user:
                session['user_id'] = user[0]

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
                flash('Invalid credentials', 'danger')
        except AttributeError:
            flash('Database connection failed. Please check your MySQL server and configuration.', 'danger')
    return render_template('login.html', form=form)


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
    print(f"Setting oauth_state in session: {state}")
    
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
    
    print("\n=== Google OAuth Callback ===")
    print(f"Session state: {session.get('oauth_state')}")
    print(f"Request state: {request.args.get('state')}")
    
    # Get the state from the session and request
    session_state = session.pop('oauth_state', None)
    request_state = request.args.get('state')
    
    # Verify the state parameter to prevent CSRF
    if not session_state or not request_state or session_state != request_state:
        error_msg = f"Invalid state parameter. Session state: {session_state}, Request state: {request_state}"
        print(error_msg)
        flash('Invalid state parameter. Please try logging in again.', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get the authorization code from the response
    code = request.args.get('code')
    print(f"Got authorization code: {code[:10]}..." if code else "No code received")
    
    # Exchange the authorization code for tokens
    try:
        flow = Flow.from_client_config(
            auth_bp.client_config,
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
        )
        
        flow.redirect_uri = Config.GOOGLE_REDIRECT_URI
        print(f"Using redirect_uri: {flow.redirect_uri}")
        
        flow.fetch_token(code=code)
        credentials = flow.credentials
        print("Successfully obtained credentials")
        
        idinfo = id_token.verify_oauth2_token(
            credentials._id_token,
            google_requests.Request(),
            auth_bp.google_client_id,
            clock_skew_in_seconds=5
        )
        print(f"Decoded ID token: {idinfo}")
        
        # Get user info
        google_id = idinfo.get('sub')
        email = idinfo.get('email')
        name = idinfo.get('name')
        
        print(f"User info - Google ID: {google_id}, Email: {email}, Name: {name}")
        
        if not email:
            error_msg = 'Could not get email from Google'
            print(error_msg)
            flash(error_msg, 'danger')
            return redirect(url_for('auth.login'))
        
        cursor = auth_bp.mysql.connection.cursor()
        
        # Check if user exists by email or google_id
        cursor.execute("SELECT * FROM users WHERE email = %s OR google_id = %s", (email, google_id))
        user = cursor.fetchone()
        print(f"Existing user from DB: {user}")
        
        if not user:
            # Create new user
            username = email.split('@')[0]
            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = %s", [username])
            if cursor.fetchone():
                username = f"{username}_{secrets.token_hex(4)}"
            
            print(f"Creating new user with username: {username}, email: {email}")
            
            # Insert new user
            cursor.execute(
                "INSERT INTO users (username, email, google_id) VALUES (%s, %s, %s)",
                (username, email, google_id)
            )
            user_id = cursor.lastrowid
            print(f"New user created with ID: {user_id}")
            
            # Create wallet for new user
            cursor.execute(
                "INSERT INTO wallet (user_id, balance) VALUES (%s, %s)",
                (user_id, 10000)
            )
            auth_bp.mysql.connection.commit()
            
            flash('Account created successfully!', 'success')
        else:
            user_id = user[0]
            print(f"Found existing user with ID: {user_id}")
            # Update Google ID if not set
            if not user[3]:
                print(f"Updating Google ID for user {user_id}")
                cursor.execute("UPDATE users SET google_id = %s WHERE id = %s", (google_id, user_id))
                auth_bp.mysql.connection.commit()
        
        # Set user session
        session.permanent = True
        session['user_id'] = user_id
        session['google_token'] = credentials._id_token
        
        print(f"Session after login: {dict(session)}")
        flash('Logged in with Google successfully!', 'success')
        return redirect(url_for('watchlist.watchlist'))
        
    except Exception as e:
        print(f"Error during Google OAuth: {str(e)}")
        flash('Failed to log in with Google. Please try again.', 'danger')
        return redirect(url_for('auth.login'))


@auth_bp.route('/logout')
def logout():
    """Logout user."""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))
