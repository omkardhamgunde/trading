from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from flask_pymysql import MySQL

mysql = MySQL()
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
import yfinance as yf
import datetime
import pytz
from datetime import datetime, timedelta
from collections import defaultdict
from decimal import Decimal
import pandas as pd

from threading import Thread
import time
import json
import os
import secrets
# nselib import removed - option chain functionality has been removed
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests as google_requests
import requests
from flask.sessions import SecureCookieSessionInterface
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Use environment variable for secret key, fallback to generated one for development
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Configure session
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_hex(16)),
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true',  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=1)  # Session expires after 1 day
)



# Google OAuth Configuration
# Only set OAUTHLIB_INSECURE_TRANSPORT for local development
if os.getenv('FLASK_ENV') == 'development' or os.getenv('OAUTHLIB_INSECURE_TRANSPORT') == '1':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Load Google OAuth credentials from environment variables
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'

# Validate that required OAuth credentials are present
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    print("⚠️  WARNING: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set in environment variables.")
    print("   Google OAuth login will not work. Please set these in your .env file.")

# Initialize the OAuth flow
# Only create client_config if credentials are available
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [
                "http://localhost:5001/login/google/authorized",
                "http://127.0.0.1:5001/login/google/authorized",
                os.getenv('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5001/login/google/authorized')
            ]
        }
    }
else:
    client_config = None

# Make sure the redirect URI is consistent
def get_google_redirect_uri():
    # Allow redirect URI to be configured via environment variable
    return os.getenv('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5001/login/google/authorized')

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

# MySQL configuration - Load from environment variables
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', '127.0.0.1')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'trading_website')
app.config['pymysql_kwargs'] = {
    "user": os.getenv('MYSQL_USER', 'root'),
    "password": os.getenv('MYSQL_PASSWORD'),
    "db": os.getenv('MYSQL_DB', 'trading_website'),
    "host": os.getenv('MYSQL_HOST', '127.0.0.1')
}

# Validate that required database credentials are present
if not app.config['MYSQL_PASSWORD']:
    print("⚠️  WARNING: MYSQL_PASSWORD not set in environment variables.")
    print("   Database connection will fail. Please set this in your .env file.")




mysql.init_app(app)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        try:
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
            user = cursor.fetchone()
            if user:
                session['user_id'] = user[0]

                # Check if wallet exists for the user
                cursor.execute("SELECT * FROM wallet WHERE user_id = %s", [user[0]])
                wallet = cursor.fetchone()
                if not wallet:
                    # Create a new wallet entry for the user with a default balance
                    cursor.execute("INSERT INTO wallet (user_id, balance) VALUES (%s, %s)", (user[0], 10000))  # Set initial balance
                    mysql.connection.commit()

                flash('Login successful!', 'success')
                return redirect('/watchlist')
            else:
                flash('Invalid credentials', 'danger')
        except AttributeError:
            flash('Database connection failed. Please check your MySQL server and configuration in app.py.', 'danger')
    return render_template('login.html', form=form)

# Google OAuth login route
@app.route('/login/google')
def google_login():
    # Check if OAuth credentials are configured
    if not client_config or not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file.', 'danger')
        return redirect(url_for('login'))
    
    # Generate a new state token for this request
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state  # Store in session
    session.modified = True  # Ensure session is saved
    print(f"Setting oauth_state in session: {state}")  # Debug log
    
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow
    flow = Flow.from_client_config(
        client_config,
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
    )
    
    # Set the redirect URI explicitly
    flow.redirect_uri = get_google_redirect_uri()
    
    # Generate the authorization URL with the state parameter
    authorization_url, _ = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        state=state,  # Use the same state we stored in the session
        prompt='select_account'
    )
    
    return redirect(authorization_url)

# Google OAuth callback route
@app.route('/login/google/authorized')
def google_authorized():
    # Check if OAuth credentials are configured
    if not client_config or not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file.', 'danger')
        return redirect(url_for('login'))
    
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
        return redirect(url_for('login'))
    
    # Get the authorization code from the response
    code = request.args.get('code')
    print(f"Got authorization code: {code[:10]}..." if code else "No code received")
    
    # Exchange the authorization code for tokens
    try:
        flow = Flow.from_client_config(
            client_config,
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
        )
        
        # Use the same redirect URI as in the authorization request
        flow.redirect_uri = get_google_redirect_uri()
        print(f"Using redirect_uri: {flow.redirect_uri}")
        
        flow.fetch_token(code=code)
        credentials = flow.credentials
        print("Successfully obtained credentials")
        
        idinfo = id_token.verify_oauth2_token(
            credentials._id_token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
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
            return redirect(url_for('login'))
        
        cursor = mysql.connection.cursor()
        
        # Check if user exists by email or google_id
        cursor.execute("SELECT * FROM users WHERE email = %s OR google_id = %s", (email, google_id))
        user = cursor.fetchone()
        print(f"Existing user from DB: {user}")
        
        if not user:
            # Create new user
            username = email.split('@')[0]  # Use part before @ as username
            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = %s", [username])
            if cursor.fetchone():
                # If username exists, append some random string
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
                (user_id, 10000)  # Initial balance
            )
            mysql.connection.commit()
            
            flash('Account created successfully!', 'success')
        else:
            user_id = user[0]
            print(f"Found existing user with ID: {user_id}")
            # Update Google ID if not set
            if not user[3]:  # Assuming google_id is the 4th column
                print(f"Updating Google ID for user {user_id}")
                cursor.execute("UPDATE users SET google_id = %s WHERE id = %s", (google_id, user_id))
                mysql.connection.commit()
        
        # Set user session
        session.permanent = True  # Make the session persistent
        session['user_id'] = user_id
        session['google_token'] = credentials._id_token
        
        print(f"Session after login: {dict(session)}")
        flash('Logged in with Google successfully!', 'success')
        return redirect(url_for('watchlist'))
        
    except Exception as e:
        print(f"Error during Google OAuth: {str(e)}")
        flash('Failed to log in with Google. Please try again.', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect('/login')



@app.route('/holdings')
def holdings():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    
    # Fetch all trades for the user
    cursor.execute("""
        SELECT stock_symbol, action, quantity, price, timestamp 
        FROM trade_log 
        WHERE user_id = %s 
        ORDER BY timestamp
    """, [user_id])
    trades = cursor.fetchall()
    
    # Calculate holdings using float instead of Decimal
    holdings = defaultdict(lambda: {'quantity': 0, 'total_cost': 0.0})
    
    # Process all trades to calculate current holdings
    for trade in trades:
        symbol, action, quantity, price, _ = trade
        # Convert Decimal to float
        price = float(price)
        quantity = int(quantity)
        
        if action == 'buy':
            current = holdings[symbol]
            total_cost = current['total_cost'] + (quantity * price)
            total_quantity = current['quantity'] + quantity
            holdings[symbol] = {
                'quantity': total_quantity,
                'total_cost': total_cost,
                'avg_price': total_cost / total_quantity if total_quantity > 0 else 0
            }
        elif action == 'sell':
            current = holdings[symbol]
            if current['quantity'] >= quantity:
                remaining_quantity = current['quantity'] - quantity
                if remaining_quantity > 0:
                    # Adjust the total cost proportionally
                    remaining_ratio = remaining_quantity / current['quantity']
                    holdings[symbol] = {
                        'quantity': remaining_quantity,
                        'total_cost': current['total_cost'] * remaining_ratio,
                        'avg_price': (current['total_cost'] * remaining_ratio) / remaining_quantity
                    }
                else:
                    # If no shares left, remove from holdings
                    holdings.pop(symbol)
    
    # Fetch current prices and calculate profits/losses
    holdings_list = []
    total_value = 0.0
    total_cost = 0.0
    
    for symbol, data in holdings.items():
        if data['quantity'] > 0:  # Only include stocks we still hold
            try:
                ticker = yf.Ticker(symbol)
                current_price = float(ticker.history(period='1d')['Close'].iloc[-1])
                
                total_value_stock = current_price * data['quantity']
                profit_loss = total_value_stock - data['total_cost']
                profit_loss_percent = (profit_loss / data['total_cost']) * 100 if data['total_cost'] > 0 else 0
                
                holdings_list.append({
                    'symbol': symbol,
                    'quantity': data['quantity'],
                    'avg_price': data['avg_price'],
                    'current_price': current_price,
                    'total_value': total_value_stock,
                    'profit_loss': profit_loss,
                    'profit_loss_percent': profit_loss_percent
                })
                
                total_value += total_value_stock
                total_cost += data['total_cost']
                
            except Exception as e:
                print(f"Error fetching price for {symbol}: {str(e)}")  # Debug print
                continue
    
    # Calculate total portfolio profits/losses
    total_profit_loss = total_value - total_cost
    total_profit_loss_percent = (total_profit_loss / total_cost * 100) if total_cost > 0 else 0
    
    return render_template('holdings.html', 
                         holdings=holdings_list,
                         total_value=total_value,
                         total_profit_loss=total_profit_loss,
                         total_profit_loss_percent=total_profit_loss_percent)
def crossover(series1, series2):
    """Check if series1 crosses over series2"""
    return series1[-2] < series2[-2] and series1[-1] > series2[-1]
def validate_dates(data):
    """Ensure data doesn't contain future dates"""
    now = datetime.now(pytz.utc).date()
    latest_date = data.index[-1].date()
    
    if latest_date > now:
        print(f"⚠️ Data anomaly: Future date {latest_date} detected")
        return False
        
    if data.index[0].date() > now:
        print(f"⚠️ Data anomaly: Start date {data.index[0].date()} is in future")
        return False
        
    return True
# Strategy automation removed

# Option chain functionality has been removed

def execute_trade(user_id, symbol, action, quantity):
    try:
        print(f"Attempting {action} order for {symbol}...")
        data = yf.download(symbol, period='1d', progress=False)
        
        if data.empty:
            print("⚠️ No price data available!")
            return False
            
        price = data['Close'][-1]
        print(f"Current price: {price:.2f}")
        
        cursor = mysql.connection.cursor()
        
        # Update wallet
        cursor.execute("SELECT balance FROM wallet WHERE user_id = %s", (user_id,))
        old_balance = cursor.fetchone()[0]
        
        # Execute trade
        if action == 'buy':
            new_balance = old_balance - (price * quantity)
        else:
            new_balance = old_balance + (price * quantity)
        
        cursor.execute("UPDATE wallet SET balance = %s WHERE user_id = %s", (new_balance, user_id))
        
        # Record trade
        cursor.execute("""
            INSERT INTO trade_log (user_id, stock_symbol, action, quantity, price)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, symbol, action, quantity, price))
        
        mysql.connection.commit()
        print(f"✅ Success: {action} {quantity} {symbol} @ {price:.2f}")
        print(f"Balance changed: {old_balance:.2f} → {new_balance:.2f}")
        return True
        
    except Exception as e:
        print(f"❌ Trade failed: {str(e)}")
        mysql.connection.rollback()
        return False

# Strategy routes removed

# Keep your existing routes for:
# - /login
# - /register
# - /watchlist
# - /holdings
# - /trade (manual trading)
@app.route('/trade', methods=['POST'])
def trade():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    stock_symbol = request.form['stock_symbol'].upper()
    quantity = int(request.form['quantity'])
    action = request.form['action']

    cursor = mysql.connection.cursor()
    
    # Check if user has enough shares when selling
    if action == 'sell':
        cursor.execute("""
            SELECT 
                COALESCE(SUM(CASE WHEN action = 'buy' THEN quantity 
                    WHEN action = 'sell' THEN -quantity END), 0) as total_quantity
            FROM trade_log 
            WHERE user_id = %s AND stock_symbol = %s
        """, (user_id, stock_symbol))
        
        current_quantity = cursor.fetchone()[0]
        if current_quantity < quantity:
            flash(f'Insufficient shares. You only have {current_quantity} shares of {stock_symbol}.', 'danger')
            return redirect('/watchlist')

    try:
        stock_data = yf.Ticker(stock_symbol).history(period='1d')
        if len(stock_data) == 0:
            flash('Invalid stock symbol or no data available.', 'danger')
            return redirect('/watchlist')
        price = float(stock_data['Close'].iloc[-1])
    except Exception as e:
        flash(f'Failed to fetch stock price: {str(e)}', 'danger')
        return redirect('/watchlist')

    # Fetch wallet balance
    cursor.execute("SELECT balance FROM wallet WHERE user_id = %s", [user_id])
    wallet = cursor.fetchone()
    balance = float(wallet[0]) if wallet else 0

    total_price = price * quantity

    if action == 'buy':
        if total_price > balance:
            flash('Insufficient funds to complete the purchase.', 'danger')
            return redirect('/watchlist')
        else:
            cursor.execute("UPDATE wallet SET balance = balance - %s WHERE user_id = %s", (total_price, user_id))
            cursor.execute(
                "INSERT INTO trade_log (user_id, stock_symbol, action, quantity, price, timestamp) VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, stock_symbol, action, quantity, price, datetime.now())
            )
            flash(f'Successfully bought {quantity} shares of {stock_symbol}.', 'success')

    elif action == 'sell':
        cursor.execute("UPDATE wallet SET balance = balance + %s WHERE user_id = %s", (total_price, user_id))
        cursor.execute(
            "INSERT INTO trade_log (user_id, stock_symbol, action, quantity, price, timestamp) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, stock_symbol, action, quantity, price, datetime.now())
        )
        flash(f'Successfully sold {quantity} shares of {stock_symbol}.', 'success')

    mysql.connection.commit()
    return redirect('/holdings')


@app.route('/clear-trade-log', methods=['POST'])
def clear_trade_log():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    cursor = mysql.connection.cursor()

    # Check if user has any holdings before clearing trade log
    # Holdings are calculated from trade_log, so clearing it would remove holdings
    cursor.execute("""
        SELECT stock_symbol, action, quantity 
        FROM trade_log 
        WHERE user_id = %s 
        ORDER BY timestamp
    """, [user_id])
    trades = cursor.fetchall()
    
    # Calculate current holdings to check if user has any
    holdings = defaultdict(lambda: {'quantity': 0})
    for trade in trades:
        symbol, action, quantity = trade  # Only 3 columns selected
        quantity = int(quantity)
        if action == 'buy':
            holdings[symbol]['quantity'] += quantity
        elif action == 'sell':
            holdings[symbol]['quantity'] -= quantity
    
    # Check if user has any active holdings
    has_holdings = any(data['quantity'] > 0 for symbol, data in holdings.items())
    
    if has_holdings:
        flash('Cannot clear trade log: You have active holdings. Clearing the trade log would remove your holdings data. Please sell all your positions first if you want to clear the trade log.', 'danger')
        return redirect('/trade-log')
    
    # Only clear if user has no holdings
    cursor.execute("DELETE FROM trade_log WHERE user_id = %s", [user_id])
    mysql.connection.commit()

    flash('Trade log cleared successfully!', 'success')
    return redirect('/trade-log')


@app.route('/delete-watchlist/<stock_symbol>', methods=['POST'])
def delete_watchlist(stock_symbol):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM watchlist WHERE user_id = %s AND stock_symbol = %s", (user_id, stock_symbol))
    mysql.connection.commit()
    flash(f'Stock {stock_symbol} removed from your watchlist.', 'success')
    return redirect('/watchlist')


@app.route('/search_stocks')
def search_stocks():
    """Search for stocks by name or symbol"""
    query = request.args.get('q', '').strip().upper()
    
    if len(query) < 2:
        return jsonify([])
    
    # Common Indian stocks mapping (name -> Yahoo symbol)
    indian_stocks = {
        'RELIANCE': ('Reliance Industries', 'RELIANCE.NS'),
        'TCS': ('Tata Consultancy Services', 'TCS.NS'),
        'HDFCBANK': ('HDFC Bank', 'HDFCBANK.NS'),
        'INFY': ('Infosys', 'INFY.NS'),
        'ICICIBANK': ('ICICI Bank', 'ICICIBANK.NS'),
        'HINDUNILVR': ('Hindustan Unilever', 'HINDUNILVR.NS'),
        'SBIN': ('State Bank of India', 'SBIN.NS'),
        'BHARTIARTL': ('Bharti Airtel', 'BHARTIARTL.NS'),
        'ITC': ('ITC Limited', 'ITC.NS'),
        'KOTAKBANK': ('Kotak Mahindra Bank', 'KOTAKBANK.NS'),
        'LT': ('Larsen & Toubro', 'LT.NS'),
        'AXISBANK': ('Axis Bank', 'AXISBANK.NS'),
        'ASIANPAINT': ('Asian Paints', 'ASIANPAINT.NS'),
        'MARUTI': ('Maruti Suzuki', 'MARUTI.NS'),
        'SUNPHARMA': ('Sun Pharma', 'SUNPHARMA.NS'),
        'TITAN': ('Titan Company', 'TITAN.NS'),
        'BAJFINANCE': ('Bajaj Finance', 'BAJFINANCE.NS'),
        'WIPRO': ('Wipro', 'WIPRO.NS'),
        'ULTRACEMCO': ('UltraTech Cement', 'ULTRACEMCO.NS'),
        'ONGC': ('ONGC', 'ONGC.NS'),
        'NTPC': ('NTPC', 'NTPC.NS'),
        'POWERGRID': ('Power Grid Corp', 'POWERGRID.NS'),
        'TATAMOTORS': ('Tata Motors', 'TATAMOTORS.NS'),
        'TATASTEEL': ('Tata Steel', 'TATASTEEL.NS'),
        'JSWSTEEL': ('JSW Steel', 'JSWSTEEL.NS'),
        'ADANIENT': ('Adani Enterprises', 'ADANIENT.NS'),
        'ADANIPORTS': ('Adani Ports', 'ADANIPORTS.NS'),
        'COALINDIA': ('Coal India', 'COALINDIA.NS'),
        'BPCL': ('BPCL', 'BPCL.NS'),
        'IOC': ('Indian Oil Corp', 'IOC.NS'),
        'GAIL': ('GAIL India', 'GAIL.NS'),
        'DRREDDY': ('Dr Reddys Labs', 'DRREDDY.NS'),
        'CIPLA': ('Cipla', 'CIPLA.NS'),
        'DIVISLAB': ('Divis Labs', 'DIVISLAB.NS'),
        'APOLLOHOSP': ('Apollo Hospitals', 'APOLLOHOSP.NS'),
        'EICHERMOT': ('Eicher Motors', 'EICHERMOT.NS'),
        'BAJAJ-AUTO': ('Bajaj Auto', 'BAJAJ-AUTO.NS'),
        'HEROMOTOCO': ('Hero MotoCorp', 'HEROMOTOCO.NS'),
        'M&M': ('Mahindra & Mahindra', 'M&M.NS'),
        'TECHM': ('Tech Mahindra', 'TECHM.NS'),
        'HCLTECH': ('HCL Technologies', 'HCLTECH.NS'),
        'NESTLEIND': ('Nestle India', 'NESTLEIND.NS'),
        'BRITANNIA': ('Britannia Industries', 'BRITANNIA.NS'),
        'DABUR': ('Dabur India', 'DABUR.NS'),
        'GODREJCP': ('Godrej Consumer', 'GODREJCP.NS'),
        'MARICO': ('Marico', 'MARICO.NS'),
        'PIDILITIND': ('Pidilite Industries', 'PIDILITIND.NS'),
        'BERGEPAINT': ('Berger Paints', 'BERGEPAINT.NS'),
        'INDUSINDBK': ('IndusInd Bank', 'INDUSINDBK.NS'),
        'BANKBARODA': ('Bank of Baroda', 'BANKBARODA.NS'),
        'PNB': ('Punjab National Bank', 'PNB.NS'),
        'CANBK': ('Canara Bank', 'CANBK.NS'),
        'SBILIFE': ('SBI Life Insurance', 'SBILIFE.NS'),
        'HDFCLIFE': ('HDFC Life', 'HDFCLIFE.NS'),
        'ICICIGI': ('ICICI Lombard', 'ICICIGI.NS'),
        'BAJAJFINSV': ('Bajaj Finserv', 'BAJAJFINSV.NS'),
        'ZOMATO': ('Zomato', 'ZOMATO.NS'),
        'PAYTM': ('Paytm', 'PAYTM.NS'),
        'NYKAA': ('Nykaa', 'NYKAA.NS'),
        'DELHIVERY': ('Delhivery', 'DELHIVERY.NS'),
        'IRCTC': ('IRCTC', 'IRCTC.NS'),
        'IRFC': ('Indian Railway Finance', 'IRFC.NS'),
        'HAL': ('Hindustan Aeronautics', 'HAL.NS'),
        'BEL': ('Bharat Electronics', 'BEL.NS'),
        'BHEL': ('BHEL', 'BHEL.NS'),
        'VEDL': ('Vedanta', 'VEDL.NS'),
        'HINDALCO': ('Hindalco', 'HINDALCO.NS'),
        'GRASIM': ('Grasim Industries', 'GRASIM.NS'),
        'SHREECEM': ('Shree Cement', 'SHREECEM.NS'),
        'AMBUJACEM': ('Ambuja Cements', 'AMBUJACEM.NS'),
        'ACC': ('ACC', 'ACC.NS'),
        'UPL': ('UPL', 'UPL.NS'),
        'TATAPOWER': ('Tata Power', 'TATAPOWER.NS'),
        'ADANIGREEN': ('Adani Green Energy', 'ADANIGREEN.NS'),
        'TATACONSUM': ('Tata Consumer', 'TATACONSUM.NS'),
        'INDIGO': ('IndiGo', 'INDIGO.NS'),
        'IDEA': ('Vodafone Idea', 'IDEA.NS'),
        'YESBANK': ('Yes Bank', 'YESBANK.NS'),
        'FEDERALBNK': ('Federal Bank', 'FEDERALBNK.NS'),
        'IDFCFIRSTB': ('IDFC First Bank', 'IDFCFIRSTB.NS'),
        'BANDHANBNK': ('Bandhan Bank', 'BANDHANBNK.NS'),
        'AUBANK': ('AU Small Finance', 'AUBANK.NS'),
        'MUTHOOTFIN': ('Muthoot Finance', 'MUTHOOTFIN.NS'),
        'CHOLAFIN': ('Cholamandalam Inv', 'CHOLAFIN.NS'),
        'RECLTD': ('REC Ltd', 'RECLTD.NS'),
        'PFC': ('Power Finance Corp', 'PFC.NS'),
        'LICHSGFIN': ('LIC Housing Finance', 'LICHSGFIN.NS'),
        'TVSMOTOR': ('TVS Motor', 'TVSMOTOR.NS'),
        'ASHOKLEY': ('Ashok Leyland', 'ASHOKLEY.NS'),
        'MRF': ('MRF', 'MRF.NS'),
        'APOLLOTYRE': ('Apollo Tyres', 'APOLLOTYRE.NS'),
        'BALKRISIND': ('Balkrishna Ind', 'BALKRISIND.NS'),
        'SIEMENS': ('Siemens', 'SIEMENS.NS'),
        'ABB': ('ABB India', 'ABB.NS'),
        'HAVELLS': ('Havells India', 'HAVELLS.NS'),
        'VOLTAS': ('Voltas', 'VOLTAS.NS'),
        'BLUESTAR': ('Blue Star', 'BLUESTAR.NS'),
        'PAGEIND': ('Page Industries', 'PAGEIND.NS'),
        'DIXON': ('Dixon Technologies', 'DIXON.NS'),
        'POLYCAB': ('Polycab India', 'POLYCAB.NS'),
        'HAPPSTMNDS': ('Happiest Minds', 'HAPPSTMNDS.NS'),
        'LTIM': ('LTIMindtree', 'LTIM.NS'),
        'PERSISTENT': ('Persistent Systems', 'PERSISTENT.NS'),
        'COFORGE': ('Coforge', 'COFORGE.NS'),
        'MPHASIS': ('Mphasis', 'MPHASIS.NS'),
        'OFSS': ('Oracle Financial', 'OFSS.NS'),
        'TATAELXSI': ('Tata Elxsi', 'TATAELXSI.NS'),
        'LICI': ('LIC India', 'LICI.NS'),
        'LODHA': ('Macrotech Developers', 'LODHA.NS'),
        'DLF': ('DLF', 'DLF.NS'),
        'GODREJPROP': ('Godrej Properties', 'GODREJPROP.NS'),
        'OBEROIRLTY': ('Oberoi Realty', 'OBEROIRLTY.NS'),
        'PRESTIGE': ('Prestige Estates', 'PRESTIGE.NS'),
        'PIIND': ('PI Industries', 'PIIND.NS'),
        'ATUL': ('Atul', 'ATUL.NS'),
        'DEEPAKNTR': ('Deepak Nitrite', 'DEEPAKNTR.NS'),
        'SRF': ('SRF', 'SRF.NS'),
        'AARTIIND': ('Aarti Industries', 'AARTIIND.NS'),
        'TRENT': ('Trent', 'TRENT.NS'),
        'ABFRL': ('Aditya Birla Fashion', 'ABFRL.NS'),
        'RAYMOND': ('Raymond', 'RAYMOND.NS'),
        'VBL': ('Varun Beverages', 'VBL.NS'),
        'JUBLFOOD': ('Jubilant FoodWorks', 'JUBLFOOD.NS'),
        'DEVYANI': ('Devyani International', 'DEVYANI.NS'),
        'BHARATFORG': ('Bharat Forge', 'BHARATFORG.NS'),
        'BOSCHLTD': ('Bosch', 'BOSCHLTD.NS'),
        'MOTHERSON': ('Motherson Sumi', 'MOTHERSON.NS'),
        'EXIDEIND': ('Exide Industries', 'EXIDEIND.NS'),
        'AMARAJABAT': ('Amara Raja Batteries', 'AMARAJABAT.NS'),
    }
    
    # Common US stocks
    us_stocks = {
        'AAPL': ('Apple Inc', 'AAPL'),
        'GOOGL': ('Alphabet (Google)', 'GOOGL'),
        'MSFT': ('Microsoft', 'MSFT'),
        'AMZN': ('Amazon', 'AMZN'),
        'META': ('Meta (Facebook)', 'META'),
        'TSLA': ('Tesla', 'TSLA'),
        'NVDA': ('NVIDIA', 'NVDA'),
        'NFLX': ('Netflix', 'NFLX'),
        'AMD': ('AMD', 'AMD'),
        'INTC': ('Intel', 'INTC'),
        'CRM': ('Salesforce', 'CRM'),
        'ORCL': ('Oracle', 'ORCL'),
        'IBM': ('IBM', 'IBM'),
        'CSCO': ('Cisco', 'CSCO'),
        'ADBE': ('Adobe', 'ADBE'),
        'PYPL': ('PayPal', 'PYPL'),
        'V': ('Visa', 'V'),
        'MA': ('Mastercard', 'MA'),
        'JPM': ('JPMorgan Chase', 'JPM'),
        'BAC': ('Bank of America', 'BAC'),
        'WMT': ('Walmart', 'WMT'),
        'DIS': ('Disney', 'DIS'),
        'KO': ('Coca-Cola', 'KO'),
        'PEP': ('PepsiCo', 'PEP'),
        'NKE': ('Nike', 'NKE'),
        'MCD': ('McDonalds', 'MCD'),
        'SBUX': ('Starbucks', 'SBUX'),
        'BA': ('Boeing', 'BA'),
        'GE': ('General Electric', 'GE'),
        'F': ('Ford', 'F'),
        'GM': ('General Motors', 'GM'),
        'UBER': ('Uber', 'UBER'),
        'LYFT': ('Lyft', 'LYFT'),
        'ABNB': ('Airbnb', 'ABNB'),
        'SNAP': ('Snap Inc', 'SNAP'),
        'TWTR': ('Twitter', 'TWTR'),
        'SPOT': ('Spotify', 'SPOT'),
        'ZM': ('Zoom', 'ZM'),
        'COIN': ('Coinbase', 'COIN'),
        'PLTR': ('Palantir', 'PLTR'),
        'SOFI': ('SoFi', 'SOFI'),
        'HOOD': ('Robinhood', 'HOOD'),
    }
    
    results = []
    
    # Search in Indian stocks
    for symbol, (name, yahoo_symbol) in indian_stocks.items():
        if query in symbol or query in name.upper():
            results.append({
                'symbol': yahoo_symbol,
                'name': name,
                'exchange': 'NSE'
            })
    
    # Search in US stocks
    for symbol, (name, yahoo_symbol) in us_stocks.items():
        if query in symbol or query in name.upper():
            results.append({
                'symbol': yahoo_symbol,
                'name': name,
                'exchange': 'NYSE/NASDAQ'
            })
    
    # Limit results to 10
    return jsonify(results[:10])


@app.route('/watchlist', methods=['GET', 'POST'])
def watchlist():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    cursor = mysql.connection.cursor()

    # Handle adding a new stock to the watchlist
    if request.method == 'POST':
        stock_symbol = request.form.get('stock_symbol').upper()
        
        # Check if the stock is already in the watchlist
        cursor.execute("SELECT * FROM watchlist WHERE user_id = %s AND stock_symbol = %s", (user_id, stock_symbol))
        if cursor.fetchone():
            flash(f'{stock_symbol} is already in your watchlist.', 'info')
        else:
            # Insert the new stock
            cursor.execute("INSERT INTO watchlist (user_id, stock_symbol) VALUES (%s, %s)", (user_id, stock_symbol))
            mysql.connection.commit()
            flash(f'{stock_symbol} has been added to your watchlist.', 'success')
        
        # Redirect to the watchlist page to prevent form resubmission
        return redirect(url_for('watchlist'))

    # Fetch the user's watchlist
    cursor.execute("SELECT stock_symbol FROM watchlist WHERE user_id = %s", [user_id])
    watchlist = cursor.fetchall()

    # Fetch real-time prices, change, and percentage change for stocks
    prices = {}
    for stock in watchlist:
        stock_symbol = stock[0]
        try:
            stock_data = yf.Ticker(stock_symbol).history(period='2d')  # Fetch last 2 days of data
            if len(stock_data) >= 2:
                prev_close = stock_data['Close'].iloc[-2]  # Previous day's closing price
                current_price = stock_data['Close'].iloc[-1]  # Current price
                change = current_price - prev_close
                change_percent = (change / prev_close) * 100
                prices[stock_symbol] = {
                    'price': round(current_price, 2),
                    'change': round(change, 2),
                    'change_percent': round(change_percent, 2)
                }
            else:
                prices[stock_symbol] = {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}
        except Exception:
            prices[stock_symbol] = {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}

    # Fetch live index prices
    indices = ['^NSEI', '^IXIC', '^DJI', '^BSESN']  # Nifty, Nasdaq, Dow Jones, Sensex
    index_prices = {}
    for index in indices:
        try:
            index_data = yf.Ticker(index).history(period='3d')  # Fetch last 3 days of data
            if len(index_data) >= 2:
                prev_close = index_data['Close'].iloc[-2]  # Previous day's closing price
                current_price = index_data['Close'].iloc[-1]  # Current price
                change = current_price - prev_close
                change_percent = (change / prev_close) * 100
                index_prices[index] = {
                    'price': round(current_price, 2),
                    'change': round(change, 2),
                    'change_percent': round(change_percent, 2)
                }
            else:
                index_prices[index] = {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}
        except Exception:
            index_prices[index] = {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}

    return render_template('watchlist.html', watchlist=watchlist, prices=prices, index_prices=index_prices)

@app.route('/add_funds', methods=['POST'])
def add_funds():
    if 'user_id' not in session:
        return redirect('/login')

    try:
        amount = float(request.form['amount'])
        if amount <= 0:
            flash('Please enter a positive amount.', 'danger')
            return redirect('/wallet')

        user_id = session['user_id']
        cursor = mysql.connection.cursor()

        # Update wallet balance
        cursor.execute("UPDATE wallet SET balance = balance + %s WHERE user_id = %s", (amount, user_id))
        
        # Log the transaction
        cursor.execute("""
            INSERT INTO wallet_transactions 
            (user_id, type, amount, balance_after, timestamp) 
            VALUES (%s, %s, %s, 
                (SELECT balance FROM wallet WHERE user_id = %s), 
                %s)
        """, (user_id, 'deposit', amount, user_id, datetime.now()))
        
        mysql.connection.commit()
        flash(f'Successfully added ${amount:.2f} to your wallet.', 'success')
        
    except ValueError:
        flash('Invalid amount entered.', 'danger')
    except Exception as e:
        flash('An error occurred while processing your request.', 'danger')
        print(f"Error adding funds: {str(e)}")  # For debugging
        
    return redirect('/wallet')

@app.route('/wallet')
def wallet():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    
    # Get wallet balance
    cursor.execute("SELECT balance FROM wallet WHERE user_id = %s", [user_id])
    wallet_data = cursor.fetchone()
    balance = float(wallet_data[0]) if wallet_data else 0.0
    
    # Get recent transactions
    cursor.execute("""
        SELECT type, amount, balance_after, timestamp 
        FROM wallet_transactions 
        WHERE user_id = %s 
        ORDER BY timestamp DESC 
        LIMIT 10
    """, [user_id])
    transactions = [
        {
            'type': row[0],
            'amount': float(row[1]),
            'balance_after': float(row[2]),
            'timestamp': row[3]
        }
        for row in cursor.fetchall()
    ]
    
    return render_template('wallet.html', balance=balance, transactions=transactions)

@app.route('/trade-log')
def trade_log():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT stock_symbol, action, quantity, price, timestamp FROM trade_log WHERE user_id = %s", [user_id])
    trades = cursor.fetchall()
    return render_template('trade_log.html', trades=trades)

# Option chain functionality has been removed

# ============================================
# WebSocket Real-Time Price Updates
# ============================================

# Store active connections and their symbols
active_connections = {}

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    if request.sid in active_connections:
        del active_connections[request.sid]
    print(f'Client disconnected: {request.sid}')

@socketio.on('subscribe_watchlist')
def handle_subscribe_watchlist(data):
    """Subscribe to watchlist price updates"""
    user_id = data.get('user_id')
    if not user_id:
        return
    
    # Store the subscription
    active_connections[request.sid] = {
        'user_id': user_id,
        'type': 'watchlist'
    }
    print(f'Client {request.sid} subscribed to watchlist for user {user_id}')

@socketio.on('subscribe_holdings')
def handle_subscribe_holdings(data):
    """Subscribe to holdings price updates"""
    user_id = data.get('user_id')
    if not user_id:
        return
    
    # Store the subscription
    active_connections[request.sid] = {
        'user_id': user_id,
        'type': 'holdings'
    }
    print(f'Client {request.sid} subscribed to holdings for user {user_id}')

def get_stock_prices(symbols):
    """Fetch current prices for multiple stocks"""
    prices = {}
    indices = ['^NSEI', '^IXIC', '^DJI', '^BSESN']
    
    for symbol in symbols:
        try:
            ticker = yf.Ticker(symbol)
            
            # For indices, get 3 days of data
            if symbol in indices:
                hist = ticker.history(period='3d')
            else:
                hist = ticker.history(period='2d')
            
            if len(hist) >= 2:
                prev_close = hist['Close'].iloc[-2]
                current_price = hist['Close'].iloc[-1]
                change = current_price - prev_close
                change_percent = (change / prev_close) * 100
                
                prices[symbol] = {
                    'price': round(float(current_price), 2),
                    'change': round(float(change), 2),
                    'change_percent': round(float(change_percent), 2)
                }
            else:
                prices[symbol] = {
                    'price': 'N/A',
                    'change': 'N/A',
                    'change_percent': 'N/A'
                }
        except Exception as e:
            print(f"Error fetching price for {symbol}: {e}")
            prices[symbol] = {
                'price': 'N/A',
                'change': 'N/A',
                'change_percent': 'N/A'
            }
    
    return prices

def background_price_updater():
    """Background task to push price updates to connected clients"""
    print("Starting background price updater...")
    
    while True:
        try:
            if active_connections:
                print(f"[Background Task] Active connections: {len(active_connections)}")
                with app.app_context():
                    # Get unique user IDs
                    user_ids = set()
                    for conn_data in active_connections.values():
                        user_ids.add(conn_data['user_id'])
                    
                    print(f"[Background Task] Fetching data for {len(user_ids)} user(s)")
                    
                    # Fetch data for each user
                    for user_id in user_ids:
                        cursor = mysql.connection.cursor()
                        
                        # Get watchlist stocks for this user
                        cursor.execute("SELECT stock_symbol FROM watchlist WHERE user_id = %s", [user_id])
                        watchlist = [row[0] for row in cursor.fetchall()]
                        print(f"[Background Task] User {user_id} watchlist: {watchlist}")
                        
                        # Get holdings stocks for this user
                        cursor.execute("SELECT stock_symbol, action, quantity, price FROM trade_log WHERE user_id = %s", [user_id])
                        trades = cursor.fetchall()
                        print(f"[Background Task] User {user_id} trades: {len(trades)} trades")
                    
                        holdings = {}
                        for stock_symbol, action, quantity, price in trades:
                            if stock_symbol not in holdings:
                                holdings[stock_symbol] = {'quantity': 0, 'total_cost': 0}
                            
                            if action == 'BUY':
                                holdings[stock_symbol]['quantity'] += quantity
                                holdings[stock_symbol]['total_cost'] += quantity * float(price)
                            elif action == 'SELL':
                                holdings[stock_symbol]['quantity'] -= quantity
                                holdings[stock_symbol]['total_cost'] -= quantity * float(price)
                        
                        holdings = {symbol: data for symbol, data in holdings.items() if data['quantity'] > 0}
                        holdings_symbols = list(holdings.keys())
                        
                        # Fetch prices for watchlist
                        if watchlist:
                            indices = ['^NSEI', '^IXIC', '^DJI', '^BSESN']
                            all_watchlist_symbols = list(set(watchlist + indices))
                            print(f"[Background Task] Fetching prices for: {all_watchlist_symbols}")
                            watchlist_prices = get_stock_prices(all_watchlist_symbols)
                            print(f"[Background Task] Fetched {len(watchlist_prices)} prices")
                            
                            # Emit to clients subscribed to watchlist
                            emitted_count = 0
                            for sid, conn_data in list(active_connections.items()):
                                if conn_data['user_id'] == user_id and conn_data['type'] == 'watchlist':
                                    socketio.emit('price_update', {
                                        'prices': watchlist_prices,
                                        'timestamp': datetime.now().isoformat()
                                    }, room=sid)
                                    emitted_count += 1
                            print(f"[Background Task] Emitted price updates to {emitted_count} client(s)")
                        
                        # Fetch prices for holdings
                        if holdings_symbols:
                            holdings_prices = get_stock_prices(holdings_symbols)
                            
                            # Calculate P/L for each holding
                            holdings_data = []
                            for symbol in holdings_symbols:
                                if holdings_prices[symbol]['price'] != 'N/A':
                                    avg_price = holdings[symbol]['total_cost'] / holdings[symbol]['quantity']
                                    current_price = holdings_prices[symbol]['price']
                                    quantity = holdings[symbol]['quantity']
                                    total_value = current_price * quantity
                                    profit_loss = total_value - (avg_price * quantity)
                                    profit_loss_percent = (profit_loss / (avg_price * quantity)) * 100
                                    
                                    holdings_data.append({
                                        'symbol': symbol,
                                        'quantity': quantity,
                                        'avg_price': round(avg_price, 2),
                                        'current_price': current_price,
                                        'total_value': round(total_value, 2),
                                        'profit_loss': round(profit_loss, 2),
                                        'profit_loss_percent': round(profit_loss_percent, 2)
                                    })
                            
                            # Emit to clients subscribed to holdings
                            for sid, conn_data in list(active_connections.items()):
                                if conn_data['user_id'] == user_id and conn_data['type'] == 'holdings':
                                    socketio.emit('holdings_update', {
                                        'holdings': holdings_data,
                                        'timestamp': datetime.now().isoformat()
                                    }, room=sid)
                        
                        cursor.close()
            
            # Update every 10 seconds (adjust as needed)
            socketio.sleep(10)
            
        except Exception as e:
            print(f"Error in background updater: {e}")
            socketio.sleep(10)

if __name__ == '__main__':
    # Start background task
    print("Initializing WebSocket server...")
    socketio.start_background_task(background_price_updater)
    
    # Use socketio.run instead of app.run
    print("Starting server on http://127.0.0.1:5001")
    socketio.run(app, debug=True, port=5001, allow_unsafe_werkzeug=True)
