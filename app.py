from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
import yfinance as yf
import datetime
import pytz
from datetime import datetime, timedelta
from collections import defaultdict
from decimal import Decimal

from threading import Thread
import time
import json
import os
import secrets
from nselib import derivatives
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests as google_requests
import requests
from flask.sessions import SecureCookieSessionInterface
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configure session
app.config.update(
    SECRET_KEY='your_secret_key',  # In production, use a strong secret key from environment variables
    SESSION_COOKIE_SECURE=False,   # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=1)  # Session expires after 1 day
)



# Google OAuth Configuration
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Remove in production
GOOGLE_CLIENT_ID = '255034053753-mpv519khm8tbltnr342fg68312dloau3.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'

# Initialize the OAuth flow
client_config = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [
            "http://localhost:5001/login/google/authorized",
            "http://127.0.0.1:5001/login/google/authorized"
        ]
    }
}

# Make sure the redirect URI is consistent
def get_google_redirect_uri():
    return 'http://localhost:5001/login/google/authorized'  # Use the same as in Google Cloud Console

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

# MySQL configuration
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'yui1987'
app.config['MYSQL_DB'] = 'trading_website'




mysql = MySQL(app)

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
    return render_template('login.html', form=form)

# Google OAuth login route
@app.route('/login/google')
def google_login():
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

    # Delete trade logs for the current user
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


@app.route('/watchlist', methods=['GET', 'POST'])
def watchlist():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    cursor = mysql.connection.cursor()

    # Handle adding a new stock to the watchlist
    if request.method == 'POST':
        stock_symbol = request.form.get('stock_symbol').upper()
        cursor.execute("INSERT INTO watchlist (user_id, stock_symbol) VALUES (%s, %s)", (user_id, stock_symbol))
        mysql.connection.commit()

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

@app.route('/option_chain/<stock_symbol>')
def option_chain(stock_symbol):
    if 'user_id' not in session:
        return redirect('/login')

    try:
        # Use nselib for Indian stock options
        # nselib.derivatives.nse_live_option_chain expects a symbol like 'RELIANCE'
        # It returns a pandas DataFrame directly
        print(f"Attempting to fetch option chain for: {stock_symbol}")
        option_data_df = derivatives.nse_live_option_chain(stock_symbol)
        print(f"Option data DataFrame head:\n{option_data_df.head()}")
        print(f"Option data DataFrame columns:\n{option_data_df.columns}")
        
        if option_data_df.empty:
            flash(f"No option data available for {stock_symbol}.", 'danger')
            return redirect('/watchlist')

        # Extract unique expiry dates
        exps = option_data_df['Expiry_Date'].unique().tolist()
        exps.sort() # Sort expiry dates for display
        print(f"Expiry dates fetched: {exps}")

        options_data = {}
        for exp in exps:
            options_data[exp] = {'calls': [], 'puts': []}
            # Filter DataFrame for the current expiry
            expiry_df = option_data_df[option_data_df['Expiry_Date'] == exp]
            
            for index, row in expiry_df.iterrows():
                # Construct Call Option data
                call_strike = row['Strike_Price']
                call_contract_symbol = f"{stock_symbol}{exp.replace('-','')}{int(call_strike)}CE"
                options_data[exp]['calls'].append({
                    'strike': call_strike,
                    'bid': row['CALLS_Bid_Price'],
                    'ask': row['CALLS_Ask_Price'],
                    'lastPrice': row['CALLS_LTP'],
                    'volume': row['CALLS_Volume'],
                    'openInterest': row['CALLS_OI'],
                    'contractSymbol': call_contract_symbol # Derived
                })
                
                # Construct Put Option data
                put_strike = row['Strike_Price']
                put_contract_symbol = f"{stock_symbol}{exp.replace('-','')}{int(put_strike)}PE"
                options_data[exp]['puts'].append({
                    'strike': put_strike,
                    'bid': row['PUTS_Bid_Price'],
                    'ask': row['PUTS_Ask_Price'],
                    'lastPrice': row['PUTS_LTP'],
                    'volume': row['PUTS_Volume'],
                    'openInterest': row['PUTS_OI'],
                    'contractSymbol': put_contract_symbol # Derived
                })
            
            # Sort calls and puts by strike price
            options_data[exp]['calls'].sort(key=lambda x: x['strike'])
            options_data[exp]['puts'].sort(key=lambda x: x['strike'])
        
        return render_template('option_chain.html', 
                               stock_symbol=stock_symbol, 
                               options_data=options_data,
                               expiries=exps)

    except Exception as e:
        print(f"Error fetching option chain for {stock_symbol}: {str(e)}")  # Debug print
        flash(f"Error fetching option chain for {stock_symbol}: {str(e)}", 'danger')
        return redirect('/watchlist')

@app.route('/trade_option', methods=['POST'])
def trade_option():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    stock_symbol = request.form['symbol'].upper()
    option_symbol = request.form['option_symbol']
    action = request.form['action']
    price = float(request.form['price']) # This is the option premium
    option_type = request.form['type'] # 'call' or 'put'
    quantity = 1 # Assuming 1 contract for simplicity for now

    cursor = mysql.connection.cursor()
    # Fetch wallet balance
    cursor.execute("SELECT balance FROM wallet WHERE user_id = %s", [user_id])
    wallet = cursor.fetchone()
    balance = float(wallet[0]) if wallet else 0

    total_price = price * quantity * 100

    # Fetch current net position for this option
    cursor.execute(
        "SELECT COALESCE(SUM(CASE WHEN action = 'buy' THEN quantity ELSE -quantity END), 0) FROM option_trade_log WHERE user_id = %s AND option_symbol = %s",
        (user_id, option_symbol)
    )
    current_quantity = cursor.fetchone()[0]

    if action == 'buy':
        # If user is short (negative quantity), allow buy to close
        if total_price > balance:
            flash('Insufficient funds to complete the purchase.', 'danger')
            return redirect(f'/option_chain/{stock_symbol}')
        else:
            cursor.execute("UPDATE wallet SET balance = balance - %s WHERE user_id = %s", (total_price, user_id))
            cursor.execute(
                "INSERT INTO option_trade_log (user_id, stock_symbol, option_symbol, option_type, action, quantity, price, timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (user_id, stock_symbol, option_symbol, option_type, action, quantity, price, datetime.now())
            )
            flash(f'Successfully bought {quantity} contract(s) of {option_symbol}.', 'success')

    elif action == 'sell':
        # Allow selling even if user has zero or negative contracts (short selling)
        cursor.execute("UPDATE wallet SET balance = balance + %s WHERE user_id = %s", (total_price, user_id))
        cursor.execute(
            "INSERT INTO option_trade_log (user_id, stock_symbol, option_symbol, option_type, action, quantity, price, timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (user_id, stock_symbol, option_symbol, option_type, action, quantity, price, datetime.now())
        )
        flash(f'Successfully sold {quantity} contract(s) of {option_symbol}.', 'success')

    mysql.connection.commit()
    return redirect(f'/option_chain/{stock_symbol}')

@app.route('/option-trade-log')
def option_trade_log():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT stock_symbol, option_symbol, option_type, action, quantity, price, timestamp FROM option_trade_log WHERE user_id = %s ORDER BY timestamp DESC", [user_id])
    trades = cursor.fetchall()

    # Aggregate positions by option_symbol
    positions = {}
    for row in trades:
        stock_symbol, option_symbol, option_type, action, quantity, price, timestamp = row
        quantity = int(quantity)
        price = float(price)
        if option_symbol not in positions:
            positions[option_symbol] = {
                'stock_symbol': stock_symbol,
                'option_symbol': option_symbol,
                'option_type': option_type,
                'quantity': 0,
                'total_cost': 0.0,
                'avg_price': 0.0
            }
        pos = positions[option_symbol]
        if action == 'buy':
            pos['total_cost'] += price * quantity * 100  # 1 contract = 100 shares
            pos['quantity'] += quantity
        elif action == 'sell':
            pos['total_cost'] -= price * quantity * 100
            pos['quantity'] -= quantity
        # Recalculate avg price if holding
        if pos['quantity'] > 0:
            pos['avg_price'] = pos['total_cost'] / (pos['quantity'] * 100)
        elif pos['quantity'] < 0:
            pos['avg_price'] = abs(pos['total_cost'] / (pos['quantity'] * 100))
        else:
            pos['avg_price'] = 0.0

    # Remove closed positions (quantity == 0)
    positions = {k: v for k, v in positions.items() if v['quantity'] != 0}

    # Fetch latest price for each open position using nselib
    from nselib import derivatives
    for pos in positions.values():
        try:
            # Parse contract details from option_symbol
            # Example: HDFCBANK28Aug20252000CE
            import re
            m = re.match(r"([A-Z]+)(\d{2}[A-Za-z]{3}\d{4})(\d+)(CE|PE)", pos['option_symbol'])
            if not m:
                pos['current_price'] = 'N/A'
                pos['profit_loss'] = 'N/A'
                pos['profit_loss_percent'] = 'N/A'
                continue
            symbol, exp, strike, opt_type = m.groups()
            # Convert exp to format in nselib (e.g., 28Aug2025 -> 28-Aug-2025)
            exp_fmt = f"{exp[:2]}-{exp[2:5]}-{exp[5:]}"
            strike = float(strike)
            # Fetch option chain for this symbol
            df = derivatives.nse_live_option_chain(symbol)
            df_exp = df[df['Expiry_Date'] == exp_fmt]
            if opt_type == 'CE':
                row = df_exp[df_exp['Strike_Price'] == strike].iloc[0]
                ltp = row['CALLS_LTP']
            else:
                row = df_exp[df_exp['Strike_Price'] == strike].iloc[0]
                ltp = row['PUTS_LTP']
            pos['current_price'] = ltp
            pos['total_value'] = ltp * pos['quantity'] * 100
            pos['profit_loss'] = pos['total_value'] - pos['total_cost']
            # Calculate profit/loss percent correctly for long and short
            if pos['quantity'] > 0:
                pos['profit_loss_percent'] = (pos['profit_loss'] / pos['total_cost'] * 100) if pos['total_cost'] else 0
            elif pos['quantity'] < 0:
                pos['profit_loss_percent'] = (pos['profit_loss'] / abs(pos['total_cost']) * 100) if pos['total_cost'] else 0
            else:
                pos['profit_loss_percent'] = 0
        except Exception as e:
            pos['current_price'] = 'N/A'
            pos['total_value'] = 'N/A'
            pos['profit_loss'] = 'N/A'
            pos['profit_loss_percent'] = 'N/A'

    return render_template('option_trade_log.html', option_trades=positions.values())

@app.route('/exit_option_position', methods=['POST'])
def exit_option_position():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    option_symbol = request.form['option_symbol']
    stock_symbol = request.form['stock_symbol']
    option_type = request.form['option_type']
    quantity = int(request.form['quantity'])
    price = float(request.form['current_price'])
    direction = request.form['direction']  # 'buy' for short, 'sell' for long
    action = direction

    cursor = mysql.connection.cursor()
    if action == 'sell':
        # Closing a long position
        total_proceeds = price * quantity * 100
        cursor.execute("UPDATE wallet SET balance = balance + %s WHERE user_id = %s", (total_proceeds, user_id))
    else:
        # Closing a short position (buy to close)
        total_cost = price * quantity * 100
        cursor.execute("UPDATE wallet SET balance = balance - %s WHERE user_id = %s", (total_cost, user_id))
    # Log the exit trade
    cursor.execute(
        "INSERT INTO option_trade_log (user_id, stock_symbol, option_symbol, option_type, action, quantity, price, timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (user_id, stock_symbol, option_symbol, option_type, action, quantity, price, datetime.now())
    )
    mysql.connection.commit()
    flash(f'Successfully exited position: {action.title()} {quantity} contract(s) of {option_symbol} at ${price:.2f}.', 'success')
    return redirect('/option-trade-log')

if __name__ == '__main__':
    app.run(debug=True, port=5001, use_reloader=False)
