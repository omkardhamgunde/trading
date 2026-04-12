"""
Trade service for trade execution and validation.
"""
import yfinance as yf
from datetime import datetime
import logging
import time
from utils.metrics import metrics_tracker

logger = logging.getLogger(__name__)


def get_current_stock_price(symbol):
    """
    Get current stock price with metrics tracking.
    
    Args:
        symbol: Stock symbol
        
    Returns:
        Current price as float, or None if error
    """
    start_time = time.time()
    try:
        stock_data = yf.Ticker(symbol).history(period='1d')
        if len(stock_data) == 0:
            metrics_tracker.record_api_call()
            return None
        
        price = float(stock_data['Close'].iloc[-1])
        
        # Record API call with duration
        duration_ms = (time.time() - start_time) * 1000
        metrics_tracker.record_api_call(duration_ms)
        
        return price
    except Exception as e:
        logger.error(f"Error fetching stock price for {symbol}: {e}", exc_info=True)
        metrics_tracker.record_api_call()
        return None


def validate_trade(mysql, user_id, symbol, action, quantity):
    """
    Validate if a trade can be executed.
    
    Args:
        mysql: MySQL connection
        user_id: User ID
        symbol: Stock symbol
        action: 'buy' or 'sell'
        quantity: Number of shares
        
    Returns:
        Tuple (is_valid, error_message, current_quantity)
    """
    cursor = mysql.connection.cursor()
    
    # Check if user has enough shares when selling
    if action == 'sell':
        cursor.execute("""
            SELECT 
                COALESCE(SUM(CASE WHEN action = 'buy' THEN quantity 
                    WHEN action = 'sell' THEN -quantity END), 0) as total_quantity
            FROM trade_log 
            WHERE user_id = %s AND stock_symbol = %s
        """, (user_id, symbol))
        
        result = cursor.fetchone()
        current_quantity = result[0] if result else 0
        
        if current_quantity < quantity:
            return False, f'Insufficient shares. You only have {current_quantity} shares of {symbol}.', current_quantity
        
        return True, None, current_quantity
    
    return True, None, 0


def check_wallet_balance(mysql, user_id, required_amount):
    """
    Check if user has sufficient wallet balance.
    
    Args:
        mysql: MySQL connection
        user_id: User ID
        required_amount: Required amount
        
    Returns:
        Tuple (has_balance, current_balance)
    """
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT balance FROM wallet WHERE user_id = %s", [user_id])
    wallet = cursor.fetchone()
    balance = float(wallet[0]) if wallet else 0
    
    return balance >= required_amount, balance


def execute_trade(mysql, user_id, symbol, action, quantity, price):
    """
    Execute a trade and update database.
    
    Args:
        mysql: MySQL connection
        user_id: User ID
        symbol: Stock symbol
        action: 'buy' or 'sell'
        quantity: Number of shares
        price: Price per share
        
    Returns:
        Tuple (success, error_message)
    """
    try:
        cursor = mysql.connection.cursor()
        
        # Update wallet
        if action == 'buy':
            cursor.execute("UPDATE wallet SET balance = balance - %s WHERE user_id = %s", 
                         (price * quantity, user_id))
        else:  # sell
            cursor.execute("UPDATE wallet SET balance = balance + %s WHERE user_id = %s", 
                         (price * quantity, user_id))
        
        # Record trade
        cursor.execute("""
            INSERT INTO trade_log (user_id, stock_symbol, action, quantity, price, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, symbol, action, quantity, price, datetime.now()))
        
        mysql.connection.commit()
        return True, None
        
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Trade execution failed: {e}", exc_info=True)
        return False, str(e)
