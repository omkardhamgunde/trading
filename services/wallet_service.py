"""
Wallet service for wallet operations.
"""
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def get_wallet_balance(mysql, user_id):
    """
    Get wallet balance for a user.
    
    Args:
        mysql: MySQL connection
        user_id: User ID
        
    Returns:
        Balance as float
    """
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT balance FROM wallet WHERE user_id = %s", [user_id])
    wallet_data = cursor.fetchone()
    return float(wallet_data[0]) if wallet_data else 0.0


def add_funds(mysql, user_id, amount):
    """
    Add funds to wallet.
    
    Args:
        mysql: MySQL connection
        user_id: User ID
        amount: Amount to add
        
    Returns:
        Tuple (success, error_message)
    """
    try:
        if amount <= 0:
            return False, 'Please enter a positive amount.'
        
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
        return True, None
        
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Error adding funds: {e}", exc_info=True)
        return False, 'An error occurred while processing your request.'


def get_wallet_transactions(mysql, user_id, limit=10):
    """
    Get recent wallet transactions.
    
    Args:
        mysql: MySQL connection
        user_id: User ID
        limit: Number of transactions to return
        
    Returns:
        List of transaction dictionaries
    """
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT type, amount, balance_after, timestamp 
        FROM wallet_transactions 
        WHERE user_id = %s 
        ORDER BY timestamp DESC 
        LIMIT %s
    """, [user_id, limit])
    
    transactions = [
        {
            'type': row[0],
            'amount': float(row[1]),
            'balance_after': float(row[2]),
            'timestamp': row[3]
        }
        for row in cursor.fetchall()
    ]
    
    return transactions
