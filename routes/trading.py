"""
Trading routes.
"""
from flask import Blueprint, request, redirect, session, flash, render_template, url_for
from services.trade_service import (
    get_current_stock_price,
    validate_trade,
    check_wallet_balance,
    execute_trade
)

trading_bp = Blueprint('trading', __name__)


def init_trading_routes(mysql):
    """Initialize trading routes with dependencies."""
    trading_bp.mysql = mysql
    return trading_bp


@trading_bp.route('/trade', methods=['POST'])
def trade():
    """Execute a trade (buy/sell)."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    stock_symbol = request.form['stock_symbol'].upper()
    quantity = int(request.form['quantity'])
    action = request.form['action']

    # Validate trade
    is_valid, error_msg, current_quantity = validate_trade(
        trading_bp.mysql, user_id, stock_symbol, action, quantity
    )
    
    if not is_valid:
        flash(error_msg, 'danger')
        return redirect(url_for('watchlist.watchlist'))

    # Get current stock price
    price = get_current_stock_price(stock_symbol)
    if price is None:
        flash('Invalid stock symbol or no data available.', 'danger')
        return redirect(url_for('watchlist.watchlist'))

    total_price = price * quantity

    # Check wallet balance for buy orders
    if action == 'buy':
        has_balance, balance = check_wallet_balance(trading_bp.mysql, user_id, total_price)
        if not has_balance:
            flash('Insufficient funds to complete the purchase.', 'danger')
            return redirect(url_for('watchlist.watchlist'))

    # Execute trade
    success, error_msg = execute_trade(
        trading_bp.mysql, user_id, stock_symbol, action, quantity, price
    )
    
    if success:
        flash(f'Successfully {action}ed {quantity} shares of {stock_symbol}.', 'success')
    else:
        flash(f'Trade failed: {error_msg}', 'danger')
    
    return redirect(url_for('holdings.holdings'))


@trading_bp.route('/trade-log')
def trade_log():
    """View trade log."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    cursor = trading_bp.mysql.connection.cursor()
    cursor.execute(
        "SELECT stock_symbol, action, quantity, price, timestamp FROM trade_log WHERE user_id = %s",
        [user_id]
    )
    trades = cursor.fetchall()
    return render_template('trade_log.html', trades=trades)


@trading_bp.route('/clear-trade-log', methods=['POST'])
def clear_trade_log():
    """Clear trade log (only if no active holdings)."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    cursor = trading_bp.mysql.connection.cursor()

    # Check if user has any holdings before clearing trade log
    cursor.execute("""
        SELECT stock_symbol, action, quantity 
        FROM trade_log 
        WHERE user_id = %s 
        ORDER BY timestamp
    """, [user_id])
    trades = cursor.fetchall()
    
    # Calculate current holdings to check if user has any
    from collections import defaultdict
    holdings = defaultdict(lambda: {'quantity': 0})
    for trade in trades:
        symbol, action, quantity = trade
        quantity = int(quantity)
        if action == 'buy':
            holdings[symbol]['quantity'] += quantity
        elif action == 'sell':
            holdings[symbol]['quantity'] -= quantity
    
    # Check if user has any active holdings
    has_holdings = any(data['quantity'] > 0 for symbol, data in holdings.items())
    
    if has_holdings:
        flash('Cannot clear trade log: You have active holdings. Clearing the trade log would remove your holdings data. Please sell all your positions first if you want to clear the trade log.', 'danger')
        return redirect(url_for('trading.trade_log'))
    
    # Only clear if user has no holdings
    cursor.execute("DELETE FROM trade_log WHERE user_id = %s", [user_id])
    trading_bp.mysql.connection.commit()

    flash('Trade log cleared successfully!', 'success')
    return redirect(url_for('trading.trade_log'))
