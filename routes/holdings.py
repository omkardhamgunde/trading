"""
Holdings routes.
"""
from flask import Blueprint, render_template, redirect, session, url_for
from services.holdings_service import calculate_holdings, get_holdings_with_prices

holdings_bp = Blueprint('holdings', __name__)


def init_holdings_routes(mysql):
    """Initialize holdings routes with dependencies."""
    holdings_bp.mysql = mysql
    return holdings_bp


@holdings_bp.route('/holdings')
def holdings():
    """View portfolio holdings."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    cursor = holdings_bp.mysql.connection.cursor()
    
    # Fetch all trades for the user
    cursor.execute("""
        SELECT stock_symbol, action, quantity, price, timestamp 
        FROM trade_log 
        WHERE user_id = %s 
        ORDER BY timestamp
    """, [user_id])
    trades = cursor.fetchall()
    
    # Calculate holdings
    holdings_dict = calculate_holdings(trades)
    
    # Get holdings with current prices and P/L
    holdings_list, total_value, total_cost, total_profit_loss, total_profit_loss_percent = \
        get_holdings_with_prices(holdings_dict)
    
    return render_template(
        'holdings.html',
        holdings=holdings_list,
        total_value=total_value,
        total_profit_loss=total_profit_loss,
        total_profit_loss_percent=total_profit_loss_percent
    )
