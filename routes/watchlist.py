from flask import Blueprint, request, redirect, session, flash, render_template, url_for, jsonify
from services.stock_service import search_stocks, get_stock_prices, get_available_markets, get_heatmap_data

watchlist_bp = Blueprint('watchlist', __name__)


def init_watchlist_routes(mysql):
    """Initialize watchlist routes with dependencies."""
    watchlist_bp.mysql = mysql
    return watchlist_bp


@watchlist_bp.route('/search_stocks')
def search_stocks_route():
    """Search for stocks by name or symbol, optionally filtered by market/category."""
    query = request.args.get('q', '').strip()
    market = request.args.get('market', '').strip().lower() or None
    category = request.args.get('category', '').strip().lower() or None
    results = search_stocks(query, market=market, category=category)
    return jsonify(results)


@watchlist_bp.route('/screener')
def screener():
    """Render the Market Screener & Heatmap page."""
    market = request.args.get('market', 'india').strip().lower()
    
    # If the request wants JSON data (AJAX update for the chart)
    if request.headers.get('Accept') == 'application/json':
        data = get_heatmap_data(market)
        return jsonify(data)
        
    # Initial page load with default market
    initial_data = get_heatmap_data(market)
    return render_template('screener.html', initial_data=initial_data, current_market=market)


@watchlist_bp.route('/watchlist', methods=['GET', 'POST'])
def watchlist():
    """View and manage watchlist."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    cursor = watchlist_bp.mysql.connection.cursor()

    # Handle adding a new stock to the watchlist
    if request.method == 'POST':
        stock_symbol = request.form.get('stock_symbol').upper()
        
        # Check if the stock is already in the watchlist
        cursor.execute(
            "SELECT * FROM watchlist WHERE user_id = %s AND stock_symbol = %s",
            (user_id, stock_symbol)
        )
        if cursor.fetchone():
            flash(f'{stock_symbol} is already in your watchlist.', 'info')
        else:
            # Insert the new stock
            cursor.execute(
                "INSERT INTO watchlist (user_id, stock_symbol) VALUES (%s, %s)",
                (user_id, stock_symbol)
            )
            watchlist_bp.mysql.connection.commit()
            flash(f'{stock_symbol} has been added to your watchlist.', 'success')
        
        return redirect(url_for('watchlist.watchlist'))

    # Fetch the user's watchlist
    cursor.execute("SELECT stock_symbol FROM watchlist WHERE user_id = %s", [user_id])
    watchlist_data = cursor.fetchall()

    # Fetch real-time prices for stocks
    stock_symbols = [stock[0] for stock in watchlist_data]
    prices = get_stock_prices(stock_symbols) if stock_symbols else {}

    # Fetch live index prices
    indices = ['^NSEI', '^IXIC', '^DJI', '^BSESN']
    index_prices = get_stock_prices(indices)

    return render_template(
        'watchlist.html',
        watchlist=watchlist_data,
        prices=prices,
        index_prices=index_prices
    )


@watchlist_bp.route('/delete-watchlist/<stock_symbol>', methods=['POST'])
def delete_watchlist(stock_symbol):
    """Remove stock from watchlist."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    cursor = watchlist_bp.mysql.connection.cursor()
    cursor.execute(
        "DELETE FROM watchlist WHERE user_id = %s AND stock_symbol = %s",
        (user_id, stock_symbol)
    )
    watchlist_bp.mysql.connection.commit()
    flash(f'Stock {stock_symbol} removed from your watchlist.', 'success')
    return redirect(url_for('watchlist.watchlist'))
