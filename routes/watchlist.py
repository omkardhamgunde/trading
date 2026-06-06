from flask import Blueprint, request, redirect, session, flash, render_template, url_for, jsonify
from services.stock_service import (
    search_stocks,
    get_stock_prices,
    get_available_markets,
    get_heatmap_data,
    get_symbol_metadata
)
from services.chart_bot_service import get_chart_bot_recommendations

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


@watchlist_bp.route('/chart-bot')
def chart_bot():
    """Render simple chart-bot stock suggestions."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    market = request.args.get('market', 'india').strip().lower()
    category = request.args.get('category', 'equity').strip().lower()
    scan_limit = request.args.get('scan_limit', 25, type=int)

    bot_result = get_chart_bot_recommendations(
        market=market,
        category=category,
        scan_limit=scan_limit
    )

    return render_template(
        'chart_bot.html',
        bot_result=bot_result,
        markets=get_available_markets()
    )


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

    watchlist_items = [
        {
            'symbol': stock_symbol,
            'metadata': get_symbol_metadata(stock_symbol)
        }
        for stock_symbol in stock_symbols
    ]

    return render_template(
        'watchlist.html',
        watchlist=watchlist_items,
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


@watchlist_bp.route('/security')
def security_log():
    """Render the Security Activity Dashboard showing recent login events."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    cursor = watchlist_bp.mysql.connection.cursor()
    
    # Fetch recent login events for the active user
    cursor.execute("""
        SELECT ip_address, user_agent, status, timestamp 
        FROM login_history 
        WHERE user_id = %s 
        ORDER BY timestamp DESC 
        LIMIT 50
    """, [user_id])
    
    # Map tuples to dictionaries
    events = []
    for row in cursor.fetchall():
        events.append({
            'ip_address': row[0],
            'user_agent': row[1],
            'status': row[2],
            'timestamp': row[3]
        })
        
    return render_template('security_log.html', events=events)
