"""
WebSocket handlers for real-time price updates.
"""
from flask import request
from flask_socketio import emit
from datetime import datetime
from services.stock_service import get_stock_prices
from services.holdings_service import calculate_holdings
import logging

# Store active connections
active_connections = {}

# Suppress Werkzeug connection errors
logging.getLogger('werkzeug').setLevel(logging.WARNING)


def init_websocket_handlers(socketio, app, mysql):
    """Initialize WebSocket handlers."""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection."""
        print(f'Client connected: {request.sid}')

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection."""
        try:
            if request.sid in active_connections:
                del active_connections[request.sid]
            print(f'Client disconnected: {request.sid}')
        except Exception:
            # Silently handle disconnection cleanup errors
            pass

    @socketio.on('subscribe_watchlist')
    def handle_subscribe_watchlist(data):
        """Subscribe to watchlist price updates."""
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
        """Subscribe to holdings price updates."""
        user_id = data.get('user_id')
        if not user_id:
            return
        
        # Store the subscription
        active_connections[request.sid] = {
            'user_id': user_id,
            'type': 'holdings'
        }
        print(f'Client {request.sid} subscribed to holdings for user {user_id}')

    def background_price_updater():
        """Background task to push price updates to connected clients."""
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
                            cursor.execute(
                                "SELECT stock_symbol, action, quantity, price FROM trade_log WHERE user_id = %s",
                                [user_id]
                            )
                            trades = cursor.fetchall()
                            print(f"[Background Task] User {user_id} trades: {len(trades)} trades")
                        
                            # Calculate holdings
                            holdings_dict = {}
                            for stock_symbol, action, quantity, price in trades:
                                if stock_symbol not in holdings_dict:
                                    holdings_dict[stock_symbol] = {'quantity': 0, 'total_cost': 0}
                                
                                if action.upper() == 'BUY':
                                    holdings_dict[stock_symbol]['quantity'] += quantity
                                    holdings_dict[stock_symbol]['total_cost'] += quantity * float(price)
                                elif action.upper() == 'SELL':
                                    holdings_dict[stock_symbol]['quantity'] -= quantity
                                    holdings_dict[stock_symbol]['total_cost'] -= quantity * float(price)
                            
                            holdings_dict = {symbol: data for symbol, data in holdings_dict.items() if data['quantity'] > 0}
                            holdings_symbols = list(holdings_dict.keys())
                            
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
                                        try:
                                            socketio.emit('price_update', {
                                                'prices': watchlist_prices,
                                                'timestamp': datetime.now().isoformat()
                                            }, room=sid)
                                            emitted_count += 1
                                        except Exception:
                                            # Client disconnected, remove from active connections
                                            if sid in active_connections:
                                                del active_connections[sid]
                                print(f"[Background Task] Emitted price updates to {emitted_count} client(s)")
                            
                            # Fetch prices for holdings
                            if holdings_symbols:
                                holdings_prices = get_stock_prices(holdings_symbols)
                                
                                # Calculate P/L for each holding
                                holdings_data = []
                                for symbol in holdings_symbols:
                                    if holdings_prices[symbol]['price'] != 'N/A':
                                        avg_price = holdings_dict[symbol]['total_cost'] / holdings_dict[symbol]['quantity']
                                        current_price = holdings_prices[symbol]['price']
                                        quantity = holdings_dict[symbol]['quantity']
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
                                        try:
                                            socketio.emit('holdings_update', {
                                                'holdings': holdings_data,
                                                'timestamp': datetime.now().isoformat()
                                            }, room=sid)
                                        except Exception:
                                            # Client disconnected, remove from active connections
                                            if sid in active_connections:
                                                del active_connections[sid]
                            
                            cursor.close()
                
                # Update every 10 seconds
                socketio.sleep(10)
                
            except Exception as e:
                print(f"Error in background updater: {e}")
                socketio.sleep(10)
    
    return background_price_updater
