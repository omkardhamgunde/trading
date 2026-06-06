"""
WebSocket handlers for real-time price updates.
"""
from flask import request
from flask_socketio import emit
from datetime import datetime
from services.stock_service import get_stock_prices
from services.holdings_service import calculate_holdings
import logging
import math

# Store active connections
active_connections = {}

# Get logger for this module
logger = logging.getLogger(__name__)


def init_websocket_handlers(socketio, app, mysql):
    """Initialize WebSocket handlers."""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection."""
        logger.debug(f'Client connected: {request.sid}')

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection."""
        try:
            if request.sid in active_connections:
                del active_connections[request.sid]
            logger.debug(f'Client disconnected: {request.sid}')
        except KeyError:
            # Client already removed, no action needed
            pass
        except Exception as e:
            # Log unexpected errors for debugging
            logger.error(f'Error during disconnect cleanup for {request.sid}: {e}')

    @socketio.on('subscribe_watchlist')
    def handle_subscribe_watchlist(data):
        """Subscribe to watchlist price updates."""
        user_id = data.get('user_id')
        if not user_id:
            return
        
        # Store or update the subscription (allow multiple subscription types)
        if request.sid not in active_connections:
            active_connections[request.sid] = {
                'user_id': user_id,
                'subscriptions': set()
            }
        active_connections[request.sid]['user_id'] = user_id
        active_connections[request.sid]['subscriptions'].add('watchlist')
        logger.debug(f'Client {request.sid} subscribed to watchlist for user {user_id}')

    @socketio.on('subscribe_holdings')
    def handle_subscribe_holdings(data):
        """Subscribe to holdings price updates."""
        user_id = data.get('user_id')
        if not user_id:
            return
        
        # Store or update the subscription (allow multiple subscription types)
        if request.sid not in active_connections:
            active_connections[request.sid] = {
                'user_id': user_id,
                'subscriptions': set()
            }
        active_connections[request.sid]['user_id'] = user_id
        active_connections[request.sid]['subscriptions'].add('holdings')
        logger.debug(f'Client {request.sid} subscribed to holdings for user {user_id}')

    def background_price_updater():
        """Background task to push price updates to connected clients."""
        logger.info("Background price updater started")
        
        while True:
            try:
                if active_connections:
                    with app.app_context():
                        # Get unique user IDs and organize connections by user
                        user_ids = set()
                        user_sids = {}
                        for sid, conn_data in active_connections.items():
                            user_id = conn_data['user_id']
                            user_ids.add(user_id)
                            if user_id not in user_sids:
                                user_sids[user_id] = []
                            user_sids[user_id].append((sid, conn_data))
                        
                        # Fetch data for each user
                        for user_id in user_ids:
                            cursor = mysql.connection.cursor()
                            
                            # Get watchlist stocks for this user
                            cursor.execute("SELECT stock_symbol FROM watchlist WHERE user_id = %s", [user_id])
                            watchlist = [row[0] for row in cursor.fetchall()]
                            
                            # Get holdings stocks for this user
                            cursor.execute(
                                "SELECT stock_symbol, action, quantity, price FROM trade_log WHERE user_id = %s",
                                [user_id]
                            )
                            trades = cursor.fetchall()
                        
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
                            
                            # Always send index updates to watchlist subscribers (even if no watchlist)
                            indices = ['^NSEI', '^IXIC', '^DJI', '^BSESN']
                            if watchlist:
                                all_watchlist_symbols = list(set(watchlist + indices))
                            else:
                                # If no watchlist, still send indices for connection verification
                                all_watchlist_symbols = indices
                            
                            watchlist_prices = get_stock_prices(all_watchlist_symbols)
                            
                            # Emit to clients subscribed to watchlist
                            emitted_count = 0
                            disconnected_sids = []
                            for sid, conn_data in user_sids.get(user_id, []):
                                # Check if this connection is subscribed to watchlist
                                # Support both new (subscriptions set) and old (type string) format
                                subscriptions = conn_data.get('subscriptions', set())
                                conn_type = conn_data.get('type', '')
                                is_watchlist_subscriber = 'watchlist' in subscriptions or conn_type == 'watchlist'
                                
                                if is_watchlist_subscriber:
                                    try:
                                        # Use emit with skip_sid to avoid errors on disconnected clients
                                        socketio.emit('price_update', {
                                            'prices': watchlist_prices,
                                            'timestamp': datetime.now().isoformat()
                                        }, room=sid, skip_sid=None)
                                        emitted_count += 1
                                    except (ConnectionError, OSError, RuntimeError):
                                        # Client disconnected, mark for removal
                                        disconnected_sids.append(sid)
                                    except Exception as e:
                                        # Log unexpected errors for debugging
                                        logger.warning(f"Error emitting to {sid}: {e}")
                                        disconnected_sids.append(sid)
                            
                            # Clean up disconnected clients
                            for sid in disconnected_sids:
                                if sid in active_connections:
                                    del active_connections[sid]
                            
                            # Fetch prices for holdings
                            if holdings_symbols:
                                holdings_prices = get_stock_prices(holdings_symbols)
                                
                                # Calculate P/L for each holding
                                holdings_data = []
                                for symbol in holdings_symbols:
                                    price_val = holdings_prices[symbol]['price']
                                    avg_price = holdings_dict[symbol]['total_cost'] / holdings_dict[symbol]['quantity']
                                    
                                    if price_val != 'N/A' and isinstance(price_val, (int, float)) and not math.isnan(price_val):
                                        current_price = float(price_val)
                                    else:
                                        # Fallback to avg_price to keep the holding in the list
                                        current_price = avg_price
                                        
                                    quantity = holdings_dict[symbol]['quantity']
                                    total_value = current_price * quantity
                                    profit_loss = total_value - (avg_price * quantity)
                                    profit_loss_percent = (profit_loss / (avg_price * quantity)) * 100 if avg_price > 0 else 0
                                    
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
                                disconnected_sids = []
                                for sid, conn_data in user_sids.get(user_id, []):
                                    # Check if this connection is subscribed to holdings
                                    # Support both new (subscriptions set) and old (type string) format
                                    subscriptions = conn_data.get('subscriptions', set())
                                    conn_type = conn_data.get('type', '')
                                    is_holdings_subscriber = 'holdings' in subscriptions or conn_type == 'holdings'
                                    
                                    if is_holdings_subscriber:
                                        try:
                                            socketio.emit('holdings_update', {
                                                'holdings': holdings_data,
                                                'timestamp': datetime.now().isoformat()
                                            }, room=sid, skip_sid=None)
                                        except (ConnectionError, OSError, RuntimeError):
                                            # Client disconnected, mark for removal
                                            disconnected_sids.append(sid)
                                        except Exception as e:
                                            # Log unexpected errors for debugging
                                            logger.warning(f"Error emitting to {sid}: {e}")
                                            disconnected_sids.append(sid)
                                
                                # Clean up disconnected clients
                                for sid in disconnected_sids:
                                    if sid in active_connections:
                                        del active_connections[sid]
                            
                            cursor.close()
                
                # Update every 10 seconds
                socketio.sleep(10)
                
            except Exception as e:
                logger.error(f"Error in background updater: {e}", exc_info=True)
                socketio.sleep(10)
    
    return background_price_updater
