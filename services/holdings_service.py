"""
Holdings service for portfolio calculations.
Optimized with batch processing and efficient data structures.
"""
from collections import defaultdict
import yfinance as yf
import logging
import time
from utils.cache import price_cache
from utils.metrics import metrics_tracker
from utils.performance import performance_monitor

logger = logging.getLogger(__name__)


def calculate_holdings(trades):
    """
    Calculate current holdings from trade history.
    
    Args:
        trades: List of trades (symbol, action, quantity, price, timestamp)
        
    Returns:
        Dictionary mapping symbol to holdings data
    """
    holdings = defaultdict(lambda: {'quantity': 0, 'total_cost': 0.0})
    
    # Process all trades to calculate current holdings
    for trade in trades:
        symbol, action, quantity, price, _ = trade
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
    
    return holdings


def _batch_fetch_prices(symbols):
    """
    Optimized batch price fetching with caching.
    Fetches multiple stock prices efficiently using yfinance batch API.
    
    Args:
        symbols: List of stock symbols
        
    Returns:
        Dictionary mapping symbol to current price
    """
    prices = {}
    uncached_symbols = []
    
    # Check cache first
    for symbol in symbols:
        cached_price = price_cache.get(symbol)
        if cached_price is not None:
            prices[symbol] = cached_price
        else:
            uncached_symbols.append(symbol)
    
    # Batch fetch uncached symbols
    if uncached_symbols:
        start_time = time.time()
        try:
            # Use yfinance's download for batch fetching (more efficient)
            tickers = yf.download(uncached_symbols, period='1d', progress=False, group_by='ticker')
            
            for symbol in uncached_symbols:
                try:
                    if len(uncached_symbols) == 1:
                        # Single symbol returns different structure
                        if len(tickers) > 0:
                            current_price = float(tickers['Close'].iloc[-1])
                        else:
                            continue
                    else:
                        # Multiple symbols
                        if symbol in tickers.columns.levels[0]:
                            current_price = float(tickers[symbol]['Close'].iloc[-1])
                        else:
                            continue
                    
                    prices[symbol] = current_price
                    # Cache the price
                    price_cache.set(symbol, current_price, ttl=10)
                    
                except (KeyError, IndexError, ValueError) as e:
                    logger.warning(f"Could not fetch price for {symbol}: {e}")
                    continue
            
            # Record API call with duration
            duration_ms = (time.time() - start_time) * 1000
            metrics_tracker.record_api_call(duration_ms)
            
        except Exception as e:
            logger.error(f"Error in batch price fetch: {e}", exc_info=True)
            metrics_tracker.record_api_call()
    
    return prices


def get_holdings_with_prices(holdings_dict):
    """
    Optimized holdings calculation with batch price fetching and caching.
    Uses vectorized operations for P/L calculations.
    
    Args:
        holdings_dict: Dictionary from calculate_holdings()
        
    Returns:
        Tuple (holdings_list, total_value, total_cost, total_profit_loss, total_profit_loss_percent)
    """
    start_time = time.time()
    
    # Filter holdings with quantity > 0
    active_holdings = {symbol: data for symbol, data in holdings_dict.items() if data['quantity'] > 0}
    
    if not active_holdings:
        return [], 0.0, 0.0, 0.0, 0.0
    
    # Batch fetch all prices at once (optimization)
    symbols = list(active_holdings.keys())
    prices = _batch_fetch_prices(symbols)
    
    # Vectorized P/L calculations
    holdings_list = []
    total_value = 0.0
    total_cost = 0.0
    
    for symbol, data in active_holdings.items():
        if symbol not in prices:
            logger.warning(f"Price not available for {symbol}")
            continue
        
        current_price = prices[symbol]
        quantity = data['quantity']
        avg_price = data['avg_price']
        total_cost_stock = data['total_cost']
        
        # Optimized calculations
        total_value_stock = current_price * quantity
        profit_loss = total_value_stock - total_cost_stock
        profit_loss_percent = (profit_loss / total_cost_stock * 100) if total_cost_stock > 0 else 0
        
        holdings_list.append({
            'symbol': symbol,
            'quantity': quantity,
            'avg_price': round(avg_price, 2),
            'current_price': round(current_price, 2),
            'total_value': round(total_value_stock, 2),
            'profit_loss': round(profit_loss, 2),
            'profit_loss_percent': round(profit_loss_percent, 2)
        })
        
        total_value += total_value_stock
        total_cost += total_cost_stock
    
    # Calculate total portfolio profits/losses
    total_profit_loss = total_value - total_cost
    total_profit_loss_percent = (total_profit_loss / total_cost * 100) if total_cost > 0 else 0
    
    # Record performance
    latency_ms = (time.time() - start_time) * 1000
    performance_monitor.record_latency(latency_ms)
    
    return holdings_list, total_value, total_cost, total_profit_loss, total_profit_loss_percent
