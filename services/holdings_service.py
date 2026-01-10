"""
Holdings service for portfolio calculations.
"""
from collections import defaultdict
import yfinance as yf


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


def get_holdings_with_prices(holdings_dict):
    """
    Get holdings with current market prices and P/L calculations.
    
    Args:
        holdings_dict: Dictionary from calculate_holdings()
        
    Returns:
        Tuple (holdings_list, total_value, total_cost, total_profit_loss, total_profit_loss_percent)
    """
    holdings_list = []
    total_value = 0.0
    total_cost = 0.0
    
    for symbol, data in holdings_dict.items():
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
                print(f"Error fetching price for {symbol}: {str(e)}")
                continue
    
    # Calculate total portfolio profits/losses
    total_profit_loss = total_value - total_cost
    total_profit_loss_percent = (total_profit_loss / total_cost * 100) if total_cost > 0 else 0
    
    return holdings_list, total_value, total_cost, total_profit_loss, total_profit_loss_percent
