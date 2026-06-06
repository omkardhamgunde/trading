"""
Currency helpers for keeping the simulator wallet in USD.
"""

INR_PER_USD = 96


def is_indian_symbol(symbol):
    """Return True when a Yahoo symbol is priced in INR by yfinance."""
    return symbol.endswith('.NS') or symbol.endswith('.BO')


def convert_price_to_usd(symbol, price):
    """Convert Indian stock prices from INR to USD; leave other markets unchanged."""
    if price is None:
        return None
    if is_indian_symbol(symbol):
        return float(price) / INR_PER_USD
    return float(price)
