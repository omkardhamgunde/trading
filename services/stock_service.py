"""
Stock service for stock search and price fetching.
Optimized with caching and metrics tracking.
"""
import yfinance as yf
import pandas as pd
import logging
import time
from utils.cache import price_cache, api_cache
from utils.metrics import metrics_tracker

logger = logging.getLogger(__name__)


# =============================================================================
# Stock Database - Categorized by Market and Asset Class
# =============================================================================

STOCKS = {
    # ── INDIA ──
    'india': {
        'equity': {
            'RELIANCE': ('Reliance Industries', 'RELIANCE.NS'),
            'TCS': ('Tata Consultancy Services', 'TCS.NS'),
            'HDFCBANK': ('HDFC Bank', 'HDFCBANK.NS'),
            'INFY': ('Infosys', 'INFY.NS'),
            'ICICIBANK': ('ICICI Bank', 'ICICIBANK.NS'),
            'HINDUNILVR': ('Hindustan Unilever', 'HINDUNILVR.NS'),
            'SBIN': ('State Bank of India', 'SBIN.NS'),
            'BHARTIARTL': ('Bharti Airtel', 'BHARTIARTL.NS'),
            'ITC': ('ITC Limited', 'ITC.NS'),
            'KOTAKBANK': ('Kotak Mahindra Bank', 'KOTAKBANK.NS'),
            'LT': ('Larsen & Toubro', 'LT.NS'),
            'AXISBANK': ('Axis Bank', 'AXISBANK.NS'),
            'ASIANPAINT': ('Asian Paints', 'ASIANPAINT.NS'),
            'MARUTI': ('Maruti Suzuki', 'MARUTI.NS'),
            'SUNPHARMA': ('Sun Pharma', 'SUNPHARMA.NS'),
            'TITAN': ('Titan Company', 'TITAN.NS'),
            'BAJFINANCE': ('Bajaj Finance', 'BAJFINANCE.NS'),
            'WIPRO': ('Wipro', 'WIPRO.NS'),
            'ULTRACEMCO': ('UltraTech Cement', 'ULTRACEMCO.NS'),
            'ONGC': ('ONGC', 'ONGC.NS'),
            'NTPC': ('NTPC', 'NTPC.NS'),
            'POWERGRID': ('Power Grid Corp', 'POWERGRID.NS'),
            'TATAMOTORS': ('Tata Motors', 'TATAMOTORS.NS'),
            'TATASTEEL': ('Tata Steel', 'TATASTEEL.NS'),
            'JSWSTEEL': ('JSW Steel', 'JSWSTEEL.NS'),
            'ADANIENT': ('Adani Enterprises', 'ADANIENT.NS'),
            'ADANIPORTS': ('Adani Ports', 'ADANIPORTS.NS'),
            'COALINDIA': ('Coal India', 'COALINDIA.NS'),
            'BPCL': ('BPCL', 'BPCL.NS'),
            'IOC': ('Indian Oil Corp', 'IOC.NS'),
            'GAIL': ('GAIL India', 'GAIL.NS'),
            'DRREDDY': ('Dr Reddys Labs', 'DRREDDY.NS'),
            'CIPLA': ('Cipla', 'CIPLA.NS'),
            'DIVISLAB': ('Divis Labs', 'DIVISLAB.NS'),
            'APOLLOHOSP': ('Apollo Hospitals', 'APOLLOHOSP.NS'),
            'EICHERMOT': ('Eicher Motors', 'EICHERMOT.NS'),
            'BAJAJ-AUTO': ('Bajaj Auto', 'BAJAJ-AUTO.NS'),
            'HEROMOTOCO': ('Hero MotoCorp', 'HEROMOTOCO.NS'),
            'M&M': ('Mahindra & Mahindra', 'M&M.NS'),
            'TECHM': ('Tech Mahindra', 'TECHM.NS'),
            'HCLTECH': ('HCL Technologies', 'HCLTECH.NS'),
            'NESTLEIND': ('Nestle India', 'NESTLEIND.NS'),
            'BRITANNIA': ('Britannia Industries', 'BRITANNIA.NS'),
            'DABUR': ('Dabur India', 'DABUR.NS'),
            'GODREJCP': ('Godrej Consumer', 'GODREJCP.NS'),
            'MARICO': ('Marico', 'MARICO.NS'),
            'PIDILITIND': ('Pidilite Industries', 'PIDILITIND.NS'),
            'BERGEPAINT': ('Berger Paints', 'BERGEPAINT.NS'),
            'INDUSINDBK': ('IndusInd Bank', 'INDUSINDBK.NS'),
            'BANKBARODA': ('Bank of Baroda', 'BANKBARODA.NS'),
            'PNB': ('Punjab National Bank', 'PNB.NS'),
            'CANBK': ('Canara Bank', 'CANBK.NS'),
            'SBILIFE': ('SBI Life Insurance', 'SBILIFE.NS'),
            'HDFCLIFE': ('HDFC Life', 'HDFCLIFE.NS'),
            'ICICIGI': ('ICICI Lombard', 'ICICIGI.NS'),
            'BAJAJFINSV': ('Bajaj Finserv', 'BAJAJFINSV.NS'),
            'ZOMATO': ('Zomato', 'ZOMATO.NS'),
            'PAYTM': ('Paytm', 'PAYTM.NS'),
            'NYKAA': ('Nykaa', 'NYKAA.NS'),
            'DELHIVERY': ('Delhivery', 'DELHIVERY.NS'),
            'IRCTC': ('IRCTC', 'IRCTC.NS'),
            'IRFC': ('Indian Railway Finance', 'IRFC.NS'),
            'HAL': ('Hindustan Aeronautics', 'HAL.NS'),
            'BEL': ('Bharat Electronics', 'BEL.NS'),
            'BHEL': ('BHEL', 'BHEL.NS'),
            'VEDL': ('Vedanta', 'VEDL.NS'),
            'HINDALCO': ('Hindalco', 'HINDALCO.NS'),
            'GRASIM': ('Grasim Industries', 'GRASIM.NS'),
            'SHREECEM': ('Shree Cement', 'SHREECEM.NS'),
            'AMBUJACEM': ('Ambuja Cements', 'AMBUJACEM.NS'),
            'ACC': ('ACC', 'ACC.NS'),
            'UPL': ('UPL', 'UPL.NS'),
            'TATAPOWER': ('Tata Power', 'TATAPOWER.NS'),
            'ADANIGREEN': ('Adani Green Energy', 'ADANIGREEN.NS'),
            'TATACONSUM': ('Tata Consumer', 'TATACONSUM.NS'),
            'INDIGO': ('IndiGo', 'INDIGO.NS'),
            'IDEA': ('Vodafone Idea', 'IDEA.NS'),
            'YESBANK': ('Yes Bank', 'YESBANK.NS'),
            'FEDERALBNK': ('Federal Bank', 'FEDERALBNK.NS'),
            'IDFCFIRSTB': ('IDFC First Bank', 'IDFCFIRSTB.NS'),
            'BANDHANBNK': ('Bandhan Bank', 'BANDHANBNK.NS'),
            'AUBANK': ('AU Small Finance', 'AUBANK.NS'),
            'MUTHOOTFIN': ('Muthoot Finance', 'MUTHOOTFIN.NS'),
            'CHOLAFIN': ('Cholamandalam Inv', 'CHOLAFIN.NS'),
            'RECLTD': ('REC Ltd', 'RECLTD.NS'),
            'PFC': ('Power Finance Corp', 'PFC.NS'),
            'LICHSGFIN': ('LIC Housing Finance', 'LICHSGFIN.NS'),
            'TVSMOTOR': ('TVS Motor', 'TVSMOTOR.NS'),
            'ASHOKLEY': ('Ashok Leyland', 'ASHOKLEY.NS'),
            'MRF': ('MRF', 'MRF.NS'),
            'APOLLOTYRE': ('Apollo Tyres', 'APOLLOTYRE.NS'),
            'BALKRISIND': ('Balkrishna Ind', 'BALKRISIND.NS'),
            'SIEMENS': ('Siemens', 'SIEMENS.NS'),
            'ABB': ('ABB India', 'ABB.NS'),
            'HAVELLS': ('Havells India', 'HAVELLS.NS'),
            'VOLTAS': ('Voltas', 'VOLTAS.NS'),
            'BLUESTAR': ('Blue Star', 'BLUESTAR.NS'),
            'PAGEIND': ('Page Industries', 'PAGEIND.NS'),
            'DIXON': ('Dixon Technologies', 'DIXON.NS'),
            'POLYCAB': ('Polycab India', 'POLYCAB.NS'),
            'HAPPSTMNDS': ('Happiest Minds', 'HAPPSTMNDS.NS'),
            'LTIM': ('LTIMindtree', 'LTIM.NS'),
            'PERSISTENT': ('Persistent Systems', 'PERSISTENT.NS'),
            'COFORGE': ('Coforge', 'COFORGE.NS'),
            'MPHASIS': ('Mphasis', 'MPHASIS.NS'),
            'OFSS': ('Oracle Financial', 'OFSS.NS'),
            'TATAELXSI': ('Tata Elxsi', 'TATAELXSI.NS'),
            'LICI': ('LIC India', 'LICI.NS'),
            'LODHA': ('Macrotech Developers', 'LODHA.NS'),
            'DLF': ('DLF', 'DLF.NS'),
            'GODREJPROP': ('Godrej Properties', 'GODREJPROP.NS'),
            'OBEROIRLTY': ('Oberoi Realty', 'OBEROIRLTY.NS'),
            'PRESTIGE': ('Prestige Estates', 'PRESTIGE.NS'),
            'PIIND': ('PI Industries', 'PIIND.NS'),
            'ATUL': ('Atul', 'ATUL.NS'),
            'DEEPAKNTR': ('Deepak Nitrite', 'DEEPAKNTR.NS'),
            'SRF': ('SRF', 'SRF.NS'),
            'AARTIIND': ('Aarti Industries', 'AARTIIND.NS'),
            'TRENT': ('Trent', 'TRENT.NS'),
            'ABFRL': ('Aditya Birla Fashion', 'ABFRL.NS'),
            'RAYMOND': ('Raymond', 'RAYMOND.NS'),
            'VBL': ('Varun Beverages', 'VBL.NS'),
            'JUBLFOOD': ('Jubilant FoodWorks', 'JUBLFOOD.NS'),
            'DEVYANI': ('Devyani International', 'DEVYANI.NS'),
            'BHARATFORG': ('Bharat Forge', 'BHARATFORG.NS'),
            'BOSCHLTD': ('Bosch', 'BOSCHLTD.NS'),
            'MOTHERSON': ('Motherson Sumi', 'MOTHERSON.NS'),
            'EXIDEIND': ('Exide Industries', 'EXIDEIND.NS'),
            'AMARAJABAT': ('Amara Raja Batteries', 'AMARAJABAT.NS'),
        },
        'commodity': {
            'GOLDIAM': ('Goldiam International', 'GOLDIAM.NS'),
            'HINDCOPPER': ('Hindustan Copper', 'HINDCOPPER.NS'),
            'NMDC': ('NMDC', 'NMDC.NS'),
            'NATIONALUM': ('National Aluminium', 'NATIONALUM.NS'),
            'MOIL': ('MOIL', 'MOIL.NS'),
            'GMRINFRA': ('GMR Airports Infra', 'GMRINFRA.NS'),
            'ONGC': ('ONGC', 'ONGC.NS'),
            'COALINDIA': ('Coal India', 'COALINDIA.NS'),
            'VEDL': ('Vedanta', 'VEDL.NS'),
            'HINDZINC': ('Hindustan Zinc', 'HINDZINC.NS'),
            'TATASTEEL': ('Tata Steel', 'TATASTEEL.NS'),
            'JSWSTEEL': ('JSW Steel', 'JSWSTEEL.NS'),
            'HINDALCO': ('Hindalco', 'HINDALCO.NS'),
            'GOLDBEES': ('Nippon Gold ETF', 'GOLDBEES.NS'),
            'SILVERBEES': ('Nippon Silver ETF', 'SILVERBEES.NS'),
        },
        'bonds': {
            'LIQUIDBEES': ('Nippon Liquid ETF', 'LIQUIDBEES.NS'),
            'CPSEETF': ('CPSE ETF', 'CPSEETF.NS'),
            'NIFTYBEES': ('Nippon Nifty BeES', 'NIFTYBEES.NS'),
            'JUNIORBEES': ('Nippon Junior BeES', 'JUNIORBEES.NS'),
            'BANKBEES': ('Nippon Bank BeES', 'BANKBEES.NS'),
            'SETFNIF50': ('SBI Nifty 50 ETF', 'SETFNIF50.NS'),
            'ICICIB22': ('ICICI Bharat Bond ETF', 'ICICIB22.NS'),
            'HDFCNIFETF': ('HDFC Nifty 50 ETF', 'HDFCNIFETF.NS'),
        },
    },

    # ── USA ──
    'usa': {
        'equity': {
            'AAPL': ('Apple Inc', 'AAPL'),
            'GOOGL': ('Alphabet (Google)', 'GOOGL'),
            'MSFT': ('Microsoft', 'MSFT'),
            'AMZN': ('Amazon', 'AMZN'),
            'META': ('Meta (Facebook)', 'META'),
            'TSLA': ('Tesla', 'TSLA'),
            'NVDA': ('NVIDIA', 'NVDA'),
            'NFLX': ('Netflix', 'NFLX'),
            'AMD': ('AMD', 'AMD'),
            'INTC': ('Intel', 'INTC'),
            'CRM': ('Salesforce', 'CRM'),
            'ORCL': ('Oracle', 'ORCL'),
            'IBM': ('IBM', 'IBM'),
            'CSCO': ('Cisco', 'CSCO'),
            'ADBE': ('Adobe', 'ADBE'),
            'PYPL': ('PayPal', 'PYPL'),
            'V': ('Visa', 'V'),
            'MA': ('Mastercard', 'MA'),
            'JPM': ('JPMorgan Chase', 'JPM'),
            'BAC': ('Bank of America', 'BAC'),
            'WMT': ('Walmart', 'WMT'),
            'DIS': ('Disney', 'DIS'),
            'KO': ('Coca-Cola', 'KO'),
            'PEP': ('PepsiCo', 'PEP'),
            'NKE': ('Nike', 'NKE'),
            'MCD': ('McDonalds', 'MCD'),
            'SBUX': ('Starbucks', 'SBUX'),
            'BA': ('Boeing', 'BA'),
            'GE': ('General Electric', 'GE'),
            'F': ('Ford', 'F'),
            'GM': ('General Motors', 'GM'),
            'UBER': ('Uber', 'UBER'),
            'LYFT': ('Lyft', 'LYFT'),
            'ABNB': ('Airbnb', 'ABNB'),
            'SNAP': ('Snap Inc', 'SNAP'),
            'TWTR': ('Twitter', 'TWTR'),
            'SPOT': ('Spotify', 'SPOT'),
            'ZM': ('Zoom', 'ZM'),
            'COIN': ('Coinbase', 'COIN'),
            'PLTR': ('Palantir', 'PLTR'),
            'SOFI': ('SoFi', 'SOFI'),
            'HOOD': ('Robinhood', 'HOOD'),
        },
    },

    # ── CRYPTO ──
    'crypto': {
        'all': {
            'BTC': ('Bitcoin', 'BTC-USD'),
            'ETH': ('Ethereum', 'ETH-USD'),
            'SOL': ('Solana', 'SOL-USD'),
            'BNB': ('Binance Coin', 'BNB-USD'),
            'XRP': ('Ripple', 'XRP-USD'),
            'ADA': ('Cardano', 'ADA-USD'),
            'DOGE': ('Dogecoin', 'DOGE-USD'),
            'AVAX': ('Avalanche', 'AVAX-USD'),
            'DOT': ('Polkadot', 'DOT-USD'),
            'MATIC': ('Polygon', 'MATIC-USD'),
            'LINK': ('Chainlink', 'LINK-USD'),
            'LTC': ('Litecoin', 'LTC-USD'),
            'UNI': ('Uniswap', 'UNI-USD'),
            'ATOM': ('Cosmos', 'ATOM-USD'),
            'SHIB': ('Shiba Inu', 'SHIB-USD'),
        },
    },
}

# Exchange label mapping for search results
MARKET_EXCHANGE_LABELS = {
    'india': {'equity': 'NSE', 'commodity': 'NSE-COMM', 'bonds': 'NSE-BOND'},
    'usa': {'equity': 'NYSE/NASDAQ'},
    'crypto': {'all': 'CRYPTO'},
}


def get_available_markets():
    """
    Return the market/category tree for the frontend.
    
    Returns:
        Dict with market names as keys and list of categories as values
    """
    return {
        'india': ['equity', 'commodity', 'bonds'],
        'usa': ['equity'],
        'crypto': ['all'],
    }


def search_stocks(query, market=None, category=None):
    """
    Search for stocks by name or symbol, optionally filtered by market and category.
    
    Args:
        query: Search query string
        market: Optional market filter ('india', 'usa', 'crypto')
        category: Optional category filter ('equity', 'commodity', 'bonds', 'all')
        
    Returns:
        List of matching stocks (max 10)
    """
    query = query.strip().upper()
    
    if len(query) < 2:
        return []
    
    results = []
    
    # Determine which market/category combos to search
    if market and market in STOCKS:
        # Search within a specific market
        if category and category in STOCKS[market]:
            search_targets = [(market, category, STOCKS[market][category])]
        else:
            # Search all categories within the selected market
            search_targets = [
                (market, cat, stocks)
                for cat, stocks in STOCKS[market].items()
            ]
    else:
        # Search across all markets and categories
        search_targets = [
            (mkt, cat, stocks)
            for mkt, mkt_data in STOCKS.items()
            for cat, stocks in mkt_data.items()
        ]
    
    seen_symbols = set()  # Avoid duplicates (e.g. ONGC appears in equity + commodity)
    
    for mkt, cat, stock_dict in search_targets:
        for symbol, (name, yahoo_symbol) in stock_dict.items():
            if yahoo_symbol in seen_symbols:
                continue
            if query in symbol or query in name.upper():
                exchange = MARKET_EXCHANGE_LABELS.get(mkt, {}).get(cat, mkt.upper())
                results.append({
                    'symbol': yahoo_symbol,
                    'name': name,
                    'exchange': exchange,
                    'market': mkt,
                    'category': cat,
                })
                seen_symbols.add(yahoo_symbol)
    
    # Limit results to 10
    return results[:10]


def get_stock_price(symbol):
    """
    Get current price for a stock symbol with caching.
    
    Args:
        symbol: Stock symbol (Yahoo Finance format)
        
    Returns:
        Current price as float, or None if error
    """
    # Check cache first
    cache_key = f"price_single_{symbol}"
    cached_price = price_cache.get(cache_key)
    if cached_price is not None:
        return cached_price
    
    # Fetch from API
    start_time = time.time()
    try:
        ticker = yf.Ticker(symbol)
        stock_data = ticker.history(period='1d')
        if len(stock_data) == 0:
            metrics_tracker.record_api_call()
            return None
        
        price = float(stock_data['Close'].iloc[-1])
        
        # Cache the result
        price_cache.set(cache_key, price, ttl=10)
        
        # Record API call
        duration_ms = (time.time() - start_time) * 1000
        metrics_tracker.record_api_call(duration_ms)
        
        return price
    except Exception as e:
        logger.error(f"Error fetching price for {symbol}: {e}", exc_info=True)
        metrics_tracker.record_api_call()
        return None


def get_stock_prices(symbols):
    """
    Optimized batch price fetching with caching and metrics tracking.
    Fetches current prices for multiple stocks efficiently.
    
    Args:
        symbols: List of stock symbols
        
    Returns:
        Dictionary mapping symbol to price data
    """
    if not symbols:
        return {}
    
    prices = {}
    indices = ['^NSEI', '^IXIC', '^DJI', '^BSESN']
    uncached_symbols = []
    
    # Check cache first
    for symbol in symbols:
        cache_key = f"price_{symbol}"
        cached_data = price_cache.get(cache_key)
        if cached_data is not None:
            prices[symbol] = cached_data
        else:
            uncached_symbols.append(symbol)
    
    # Fetch uncached symbols individually (more reliable than batch)
    # Batch download can be unreliable with yfinance, so we use individual fetches
    if uncached_symbols:
        start_time = time.time()
        
        for symbol in uncached_symbols:
            try:
                ticker = yf.Ticker(symbol)
                # Use appropriate period based on symbol type
                period = '3d' if symbol in indices else '2d'
                hist = ticker.history(period=period)
                
                if hist.empty or len(hist) == 0:
                    logger.warning(f"No data returned for {symbol}")
                    prices[symbol] = {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}
                    continue
                
                # Get the latest close price
                current_price = hist['Close'].iloc[-1]
                
                # Check for NaN values
                if pd.isna(current_price):
                    logger.warning(f"NaN price for {symbol}")
                    prices[symbol] = {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}
                    continue
                
                current_price = float(current_price)
                
                # Calculate change if we have at least 2 rows
                if len(hist) >= 2:
                    prev_close = hist['Close'].iloc[-2]
                    
                    if pd.isna(prev_close):
                        # If previous close is NaN, use current price
                        change = 0.0
                        change_percent = 0.0
                    else:
                        prev_close = float(prev_close)
                        change = current_price - prev_close
                        change_percent = (change / prev_close) * 100 if prev_close != 0 else 0.0
                else:
                    # Only one row available
                    change = 0.0
                    change_percent = 0.0
                
                price_data = {
                    'price': round(current_price, 2),
                    'change': round(change, 2),
                    'change_percent': round(change_percent, 2)
                }
                
                prices[symbol] = price_data
                
                # Cache the result
                cache_key = f"price_{symbol}"
                price_cache.set(cache_key, price_data, ttl=10)
                
            except Exception as e:
                logger.error(f"Error fetching price for {symbol}: {e}", exc_info=True)
                prices[symbol] = {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}
        
        # Record API call with duration
        duration_ms = (time.time() - start_time) * 1000
        metrics_tracker.record_api_call(duration_ms)
    
    return prices

def get_heatmap_data(market='india'):
    """
    Returns data formatted for a Treemap/Heatmap visualization.
    Includes symbol, name, price, change %, and a simulated market cap for sizing.
    Fetches real-time prices for an impactful visual display.
    """
    # Select top symbols to display in the heatmap (limit to 30 for performance)
    symbols_to_fetch = []
    symbol_data = {}
    
    if market in STOCKS:
        if isinstance(STOCKS[market], dict):
            # E.g., india or usa which have subcategories
            for category, stocks in STOCKS[market].items():
                for key, (company_name, ticker) in list(stocks.items())[:15]: # Take top 15 from each category
                    if ticker not in symbol_data:
                        symbols_to_fetch.append(ticker)
                        symbol_data[ticker] = company_name
        else:
            # Flat list
            pass
            
    # Default fallback to some major Indian stocks if nothing found or to limit
    if not symbols_to_fetch:
        for key, (company_name, ticker) in list(STOCKS['india']['equity'].items())[:30]:
            symbols_to_fetch.append(ticker)
            symbol_data[ticker] = company_name
            
    # Cap at 30 to keep API fast during page load
    symbols_to_fetch = symbols_to_fetch[:30]
    
    # Fetch live prices
    live_prices = get_stock_prices(symbols_to_fetch)
    
    heatmap_data = []
    
    import hashlib
    for symbol in symbols_to_fetch:
        price_info = live_prices.get(symbol, {'price': 0, 'change': 0, 'change_percent': 0})
        
        # Generate a stable, pseudo-random "market cap" for sizing the Treemap blocks
        # using the string hash of the symbol so it stays consistent between refreshes
        hash_val = int(hashlib.md5(symbol.encode()).hexdigest(), 16)
        # Size between 10,000 and 100,000 for visual distribution
        simulated_mcap = 10000 + (hash_val % 90000)
        
        # Only add valid entries
        if price_info.get('price') != 'N/A' and price_info.get('price', 0) > 0:
            heatmap_data.append({
                'x': symbol.replace('.NS', ''), # For ApexCharts: x is the label
                'y': simulated_mcap,           # For ApexCharts: y is the size
                'name': symbol_data.get(symbol, symbol),
                'price': price_info.get('price', 0),
                'change_percent': price_info.get('change_percent', 0)
            })
            
    return heatmap_data
