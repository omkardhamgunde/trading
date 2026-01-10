"""
Stock service for stock search and price fetching.
"""
import yfinance as yf


# Stock database - Indian and US stocks
INDIAN_STOCKS = {
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
}

US_STOCKS = {
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
}


def search_stocks(query):
    """
    Search for stocks by name or symbol.
    
    Args:
        query: Search query string
        
    Returns:
        List of matching stocks (max 10)
    """
    query = query.strip().upper()
    
    if len(query) < 2:
        return []
    
    results = []
    
    # Search in Indian stocks
    for symbol, (name, yahoo_symbol) in INDIAN_STOCKS.items():
        if query in symbol or query in name.upper():
            results.append({
                'symbol': yahoo_symbol,
                'name': name,
                'exchange': 'NSE'
            })
    
    # Search in US stocks
    for symbol, (name, yahoo_symbol) in US_STOCKS.items():
        if query in symbol or query in name.upper():
            results.append({
                'symbol': yahoo_symbol,
                'name': name,
                'exchange': 'NYSE/NASDAQ'
            })
    
    # Limit results to 10
    return results[:10]


def get_stock_price(symbol):
    """
    Get current price for a stock symbol.
    
    Args:
        symbol: Stock symbol (Yahoo Finance format)
        
    Returns:
        Current price as float, or None if error
    """
    try:
        ticker = yf.Ticker(symbol)
        stock_data = ticker.history(period='1d')
        if len(stock_data) == 0:
            return None
        return float(stock_data['Close'].iloc[-1])
    except Exception as e:
        print(f"Error fetching price for {symbol}: {e}")
        return None


def get_stock_prices(symbols):
    """
    Fetch current prices for multiple stocks.
    
    Args:
        symbols: List of stock symbols
        
    Returns:
        Dictionary mapping symbol to price data
    """
    prices = {}
    indices = ['^NSEI', '^IXIC', '^DJI', '^BSESN']
    
    for symbol in symbols:
        try:
            ticker = yf.Ticker(symbol)
            
            # For indices, get 3 days of data
            if symbol in indices:
                hist = ticker.history(period='3d')
            else:
                hist = ticker.history(period='2d')
            
            if len(hist) >= 2:
                prev_close = hist['Close'].iloc[-2]
                current_price = hist['Close'].iloc[-1]
                change = current_price - prev_close
                change_percent = (change / prev_close) * 100
                
                prices[symbol] = {
                    'price': round(float(current_price), 2),
                    'change': round(float(change), 2),
                    'change_percent': round(float(change_percent), 2)
                }
            else:
                prices[symbol] = {
                    'price': 'N/A',
                    'change': 'N/A',
                    'change_percent': 'N/A'
                }
        except Exception as e:
            print(f"Error fetching price for {symbol}: {e}")
            prices[symbol] = {
                'price': 'N/A',
                'change': 'N/A',
                'change_percent': 'N/A'
            }
    
    return prices
