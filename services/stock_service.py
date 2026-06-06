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
from utils.currency import convert_price_to_usd

logger = logging.getLogger(__name__)

INDEX_SYMBOLS = {'^NSEI', '^IXIC', '^DJI', '^BSESN'}
INDEX_CACHE_TTL = 20
PRICE_CACHE_TTL = 20

INDEX_FALLBACK_PRICES = {
    '^NSEI': {'price': 23366.70, 'change': -49.85, 'change_percent': -0.21},
    '^IXIC': {'price': 25709.43, 'change': -1121.53, 'change_percent': -4.18},
    '^DJI': {'price': 50866.78, 'change': -695.15, 'change_percent': -1.35},
    '^BSESN': {'price': 74243.34, 'change': -116.66, 'change_percent': -0.16},
}


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
            'GOLD1': ('Gold ETF', 'GOLD1.NS'),
            'LICMFGOLD': ('LIC MF Gold ETF', 'LICMFGOLD.NS'),
            'KOTAKGOLD': ('Kotak Gold ETF', 'KOTAKGOLD.NS'),
            'AXISGOLD': ('Axis Gold ETF', 'AXISGOLD.NS'),
            'SETFGOLD': ('SBI Gold ETF', 'SETFGOLD.NS'),
            'ABSLBANETF': ('Aditya Birla Sun Life Nifty SDL Apr 2026 ETF', 'ABSLBANETF.NS'),
            'GOLDSHARE': ('UTI Gold ETF', 'GOLDSHARE.NS'),
            'SILVER1': ('Silver ETF', 'SILVER1.NS'),
            'ICICISILVE': ('ICICI Prudential Silver ETF', 'ICICISILVE.NS'),
            'AXISILVER': ('Axis Silver ETF', 'AXISILVER.NS'),
            'SETFSILV': ('SBI Silver ETF', 'SETFSILV.NS'),
            'HDFCSILVER': ('HDFC Silver ETF', 'HDFCSILVER.NS'),
            'HDFCGOLD': ('HDFC Gold ETF', 'HDFCGOLD.NS'),
            'GRAVITA': ('Gravita India', 'GRAVITA.NS'),
            'HGINFRA': ('HG Infra Engineering', 'HGINFRA.NS'),
            'JINDALSTEL': ('Jindal Steel & Power', 'JINDALSTEL.NS'),
            'SAIL': ('Steel Authority of India', 'SAIL.NS'),
            'APLAPOLLO': ('APL Apollo Tubes', 'APLAPOLLO.NS'),
            'RATNAMANI': ('Ratnamani Metals', 'RATNAMANI.NS'),
            'JSWHL': ('JSW Holdings', 'JSWHL.NS'),
            'WELCORP': ('Welspun Corp', 'WELCORP.NS'),
            'OIL': ('Oil India', 'OIL.NS'),
            'PETRONET': ('Petronet LNG', 'PETRONET.NS'),
            'GSPL': ('Gujarat State Petronet', 'GSPL.NS'),
            'MGL': ('Mahanagar Gas', 'MGL.NS'),
            'IGL': ('Indraprastha Gas', 'IGL.NS'),
            'ATGL': ('Adani Total Gas', 'ATGL.NS'),
            'AEGISLOG': ('Aegis Logistics', 'AEGISLOG.NS'),
            'CASTROLIND': ('Castrol India', 'CASTROLIND.NS'),
            'GUJGASLTD': ('Gujarat Gas', 'GUJGASLTD.NS'),
            'GMDCLTD': ('Gujarat Mineral Development', 'GMDCLTD.NS'),
            'NLCINDIA': ('NLC India', 'NLCINDIA.NS'),
            'ASHAPURMIN': ('Ashapura Minechem', 'ASHAPURMIN.NS'),
            'ORISSAMINE': ('Orissa Minerals Development', 'ORISSAMINE.NS'),
            'RAIN': ('Rain Industries', 'RAIN.NS'),
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
            'BHARATBOND': ('Bharat Bond ETF April 2030', 'BHARATBOND.NS'),
            'EBBETF0425': ('Edelweiss Bharat Bond ETF April 2025', 'EBBETF0425.NS'),
            'EBBETF0430': ('Edelweiss Bharat Bond ETF April 2030', 'EBBETF0430.NS'),
            'SDL26BEES': ('Nippon India ETF Nifty SDL 2026', 'SDL26BEES.NS'),
            'GILT5YBEES': ('Nippon India ETF 5 Year Gilt', 'GILT5YBEES.NS'),
            'GILT10YBEES': ('Nippon India ETF 10 Year Gilt', 'GILT10YBEES.NS'),
            'PSUBNKBEES': ('Nippon PSU Bank Bees ETF', 'PSUBNKBEES.NS'),
            'ITBEES': ('Nippon IT Bees ETF', 'ITBEES.NS'),
            'AUTOBEES': ('Nippon Auto Bees ETF', 'AUTOBEES.NS'),
            'PHARMABEES': ('Nippon Pharma Bees ETF', 'PHARMABEES.NS'),
            'CONSUMBEES': ('Nippon Consumption Bees ETF', 'CONSUMBEES.NS'),
            'INFRABEES': ('Nippon Infra Bees ETF', 'INFRABEES.NS'),
            'MAFANG': ('Mirae Asset NYSE FANG Plus ETF', 'MAFANG.NS'),
            'MON100': ('Motilal Oswal Nasdaq 100 ETF', 'MON100.NS'),
            'MOM50': ('Motilal Oswal S&P 500 ETF', 'MOM50.NS'),
            'MOVALUE': ('Motilal Oswal Nifty 200 Value 30 ETF', 'MOVALUE.NS'),
            'MOLOWVOL': ('Motilal Oswal Nifty Low Volatility ETF', 'MOLOWVOL.NS'),
            'ALPHA': ('Nippon Alpha ETF', 'ALPHA.NS'),
            'QUAL30IETF': ('Quality 30 ETF', 'QUAL30IETF.NS'),
            'MID150BEES': ('Nippon Nifty Midcap 150 ETF', 'MID150BEES.NS'),
            'NEXT50IETF': ('Nifty Next 50 ETF', 'NEXT50IETF.NS'),
            'AXISBNKETF': ('Axis Banking ETF', 'AXISBNKETF.NS'),
            'AXISTECETF': ('Axis Nifty IT ETF', 'AXISTECETF.NS'),
            'UTINEXT50': ('UTI Nifty Next 50 ETF', 'UTINEXT50.NS'),
            'UTISXN50': ('UTI Sensex Next 50 ETF', 'UTISXN50.NS'),
            'ICICINF100': ('ICICI Prudential Nifty 100 ETF', 'ICICINF100.NS'),
            'ICICIBANKN': ('ICICI Prudential Bank ETF', 'ICICIBANKN.NS'),
            'DSPN50ETF': ('DSP Nifty 50 ETF', 'DSPN50ETF.NS'),
            'DSPQ50ETF': ('DSP Nifty Next 50 ETF', 'DSPQ50ETF.NS'),
            'ABSLNN50ET': ('Aditya Birla Sun Life Nifty Next 50 ETF', 'ABSLNN50ET.NS'),
            'HDFCSENSEX': ('HDFC Sensex ETF', 'HDFCSENSEX.NS'),
            'SETFNN50': ('SBI Nifty Next 50 ETF', 'SETFNN50.NS'),
            'SETFGILT': ('SBI 10 Year Gilt ETF', 'SETFGILT.NS'),
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
            'BRK-B': ('Berkshire Hathaway Class B', 'BRK-B'),
            'JNJ': ('Johnson & Johnson', 'JNJ'),
            'PG': ('Procter & Gamble', 'PG'),
            'XOM': ('Exxon Mobil', 'XOM'),
            'CVX': ('Chevron', 'CVX'),
            'LLY': ('Eli Lilly', 'LLY'),
            'MRK': ('Merck', 'MRK'),
            'PFE': ('Pfizer', 'PFE'),
            'ABBV': ('AbbVie', 'ABBV'),
            'UNH': ('UnitedHealth Group', 'UNH'),
            'HD': ('Home Depot', 'HD'),
            'COST': ('Costco', 'COST'),
            'TMO': ('Thermo Fisher Scientific', 'TMO'),
            'AVGO': ('Broadcom', 'AVGO'),
            'QCOM': ('Qualcomm', 'QCOM'),
            'TXN': ('Texas Instruments', 'TXN'),
            'MU': ('Micron Technology', 'MU'),
            'SHOP': ('Shopify', 'SHOP'),
            'PANW': ('Palo Alto Networks', 'PANW'),
            'CRWD': ('CrowdStrike', 'CRWD'),
            'NOW': ('ServiceNow', 'NOW'),
            'INTU': ('Intuit', 'INTU'),
            'BKNG': ('Booking Holdings', 'BKNG'),
            'CAT': ('Caterpillar', 'CAT'),
            'DE': ('Deere & Company', 'DE'),
            'GS': ('Goldman Sachs', 'GS'),
            'MS': ('Morgan Stanley', 'MS'),
            'C': ('Citigroup', 'C'),
            'T': ('AT&T', 'T'),
            'VZ': ('Verizon', 'VZ'),
            'ARM': ('Arm Holdings ADR', 'ARM'),
            'RIVN': ('Rivian Automotive', 'RIVN'),
            'LCID': ('Lucid Group', 'LCID'),
            'SQ': ('Block', 'SQ'),
            'DDOG': ('Datadog', 'DDOG'),
            'SNOW': ('Snowflake', 'SNOW'),
            'NET': ('Cloudflare', 'NET'),
            'MDB': ('MongoDB', 'MDB'),
            'ADSK': ('Autodesk', 'ADSK'),
            'CMCSA': ('Comcast', 'CMCSA'),
            'TTD': ('Trade Desk', 'TTD'),
            'PINS': ('Pinterest', 'PINS'),
            'RBLX': ('Roblox', 'RBLX'),
        },
        'commodity': {
            'GLD': ('SPDR Gold Shares ETF', 'GLD'),
            'IAU': ('iShares Gold Trust', 'IAU'),
            'GLDM': ('SPDR Gold MiniShares Trust', 'GLDM'),
            'SLV': ('iShares Silver Trust', 'SLV'),
            'SIVR': ('Aberdeen Standard Physical Silver Shares ETF', 'SIVR'),
            'PPLT': ('Aberdeen Physical Platinum Shares ETF', 'PPLT'),
            'PALL': ('Aberdeen Physical Palladium Shares ETF', 'PALL'),
            'USO': ('United States Oil Fund', 'USO'),
            'BNO': ('United States Brent Oil Fund', 'BNO'),
            'UNG': ('United States Natural Gas Fund', 'UNG'),
            'DBO': ('Invesco DB Oil Fund', 'DBO'),
            'DBA': ('Invesco DB Agriculture Fund', 'DBA'),
            'DBC': ('Invesco DB Commodity Index Tracking Fund', 'DBC'),
            'COMT': ('iShares GSCI Commodity Dynamic Roll Strategy ETF', 'COMT'),
            'PDBC': ('Invesco Optimum Yield Diversified Commodity Strategy', 'PDBC'),
            'XLE': ('Energy Select Sector SPDR Fund', 'XLE'),
            'XOP': ('SPDR S&P Oil & Gas Exploration & Production ETF', 'XOP'),
            'COPX': ('Global X Copper Miners ETF', 'COPX'),
            'CPER': ('United States Copper Index Fund', 'CPER'),
            'URA': ('Global X Uranium ETF', 'URA'),
            'LIT': ('Global X Lithium & Battery Tech ETF', 'LIT'),
            'WEAT': ('Teucrium Wheat Fund', 'WEAT'),
            'CORN': ('Teucrium Corn Fund', 'CORN'),
            'SOYB': ('Teucrium Soybean Fund', 'SOYB'),
            'JO': ('iPath Series B Bloomberg Coffee Subindex ETN', 'JO'),
            'NIB': ('iPath Series B Bloomberg Cocoa Subindex ETN', 'NIB'),
            'BAL': ('iPath Series B Bloomberg Cotton Subindex ETN', 'BAL'),
            'SGG': ('iPath Series B Bloomberg Sugar Subindex ETN', 'SGG'),
        },
        'bonds': {
            'BND': ('Vanguard Total Bond Market ETF', 'BND'),
            'AGG': ('iShares Core U.S. Aggregate Bond ETF', 'AGG'),
            'TLT': ('iShares 20+ Year Treasury Bond ETF', 'TLT'),
            'IEF': ('iShares 7-10 Year Treasury Bond ETF', 'IEF'),
            'SHY': ('iShares 1-3 Year Treasury Bond ETF', 'SHY'),
            'VGIT': ('Vanguard Intermediate-Term Treasury ETF', 'VGIT'),
            'VGLT': ('Vanguard Long-Term Treasury ETF', 'VGLT'),
            'TIP': ('iShares TIPS Bond ETF', 'TIP'),
            'SCHP': ('Schwab U.S. TIPS ETF', 'SCHP'),
            'LQD': ('iShares iBoxx Investment Grade Corporate Bond ETF', 'LQD'),
            'HYG': ('iShares iBoxx High Yield Corporate Bond ETF', 'HYG'),
            'JNK': ('SPDR Bloomberg High Yield Bond ETF', 'JNK'),
            'MUB': ('iShares National Muni Bond ETF', 'MUB'),
            'BIL': ('SPDR Bloomberg 1-3 Month T-Bill ETF', 'BIL'),
            'SGOV': ('iShares 0-3 Month Treasury Bond ETF', 'SGOV'),
            'GOVT': ('iShares U.S. Treasury Bond ETF', 'GOVT'),
            'MINT': ('PIMCO Enhanced Short Maturity Active ETF', 'MINT'),
            'VCIT': ('Vanguard Intermediate-Term Corporate Bond ETF', 'VCIT'),
            'VCSH': ('Vanguard Short-Term Corporate Bond ETF', 'VCSH'),
            'BSV': ('Vanguard Short-Term Bond ETF', 'BSV'),
            'BSVN': ('BondBloxx Bloomberg Seven Year Target Duration US Treasury ETF', 'BSVN'),
            'EDV': ('Vanguard Extended Duration Treasury ETF', 'EDV'),
            'HYLB': ('Xtrackers USD High Yield Corporate Bond ETF', 'HYLB'),
            'ANGL': ('VanEck Fallen Angel High Yield Bond ETF', 'ANGL'),
            'EMB': ('iShares J.P. Morgan USD Emerging Markets Bond ETF', 'EMB'),
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

ADDITIONAL_INDIAN_EQUITIES = {
    '360ONE': ('360 One Wam', '360ONE.NS'),
    '3MINDIA': ('3M India', '3MINDIA.NS'),
    'AARTIDRUGS': ('Aarti Drugs', 'AARTIDRUGS.NS'),
    'AAVAS': ('Aavas Financiers', 'AAVAS.NS'),
    'ABCAPITAL': ('Aditya Birla Capital', 'ABCAPITAL.NS'),
    'ABSLAMC': ('Aditya Birla Sun Life AMC', 'ABSLAMC.NS'),
    'ADANIENSOL': ('Adani Energy Solutions', 'ADANIENSOL.NS'),
    'ADANIPOWER': ('Adani Power', 'ADANIPOWER.NS'),
    'AEGISCHEM': ('Aegis Logistics', 'AEGISCHEM.NS'),
    'AFFLE': ('Affle India', 'AFFLE.NS'),
    'AJANTPHARM': ('Ajanta Pharma', 'AJANTPHARM.NS'),
    'ALKEM': ('Alkem Laboratories', 'ALKEM.NS'),
    'ALKYLAMINE': ('Alkyl Amines Chemicals', 'ALKYLAMINE.NS'),
    'AMBER': ('Amber Enterprises', 'AMBER.NS'),
    'ANGELONE': ('Angel One', 'ANGELONE.NS'),
    'ANURAS': ('Anupam Rasayan India', 'ANURAS.NS'),
    'APTUS': ('Aptus Value Housing Finance', 'APTUS.NS'),
    'ARE&M': ('Amara Raja Energy & Mobility', 'ARE&M.NS'),
    'ASTERDM': ('Aster DM Healthcare', 'ASTERDM.NS'),
    'ASTRAL': ('Astral', 'ASTRAL.NS'),
    'ATGL': ('Adani Total Gas', 'ATGL.NS'),
    'AUROPHARMA': ('Aurobindo Pharma', 'AUROPHARMA.NS'),
    'AVANTIFEED': ('Avanti Feeds', 'AVANTIFEED.NS'),
    'BALKRISIND': ('Balkrishna Industries', 'BALKRISIND.NS'),
    'BASF': ('BASF India', 'BASF.NS'),
    'BATAINDIA': ('Bata India', 'BATAINDIA.NS'),
    'BAYERCROP': ('Bayer Cropscience', 'BAYERCROP.NS'),
    'BBTC': ('Bombay Burmah Trading Corp', 'BBTC.NS'),
    'BDL': ('Bharat Dynamics', 'BDL.NS'),
    'BHARATFORG': ('Bharat Forge', 'BHARATFORG.NS'),
    'BIKAJI': ('Bikaji Foods International', 'BIKAJI.NS'),
    'BIOCON': ('Biocon', 'BIOCON.NS'),
    'BIRLACORPN': ('Birla Corporation', 'BIRLACORPN.NS'),
    'BLUEDART': ('Blue Dart Express', 'BLUEDART.NS'),
    'BORORENEW': ('Borosil Renewables', 'BORORENEW.NS'),
    'BSE': ('BSE', 'BSE.NS'),
    'CAMS': ('Computer Age Management Services', 'CAMS.NS'),
    'CANFINHOME': ('Can Fin Homes', 'CANFINHOME.NS'),
    'CARBORUNIV': ('Carborundum Universal', 'CARBORUNIV.NS'),
    'CASTROLIND': ('Castrol India', 'CASTROLIND.NS'),
    'CDSL': ('Central Depository Services', 'CDSL.NS'),
    'CENTRALBK': ('Central Bank of India', 'CENTRALBK.NS'),
    'CENTURYPLY': ('Century Plyboards', 'CENTURYPLY.NS'),
    'CESC': ('CESC', 'CESC.NS'),
    'CGCL': ('Capri Global Capital', 'CGCL.NS'),
    'CGPOWER': ('CG Power and Industrial Solutions', 'CGPOWER.NS'),
    'CHALET': ('Chalet Hotels', 'CHALET.NS'),
    'CHAMBLFERT': ('Chambal Fertilisers', 'CHAMBLFERT.NS'),
    'CLEAN': ('Clean Science and Technology', 'CLEAN.NS'),
    'COCHINSHIP': ('Cochin Shipyard', 'COCHINSHIP.NS'),
    'COLPAL': ('Colgate Palmolive India', 'COLPAL.NS'),
    'CONCOR': ('Container Corporation of India', 'CONCOR.NS'),
    'COROMANDEL': ('Coromandel International', 'COROMANDEL.NS'),
    'CROMPTON': ('Crompton Greaves Consumer Electricals', 'CROMPTON.NS'),
    'CUB': ('City Union Bank', 'CUB.NS'),
    'CUMMINSIND': ('Cummins India', 'CUMMINSIND.NS'),
    'CYIENT': ('Cyient', 'CYIENT.NS'),
    'DATAPATTNS': ('Data Patterns India', 'DATAPATTNS.NS'),
    'DCMSHRIRAM': ('DCM Shriram', 'DCMSHRIRAM.NS'),
    'DEEPAKFERT': ('Deepak Fertilisers', 'DEEPAKFERT.NS'),
    'DMART': ('Avenue Supermarts', 'DMART.NS'),
    'DOMS': ('DOMS Industries', 'DOMS.NS'),
    'ECLERX': ('eClerx Services', 'ECLERX.NS'),
    'EMAMILTD': ('Emami', 'EMAMILTD.NS'),
    'ENDURANCE': ('Endurance Technologies', 'ENDURANCE.NS'),
    'ENGINERSIN': ('Engineers India', 'ENGINERSIN.NS'),
    'EPL': ('EPL', 'EPL.NS'),
    'ESCORTS': ('Escorts Kubota', 'ESCORTS.NS'),
    'FACT': ('Fertilisers and Chemicals Travancore', 'FACT.NS'),
    'FINEORG': ('Fine Organic Industries', 'FINEORG.NS'),
    'FLUOROCHEM': ('Gujarat Fluorochemicals', 'FLUOROCHEM.NS'),
    'FORTIS': ('Fortis Healthcare', 'FORTIS.NS'),
    'FSL': ('Firstsource Solutions', 'FSL.NS'),
    'GESHIP': ('Great Eastern Shipping', 'GESHIP.NS'),
    'GICRE': ('General Insurance Corporation of India', 'GICRE.NS'),
    'GILLETTE': ('Gillette India', 'GILLETTE.NS'),
    'GLAND': ('Gland Pharma', 'GLAND.NS'),
    'GLAXO': ('GlaxoSmithKline Pharmaceuticals', 'GLAXO.NS'),
    'GLENMARK': ('Glenmark Pharmaceuticals', 'GLENMARK.NS'),
    'GMMPFAUDLR': ('GMM Pfaudler', 'GMMPFAUDLR.NS'),
    'GNFC': ('Gujarat Narmada Valley Fertilizers', 'GNFC.NS'),
    'GODFRYPHLP': ('Godfrey Phillips India', 'GODFRYPHLP.NS'),
    'GPIL': ('Godawari Power and Ispat', 'GPIL.NS'),
    'GRINDWELL': ('Grindwell Norton', 'GRINDWELL.NS'),
    'GSFC': ('Gujarat State Fertilizers', 'GSFC.NS'),
    'GSPL': ('Gujarat State Petronet', 'GSPL.NS'),
    'GUJGASLTD': ('Gujarat Gas', 'GUJGASLTD.NS'),
    'HATSUN': ('Hatsun Agro Product', 'HATSUN.NS'),
    'HINDPETRO': ('Hindustan Petroleum', 'HINDPETRO.NS'),
    'HINDZINC': ('Hindustan Zinc', 'HINDZINC.NS'),
    'HOMEFIRST': ('Home First Finance', 'HOMEFIRST.NS'),
    'HUDCO': ('Housing and Urban Development Corporation', 'HUDCO.NS'),
    'IEX': ('Indian Energy Exchange', 'IEX.NS'),
    'IFCI': ('IFCI', 'IFCI.NS'),
    'IGL': ('Indraprastha Gas', 'IGL.NS'),
    'IIFL': ('IIFL Finance', 'IIFL.NS'),
    'INDHOTEL': ('Indian Hotels Company', 'INDHOTEL.NS'),
    'INDIACEM': ('India Cements', 'INDIACEM.NS'),
    'INDIAMART': ('IndiaMART InterMESH', 'INDIAMART.NS'),
    'INOXWIND': ('Inox Wind', 'INOXWIND.NS'),
    'INTELLECT': ('Intellect Design Arena', 'INTELLECT.NS'),
    'IOB': ('Indian Overseas Bank', 'IOB.NS'),
    'IPCALAB': ('IPCA Laboratories', 'IPCALAB.NS'),
    'ISEC': ('ICICI Securities', 'ISEC.NS'),
    'JBCHEPHARM': ('JB Chemicals and Pharmaceuticals', 'JBCHEPHARM.NS'),
    'JINDALSAW': ('Jindal Saw', 'JINDALSAW.NS'),
    'JINDALSTEL': ('Jindal Steel and Power', 'JINDALSTEL.NS'),
    'JKCEMENT': ('JK Cement', 'JKCEMENT.NS'),
    'JKLAKSHMI': ('JK Lakshmi Cement', 'JKLAKSHMI.NS'),
    'JMFINANCIL': ('JM Financial', 'JMFINANCIL.NS'),
    'JSL': ('Jindal Stainless', 'JSL.NS'),
    'JSWINFRA': ('JSW Infrastructure', 'JSWINFRA.NS'),
    'JUBLINGREA': ('Jubilant Ingrevia', 'JUBLINGREA.NS'),
    'JYOTHYLAB': ('Jyothy Labs', 'JYOTHYLAB.NS'),
    'KAJARIACER': ('Kajaria Ceramics', 'KAJARIACER.NS'),
    'KALYANKJIL': ('Kalyan Jewellers India', 'KALYANKJIL.NS'),
    'KANSAINER': ('Kansai Nerolac Paints', 'KANSAINER.NS'),
    'KARURVYSYA': ('Karur Vysya Bank', 'KARURVYSYA.NS'),
    'KEC': ('KEC International', 'KEC.NS'),
    'KEI': ('KEI Industries', 'KEI.NS'),
    'KFINTECH': ('KFin Technologies', 'KFINTECH.NS'),
    'KNRCON': ('KNR Constructions', 'KNRCON.NS'),
    'KPITTECH': ('KPIT Technologies', 'KPITTECH.NS'),
    'KPRMILL': ('KPR Mill', 'KPRMILL.NS'),
    'LALPATHLAB': ('Dr Lal PathLabs', 'LALPATHLAB.NS'),
    'LAURUSLABS': ('Laurus Labs', 'LAURUSLABS.NS'),
    'LAXMIMACH': ('Lakshmi Machine Works', 'LAXMIMACH.NS'),
    'LEMONTREE': ('Lemon Tree Hotels', 'LEMONTREE.NS'),
    'LINDEINDIA': ('Linde India', 'LINDEINDIA.NS'),
    'LLOYDSME': ('Lloyds Metals and Energy', 'LLOYDSME.NS'),
    'LTTS': ('L&T Technology Services', 'LTTS.NS'),
    'LUPIN': ('Lupin', 'LUPIN.NS'),
    'M&MFIN': ('Mahindra and Mahindra Financial Services', 'M&MFIN.NS'),
    'MAHABANK': ('Bank of Maharashtra', 'MAHABANK.NS'),
    'MAHLIFE': ('Mahindra Lifespace Developers', 'MAHLIFE.NS'),
    'MANAPPURAM': ('Manappuram Finance', 'MANAPPURAM.NS'),
    'MANKIND': ('Mankind Pharma', 'MANKIND.NS'),
    'MASTEK': ('Mastek', 'MASTEK.NS'),
    'MAXHEALTH': ('Max Healthcare Institute', 'MAXHEALTH.NS'),
    'MAZDOCK': ('Mazagon Dock Shipbuilders', 'MAZDOCK.NS'),
    'MCX': ('Multi Commodity Exchange of India', 'MCX.NS'),
    'MEDANTA': ('Global Health', 'MEDANTA.NS'),
    'METROPOLIS': ('Metropolis Healthcare', 'METROPOLIS.NS'),
    'MFSL': ('Max Financial Services', 'MFSL.NS'),
    'MGL': ('Mahanagar Gas', 'MGL.NS'),
    'MINDACORP': ('Minda Corporation', 'MINDACORP.NS'),
    'MOTILALOFS': ('Motilal Oswal Financial Services', 'MOTILALOFS.NS'),
    'MRPL': ('Mangalore Refinery and Petrochemicals', 'MRPL.NS'),
    'MSUMI': ('Motherson Sumi Wiring India', 'MSUMI.NS'),
    'NATCOPHARM': ('Natco Pharma', 'NATCOPHARM.NS'),
    'NATIONALUM': ('National Aluminium Company', 'NATIONALUM.NS'),
    'NAUKRI': ('Info Edge India', 'NAUKRI.NS'),
    'NAVINFLUOR': ('Navin Fluorine International', 'NAVINFLUOR.NS'),
    'NH': ('Narayana Hrudayalaya', 'NH.NS'),
    'NHPC': ('NHPC', 'NHPC.NS'),
    'NIACL': ('New India Assurance Company', 'NIACL.NS'),
    'NLCINDIA': ('NLC India', 'NLCINDIA.NS'),
    'NMDC': ('NMDC', 'NMDC.NS'),
    'NSLNISP': ('NMDC Steel', 'NSLNISP.NS'),
    'NUVAMA': ('Nuvama Wealth Management', 'NUVAMA.NS'),
    'NUVOCO': ('Nuvoco Vistas Corporation', 'NUVOCO.NS'),
    'OBEROIRLTY': ('Oberoi Realty', 'OBEROIRLTY.NS'),
    'OIL': ('Oil India', 'OIL.NS'),
    'PATANJALI': ('Patanjali Foods', 'PATANJALI.NS'),
    'PEL': ('Piramal Enterprises', 'PEL.NS'),
    'PERSISTENT': ('Persistent Systems', 'PERSISTENT.NS'),
    'PETRONET': ('Petronet LNG', 'PETRONET.NS'),
    'PFC': ('Power Finance Corporation', 'PFC.NS'),
    'PHOENIXLTD': ('Phoenix Mills', 'PHOENIXLTD.NS'),
    'POLICYBZR': ('PB Fintech', 'POLICYBZR.NS'),
    'POLYMED': ('Poly Medicure', 'POLYMED.NS'),
    'POONAWALLA': ('Poonawalla Fincorp', 'POONAWALLA.NS'),
    'PRAJIND': ('Praj Industries', 'PRAJIND.NS'),
    'PRESTIGE': ('Prestige Estates Projects', 'PRESTIGE.NS'),
    'PRINCEPIPE': ('Prince Pipes and Fittings', 'PRINCEPIPE.NS'),
    'QUESS': ('Quess Corp', 'QUESS.NS'),
    'RADICO': ('Radico Khaitan', 'RADICO.NS'),
    'RAILTEL': ('RailTel Corporation of India', 'RAILTEL.NS'),
    'RAJESHEXPO': ('Rajesh Exports', 'RAJESHEXPO.NS'),
    'RAMCOCEM': ('Ramco Cements', 'RAMCOCEM.NS'),
    'RATNAMANI': ('Ratnamani Metals and Tubes', 'RATNAMANI.NS'),
    'RBLBANK': ('RBL Bank', 'RBLBANK.NS'),
    'REDINGTON': ('Redington', 'REDINGTON.NS'),
    'RENUKA': ('Shree Renuka Sugars', 'RENUKA.NS'),
    'RHIM': ('RHI Magnesita India', 'RHIM.NS'),
    'RITES': ('RITES', 'RITES.NS'),
    'ROUTE': ('Route Mobile', 'ROUTE.NS'),
    'SAIL': ('Steel Authority of India', 'SAIL.NS'),
    'SANOFI': ('Sanofi India', 'SANOFI.NS'),
    'SAPPHIRE': ('Sapphire Foods India', 'SAPPHIRE.NS'),
    'SCHAEFFLER': ('Schaeffler India', 'SCHAEFFLER.NS'),
    'SCHNEIDER': ('Schneider Electric Infrastructure', 'SCHNEIDER.NS'),
    'SHYAMMETL': ('Shyam Metalics and Energy', 'SHYAMMETL.NS'),
    'SJVN': ('SJVN', 'SJVN.NS'),
    'SKFINDIA': ('SKF India', 'SKFINDIA.NS'),
    'SOBHA': ('Sobha', 'SOBHA.NS'),
    'SOLARINDS': ('Solar Industries India', 'SOLARINDS.NS'),
    'SONACOMS': ('Sona BLW Precision Forgings', 'SONACOMS.NS'),
    'SONATSOFTW': ('Sonata Software', 'SONATSOFTW.NS'),
    'STARHEALTH': ('Star Health and Allied Insurance', 'STARHEALTH.NS'),
    'SUNDARMFIN': ('Sundaram Finance', 'SUNDARMFIN.NS'),
    'SUNDRMFAST': ('Sundram Fasteners', 'SUNDRMFAST.NS'),
    'SUNTV': ('Sun TV Network', 'SUNTV.NS'),
    'SUPREMEIND': ('Supreme Industries', 'SUPREMEIND.NS'),
    'SUVENPHAR': ('Suven Pharmaceuticals', 'SUVENPHAR.NS'),
    'SUZLON': ('Suzlon Energy', 'SUZLON.NS'),
    'SWANENERGY': ('Swan Energy', 'SWANENERGY.NS'),
    'SYNGENE': ('Syngene International', 'SYNGENE.NS'),
    'TANLA': ('Tanla Platforms', 'TANLA.NS'),
    'TATACHEM': ('Tata Chemicals', 'TATACHEM.NS'),
    'TATACOMM': ('Tata Communications', 'TATACOMM.NS'),
    'TATAINVEST': ('Tata Investment Corporation', 'TATAINVEST.NS'),
    'TATASTEEL': ('Tata Steel', 'TATASTEEL.NS'),
    'TATATECH': ('Tata Technologies', 'TATATECH.NS'),
    'TITAGARH': ('Titagarh Rail Systems', 'TITAGARH.NS'),
    'TORNTPHARM': ('Torrent Pharmaceuticals', 'TORNTPHARM.NS'),
    'TORNTPOWER': ('Torrent Power', 'TORNTPOWER.NS'),
    'TRIDENT': ('Trident', 'TRIDENT.NS'),
    'TRITURBINE': ('Triveni Turbine', 'TRITURBINE.NS'),
    'TTKPRESTIG': ('TTK Prestige', 'TTKPRESTIG.NS'),
    'UCOBANK': ('UCO Bank', 'UCOBANK.NS'),
    'UJJIVANSFB': ('Ujjivan Small Finance Bank', 'UJJIVANSFB.NS'),
    'UNIONBANK': ('Union Bank of India', 'UNIONBANK.NS'),
    'UNITDSPR': ('United Spirits', 'UNITDSPR.NS'),
    'UTIAMC': ('UTI Asset Management Company', 'UTIAMC.NS'),
    'VARROC': ('Varroc Engineering', 'VARROC.NS'),
    'VIJAYA': ('Vijaya Diagnostic Centre', 'VIJAYA.NS'),
    'VINATIORGA': ('Vinati Organics', 'VINATIORGA.NS'),
    'WELSPUNLIV': ('Welspun Living', 'WELSPUNLIV.NS'),
    'WESTLIFE': ('Westlife Foodworld', 'WESTLIFE.NS'),
    'WHIRLPOOL': ('Whirlpool of India', 'WHIRLPOOL.NS'),
    'YESBANK': ('Yes Bank', 'YESBANK.NS'),
    'ZEEL': ('Zee Entertainment Enterprises', 'ZEEL.NS'),
    'ZENSARTECH': ('Zensar Technologies', 'ZENSARTECH.NS'),
    'ZYDUSLIFE': ('Zydus Lifesciences', 'ZYDUSLIFE.NS'),
}

ADDITIONAL_CRYPTOS = {
    'AAVE': ('Aave', 'AAVE-USD'),
    'ALGO': ('Algorand', 'ALGO-USD'),
    'APE': ('ApeCoin', 'APE-USD'),
    'APT': ('Aptos', 'APT-USD'),
    'ARB': ('Arbitrum', 'ARB-USD'),
    'AR': ('Arweave', 'AR-USD'),
    'AXS': ('Axie Infinity', 'AXS-USD'),
    'BCH': ('Bitcoin Cash', 'BCH-USD'),
    'BGB': ('Bitget Token', 'BGB-USD'),
    'BTT': ('BitTorrent', 'BTT-USD'),
    'CAKE': ('PancakeSwap', 'CAKE-USD'),
    'CHZ': ('Chiliz', 'CHZ-USD'),
    'COMP': ('Compound', 'COMP-USD'),
    'CRO': ('Cronos', 'CRO-USD'),
    'CRV': ('Curve DAO Token', 'CRV-USD'),
    'DAI': ('Dai', 'DAI-USD'),
    'DASH': ('Dash', 'DASH-USD'),
    'EGLD': ('MultiversX', 'EGLD-USD'),
    'ENA': ('Ethena', 'ENA-USD'),
    'ETC': ('Ethereum Classic', 'ETC-USD'),
    'FET': ('Artificial Superintelligence Alliance', 'FET-USD'),
    'FIL': ('Filecoin', 'FIL-USD'),
    'FLOW': ('Flow', 'FLOW-USD'),
    'FTM': ('Fantom', 'FTM-USD'),
    'GALA': ('Gala', 'GALA-USD'),
    'GRT': ('The Graph', 'GRT-USD'),
    'HBAR': ('Hedera', 'HBAR-USD'),
    'ICP': ('Internet Computer', 'ICP-USD'),
    'IMX': ('Immutable', 'IMX-USD'),
    'INJ': ('Injective', 'INJ-USD'),
    'JASMY': ('JasmyCoin', 'JASMY-USD'),
    'JUP': ('Jupiter', 'JUP-USD'),
    'KAS': ('Kaspa', 'KAS-USD'),
    'LDO': ('Lido DAO', 'LDO-USD'),
    'LEO': ('UNUS SED LEO', 'LEO-USD'),
    'MANA': ('Decentraland', 'MANA-USD'),
    'MKR': ('Maker', 'MKR-USD'),
    'NEAR': ('NEAR Protocol', 'NEAR-USD'),
    'OKB': ('OKB', 'OKB-USD'),
    'OP': ('Optimism', 'OP-USD'),
    'PEPE': ('Pepe', 'PEPE-USD'),
    'PYTH': ('Pyth Network', 'PYTH-USD'),
    'QNT': ('Quant', 'QNT-USD'),
    'RENDER': ('Render', 'RENDER-USD'),
    'RUNE': ('THORChain', 'RUNE-USD'),
    'SAND': ('The Sandbox', 'SAND-USD'),
    'SEI': ('Sei', 'SEI-USD'),
    'STX': ('Stacks', 'STX-USD'),
    'SUI': ('Sui', 'SUI-USD'),
    'TAO': ('Bittensor', 'TAO-USD'),
    'TIA': ('Celestia', 'TIA-USD'),
    'TON': ('Toncoin', 'TON-USD'),
    'TRX': ('TRON', 'TRX-USD'),
    'USDC': ('USD Coin', 'USDC-USD'),
    'USDT': ('Tether', 'USDT-USD'),
    'VET': ('VeChain', 'VET-USD'),
    'WIF': ('dogwifhat', 'WIF-USD'),
    'WLD': ('Worldcoin', 'WLD-USD'),
    'XLM': ('Stellar', 'XLM-USD'),
    'XMR': ('Monero', 'XMR-USD'),
    'XTZ': ('Tezos', 'XTZ-USD'),
    'ZEC': ('Zcash', 'ZEC-USD'),
}

STOCKS['india']['equity'].update(ADDITIONAL_INDIAN_EQUITIES)
STOCKS['crypto']['all'].update(ADDITIONAL_CRYPTOS)

# Exchange label mapping for search results
MARKET_EXCHANGE_LABELS = {
    'india': {'equity': 'NSE', 'commodity': 'NSE-COMM', 'bonds': 'NSE-BOND'},
    'usa': {'equity': 'NYSE/NASDAQ', 'commodity': 'NYSEARCA/ETF', 'bonds': 'NYSEARCA/BOND'},
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
        'usa': ['equity', 'commodity', 'bonds'],
        'crypto': ['all'],
    }


def get_symbol_metadata(symbol):
    """
    Resolve a watchlist symbol to its configured market/category metadata.

    Args:
        symbol: Yahoo Finance symbol stored in the watchlist

    Returns:
        Dict with symbol, display_symbol, name, market, category, exchange.
        Falls back to a best-effort market guess if the symbol is not in STOCKS.
    """
    for market, market_data in STOCKS.items():
        for category, stock_dict in market_data.items():
            for _, (name, yahoo_symbol) in stock_dict.items():
                if yahoo_symbol == symbol:
                    return {
                        'symbol': symbol,
                        'display_symbol': symbol.replace('.NS', '').replace('.BO', ''),
                        'name': name,
                        'market': market,
                        'category': category,
                        'exchange': MARKET_EXCHANGE_LABELS.get(market, {}).get(category, market.upper())
                    }

    if symbol.endswith('.NS') or symbol.endswith('.BO'):
        fallback_market = 'india'
    elif symbol.endswith('-USD'):
        fallback_market = 'crypto'
    else:
        fallback_market = 'usa'

    fallback_category = 'all' if fallback_market == 'crypto' else 'equity'
    return {
        'symbol': symbol,
        'display_symbol': symbol.replace('.NS', '').replace('.BO', ''),
        'name': symbol,
        'market': fallback_market,
        'category': fallback_category,
        'exchange': MARKET_EXCHANGE_LABELS.get(fallback_market, {}).get(fallback_category, fallback_market.upper())
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
        
        price = convert_price_to_usd(symbol, stock_data['Close'].iloc[-1])
        
        # Cache the result
        price_cache.set(cache_key, price, ttl=PRICE_CACHE_TTL)
        
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
                period = '3d' if symbol in INDEX_SYMBOLS else '2d'
                hist = ticker.history(period=period)
                
                if hist.empty or len(hist) == 0:
                    logger.warning(f"No data returned for {symbol}")
                    prices[symbol] = INDEX_FALLBACK_PRICES.get(
                        symbol,
                        {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}
                    )
                    continue
                
                # Get the latest close price
                current_price = hist['Close'].iloc[-1]
                
                # Check for NaN values
                if pd.isna(current_price):
                    logger.warning(f"NaN price for {symbol}")
                    prices[symbol] = INDEX_FALLBACK_PRICES.get(
                        symbol,
                        {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}
                    )
                    continue
                
                current_price = convert_price_to_usd(symbol, current_price)
                
                # Calculate change if we have at least 2 rows
                if len(hist) >= 2:
                    prev_close = hist['Close'].iloc[-2]
                    
                    if pd.isna(prev_close):
                        # If previous close is NaN, use current price
                        change = 0.0
                        change_percent = 0.0
                    else:
                        prev_close = convert_price_to_usd(symbol, prev_close)
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
                cache_ttl = INDEX_CACHE_TTL if symbol in INDEX_SYMBOLS else PRICE_CACHE_TTL
                price_cache.set(cache_key, price_data, ttl=cache_ttl)
                
            except Exception as e:
                logger.error(f"Error fetching price for {symbol}: {e}", exc_info=True)
                prices[symbol] = INDEX_FALLBACK_PRICES.get(
                    symbol,
                    {'price': 'N/A', 'change': 'N/A', 'change_percent': 'N/A'}
                )
        
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
