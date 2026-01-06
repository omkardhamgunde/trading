# Trading Dashboard (Flask + MySQL)

Beautiful, production-minded trading dashboard that showcases full‑stack skills: authentication (email + Google OAuth), watchlists, simulated equity trading, live holdings P/L using Yahoo Finance, and modern UI with Tailwind CSS.

<p align="center">
  <img src="https://img.shields.io/badge/Flask-2.x-000?logo=flask&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/MySQL-8.x-4479A1?logo=mysql&logoColor=white" />
  <img src="https://img.shields.io/badge/TailwindCSS-3.x-06B6D4?logo=tailwindcss&logoColor=white" />
  <img src="https://img.shields.io/badge/yfinance-latest-green" />
</p>

> Built for learning, demoing, and interviewing: clear architecture, secure patterns, intelligent stock search, and thoughtful UX. Easy to run locally on Windows/macOS/Linux.

## Dashboard Preview
> A modern, dark-themed trading dashboard with real-time price tracking, intelligent stock search, and portfolio management.

## Table of Contents
- [Features](#features)
- [Dashboard Preview](#dashboard-preview)
- [Architecture](#architecture)
- [Local Setup](#local-setup)
- [Key Routes](#key-routes)
- [Database Schema](#database-schema)
- [How to Use](#how-to-use)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [License](#license)


## Features

### 🔐 Authentication
- **Email/Password Login** via `WTForms` with secure validation
- **Google OAuth 2.0** integration with CSRF-safe state management
- Session-based authentication with secure cookie handling

### 📊 Portfolio Management
- **Holdings View** with real-time data:
  - Average buy price tracking
  - Current market price via `yfinance`
  - Profit/Loss calculation (absolute & percentage)
  - Total portfolio value and performance
- **Trade Log** with complete transaction history
- Protection against accidental data loss (holdings must be exited before clearing logs)

### 👀 Smart Watchlist
- Add/remove stock tickers with intuitive UI
- **Intelligent Stock Search** with autocomplete:
  - Search by company name (e.g., "Reliance", "HDFC Bank")
  - Automatic Yahoo Finance symbol lookup
  - Works for both Indian (.NS, .BO) and US stocks
- Real-time price updates with change indicators
- Live index tracking (Nifty, Sensex, Nasdaq, Dow Jones)

### 💰 Trading Simulator
- **Quick Trade** feature for fast buy/sell execution
- Market order simulation with real-time pricing
- Wallet balance management with add funds feature
- Trade validation (sufficient balance, positive quantities)
- Complete audit trail of all transactions

### 🎨 Modern UI
- Clean, dark-themed interface with Tailwind CSS
- Responsive design for desktop and mobile
- Real-time price change indicators (green/red)
- Smooth transitions and hover effects
- Professional dashboard layout


## Architecture

### Project Structure
```
trading-main/
├── app.py                      # Main Flask application with all routes
├── templates/
│   ├── base.html              # Base template with navigation
│   ├── home.html              # Landing page
│   ├── login.html             # Login page (email/password + Google OAuth)
│   ├── watchlist.html         # Watchlist with stock search & quick trade
│   ├── holdings.html          # Portfolio holdings with P/L
│   ├── trade_log.html         # Transaction history
│   └── wallet.html            # Wallet balance management
├── .gitignore                  # Git ignore file
└── README.md                   # This file
```

### High-Level Flow
1. **Authentication**: User logs in via email/password or Google OAuth
2. **Stock Discovery**: Search stocks by company name with intelligent autocomplete
3. **Watchlist**: Add stocks to watchlist, view real-time prices and indices
4. **Trading**: Execute buy/sell orders with wallet balance validation
5. **Portfolio**: View holdings with live P/L calculations using `yfinance`
6. **Persistence**: All data stored in MySQL (users, watchlist, trades, wallet)

### Key Technologies
- **Backend**: Flask (Python) with session-based auth
- **Database**: MySQL with PyMySQL connector
- **Stock Data**: Yahoo Finance API via `yfinance` library
- **Frontend**: Jinja2 templates + Tailwind CSS + vanilla JavaScript
- **OAuth**: Google OAuth 2.0 with `google-auth-oauthlib`


## Local Setup

### Prerequisites
- Python 3.10 or higher
- MySQL 8.x
- pip (Python package manager)

### Installation Steps

1. **Clone the repository**
```bash
git clone https://github.com/omkardhamgunde/trading.git
cd trading
```

2. **Install Python dependencies**
```bash
pip install flask flask-pymysql flask-wtf wtforms yfinance google-auth google-auth-oauthlib requests
```

3. **Set up MySQL database**
```sql
CREATE DATABASE trading_db;
USE trading_db;
-- Run the SQL schema from "Database Schema" section above
```

4. **Configure MySQL connection in app.py**
```python
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'your_password'
app.config['MYSQL_DB'] = 'trading_db'
```

5. **Set up Google OAuth** (optional, for Google login)
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Add `http://localhost:5001/login/google/authorized` as authorized redirect URI
   - Update `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `app.py`

6. **Run the application**
```powershell
# PowerShell (Windows)
$env:OAUTHLIB_INSECURE_TRANSPORT="1"  # For local development only
python app.py
```

```bash
# Bash (Linux/Mac)
export OAUTHLIB_INSECURE_TRANSPORT=1  # For local development only
python app.py
```

7. **Access the app**
   - Open browser: http://localhost:5001
   - Create an account or login with Google
   - Start trading!


## Key Routes

### Public Routes
- `GET /` - Landing page with app overview
- `GET /login` - Login page (email/password or Google OAuth)
- `POST /login` - Process email/password authentication
- `GET /login/google` - Initiate Google OAuth flow
- `GET /login/google/authorized` - Google OAuth callback handler

### Protected Routes (require authentication)
- `GET /watchlist` - View watchlist with real-time prices and indices
- `POST /watchlist` - Add stock to watchlist
- `POST /remove_from_watchlist` - Remove stock from watchlist
- `GET /search_stocks` - API endpoint for stock search autocomplete
- `POST /trade` - Execute buy/sell trade (Quick Trade feature)
- `GET /holdings` - View portfolio holdings with P/L calculations
- `GET /trade_log` - View complete transaction history
- `POST /clear_trade_log` - Clear trade log (protected: prevents deletion if holdings exist)
- `GET /wallet` - View wallet balance
- `POST /add_funds` - Add funds to wallet
- `GET /logout` - End user session


 


## How to Use

### 1. Getting Started
- **Register**: Create an account with email/password or use Google OAuth
- **Add Funds**: Navigate to Wallet and add funds to start trading

### 2. Building Your Watchlist
- Go to **Watchlist** page
- Type company name in search box (e.g., "Reliance", "Apple", "Tesla")
- Select from autocomplete dropdown
- Stock is added with real-time price tracking

### 3. Trading Stocks
**Method 1: Quick Trade (from Watchlist)**
- In the watchlist page, use the "Quick Trade" form
- Search stock by company name (shows Yahoo symbol in brackets)
- Select "Buy" or "Sell"
- Enter quantity
- Click "Execute Trade"

**Method 2: Regular Trade**
- Enter stock symbol directly if you know it
- Specify action (Buy/Sell) and quantity
- System validates balance and executes trade

### 4. Monitoring Portfolio
- **Holdings**: View all your positions with:
  - Average buy price
  - Current market price
  - Profit/Loss ($ and %)
  - Total portfolio value
- **Trade Log**: Complete history of all transactions
  - Clear log only when no active holdings

### 5. Managing Wallet
- Add funds anytime from Wallet page
- Balance updates automatically after trades
- View current balance in Wallet section

## Security Notes
- ⚠️ **Never commit real secrets** - Use environment variables or secret stores
- 🔒 Set `SESSION_COOKIE_SECURE=True` behind HTTPS in production
- 🔐 Restrict Google OAuth credentials to correct redirect URI
- ✅ All user inputs are validated and sanitized
- 🛡️ Passwords are hashed using Werkzeug security
- 🔑 Sessions use secure cookie handling with HTTPONLY flag
- 💾 SQL queries use parameterized statements to prevent injection


## Database Schema

### Required Tables

```sql
-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Watchlist table
CREATE TABLE watchlist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    stock_symbol VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY unique_user_stock (user_id, stock_symbol)
);

-- Trade log table
CREATE TABLE trade_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    stock_symbol VARCHAR(50) NOT NULL,
    action VARCHAR(10) NOT NULL,  -- 'BUY' or 'SELL'
    quantity INT NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Wallet table
CREATE TABLE wallet (
    user_id INT PRIMARY KEY,
    balance DECIMAL(15, 2) DEFAULT 0.00,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## Roadmap

### Planned Features
- ⏱️ **Real-time price updates** via WebSocket connections
- 📄 **Pagination and filters** on trade logs
- 📊 **Advanced charts** for portfolio performance tracking
- 🔔 **Price alerts** for watchlist stocks
- 📱 **Mobile app** (React Native or Flutter)
- 🐳 **Docker containerization** (app + MySQL via docker-compose)
- ✅ **Unit & integration tests** (pytest)
- 🌐 **API endpoints** for third-party integrations
- 📈 **Portfolio analytics** (Sharpe ratio, max drawdown, etc.)


## License
MIT — feel free to use for learning and portfolio projects. Attribution appreciated.
