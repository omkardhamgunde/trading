# Design and Implementation of a Real-Time Trading Simulation and Portfolio Analytics Platform

## Abstract

This paper presents the design and implementation of a real-time trading simulation and portfolio analytics platform developed using Flask, MySQL, Flask-SocketIO, Jinja2 templates, and Yahoo Finance data through the `yfinance` library. The system is intended as an educational and demonstrative financial technology application where users can authenticate, maintain watchlists, search tradable instruments, execute simulated buy and sell orders, manage a virtual wallet, and monitor portfolio holdings with live profit and loss calculations. The platform supports Indian equities, U.S. equities, commodity-linked instruments, bonds, exchange-traded funds, and selected cryptocurrencies through mapped Yahoo Finance symbols. A WebSocket-based update engine pushes price and portfolio updates to connected clients, while an in-memory time-to-live cache reduces repeated external price requests and improves responsiveness.

The project addresses common problems in beginner trading platforms: static price displays, weak separation between route handling and business logic, limited instrument discovery, and incomplete portfolio feedback. Its architecture separates authentication, trading, watchlist management, wallet operations, holdings computation, stock search, caching, metrics, and WebSocket communication into dedicated modules. Security features include session-based authentication, password hashing, Google OAuth/OpenID Connect login, CSRF-aware Flask-WTF forms, rate limiting for login attempts, secure cookie options, and login-history tracking. Results show that the implemented platform provides a working simulation workflow from stock discovery to trade execution and portfolio visualization. The paper also discusses limitations, including reliance on external market-data availability, the educational nature of simulated trading, and the need for deeper production-grade testing before real financial use.

Keywords: Flask, trading simulator, portfolio analytics, WebSocket, MySQL, Yahoo Finance, ETF, OAuth, real-time dashboard.

## 1. Introduction

Digital trading platforms have changed how retail users interact with financial markets. A modern trading interface is expected to provide live prices, simple instrument discovery, quick order entry, portfolio summaries, historical records, and visual performance feedback. However, building such a platform is not only a frontend design problem. It requires coordination between authentication, database persistence, transaction consistency, market-data fetching, portfolio computation, caching, and real-time client updates.

The project discussed in this paper is a real-time trading simulation and portfolio analytics platform. It is not designed to execute real trades on an exchange. Instead, it simulates trading using live or near-live price data from Yahoo Finance through the `yfinance` Python library. This makes the platform suitable for learning, academic demonstration, portfolio projects, and interview discussion. Users can log in, add instruments to a watchlist, view live market index data, place buy or sell orders using a virtual wallet, and track holdings with calculated profit and loss.

The system is implemented with Flask as the web framework, MySQL as the relational database, Flask-SocketIO for real-time communication, and Jinja2 templates for server-rendered pages. The route layer is divided into blueprints for authentication, trading, holdings, wallet, watchlist, and health endpoints. Business logic is placed in services such as `stock_service`, `trade_service`, `holdings_service`, and `wallet_service`. This modular organization improves maintainability and follows the separation-of-concerns principle.

A key requirement of the project is that users should be able to trade different asset categories. The symbol mapping layer connects user-facing instrument names with Yahoo Finance ticker symbols. For example, Indian equities usually require the `.NS` suffix, U.S. equities use their exchange tickers directly, cryptocurrencies use pairs such as `BTC-USD`, and many ETFs use specific Yahoo symbols. Recent expansion of the platform added broader support for Equity, Commodity, and Bonds/ETFs categories, allowing both search and watchlist filtering by category.

The motivation for this project comes from the gap between simple CRUD-based web applications and real-world financial interfaces. A trading platform needs stateful user sessions, strict trade validation, consistent wallet updates, historical audit trails, dynamic portfolio calculations, and real-time user feedback. The project demonstrates these concepts in a manageable educational system.

The objectives of the project are:

1. To design a modular Flask-based trading simulation platform.
2. To integrate real-time price updates using WebSocket communication.
3. To implement simulated trading with wallet validation and transaction logging.
4. To compute holdings, average buy price, current value, and profit/loss from trade history.
5. To support multiple categories of financial instruments using Yahoo Finance symbol mapping.
6. To provide security features suitable for a web-based authenticated application.
7. To expose health, metrics, and performance data for observability.

## 2. Literature Review

The financial logic of the project is related to portfolio theory and market behavior. Markowitz introduced portfolio selection as a mean-variance problem, showing that investors should consider the relationship between risk and return across the whole portfolio rather than evaluating securities in isolation [1]. Although this project does not implement advanced optimization, it applies the same basic idea that portfolio-level metrics are more useful than isolated trade records. By calculating total portfolio value and profit/loss, the platform gives users a portfolio-level view.

Sharpe's capital asset pricing model connected expected return to systematic market risk [2]. The present system does not estimate beta or expected return, but its holdings page and market index display provide the foundation for later extensions such as benchmark comparison and risk-adjusted analytics. Fama's efficient market hypothesis explains the importance of timely information in financial markets [3]. This supports the project's real-time design goal: even in a simulated environment, delayed or stale price information reduces the realism of trading decisions.

From a software architecture perspective, Fielding's work on REST emphasized uniform interfaces, stateless request handling, and scalable network-based application design [4]. The platform uses traditional HTTP routes for login, watchlist management, trade submission, wallet updates, health checks, and metrics. These routes fit common REST-like patterns where each request triggers a specific server-side operation and returns either HTML or JSON.

However, REST alone is not sufficient for live price updates. The WebSocket protocol was standardized to support bidirectional communication over a persistent connection [5]. The project uses Flask-SocketIO and the Socket.IO client to maintain real-time communication between the browser and backend [11], [12]. This allows the server to push `price_update` and `holdings_update` events without requiring the browser to repeatedly reload the page.

Authentication and identity management are also important in web-based trading platforms. OAuth 2.0 provides a widely used authorization framework [6], and OpenID Connect adds an identity layer on top of OAuth 2.0 [7]. The project uses Google OAuth login in addition to username/password authentication. For password-based login, the project uses Werkzeug password hashing utilities, which provide secure password hash generation and verification [17]. Flask-WTF provides form validation and CSRF-aware forms [16].

Security guidance from NIST and OWASP supports the use of secure password handling, session protection, and careful authentication lifecycle design [8], [9]. In this project, session cookies are configured with `HTTPONLY` and `SAMESITE` behavior, and the login route is protected by rate limiting. A login history table records successful and failed login attempts for account activity review.

The backend storage layer uses MySQL. Relational databases remain appropriate for trading simulation because wallet updates and trade-log insertions must stay consistent. MySQL's transaction model and InnoDB ACID behavior support commit and rollback semantics [13], [14]. In this platform, a trade updates wallet balance and inserts a trade record in the same service operation, reducing the risk of inconsistent trading state.

For market-data integration, `yfinance` provides a Python interface to Yahoo Finance data [15]. This enables current and historical price fetching for equities, ETFs, indices, commodities, and cryptocurrencies where Yahoo symbols are available. Since repeated external API calls can be slow and unreliable, the project uses a time-to-live cache. Python's standard library logging and rotating file handlers support observability for application logs and errors [18].

Finally, the frontend visualization layer uses Chart.js for portfolio charts and ApexCharts for the market heatmap [19], [20]. These libraries allow financial data to be presented as charts rather than only tables, making the platform easier to scan and more suitable for a dashboard-style experience.

## 3. Methodology

### 3.1 Requirement Analysis

The project requirements were identified from common trading dashboard workflows. A user should be able to log in, search financial instruments, add symbols to a watchlist, view current prices, place simulated buy and sell orders, inspect trade history, add wallet funds, and monitor portfolio performance. The system should also provide basic security controls and enough modularity to support future expansion.

The functional requirements are:

1. User authentication through username/password and Google OAuth.
2. Session-based access control for protected pages.
3. Watchlist creation and deletion per user.
4. Instrument search by symbol or company/fund name.
5. Trading simulation with buy and sell actions.
6. Wallet balance validation before purchase.
7. Prevention of selling more shares than currently held.
8. Trade log persistence.
9. Holdings computation from historical trades.
10. Real-time price updates through WebSocket events.
11. ETF, commodity, bond, equity, and crypto symbol support.
12. Health and metrics endpoints.

Non-functional requirements include maintainability, modularity, responsiveness, reasonable security, and observability. The project is educational, so simplicity and clarity are prioritized over the complexity required by real brokerage systems.

### 3.2 Technology Selection

Flask was selected because it is lightweight, flexible, and suitable for modular web applications. Flask blueprints allow route groups to be separated by domain. MySQL was selected because the system needs relational consistency between users, wallets, watchlists, and trades. Flask-SocketIO was selected for real-time communication because financial dashboards benefit from server-pushed updates. The frontend uses Jinja2 templates, Tailwind/Bootstrap-style styling, vanilla JavaScript, Chart.js, ApexCharts, and the Socket.IO browser client.

The project uses `yfinance` for market data because it supports many Yahoo Finance symbols and is simple to integrate with Python. Google OAuth is implemented using Google authentication libraries and OAuth flow handling. Flask-WTF is used for login form validation and CSRF-related form behavior.

### 3.3 Modular Backend Design

The application starts in `app.py`, where configuration, logging, MySQL, Socket.IO, blueprints, and WebSocket handlers are initialized. The backend is divided into route modules:

- `routes/auth.py` handles login, logout, Google OAuth, and login history.
- `routes/watchlist.py` handles watchlist display, stock search, screener, deletion, and metadata for watchlist rows.
- `routes/trading.py` handles trade execution and trade-log display.
- `routes/holdings.py` renders calculated portfolio holdings.
- `routes/wallet.py` handles wallet display and fund deposits.
- `routes/health.py` exposes health, cache, metrics, and performance endpoints.

Business logic is separated into services:

- `services/stock_service.py` stores instrument mappings, search logic, symbol metadata, and price fetching.
- `services/trade_service.py` validates and executes simulated trades.
- `services/holdings_service.py` computes current holdings and profit/loss.
- `services/wallet_service.py` handles wallet balance and wallet transaction records.

This division avoids placing all behavior inside one large Flask file and makes each area easier to test or extend.

### 3.4 Data Collection and Symbol Mapping

The platform does not maintain its own live exchange feed. Instead, it maps user-facing instruments to Yahoo Finance symbols and retrieves price data through `yfinance`. Symbol mapping is essential because users may search for "Reliance", "Gold ETF", "Apple", or "Nasdaq ETF", while the price service needs exact Yahoo symbols such as `RELIANCE.NS`, `GOLDBEES.NS`, `AAPL`, or `MON100.NS`.

The `STOCKS` dictionary in `stock_service.py` organizes instruments by market and category. Supported markets include India, USA, and crypto. Supported categories include equity, commodity, bonds/ETFs, and crypto assets. The search function scans symbols and names, returns matching Yahoo symbols, and labels the exchange/category for the frontend. A metadata resolver maps a stored watchlist symbol back to its market and category so that the watchlist page can filter rows correctly.

### 3.5 Authentication and Session Methodology

The system supports two login paths. The first path uses username and password verification. Passwords are checked using Werkzeug's secure hash verification. The second path uses Google OAuth/OpenID Connect. During Google login, the application generates a state token, redirects the user to Google, validates the returned state, verifies the ID token, and creates or updates the local user record.

After successful login, the system stores `session['user_id']`. Protected routes check this session value and redirect unauthenticated users to the login page. The Flask session is configured with secure cookie properties such as `HTTPONLY` and `SAMESITE`. Login attempts are rate-limited to reduce brute-force risk, and login events are stored in a `login_history` table for security review.

### 3.6 Trading Simulation Methodology

The trade route receives form data containing the stock symbol, quantity, and action. The system first checks whether the user is authenticated. It then validates the trade:

1. The stock symbol is normalized to uppercase.
2. The quantity is converted to an integer.
3. For sell orders, the system calculates existing quantity from the trade log.
4. The current price is fetched from Yahoo Finance through `yfinance`.
5. For buy orders, the wallet balance is checked.
6. If validation passes, wallet balance is updated and the trade is inserted into `trade_log`.
7. The database transaction is committed on success and rolled back on failure.

This simulation treats market orders as immediate executions at the current fetched price. It does not implement order books, bid/ask spreads, slippage, brokerage fees, taxes, margin, settlement cycles, or exchange-level validations.

### 3.7 Portfolio Calculation Methodology

Holdings are computed dynamically from the trade log. For each buy transaction, the system increases quantity and total cost. For each sell transaction, the system reduces quantity and proportionally adjusts remaining cost. The average buy price is calculated as:

Average Buy Price = Total Cost / Current Quantity

The current value is calculated as:

Current Value = Current Market Price * Quantity

The absolute profit or loss is:

Profit/Loss = Current Value - Total Cost

The percentage profit or loss is:

Profit/Loss % = (Profit/Loss / Total Cost) * 100

This approach avoids storing a separate holdings table that could become inconsistent. The trade log acts as the source of truth.

### 3.8 Real-Time Update Methodology

The browser creates a Socket.IO connection when the watchlist or holdings page loads. It then emits either `subscribe_watchlist` or `subscribe_holdings` with the current user ID. The backend stores the Socket.IO session ID and the user's subscription type in an `active_connections` dictionary.

A background price updater runs repeatedly. For each connected user, it queries the user's watchlist and trade log, fetches prices through `stock_service`, and emits updates to subscribed sockets. Watchlist subscribers receive `price_update` events, while holdings subscribers receive `holdings_update` events. The update loop sleeps between iterations to avoid excessive API calls.

### 3.9 Caching and Metrics Methodology

The project uses an in-memory TTL cache. Price data is cached for a short duration so that repeated requests for the same symbol do not always call Yahoo Finance. This reduces latency and external dependency pressure while keeping prices reasonably fresh for a simulation platform.

Metrics are tracked in memory. The metrics tracker records total API calls, daily API calls, weekly API calls, average response time, uptime seconds, and cache statistics. The `/metrics` endpoint exposes this data as JSON. The `/health` endpoint provides a basic health response for monitoring.

### 3.10 Security Methodology

Security is addressed at several layers:

1. Password verification uses secure hashing rather than plain-text comparison for migrated users.
2. Google OAuth uses state validation to reduce CSRF risk in the OAuth flow.
3. Flask sessions store only the user ID and token-related session values.
4. Cookie settings include `HTTPONLY` and `SAMESITE`.
5. Login attempts are rate-limited.
6. Login history records IP address, user agent, status, and timestamp.
7. Database statements use parameterized SQL queries.
8. Trade execution uses commit/rollback behavior to maintain consistency.

The system is not positioned as production-ready financial infrastructure, but the security methodology demonstrates important web application practices.

## 4. Model Architecture

In this project, "model architecture" refers to the software and data-flow architecture rather than a machine learning model. The platform is built as a layered web application.

### 4.1 High-Level Architecture

The architecture can be represented as:

```text
Browser Client
    |
    | HTTP requests, HTML responses, JSON APIs
    | Socket.IO WebSocket events
    v
Flask Application
    |
    | Blueprints: auth, watchlist, trading, holdings, wallet, health
    v
Service Layer
    |
    | stock_service, trade_service, holdings_service, wallet_service
    v
MySQL Database + In-Memory TTL Cache + Metrics Tracker
    |
    v
Yahoo Finance Data via yfinance
```

The browser renders pages such as login, watchlist, holdings, wallet, trade log, screener, and security activity. HTTP routes handle traditional request-response operations, while Socket.IO handles real-time price and portfolio updates.

### 4.2 Route Layer

The route layer receives user input and coordinates service calls. It is intentionally thin. For example, the trading route checks authentication, reads form values, calls validation and execution functions from `trade_service`, flashes a result message, and redirects the user. This keeps business rules outside the route handler.

### 4.3 Service Layer

The service layer contains reusable business logic:

- Stock service: symbol mapping, search, metadata resolution, price fetching, and heatmap data.
- Trade service: trade validation, price lookup, wallet balance check, and trade execution.
- Holdings service: aggregation of historical trades into current positions.
- Wallet service: wallet balance and transaction retrieval.

This architecture makes future work easier. For example, if the market-data provider changes from Yahoo Finance to another provider, most changes would be concentrated in `stock_service.py`.

### 4.4 Data Model

The platform uses a relational database model. The main tables are:

- `users`: stores user identity, username, email, password hash, and optional Google ID.
- `wallet`: stores user balance.
- `watchlist`: stores selected symbols per user.
- `trade_log`: stores every buy and sell event.
- `wallet_transactions`: stores wallet deposit history.
- `login_history`: stores authentication activity.

The trade log is the most important table for portfolio computation. Instead of storing holdings as a mutable record, holdings are derived from the event history. This is similar to an event-sourced approach at a small scale.

### 4.5 Real-Time Communication Model

The WebSocket model has four steps:

1. Client connects to Socket.IO.
2. Client subscribes to watchlist or holdings updates.
3. Background task fetches symbols and prices.
4. Server emits updates to each subscribed client.

This model avoids full-page refreshes. It also supports multiple connected clients for the same user, because each socket session ID is tracked independently.

### 4.6 Instrument Classification Model

The instrument classification model maps each symbol to a market and category:

- Market: India, USA, or Crypto.
- Category: Equity, Commodity, Bonds/ETFs, or all crypto.
- Yahoo Symbol: exact symbol required by `yfinance`.
- Display Name: readable company, fund, or asset name.

This model powers both autocomplete and watchlist filtering. When a watchlist row is rendered, the backend attaches metadata such as `data-market="india"` and `data-category="bonds"`. The frontend filter buttons then hide or show rows based on those metadata attributes.

## 5. Results

The implemented platform demonstrates a complete simulated trading workflow. A user can log in, search instruments, add them to a watchlist, view current prices, place trades, and see updated holdings. The project supports multiple markets and instrument categories through Yahoo Finance symbol mapping. The latest expansion increased support for Indian and U.S. equities, commodity-linked instruments, and bond/ETF instruments.

### 5.1 Functional Results

The following functional outcomes were achieved:

| Requirement | Implemented Result |
| --- | --- |
| User login | Username/password login and Google OAuth login are supported. |
| Watchlist | Users can add and remove symbols from a personal watchlist. |
| Search | Users can search by ticker or instrument name. |
| Category support | Equity, Commodity, and Bonds/ETFs categories are mapped and searchable. |
| Watchlist filtering | Category buttons hide and show watchlist rows based on metadata. |
| Trading | Buy and sell actions are simulated using current fetched prices. |
| Wallet validation | Buy orders require sufficient wallet balance. |
| Sell validation | Sell orders require sufficient existing quantity. |
| Holdings | Current quantity, average price, current value, and P/L are calculated. |
| Trade history | All trades are recorded in the trade log. |
| Real-time updates | Watchlist and holdings pages receive WebSocket updates. |
| Visualization | Holdings charts and screener heatmap improve portfolio readability. |
| Observability | Health, metrics, logging, and cache statistics are available. |

### 5.2 Instrument Mapping Results

The platform now supports a broader instrument universe. Indian instruments include major equities, commodity-related companies, gold and silver ETFs, Nifty ETFs, bank ETFs, technology ETFs, and Bharat Bond/Gilt instruments. U.S. instruments include major equities, commodity ETFs, energy funds, agriculture funds, bond ETFs, Treasury ETFs, corporate bond ETFs, and high-yield bond ETFs. Crypto mappings include major coin pairs such as Bitcoin, Ethereum, Solana, XRP, Dogecoin, and others.

This mapping improves usability because the user no longer needs to know all Yahoo Finance ticker formats. A search for a recognizable company or ETF name can return the correct tradable symbol.

### 5.3 Portfolio Analytics Results

The holdings page provides a portfolio summary with total invested amount, current value, total return, number of assets, asset allocation chart, and profit/loss chart. Individual holdings display quantity, average buy price, current market price, total value, absolute profit/loss, and percentage profit/loss.

Because holdings are calculated from trade history, the system preserves an audit trail. This makes the portfolio view explainable: every current position is derived from previous buy and sell records.

### 5.4 Real-Time Dashboard Results

The WebSocket design allows updates to be pushed to the browser approximately every few seconds depending on the configured update interval. Price changes can update on the watchlist page without a full reload. The holdings page can also update current prices and profit/loss values dynamically.

This creates a more realistic trading-dashboard experience than a static page. It also demonstrates an important backend/frontend communication pattern: HTTP for user actions and WebSockets for live state updates.

### 5.5 Security and Reliability Results

The project includes several security improvements compared with a basic login form. Password verification uses secure hash checking for migrated users, Google OAuth validates state, login attempts are rate-limited, and session cookies are configured with safer options. Login history gives users a way to inspect account activity.

Reliability is improved by transactional trade execution. If a wallet update or trade-log insertion fails, the database operation can be rolled back. Caching improves resilience against repeated market-data requests.

### 5.6 Limitations of Results

The results are appropriate for an academic and demonstration project, but not for production brokerage use. The system depends on Yahoo Finance data availability through `yfinance`, which is not a guaranteed exchange-grade data feed. It does not model brokerage charges, taxes, bid/ask spreads, liquidity, settlement cycles, regulatory requirements, or real exchange order execution. Large-scale load testing, penetration testing, and database race-condition testing would be needed before production deployment.

## 6. Conclusions

This project successfully demonstrates a modular real-time trading simulation platform using Flask, MySQL, WebSockets, and Yahoo Finance data. It shows how a web application can combine traditional HTTP routes with live Socket.IO updates to provide an interactive financial dashboard. The system supports authentication, watchlist management, symbol search, simulated trading, wallet validation, trade history, portfolio analytics, category filtering, chart visualization, caching, metrics, and security logging.

The strongest architectural decision is the separation between route handlers and service modules. This keeps the codebase understandable and prepares it for future enhancements. Another important decision is deriving holdings from the trade log rather than storing a separate holdings table. This improves traceability and reduces the risk of inconsistency.

The project also demonstrates the practical importance of symbol mapping in financial applications. Users think in terms of company names, ETF names, and asset classes, while market-data systems require exact ticker syntax. The expanded mapping for Equity, Commodity, and Bonds/ETFs makes the platform more useful and closer to a real trading interface.

Future work can include advanced portfolio analytics, benchmark comparison, alerts, improved search ranking, paginated trade logs, database-level locking for concurrent trades, Redis-backed caching, Docker deployment, automated tests, and a more formal performance evaluation. A production version would also require certified market data, stronger identity management, audit controls, regulatory compliance, and integration with a licensed brokerage API.

Overall, the system provides a strong educational foundation for understanding full-stack financial technology development, real-time dashboard architecture, and secure transaction-oriented web applications.

## 7. Acknowledgement

I would like to express my sincere gratitude to my project guide, faculty members, and department for their guidance and support during the development of this project. I also acknowledge the open-source communities behind Flask, Flask-SocketIO, MySQL, Python, Chart.js, ApexCharts, and related libraries, whose documentation and tools made the implementation possible. Finally, I thank my peers and reviewers for their feedback during the design and testing of the trading simulation platform.

## 8. References

[1] Markowitz, H. M. (1952). Portfolio selection. The Journal of Finance, 7(1), 77-91. https://doi.org/10.1111/j.1540-6261.1952.tb01525.x

[2] Sharpe, W. F. (1964). Capital asset prices: A theory of market equilibrium under conditions of risk. The Journal of Finance, 19(3), 425-442. https://doi.org/10.1111/j.1540-6261.1964.tb02865.x

[3] Fama, E. F. (1970). Efficient capital markets: A review of theory and empirical work. The Journal of Finance, 25(2), 383-417. https://doi.org/10.2307/2325486

[4] Fielding, R. T. (2000). Architectural styles and the design of network-based software architectures. Doctoral dissertation, University of California, Irvine. https://ics.uci.edu/~fielding/pubs/dissertation/top.htm

[5] Fette, I., & Melnikov, A. (2011). The WebSocket Protocol. RFC 6455. Internet Engineering Task Force. https://datatracker.ietf.org/doc/html/rfc6455

[6] Hardt, D. (2012). The OAuth 2.0 Authorization Framework. RFC 6749. Internet Engineering Task Force. https://datatracker.ietf.org/doc/html/rfc6749

[7] OpenID Foundation. (2014). OpenID Connect Core 1.0. https://openid.net/specs/openid-connect-core-1_0-final.html

[8] National Institute of Standards and Technology. (2017). Digital Identity Guidelines: Authentication and Lifecycle Management, NIST SP 800-63B. https://doi.org/10.6028/NIST.SP.800-63b

[9] OWASP Foundation. (2026). Session Management Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

[10] Pallets Projects. (2026). Flask Documentation. https://flask.palletsprojects.com/

[11] Grinberg, M. (2026). Flask-SocketIO Documentation. https://flask-socketio.readthedocs.io/

[12] Socket.IO. (2026). Socket.IO Documentation. https://socket.io/docs/v4/

[13] Oracle. (2026). MySQL Reference Manual: InnoDB and the ACID Model. https://dev.mysql.com/doc/mysql/en/mysql-acid.html

[14] Oracle. (2026). MySQL 8.0 Reference Manual: START TRANSACTION, COMMIT, and ROLLBACK Statements. https://dev.mysql.com/doc/refman/8.0/en/commit.html

[15] yfinance Developers. (2026). yfinance Documentation. https://yfinance.readthedocs.io/en/documentation/

[16] Flask-WTF Developers. (2026). CSRF Protection - Flask-WTF Documentation. https://flask-wtf.readthedocs.io/en/latest/csrf/

[17] Pallets Projects. (2026). Werkzeug Security Helpers. https://werkzeug.palletsprojects.com/en/stable/utils/

[18] Python Software Foundation. (2026). logging.handlers - Logging handlers. Python Documentation. https://docs.python.org/3/library/logging.handlers.html

[19] Chart.js Contributors. (2026). Chart.js Documentation. https://www.chartjs.org/docs/latest/

[20] ApexCharts. (2026). ApexCharts Documentation. https://apexcharts.com/docs/
