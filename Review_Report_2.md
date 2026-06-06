# Progress Review Report 2

Group No.: TY-C16  
Review No.: 2  
Review Schedule: End of Semester  
Date: 23/05/2026  

## Progress Review Report

After Review 1, the Trading and Portfolio Analysis Platform has progressed from a core real-time trading simulator into a more complete multi-category portfolio dashboard. The first review suggestions were addressed by expanding the instrument universe beyond regular equities. The platform now supports organized categories such as Equity, Commodity, and Bonds/ETFs, with mapped Yahoo Finance symbols for Indian and U.S. markets. The watchlist page has been upgraded with category filters so that users can separately view equity stocks, commodity-linked instruments, and ETF/bond instruments. The stock search feature also uses the same market and category logic, allowing users to find instruments by readable company or ETF names instead of manually remembering Yahoo Finance ticker formats.

In addition to category expansion, a new Chart Bot page has been introduced as an educational decision-support module. The Chart Bot scans mapped instruments and applies simple technical-analysis rules such as 20-day moving average, 50-day moving average, RSI, 30-day momentum, daily change, and volatility. Based on these indicators, it gives simulator-focused signals such as Buy Signal, Watch to Buy, Neutral, and Avoid. This feature improves the analytical value of the project by showing how chart-based rules can assist simulated trade selection while clearly remaining separate from real financial advice.

The project has also improved its accuracy and consistency in handling Indian market prices. Since Yahoo Finance returns Indian NSE/BSE stock prices in rupees while the virtual wallet is displayed in dollars, Indian stock prices are now converted to dollar value by dividing the rupee price by 96. This conversion is applied consistently in the watchlist, trading engine, holdings calculation, and Chart Bot price display. As a result, wallet deductions, portfolio values, and profit/loss calculations remain consistent with the dollar-based simulator interface.

Further improvements were made in the security and usability areas. The application includes session-based route protection, Google OAuth authentication, password hashing support, login rate limiting, login-history tracking, secure session cookie configuration, and an inactivity warning before session expiry. The frontend now provides a more complete dashboard experience with watchlist filtering, portfolio analytics charts, market heatmap visualization, wallet management, trade logs, security activity view, and real-time WebSocket updates.

Overall, by the end of the semester, the project has achieved the main objectives of a full-stack trading simulation platform: secure login, instrument discovery, simulated trade execution, wallet validation, real-time market updates, portfolio profit/loss calculation, category-based filtering, and basic chart-based stock suggestions. The system is suitable for academic demonstration and can be further extended toward more advanced analytics and deployment readiness.

## Further Steps

1. Add an Options and Futures simulation module with separate validation rules and risk warnings.
2. Improve the Chart Bot by adding backtesting, confidence score, stop-loss suggestion, and target-price logic.
3. Add price alerts so users can receive notifications when watchlist symbols cross selected levels.
4. Add pagination, sorting, and filtering to the trade log for users with large transaction history.
5. Add automated unit and integration tests for authentication, trading, wallet, holdings, and stock-search services.
6. Improve deployment readiness using Docker, Gunicorn/gevent workers, production environment variables, and a stable database setup.
7. Replace in-memory cache with Redis for multi-worker deployment and better persistence of cached market data.
8. Add a currency mode so users can choose whether Indian instruments should be displayed in INR or converted to USD.
9. Add advanced portfolio analytics such as sector allocation, benchmark comparison, Sharpe ratio, and drawdown.
10. Improve documentation with setup instructions, database schema updates, screenshots, and final user manual.

## Suggestions

1. The project should next focus on testing and deployment so that all implemented features can be demonstrated reliably.
2. The Chart Bot should be clearly labelled as an educational simulator feature and not as real investment advice.
3. Options and Futures can be added as future modules after the current Equity, Commodity, and Bonds/ETFs workflow is fully stable.
4. Screenshots of Login, Watchlist, Quick Trade, Holdings, Screener, and Chart Bot pages should be added to the final report and presentation.

Signature of Guide:
