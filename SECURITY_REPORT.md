# 🛡️ Application Security & Architecture Report

This document outlines the enterprise-level security mechanisms implemented in the Trading & Portfolio Analysis Platform to ensure data integrity, user privacy, and defense against common web vulnerabilities.

## 1. Authentication & Identity Management

### Cryptographic Password Hashing
We have eradicated all plain-text passwords from the backend database schema. The application uses `werkzeug.security` to automatically generate heavily salted `pbkdf2:sha256` cryptographic hashes for all local user credentials. Even if the database is exposed, attacker decryption via rainbow tables or brute force is mathematically unfeasible.

### Delegated Authentication (OAuth 2.0)
To reduce the risk of credential theft, we implemented **Google OAuth 2.0** Single Sign-On (SSO). This allows users to rely on Google's world-class infrastructural security and multi-factor authentication rather than storing passwords locally on our servers.

## 2. Attack Vector Defenses

### Anti-Brute Force & Rate Limiting
To prevent automated scripts or dictionary attacks against the local authentication system, the `/login` endpoint is wrapped with an aggressive `Flask-Limiter` directive.
- **Rule:** A maximum of 5 requests per minute are allowed per IP Address.
- **Response:** If the limit is exceeded, the server automatically drops the request, locking the IP, and serves a structured `429 Too Many Requests - Brute Force Blocked` security page.

### SQL Injection (SQLi) Prevention
The platform interacts with the MySQL database purely through **Parameterized Queries** (Prepared Statements). By using formatting techniques like `cursor.execute("SELECT * FROM users WHERE username = %s", (username,))`, the database driver natively sanitizes all user inputs. It is immune to malicious SQL payload injections like `' OR 1=1 --`.

## 3. Session & Data Security

### Secure Cookie Configuration
Session cookies are hardened against hijacking and client-side access:
- **HttpOnly:** True (Prevents Cross-Site Scripting (XSS) scripts from reading the session cookie via `document.cookie`).
- **Secure:** Enforced to ensure cookies are only transmitted over strongly encrypted HTTPS protocols in production.
- **SameSite:** Configured to mitigate Cross-Site Request Forgery (CSRF) by preventing the browser from sending the cookie with cross-site requests.

### Session Inactivity Auto-Logout
To protect users who might step away from shared or public computers, the application enforces a strict idle timeout:
- **Frontend Tracking:** JavaScript event listeners actively monitor mouse movement, scrolling, and keypresses. If zero interaction occurs for exactly 5 minutes (300,000ms), the client is forcefully purged from the dashboard and redirected to the `/logout` endpoint.
- **Backend Expiration:** The core `PERMANENT_SESSION_LIFETIME` is reduced to 15 minutes, ensuring that even if the client bypasses the frontend JS, the server automatically invalidates the session token entirely.

## 4. Financial Transaction Safety

### Atomic Database Transactions (ACID Properties)
Because this is a financial platform managing a simulated wallet, preventing race conditions or "Double Spending" attacks is critical. When a user requests to Buy or Sell a stock:
1. We lock the state and verify wallet balance.
2. We write the transaction to the trade log.
3. We update the wallet balance.
4. If **any** mathematical error or exception occurs mid-process, the entire database action triggers a `rollback()`, ensuring users cannot exploit lag to gain infinite money.

### Thread-Safe Concurrent Caching
To optimize the `yfinance` API limit without causing data corruption during concurrent user loads, we implemented a custom, highly secure **Thread-Safe LRU Cache**. It utilizes Python `threading.Lock()` mutexes to ensure that when hundreds of real-time WebSocket connection attempt to read/write cached stock prices simultaneously, race conditions do not crash the server or serve mismatched asset prices.
