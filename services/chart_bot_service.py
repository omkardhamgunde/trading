"""
Simple chart-bot analysis for educational trade ideas.
"""
import logging

import pandas as pd
import yfinance as yf

from services.stock_service import MARKET_EXCHANGE_LABELS, STOCKS
from utils.cache import api_cache
from utils.currency import convert_price_to_usd

logger = logging.getLogger(__name__)


def _calculate_rsi(close_prices, period=14):
    """Calculate RSI from a pandas Series of closing prices."""
    delta = close_prices.diff()
    gains = delta.clip(lower=0)
    losses = -delta.clip(upper=0)

    avg_gain = gains.rolling(window=period).mean()
    avg_loss = losses.rolling(window=period).mean()
    relative_strength = avg_gain / avg_loss.replace(0, pd.NA)
    rsi = 100 - (100 / (1 + relative_strength))

    latest = rsi.dropna()
    if latest.empty:
        return None
    return float(latest.iloc[-1])


def _get_candidates(market, category, limit):
    candidates = []
    market_data = STOCKS.get(market, {})

    categories = [category] if category and category in market_data else list(market_data.keys())
    for cat in categories:
        for key, (name, yahoo_symbol) in market_data.get(cat, {}).items():
            exchange = MARKET_EXCHANGE_LABELS.get(market, {}).get(cat, market.upper())
            candidates.append({
                'key': key,
                'name': name,
                'symbol': yahoo_symbol,
                'market': market,
                'category': cat,
                'exchange': exchange,
            })
            if len(candidates) >= limit:
                return candidates

    return candidates


def _score_candidate(candidate):
    cache_key = f"chart_bot_{candidate['symbol']}"
    cached = api_cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        history = yf.Ticker(candidate['symbol']).history(period='6mo', interval='1d')
        if history.empty or len(history) < 55:
            return None

        close = history['Close'].dropna().astype(float)
        if len(close) < 55:
            return None

        close = close.apply(lambda price: convert_price_to_usd(candidate['symbol'], price))

        current_price = float(close.iloc[-1])
        previous_price = float(close.iloc[-2])
        sma20 = float(close.rolling(window=20).mean().iloc[-1])
        sma50 = float(close.rolling(window=50).mean().iloc[-1])
        rsi = _calculate_rsi(close)
        return_30d = ((current_price / float(close.iloc[-22])) - 1) * 100 if len(close) >= 22 else 0
        day_change = ((current_price / previous_price) - 1) * 100 if previous_price else 0
        volatility = float(close.pct_change().tail(20).std() * 100)

        score = 0
        reasons = []

        if current_price > sma20:
            score += 2
            reasons.append('Price above 20-day average')
        else:
            reasons.append('Price below 20-day average')

        if sma20 > sma50:
            score += 2
            reasons.append('20-day average above 50-day average')
        else:
            reasons.append('Short trend weaker than 50-day average')

        if return_30d > 3:
            score += 2
            reasons.append('Positive 30-day momentum')
        elif return_30d > 0:
            score += 1
            reasons.append('Mild 30-day momentum')
        else:
            reasons.append('Negative 30-day momentum')

        if rsi is not None:
            if 45 <= rsi <= 65:
                score += 2
                reasons.append('RSI in healthy range')
            elif 35 <= rsi < 45 or 65 < rsi <= 75:
                score += 1
                reasons.append('RSI acceptable but watch closely')
            elif rsi > 75:
                score -= 1
                reasons.append('RSI looks overbought')
            else:
                reasons.append('RSI is weak')

        if day_change > 0:
            score += 1
            reasons.append('Today is positive')

        if volatility < 4:
            score += 1
            reasons.append('Recent volatility is controlled')
        elif volatility > 8:
            score -= 1
            reasons.append('Recent volatility is high')

        if score >= 7:
            recommendation = 'Buy Signal'
            strength = 'strong'
        elif score >= 5:
            recommendation = 'Watch to Buy'
            strength = 'good'
        elif score >= 3:
            recommendation = 'Neutral'
            strength = 'neutral'
        else:
            recommendation = 'Avoid'
            strength = 'weak'

        result = {
            **candidate,
            'score': score,
            'recommendation': recommendation,
            'strength': strength,
            'current_price': round(current_price, 2),
            'day_change': round(day_change, 2),
            'return_30d': round(return_30d, 2),
            'sma20': round(sma20, 2),
            'sma50': round(sma50, 2),
            'rsi': round(rsi, 2) if rsi is not None else None,
            'volatility': round(volatility, 2),
            'reasons': reasons[:4],
        }
        api_cache.set(cache_key, result, ttl=300)
        return result
    except Exception as exc:
        logger.warning("Chart bot could not analyze %s: %s", candidate['symbol'], exc)
        return None


def get_chart_bot_recommendations(market='india', category='equity', scan_limit=25):
    """
    Rank mapped instruments using simple technical-analysis rules.
    This is for simulator education, not financial advice.
    """
    market = market if market in STOCKS else 'india'
    market_categories = STOCKS.get(market, {})
    category = category if category in market_categories else next(iter(market_categories), 'equity')
    scan_limit = max(5, min(int(scan_limit or 25), 60))

    analyzed = []
    for candidate in _get_candidates(market, category, scan_limit):
        result = _score_candidate(candidate)
        if result:
            analyzed.append(result)

    ranked = sorted(
        analyzed,
        key=lambda item: (item['score'], item['return_30d'], -item['volatility']),
        reverse=True
    )

    return {
        'market': market,
        'category': category,
        'scan_limit': scan_limit,
        'available_categories': list(market_categories.keys()),
        'recommendations': ranked[:10],
        'analyzed_count': len(analyzed),
    }
