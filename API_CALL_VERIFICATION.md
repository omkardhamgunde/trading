# API Call Reduction Baseline

This document gives the baseline behind the resume claim about reduced external market-data calls.

## Baseline

Old/unoptimized model:

- Each connected client polls market data every 10 seconds.
- Each symbol request can call Yahoo Finance through `yfinance`.
- No shared server-side cache.

Formula:

```text
baseline_daily_calls = (86400 / 10) * users * symbols_per_user
baseline_daily_calls = 8640 * users * symbols_per_user
```

## Current Design

Current optimized model:

- WebSocket refresh interval: 20 seconds.
- Price cache TTL: 20 seconds.
- Cache type: thread-safe TTL/LRU cache in `utils/cache.py`.
- Cache scope: shared inside the app process, so repeated users/sessions can reuse the same symbol price within the TTL.

Formula:

```text
current_daily_calls = (86400 / 20) * unique_symbols_requested
current_daily_calls = 4320 * unique_symbols_requested
```

## Conservative Scenarios

### Scenario 1: Single user, continuous dashboard

Assume 1 user watches 12 symbols.

```text
baseline = 8640 * 1 * 12 = 103,680 calls/day
current  = 4320 * 12 = 51,840 calls/day
reduction = 50.0%
```

This is the minimum benefit from moving from 10-second polling to 20-second server refresh.

### Scenario 2: Five users, mostly unique watchlists, shared indices

Assume 5 users, each with 8 unique stocks plus the same 4 market indices.

```text
baseline symbols per user = 8 + 4 = 12
baseline = 8640 * 5 * 12 = 518,400 calls/day

unique current symbols = 40 unique stocks + 4 shared indices = 44
current = 4320 * 44 = 190,080 calls/day

reduction = (518400 - 190080) / 518400 = 63.3%
```

This is a realistic resume baseline because every dashboard shares index symbols.

### Scenario 3: Five users watching the same symbols

Assume 5 users watch the same 12 symbols.

```text
baseline = 8640 * 5 * 12 = 518,400 calls/day
current  = 4320 * 12 = 51,840 calls/day
reduction = 90.0%
```

This is the best-case benefit of shared server-side caching.

## Recommended Resume Claim

Use a range and include the baseline:

```text
Optimized yfinance polling with thread-safe TTL/LRU caching,
cutting external calls by 50-75% versus 10-second uncached
per-client polling.
```

This is safer than a vague "60% reduced API calls" claim because the baseline is explicit and the range covers both one-user and multi-user cases.

## How To Verify In The App

Run the app and open:

```text
/metrics
```

Important fields:

- `cache.price_cache.hits`
- `cache.price_cache.misses`
- `cache.price_cache.hit_rate_percent`
- `metrics.total_api_calls`
- `metrics.average_response_time_ms`

Run the unit tests:

```bash
python -m pytest -q
```

The test suite includes a cache test proving a repeated symbol request uses the cache instead of making a second `yfinance` fetch.
