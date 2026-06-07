import pandas as pd

from services import stock_service
from services.stock_service import get_stock_prices, search_stocks
from tests.conftest import QueueCursor, login_as


def test_watchlist_adds_uppercase_symbol_for_logged_in_user(client, fake_db, set_mysql):
    cursor = QueueCursor(fetchone_results=[None])
    mysql = fake_db(cursor)
    set_mysql(mysql)
    login_as(client, user_id=12)

    response = client.post("/watchlist", data={"stock_symbol": "reliance.ns"})

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/watchlist")
    assert mysql.connection.commits == 1

    insert_query = next(query for query in cursor.queries if "INSERT INTO watchlist" in query[0])
    assert insert_query[1] == (12, "RELIANCE.NS")


def test_watchlist_does_not_insert_duplicate_symbol(client, fake_db, set_mysql):
    cursor = QueueCursor(fetchone_results=[(1, 12, "AAPL")])
    mysql = fake_db(cursor)
    set_mysql(mysql)
    login_as(client, user_id=12)

    response = client.post("/watchlist", data={"stock_symbol": "AAPL"})

    assert response.status_code == 302
    assert not any("INSERT INTO watchlist" in query for query, _ in cursor.queries)
    assert mysql.connection.commits == 0


def test_search_stocks_filters_indian_equities():
    results = search_stocks("reliance", market="india", category="equity")

    assert results
    assert results[0]["symbol"] == "RELIANCE.NS"
    assert results[0]["market"] == "india"
    assert results[0]["category"] == "equity"


def test_search_endpoint_returns_json(client):
    response = client.get("/search_stocks?q=bitcoin&market=crypto")

    assert response.status_code == 200
    assert any(item["symbol"] == "BTC-USD" for item in response.get_json())


def test_get_stock_prices_uses_cache_after_first_fetch(monkeypatch):
    class FakeTicker:
        calls = 0

        def __init__(self, symbol):
            self.symbol = symbol

        def history(self, period):
            FakeTicker.calls += 1
            return pd.DataFrame({"Close": [100.0, 110.0]})

    monkeypatch.setattr(stock_service.yf, "Ticker", FakeTicker)

    first = get_stock_prices(["AAPL"])
    second = get_stock_prices(["AAPL"])

    assert FakeTicker.calls == 1
    assert first["AAPL"] == {"price": 110.0, "change": 10.0, "change_percent": 10.0}
    assert second == first
