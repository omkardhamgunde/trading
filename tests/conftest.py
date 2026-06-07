import pytest

from app import app as flask_app
from routes.auth import auth_bp
from routes.holdings import holdings_bp
from routes.trading import trading_bp
from routes.wallet import wallet_bp
from routes.watchlist import watchlist_bp
from utils.cache import api_cache, price_cache


class QueueCursor:
    """Small DB cursor fake for route and service unit tests."""

    def __init__(self, fetchone_results=None, fetchall_results=None, lastrowid=1):
        self.fetchone_results = list(fetchone_results or [])
        self.fetchall_results = list(fetchall_results or [])
        self.lastrowid = lastrowid
        self.queries = []
        self.closed = False

    def execute(self, query, params=None):
        normalized_query = " ".join(query.split())
        self.queries.append((normalized_query, params))
        return 1

    def fetchone(self):
        if self.fetchone_results:
            return self.fetchone_results.pop(0)
        return None

    def fetchall(self):
        if self.fetchall_results:
            return self.fetchall_results.pop(0)
        return []

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_obj = cursor
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class FakeMySQL:
    def __init__(self, cursor):
        self.connection = FakeConnection(cursor)


@pytest.fixture(autouse=True)
def app_test_config():
    flask_app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=False,
    )
    price_cache.clear()
    api_cache.clear()
    yield
    price_cache.clear()
    api_cache.clear()


@pytest.fixture
def app():
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def fake_db():
    def _build(cursor):
        return FakeMySQL(cursor)

    return _build


@pytest.fixture
def set_mysql():
    def _set(mysql):
        auth_bp.mysql = mysql
        wallet_bp.mysql = mysql
        watchlist_bp.mysql = mysql
        trading_bp.mysql = mysql
        holdings_bp.mysql = mysql
        flask_app.blueprints["health"].mysql = mysql

    return _set


def login_as(client, user_id=1):
    with client.session_transaction() as session:
        session["user_id"] = user_id
