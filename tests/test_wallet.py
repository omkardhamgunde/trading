from datetime import datetime

from services.wallet_service import add_funds, get_wallet_balance, get_wallet_transactions
from tests.conftest import QueueCursor


def test_get_wallet_balance_returns_existing_balance(fake_db):
    cursor = QueueCursor(fetchone_results=[("12345.67",)])
    mysql = fake_db(cursor)

    assert get_wallet_balance(mysql, user_id=5) == 12345.67


def test_get_wallet_balance_returns_zero_when_wallet_missing(fake_db):
    cursor = QueueCursor(fetchone_results=[None])
    mysql = fake_db(cursor)

    assert get_wallet_balance(mysql, user_id=5) == 0.0


def test_add_funds_rejects_non_positive_amount(fake_db):
    cursor = QueueCursor()
    mysql = fake_db(cursor)

    success, error = add_funds(mysql, user_id=5, amount=0)

    assert success is False
    assert error == "Please enter a positive amount."
    assert cursor.queries == []
    assert mysql.connection.commits == 0


def test_add_funds_updates_balance_records_transaction_and_commits(fake_db):
    cursor = QueueCursor()
    mysql = fake_db(cursor)

    success, error = add_funds(mysql, user_id=5, amount=2500)

    assert success is True
    assert error is None
    assert mysql.connection.commits == 1
    assert any("UPDATE wallet SET balance = balance + %s" in query for query, _ in cursor.queries)
    assert any("INSERT INTO wallet_transactions" in query for query, _ in cursor.queries)


def test_get_wallet_transactions_maps_rows_to_dicts(fake_db):
    timestamp = datetime(2026, 1, 1, 10, 30)
    cursor = QueueCursor(
        fetchall_results=[
            [
                ("deposit", "1000.00", "11000.00", timestamp),
                ("buy", "250.50", "10749.50", timestamp),
            ]
        ]
    )
    mysql = fake_db(cursor)

    transactions = get_wallet_transactions(mysql, user_id=5, limit=10)

    assert transactions == [
        {
            "type": "deposit",
            "amount": 1000.0,
            "balance_after": 11000.0,
            "timestamp": timestamp,
        },
        {
            "type": "buy",
            "amount": 250.5,
            "balance_after": 10749.5,
            "timestamp": timestamp,
        },
    ]
