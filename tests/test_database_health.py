from tests.conftest import QueueCursor


REQUIRED_TABLES = {
    "users",
    "wallet",
    "watchlist",
    "trade_log",
    "wallet_transactions",
    "login_history",
}


class HealthCursor(QueueCursor):
    def __init__(self, tables):
        super().__init__()
        self.tables = tables

    def execute(self, query, params=None):
        super().execute(query, params)
        if "SELECT DATABASE()" in query:
            self.fetchone_results.append(("trading_website",))
        elif "SHOW TABLES" in query:
            self.fetchall_results.append([(table,) for table in self.tables])
        return 1


def test_database_health_is_healthy_when_required_tables_exist(client, fake_db, set_mysql):
    mysql = fake_db(HealthCursor(REQUIRED_TABLES))
    set_mysql(mysql)

    response = client.get("/health/db")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "healthy"
    assert set(payload["tables_found"]) == REQUIRED_TABLES


def test_database_health_reports_missing_tables(client, fake_db, set_mysql):
    tables = REQUIRED_TABLES - {"users", "wallet"}
    mysql = fake_db(HealthCursor(tables))
    set_mysql(mysql)

    response = client.get("/health/db")

    assert response.status_code == 500
    payload = response.get_json()
    assert payload["status"] == "unhealthy"
    assert payload["missing_tables"] == ["users", "wallet"]
