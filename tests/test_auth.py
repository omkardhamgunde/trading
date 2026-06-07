from werkzeug.security import check_password_hash, generate_password_hash

from tests.conftest import QueueCursor, login_as


def test_signup_creates_hashed_user_and_starting_wallet(client, fake_db, set_mysql):
    cursor = QueueCursor(fetchone_results=[None], lastrowid=42)
    mysql = fake_db(cursor)
    set_mysql(mysql)

    response = client.post(
        "/signup",
        data={
            "username": "newuser",
            "email": "NewUser@Example.COM",
            "password": "Password123",
            "confirm_password": "Password123",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/watchlist")
    assert mysql.connection.commits == 1

    insert_user = next(query for query in cursor.queries if "INSERT INTO users" in query[0])
    username, email, stored_password = insert_user[1]
    assert username == "newuser"
    assert email == "newuser@example.com"
    assert stored_password != "Password123"
    assert check_password_hash(stored_password, "Password123")

    insert_wallet = next(query for query in cursor.queries if "INSERT INTO wallet" in query[0])
    assert insert_wallet[1] == (42, 10000)

    with client.session_transaction() as session:
        assert session["user_id"] == 42


def test_login_accepts_valid_password_logs_activity_and_creates_missing_wallet(client, fake_db, set_mysql):
    password_hash = generate_password_hash("Password123")
    cursor = QueueCursor(fetchone_results=[(7, password_hash), None])
    mysql = fake_db(cursor)
    set_mysql(mysql)

    response = client.post(
        "/login",
        data={"username": "demo_user", "password": "Password123"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/watchlist")
    assert mysql.connection.commits == 1

    history_insert = next(query for query in cursor.queries if "INSERT INTO login_history" in query[0])
    assert history_insert[1][0] == 7
    assert history_insert[1][1] == "demo_user"
    assert history_insert[1][4] == "Success"

    wallet_insert = next(query for query in cursor.queries if "INSERT INTO wallet" in query[0])
    assert wallet_insert[1] == (7, 10000)

    with client.session_transaction() as session:
        assert session["user_id"] == 7


def test_login_rejects_invalid_password_and_logs_failure(client, fake_db, set_mysql):
    cursor = QueueCursor(fetchone_results=[(7, generate_password_hash("CorrectPassword"))])
    mysql = fake_db(cursor)
    set_mysql(mysql)

    response = client.post(
        "/login",
        data={"username": "demo_user", "password": "WrongPassword"},
    )

    assert response.status_code == 200
    assert mysql.connection.commits == 1

    history_insert = next(query for query in cursor.queries if "INSERT INTO login_history" in query[0])
    assert history_insert[1][0] == 7
    assert history_insert[1][1] == "demo_user"
    assert history_insert[1][4] == "Failure"

    with client.session_transaction() as session:
        assert "user_id" not in session


def test_protected_pages_redirect_to_login_when_logged_out(client):
    response = client.get("/wallet")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_logged_in_session_helper(client):
    login_as(client, user_id=99)

    with client.session_transaction() as session:
        assert session["user_id"] == 99
