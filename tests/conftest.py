import pytest
from tradelink.app import create_app
from tradelink.cli import DEMO_PASSWORD, seed


@pytest.fixture()
def lab(tmp_path):
    path = tmp_path / "lab.sqlite3"
    seed(path)
    app = create_app({"DATABASE": str(path), "TESTING": True})
    return app.test_client(), str(path)


@pytest.fixture()
def credentials():
    return {"password": DEMO_PASSWORD}


def login(client, user, pw="TradeLink-Demo-Only!", ip="127.0.0.1"):
    result = client.post("/api/auth/login", json={"username": user, "password": pw},
                         environ_base={"REMOTE_ADDR": ip})
    assert result.status_code == 200
    return {"Authorization": "Bearer " + result.json["access_token"]}
