from fastapi.testclient import TestClient

from apps.api.main import create_app


def test_health_and_version() -> None:
    client = TestClient(create_app())

    assert client.get("/api/v1/health").json() == {"status": "ok"}
    assert client.get("/api/v1/version").json()["name"] == "Aegis"
