import pytest
from fastapi.testclient import TestClient
from backend.server import app, analyzer
from config import API_TOKEN

@pytest.fixture
def client():
    return TestClient(app)

def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_get_interfaces(client):
    response = client.get("/api/interfaces")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    # Every interface has id, name, ip, mac, status
    first = data[0]
    assert "id" in first
    assert "name" in first
    assert "status" in first

def test_auth_required_endpoints(client):
    # Without header -> 401
    assert client.post("/api/start", json={"interface_id": "test"}).status_code == 401
    assert client.post("/api/stop").status_code == 401
    assert client.post("/api/clear").status_code == 401
    assert client.get("/api/download-pcap").status_code == 401

    # With invalid header -> 401
    invalid_header = {"Authorization": "Bearer wrong-token"}
    assert client.post("/api/start", json={"interface_id": "test"}, headers=invalid_header).status_code == 401
    assert client.post("/api/stop", headers=invalid_header).status_code == 401
    assert client.post("/api/clear", headers=invalid_header).status_code == 401
    assert client.get("/api/download-pcap", headers=invalid_header).status_code == 401

def test_auth_authorized_actions(client):
    auth_header = {"Authorization": f"Bearer {API_TOKEN}"}
    
    # Clear endpoint
    clear_res = client.post("/api/clear", headers=auth_header)
    assert clear_res.status_code == 200
    assert clear_res.json() == {"status": "cleared"}

    # Stop endpoint (when not running)
    stop_res = client.post("/api/stop", headers=auth_header)
    assert stop_res.status_code == 200
    assert stop_res.json()["status"] in ["already stopped", "stopped"]

def test_websocket_connection(client):
    with client.websocket_connect(f"/ws?token={API_TOKEN}") as websocket:
        # Initial message should be stats and alerts
        stats_msg = websocket.receive_json()
        assert stats_msg["type"] == "stats"
        assert "total_packets" in stats_msg["data"]

        alerts_msg = websocket.receive_json()
        assert alerts_msg["type"] == "alerts"
        assert isinstance(alerts_msg["data"], list)
