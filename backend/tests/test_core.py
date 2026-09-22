import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "TOKEN_SECRET_PATH", tmp_path / ".token_secret")
    main._SUMMARY_CACHE["at"] = 0
    main._SUMMARY_CACHE["data"] = None
    main._RATE_BUCKETS.clear()
    main.init_db()
    return TestClient(main.app)


def login(client, police_id="POLICE-042", pin="1234"):
    r = client.post("/api/authority/login", json={"police_id": police_id, "pin": pin})
    assert r.status_code == 200
    return r.json()["token"]


def test_server_normalises_location_and_hides_token(client):
    raw = "x" * 72
    r = client.post("/api/reports", json={
        "category": "catcalling", "happened_when": "just_now", "reporter_type": "self",
        "still_happening": False, "reporter_token": raw, "latitude": 18.5204, "longitude": 73.8567,
        "location_label": "fake", "location_source": "registered", "location_consent": True,
    })
    assert r.status_code == 201
    assert r.json()["location_source"] == "registered"
    conn = main.get_db()
    stored = conn.execute("SELECT reporter_token FROM reports").fetchone()[0]
    assert stored != raw and len(stored) == 64
    assert client.get(f"/api/reports/mine/{raw}").status_code == 200


def test_distant_registered_claim_cannot_upgrade_gps(client):
    raw = "y" * 72
    r = client.post("/api/reports", json={
        "spot_id": "SPOT-042", "category": "following", "happened_when": "just_now", "reporter_type": "witness",
        "still_happening": False, "reporter_token": raw, "latitude": 18.5230, "longitude": 73.8590,
        "location_label": "University North Gate", "location_source": "registered", "location_consent": True,
    })
    assert r.status_code == 201
    assert r.json()["location_source"] == "registered"
    assert r.json()["spot_id"] == "SPOT-060"


def test_scoring_handles_patient_and_repeated_attacks():
    base = main.now() - timedelta(days=7)
    genuine = [
        {"received_at": (base + timedelta(days=i * .8)).isoformat(), "reporter_token": f"g{i}", "location_source": "registered", "category": "catcalling"}
        for i in range(9)
    ]
    score = main.score_votes(genuine, [[r] for r in genuine], {f"g{i}": 1 for i in range(9)})
    assert score["effective_signal"] >= 4
    assert "high first-seen source concentration over short horizon" not in score["integrity_flags"]

    patient = [
        {"received_at": (base + timedelta(days=i * .35)).isoformat(), "reporter_token": f"f{i}", "location_source": "registered", "category": "catcalling"}
        for i in range(10)
    ]
    score = main.score_votes(patient, [[r] for r in patient], {f"f{i}": 1 for i in range(10)})
    assert "high first-seen source concentration over short horizon" in score["integrity_flags"]

    repeated = [
        {"received_at": (base + timedelta(days=i // 9)).isoformat(), "reporter_token": f"x{i % 5}", "location_source": "registered", "category": "catcalling"}
        for i in range(25)
    ]
    score = main.score_votes(repeated, [repeated[:9], repeated[9:18], repeated[18:]], {f"x{i}": 5 for i in range(5)})
    assert "repeated-source influence" in score["integrity_flags"]


def test_destructive_demo_endpoints_need_supervisor(client):
    duty = login(client)
    supervisor = login(client, "POLICE-099", "5678")
    assert client.post("/api/demo/reset", headers={"Authorization": f"Bearer {duty}"}).status_code == 403
    assert client.post("/api/demo/reset", headers={"Authorization": f"Bearer {supervisor}"}).status_code == 200


def test_help_now_is_rate_limited(client):
    for _ in range(5):
        assert client.post("/api/help-now", json={"latitude": 18.52, "longitude": 73.85, "location_label": "Demo"}).status_code == 200
    assert client.post("/api/help-now", json={"latitude": 18.52, "longitude": 73.85, "location_label": "Demo"}).status_code == 429
