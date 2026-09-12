from datetime import timedelta
from uuid import uuid4
import pytest
from app.models.entities import now
from app.detection.risk import score_risk, severity_for
from app.detection.rules import parse_rule, RULES_DIR


def event(kind="ssh_failed", offset=0, **kwargs):
    return {
        "event_id": str(uuid4()),
        "timestamp": (now() - timedelta(minutes=2) + timedelta(seconds=offset)).isoformat(),
        "hostname": "test-server",
        "source_ip": "198.51.100.25",
        "destination_ip": "10.0.0.2",
        "event_type": kind,
        "username": "root",
        **kwargs,
    }


def ingest(client, accounts, events):
    return client.post("/api/events", headers=accounts["analyst"], json={"events": events})


def test_ssh_threshold_replay_and_suppression(client, accounts):
    records = [event(offset=i) for i in range(10)]
    assert ingest(client, accounts, records).json()["alerts_created"] == 0
    result = ingest(client, accounts, [event(offset=11)])
    assert result.status_code == 201 and result.json()["alerts_created"] == 1
    alert = client.get("/api/alerts", headers=accounts["viewer"]).json()["items"][0]
    assert alert["detection_rule"] == "ssh_bruteforce" and alert["evidence"]["matching_count"] == 11
    assert alert["risk_score"] >= 65 and alert["technique_id"] == "T1110"
    assert ingest(client, accounts, [event(offset=12)]).json()["alerts_created"] == 0
    assert ingest(client, accounts, records).json()["duplicates"] == 10


def test_window_and_host_isolation(client, accounts):
    records = [event(offset=i, hostname=f"host-{i}") for i in range(12)]
    assert ingest(client, accounts, records).json()["alerts_created"] == 0
    records = [event(offset=-600 + i) for i in range(10)] + [event()]
    assert ingest(client, accounts, records).json()["alerts_created"] == 0


def test_port_scan_unique_ports(client, accounts):
    assert ingest(client, accounts, [event("connection", destination_port=80) for _ in range(25)]).json()["alerts_created"] == 0
    result = ingest(client, accounts, [event("connection", offset=i, destination_port=i + 100) for i in range(20)])
    assert result.json()["alerts_created"] == 1


def test_success_after_failures_same_account(client, accounts):
    records = [event("login_failed", offset=i) for i in range(5)]
    records.append(event("login_success", offset=6, username="other"))
    assert ingest(client, accounts, records).json()["alerts_created"] == 0
    assert ingest(client, accounts, [event("login_success", offset=8)]).json()["alerts_created"] == 1


def test_spray_and_new_source(client, accounts):
    assert ingest(client, accounts, [event("login_failed", offset=i, username="user" + str(i)) for i in range(5)]).json()["alerts_created"] == 1
    history = [event("login_success", offset=i - 60, username="alice") for i in range(3)]
    assert ingest(client, accounts, history).json()["alerts_created"] == 0
    assert ingest(client, accounts, [event("login_success", username="alice", source_ip="203.0.113.8")]).json()["alerts_created"] == 1


@pytest.mark.parametrize(
    "kind,fields,expected",
    [
        ("process_start", {"message": "powershell -EncodedCommand inert-sample"}, 1),
        ("process_start", {"message": "python report.py"}, 0),
        ("file_modified", {"file_path": "/etc/shadow"}, 1),
        ("file_modified", {"file_path": "/tmp/notes.txt"}, 0),
        ("suricata_alert", {"severity": "critical"}, 1),
        ("login_success", {}, 0),
    ],
)
def test_single_event_rules(client, accounts, kind, fields, expected):
    assert ingest(client, accounts, [event(kind, **fields)]).json()["alerts_created"] == expected


@pytest.mark.parametrize(
    "score,label",
    [
        (0, "informational"),
        (20, "informational"),
        (21, "low"),
        (40, "low"),
        (41, "medium"),
        (60, "medium"),
        (61, "high"),
        (80, "high"),
        (81, "critical"),
        (100, "critical"),
    ],
)
def test_risk_boundaries(score, label):
    assert severity_for(score) == label


def test_risk_factors_explain_score():
    score, level, factors = score_risk("high", 20, 3, 6, 30, 4)
    assert score == min(100, sum(f["points"] for f in factors)) and level == "critical"
    assert score_risk("low")[0] == 25


def test_rules_reject_unsafe_and_unsupported_syntax():
    definition = (RULES_DIR / "port_scan.yml").read_text()
    assert parse_rule(definition)["id"] == "port_scan"
    for text in [
        "!!python/object/apply:os.system [echo bad]",
        definition.replace('"condition": "selection"', '"condition": "selection or anything"'),
        definition.replace('"event_type"', '"event_type|regex"'),
    ]:
        with pytest.raises((ValueError, __import__("yaml").YAMLError)):
            parse_rule(text)
