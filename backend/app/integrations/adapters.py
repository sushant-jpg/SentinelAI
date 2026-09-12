import json
from app.schemas.inputs import EventInput
from app.services.ingestion import stable_id


def suricata(payload: dict) -> EventInput:
    if payload.get("event_type") != "alert" or not isinstance(payload.get("alert"), dict):
        raise ValueError("Expected a Suricata EVE alert record")
    alert = payload["alert"]
    return EventInput(
        event_id="suricata:" + stable_id(json.dumps(payload, sort_keys=True)),
        timestamp=payload["timestamp"],
        source_ip=payload.get("src_ip"),
        destination_ip=payload.get("dest_ip"),
        source_port=payload.get("src_port"),
        destination_port=payload.get("dest_port"),
        protocol=payload.get("proto"),
        hostname=payload.get("host") or payload.get("dest_ip") or "suricata-sensor",
        event_type="suricata_alert",
        severity={1: "critical", 2: "high", 3: "medium"}.get(int(alert.get("severity", 3)), "low"),
        message=f"{alert.get('signature', 'Unknown signature')} — {alert.get('category', 'Uncategorized')}",
        detection_rule=str(alert.get("signature_id", "unknown")),
    )


def wazuh(payload: dict) -> EventInput:
    rule, agent, data = payload.get("rule", {}), payload.get("agent", {}), payload.get("data", {})
    if not rule or "timestamp" not in payload:
        raise ValueError("Expected Wazuh rule and timestamp")
    groups = rule.get("groups", [])
    event_type = (
        "ssh_failed"
        if "authentication_failed" in groups and "sshd" in groups
        else "login_failed"
        if "authentication_failed" in groups
        else "login_success"
        if "authentication_success" in groups
        else "file_modified"
        if payload.get("syscheck")
        else "wazuh_alert"
    )
    level = int(rule.get("level", 0))
    return EventInput(
        event_id="wazuh:" + str(payload.get("id") or stable_id(json.dumps(payload, sort_keys=True))),
        timestamp=payload["timestamp"],
        source_ip=data.get("srcip"),
        destination_ip=agent.get("ip") if agent.get("ip") != "any" else None,
        hostname=agent.get("name", "wazuh-agent"),
        username=data.get("dstuser") or data.get("srcuser"),
        device_id=agent.get("id"),
        event_type=event_type,
        severity="critical" if level >= 12 else "high" if level >= 9 else "medium" if level >= 6 else "low",
        message=rule.get("description", ""),
        file_path=payload.get("syscheck", {}).get("path"),
        detection_rule=str(rule.get("id", "unknown")),
    )
