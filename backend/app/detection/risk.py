"""Deterministic scoring; each contribution is returned for analyst inspection."""

BASE = {"informational": 10, "low": 25, "medium": 45, "high": 65, "critical": 85}


def severity_for(score: int) -> str:
    return "informational" if score <= 20 else "low" if score <= 40 else "medium" if score <= 60 else "high" if score <= 80 else "critical"


def score_risk(severity: str, repetitions: int = 1, sensitivity: int = 1, accounts: int = 1, ports: int = 1, previous: int = 0):
    factors = [{"factor": "Detection severity", "points": BASE[severity]}]
    for label, points in [
        ("Repeated events", min(10, max(0, repetitions - 1) // 5)),
        ("Asset sensitivity", max(0, min(2, sensitivity - 1)) * 5),
        ("Affected accounts", min(8, max(0, accounts - 1) * 2)),
        ("Targeted ports", min(7, max(0, ports - 1) // 5)),
        ("Prior incidents from source", min(10, previous * 2)),
    ]:
        if points:
            factors.append({"factor": label, "points": points})
    score = min(100, sum(item["points"] for item in factors))
    return score, severity_for(score), factors
