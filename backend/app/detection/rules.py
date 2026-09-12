"""A deliberately bounded Sigma subset. Never evaluates Python or shell code."""

from pathlib import Path
import re
import yaml
from sqlalchemy import select
from app.models.entities import DetectionRule, MitreTechnique

RULES_DIR = Path(__file__).resolve().parents[3] / "rules"
if not RULES_DIR.exists():
    RULES_DIR = Path("/app/rules")
FIELDS = {"event_type", "process_name", "file_path", "message", "severity", "protocol", "destination_port"}
KINDS = {"count", "distinct_ports", "accounts", "success_after_failures", "unusual_source", "single"}


def parse_rule(text: str) -> dict:
    if len(text) > 65536 or re.search(r"(^|\s)[&*][\w-]+", text):
        raise ValueError("Oversized rules and YAML aliases are not supported")
    rule = yaml.safe_load(text)
    required = {"title", "id", "description", "author", "level", "logsource", "detection", "falsepositives", "tags", "sentinel"}
    if not isinstance(rule, dict) or not required.issubset(rule):
        raise ValueError("Missing rule metadata")
    detection = rule["detection"]
    if detection.get("condition") != "selection" or not isinstance(detection.get("selection"), dict) or not detection["selection"]:
        raise ValueError("Only the selection condition is supported")
    for expression, value in detection["selection"].items():
        parts = expression.split("|")
        if parts[0] not in FIELDS or len(parts) > 2 or (len(parts) == 2 and parts[1] not in ("contains", "endswith", "startswith")):
            raise ValueError("Unsupported field or modifier")
        values = value if isinstance(value, list) else [value]
        if not values or any(not isinstance(v, (str, int)) for v in values):
            raise ValueError("Selection values must be strings or integers")
    options = rule["sentinel"]
    if options["kind"] not in KINDS or rule["level"] not in ("informational", "low", "medium", "high", "critical"):
        raise ValueError("Invalid correlation or severity")
    if not 1 <= options.get("window_seconds", 300) <= 86400 or not 1 <= options.get("threshold", 1) <= 10000:
        raise ValueError("Invalid correlation bounds")
    if not re.fullmatch(r"T\d{4}(\.\d{3})?", options["technique_id"]):
        raise ValueError("Invalid ATT&CK identifier")
    return rule


def matches(rule: dict, event) -> bool:
    for expression, expected in rule["detection"]["selection"].items():
        parts = expression.split("|")
        actual = getattr(event, parts[0], None)
        if actual is None:
            return False
        choices = expected if isinstance(expected, list) else [expected]

        def check(value):
            if len(parts) == 1:
                return str(actual).casefold() == str(value).casefold()
            a, b = str(actual).casefold(), str(value).casefold()
            return b in a if parts[1] == "contains" else a.endswith(b) if parts[1] == "endswith" else a.startswith(b)

        if not any(check(v) for v in choices):
            return False
    return True


def sync_rules(db):
    for path in sorted(RULES_DIR.glob("*.yml")):
        definition = parse_rule(path.read_text())
        options = definition["sentinel"]
        technique = db.get(MitreTechnique, options["technique_id"])
        if not technique:
            db.add(MitreTechnique(technique_id=options["technique_id"], technique_name=options["technique_name"], tactic=options["tactic"]))
        else:
            technique.technique_name, technique.tactic = options["technique_name"], options["tactic"]
        existing = db.get(DetectionRule, definition["id"])
        if existing:
            existing.title, existing.definition = definition["title"], definition
        else:
            db.add(DetectionRule(id=definition["id"], title=definition["title"], definition=definition))
    db.commit()
    if not db.scalar(select(DetectionRule.id).limit(1)):
        raise RuntimeError("No detection rules found")
