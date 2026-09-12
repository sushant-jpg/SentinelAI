# College project defense

## Short explanation

“SentinelAI is a defensive security operations platform. It normalizes security logs, correlates suspicious patterns using deterministic rules, and generates prioritized alerts with transparent risk scores. Analysts can inspect original evidence, map the behavior to MITRE ATT&CK, add notes, assign responsibility, and group related alerts into incidents. An optional AI assistant explains detections and suggests investigation steps, while the evidence and severity remain controlled by the rule engine. The system combines FastAPI, PostgreSQL, React and modular Wazuh/Suricata adapters, and includes a safe simulated-event lab.”

## Five-minute demonstration

1. Sign in with the generated local administrator account. Explain the Viewer/Analyst/Admin boundary.
2. Generate simulated events. Show that the alert counts are computed from stored detections rather than hard-coded UI data.
3. Open SSH brute force: show the threshold of more than ten failures in five minutes, linked event IDs, source/target, T1110 and score contributions.
4. Explain the alert using the local assistant. Distinguish observed evidence, interpretation and recommendations.
5. Add an investigation note, select related alerts, create an incident, and close it with a resolution.
6. Show the audit trail and demonstrate that a viewer cannot change rules or incidents.
7. Describe adapter boundaries, tests, known limitations and planned improvements.

## Likely questions

**Why use rules before AI?** Rules provide repeatable detections and measurable thresholds. AI language output can be useful but cannot independently establish evidence. Separating them prevents generated text from silently altering the detection decision.

**How does correlation survive a restart?** It queries persisted event history, not an in-memory counter. Replay IDs are unique. PostgreSQL ingestion is serialized for deterministic correlation within the supported lab workload.

**Is a score of 90 a 90% chance of attack?** No. It is a transparent prioritization heuristic built from severity and bounded contextual factors. It would require labeled data and calibration to become a probability estimate.

**Is this fully Sigma-compatible?** It supports a defined safe subset of Sigma selection syntax and explicit SentinelAI correlation extensions. A complete Sigma compiler and backend conversion pipeline is future work.

**How do you handle false positives?** Rules include false-positive examples, analysts see original evidence, and alerts can be marked False Positive with investigation notes. Thresholds and metadata are configurable.

**What are the biggest limits?** No stream-processing queue, incomplete sensor-specific mappings, no full Sigma expression support, no MFA/SSO, no immutable audit export, and no independent production security/load certification. Late events in later batches do not retroactively re-evaluate prior triggers.

**What makes this safe to demonstrate?** The demo creates inert event objects and uses documentation IP ranges. The code does not execute suspicious process strings, attack machines, or automatically contain hosts.
