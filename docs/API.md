# Database and API reference

## Schema

| Table | Responsibility and relationships |
| --- | --- |
| users | UUID, unique normalized email, display name, Argon2 hash, active state, role, created time |
| auth_sessions | User FK, unique SHA-256 refresh-token hash, absolute expiry, revocation flag |
| login_attempts | Hashed limiter key and indexed timestamp; no submitted passwords |
| events | Caller/sensor event ID, UTC timestamp, source/destination IP/ports, host, user, event type, protocol, severity, message, process, file, device, sensor rule, status, origin |
| assets | Unique hostname, OS, observed IP, last seen, sensitivity |
| detection_rules | Rule ID, title, enabled flag, validated JSON definition |
| mitre_techniques | Technique ID, name and tactic configured by rules |
| alerts | UUID, title, explanation, timestamp, severity, risk, source/destination, host, user, event type, category, rule FK, technique FK, status, assignee FK, immutable evidence snapshot, risk contributions, unique dedup key |
| analyst_notes | Alert FK, author FK, text and timestamp |
| incidents | UUID, title/description, severity, status, created/updated/resolved time, assignee FK, affected assets, resolution |
| incident_alerts | Composite incident/alert foreign-key relationship; prevents duplicate links |
| incident_timeline | Incident FK, author FK, action, investigation note and timestamp |
| audit_logs | Actor identifier, action, target, UTC time and connection source IP; no credentials |

Roles are a validated fixed set in `users.role` and application authorization, not a separate mutable roles table. Public registration cannot set a role. Notes and timeline entries are separate records. Foreign keys enforce referential integrity. Common searches use indexes on alert time, severity, risk, status, host, source IP, and username, and event correlation uses a composite source/host/time index. Production schema is managed by Alembic.

## Roles

| Capability | Viewer | Analyst | Admin | Collector key |
| --- | --- | --- | --- | --- |
| Read alerts, events, incidents, assets, analytics and rules | Yes | Yes | Yes | No |
| Request an AI explanation | Yes | Yes | Yes | No |
| Ingest and import records | No | Yes | Yes | Yes |
| Update alerts and incidents, add notes | No | Yes | Yes | No |
| Change rules, asset metadata, user access | No | No | Yes | No |
| Read audit logs | No | No | Yes | No |
| Generate demo events when enabled | No | No | Yes | No |

## Endpoint list

All paths below begin with `/api`. Bearer authentication is required unless marked public. Mutations are audited.

| Method | Path | Purpose / access |
| --- | --- | --- |
| GET | /health | Database readiness; public |
| POST | /auth/register | Viewer registration, configurable; public, rate limited |
| POST | /auth/login | JSON email/password; returns access token and sets refresh cookie |
| POST | /auth/refresh | Rotate refresh cookie and mint access token |
| POST | /auth/logout | Revoke current session and clear cookie; 204 |
| GET | /auth/me | Current public user record |
| GET | /users/assignable | Active analyst/admin IDs and names |
| GET | /users | Members; admin |
| PATCH | /users/{id} | Role or active state; admin; revokes target sessions |
| POST | /events | `{events: [...]}`; 1–500 events; analyst/admin/collector |
| GET | /events | Paginated records; optional exact event_id |
| POST | /events/import/wazuh | JSON object, array or NDJSON; sensor normalization |
| POST | /events/import/suricata | JSON object, array or NDJSON; EVE alerts only |
| POST | /events/demo | Simulated data; admin; demo flag; rate limited |
| GET | /alerts | Search/filter/page; described below |
| GET | /alerts/{id} | Evidence, first 100 linked raw events, notes and technique |
| PATCH | /alerts/{id} | Status and/or assigned_to, null clears assignment |
| POST | /alerts/{id}/notes | `{text: "..."}`; analyst/admin |
| GET | /incidents | Paginated incidents ordered by update time |
| POST | /incidents | Title, description, related_alerts, optional assigned_analyst |
| GET | /incidents/{id} | Linked alerts and chronological timeline |
| PATCH | /incidents/{id} | Status, assignment, resolution and/or note |
| GET | /assets | Observed hosts, open-alert count and maximum open risk |
| PATCH | /assets/{id} | Operating system and sensitivity 1–3; admin |
| GET | /rules | Rule definitions and enabled state |
| PATCH | /rules/{id} | `{enabled: true/false}`; admin |
| GET | /analytics | days=1–90; daily counts, rankings, severity and incident MTTR |
| POST | /ai/alerts/{id} | Explanation of an existing alert; rate limited |
| GET | /audit | Paginated audit records; admin |
| GET | /settings | Non-secret configuration status |

Pagination uses `page` (1+) and `page_size` (1–100), and returns `items`, `total`, `page`, `page_size`. Alert default page size is 20. Filter parameters: `q`, `severity`, `status`, `ip`, `host`, `username`, `event_type`, `technique`, `min_risk`, `max_risk`, `start`, `end`. `q` searches title, source IP, host, username, and technique with escaped substring matching. Use ISO-8601 dates with offsets. UI date controls use local browser time.

Statuses are `New`, `Investigating`, `Resolved`, `False Positive`. Severities are lowercase `informational`, `low`, `medium`, `high`, `critical`. Resolving an incident requires nonempty resolution text. Closing incidents leaves alert statuses under independent analyst control.

Successful ingestion returns `accepted`, `duplicates`, `alerts_created`, `alert_ids`. Invalid batches are rejected atomically. Duplicate event IDs are skipped; callers must preserve IDs for safe retry. HTTP 401 means missing/expired authentication, 403 insufficient access, 404 unknown record, 409 duplicate registration, 413 body limit, 422 invalid input, and 429 rate limit. Unexpected errors return a generic 500 without stack traces.
