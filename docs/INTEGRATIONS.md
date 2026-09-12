# Sensor integrations and authorized lab

The integration boundary is an authenticated ingestion API. SentinelAI receives records; it does not install agents, sniff interfaces, control test machines, launch scans, or generate hostile traffic. Wazuh and Suricata are optional independent systems.

```text
Kali or administrator workstation (optional, authorized test environment)
                            |
              isolated host-only lab network
                            |
             Ubuntu / Windows test machines
                            |
                  Wazuh / Suricata sensors
                            |
             JSON alert export or operator log shipper
                            |
              SentinelAI authenticated ingestion
                            |
               PostgreSQL → React dashboard
```

Use owned test VMs and an isolated lab network. The built-in demonstration needs no Kali VM, sensor, or network testing; it only constructs event records with documentation IP ranges.

## Authentication and transport

Send a valid analyst/admin Bearer token or `X-Ingest-Key` matching the server's `INGEST_API_KEY`. Collector keys grant only ingestion and cannot read dashboards or change users/rules. Store them in a secret manager or protected environment, never in Git, browser JavaScript, or command history. Use HTTPS outside loopback. The default Compose backend port binds only to loopback; route remote collectors through an explicitly configured authenticated TLS ingress.

The UI import dialog is available to analysts and administrators. `scripts/import_logs.py` reads `.env` and posts a local file. Neither helper executes the file. Keys are not printed. Responses include accepted, duplicate, and alert counts. Up to 500 records and 2 MB are allowed in one request. Invalid records reject the entire batch. Send smaller sequential batches for long files. Reuse original event IDs to avoid duplicates on retry.

## Wazuh

Export records from Wazuh's JSON alerts output through your existing authorized forwarding tooling. The adapter accepts one JSON object, an array, or NDJSON at `POST /api/events/import/wazuh`. Live Wazuh API polling and manager provisioning are not implemented; no manager credentials are required for imports.

| Wazuh | SentinelAI |
| --- | --- |
| id | `wazuh:`-prefixed event ID; canonical payload hash if absent |
| timestamp | UTC event time; timezone required |
| agent.name / agent.id / agent.ip | hostname / device_id / destination_ip |
| data.srcip | source_ip |
| data.dstuser or srcuser | username |
| rule.description / rule.id | message / original detection_rule |
| rule.level | critical ≥12, high ≥9, medium ≥6, low otherwise |
| authentication_failed + sshd groups | ssh_failed |
| authentication_failed group | login_failed |
| authentication_success group | login_success |
| syscheck.path | file_modified with file_path |
| other rule records | wazuh_alert |

Actual Wazuh configurations vary; extend the adapter and add fixtures for your deployment's schema. This generic fallback retains sensor level but requires rule-specific context before associating it with a real technique. Historical sample files import as historical events and may not appear in the dashboard's recent date range; the Alerts feed is not date-limited by default.

## Suricata

`POST /api/events/import/suricata` accepts EVE records where `event_type` is `alert`. Configure your sensor to emit EVE JSON using Suricata's supported configuration. This project intentionally rejects non-alert records in this adapter; normalize connection records through `/api/events` if you need port-scan correlation.

Fields map from timestamp, src_ip, dest_ip, src_port, dest_port, proto, and the alert signature/category/severity. Signature ID is retained as the originating sensor rule. Priority 1 maps to critical, 2 to high, 3 to medium. Host is taken from `host`, then destination IP, then a sensor fallback. Canonical payload hashing provides stable event IDs for retries.

The generic network rule's T1071 mapping is provisional. Replace it with signature-specific mappings for production analysis; an arbitrary Suricata signature does not establish command-and-control activity.

Primary sensor references: [Wazuh alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html) and [Suricata EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html).
