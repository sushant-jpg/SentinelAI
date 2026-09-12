# Detection and scoring

| Rule ID | Trigger | Window | ATT&CK context |
| --- | --- | --- | --- |
| ssh_bruteforce | At least 11 `ssh_failed` events from one source to one host | 300 s | T1110 Brute Force |
| port_scan | At least 20 distinct destination ports in `connection` records | 120 s | T1046 Network Service Discovery |
| failed_logins | At least 10 `login_failed` events | 300 s | T1110 |
| suspicious_login | `login_success` after at least 5 failed SSH/login records, same source/host/account | 300 s | T1078 Valid Accounts |
| password_spray | Failed authentication for at least 5 distinct usernames | 300 s | T1110.003 Password Spraying |
| unusual_source | Successful login from unseen source after at least 3 prior successes for same host/account | 24 h baseline | T1078 |
| suspicious_process | `process_start` message contains encoded PowerShell or listed shell execution pattern | Single event | T1059 Command and Scripting Interpreter |
| file_integrity | `file_modified` for /etc/passwd, /etc/shadow, /etc/sudoers or /etc/ssh/sshd_config | Single event | T1098 Account Manipulation, provisional |
| suricata_network | Normalized EVE alert record | Single event | T1071 Application Layer Protocol, provisional |
| wazuh_alert | Other normalized Wazuh rule record | Single event | T1082 System Information Discovery, provisional |

These are suspicious patterns, not claims of compromise. The process rule matches supplied strings; it never invokes a shell. Wazuh authentication and syscheck records are mapped to more specific internal types when possible. Broad sensor mappings require rule-specific tuning before real-world interpretation. File changes can also be routine maintenance.

## Correlation semantics

Batches are sorted by event timestamp and stable event ID. The current event is persisted before detection, and windows include both boundaries. Source and hostname scope aggregate detection; successful-login correlation also checks username. Unique destination ports exclude missing values. Account counts exclude missing usernames. Unusual-source detection excludes the triggering record from its historical baseline.

Evidence stores linked event IDs, matched count, unique accounts/ports, window, trigger message and adapter origin. A login-success alert references both failures and the successful trigger. Aggregate alert suppression applies per source/host/rule for one rolling rule window, regardless of alert resolution state. Individual signature/process/file rules deduplicate by rule plus exact event ID. PostgreSQL serializes ingestion transactions with an advisory lock. This is correct for modest lab throughput; a stream-processing design is preferable at scale.

Already persisted late events can participate in later detections. An event that arrives in a later batch with a timestamp before an already evaluated trigger does not cause retroactive re-evaluation. Send ordered streams or sorted backfill batches.

## Risk model

Base points: informational 10, low 25, medium 45, high 65, critical 85. Sensor alerts use their normalized sensor severity; other detections use their configured rule level.

Additional contributions:

- Repeated matching records: one point per five records beyond the first, maximum 10.
- Asset sensitivity: 0, 5 or 10 points for levels 1, 2 or 3.
- Affected accounts: two points per additional account, maximum 8.
- Targeted ports: one point per five extra ports, maximum 7.
- Previous incidents linked to alerts from the source: two points per incident, maximum 10.

Total is capped at 100. Labels: 0–20 informational; 21–40 low; 41–60 medium; 61–80 high; 81–100 critical. Alert details show every nonzero contribution. This is an interpretable priority heuristic, not a calibrated probability of compromise.

## Safe Sigma subset

Rules are local operator-controlled files loaded using `yaml.safe_load`; aliases and oversized files are rejected. Selection fields are allowlisted. Values can be literal strings/integers or lists. Lists use OR; fields use AND. Case-insensitive equality and one `contains`, `startswith`, or `endswith` modifier are supported. `condition` must be exactly `selection`. There is no eval, executable YAML, template execution, regex engine, shell execution, general expression language, or remote rule download.

The `sentinel` extension specifies correlation kind, threshold, window, category, tactic, technique ID and name. Change files and restart the backend to synchronize definitions. Database enable/disable state persists across synchronization. Existing alerts retain their original evidence and scoring. This implementation does not claim full Sigma interoperability; rule conversion to other SIEMs requires adapting the extensions.
