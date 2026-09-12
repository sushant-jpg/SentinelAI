# Security design and operational boundaries

## Implemented controls

- Argon2id password hashing through pwdlib; passwords require at least 12 characters, letters and numbers. Maximum password length is 128. Unknown-user login performs a dummy password verification.
- HS256 JWT validation with a fixed algorithm, audience, issuer, token type, issued-at/expiry, subject and server-side session ID. Tokens expire after 15 minutes. Production requires a configured secret of at least 32 characters.
- Refresh tokens are random 48-byte URL-safe values, stored only as SHA-256 hashes. Refresh rotates them using a database compare-and-swap. Sessions have a seven-day absolute expiry. Logout revokes the server session, invalidating outstanding access tokens. Role changes/deactivation revoke target sessions.
- Access tokens remain in JavaScript memory; refresh cookies are HttpOnly, SameSite=Strict, and path-restricted. Production enforces Secure cookies. Refresh/login/logout check browser Origin against the exact CORS allowlist. Missing Origin is permitted for non-browser clients.
- Public registration always creates a viewer. Separate read, analyst, admin, and collector dependencies protect sensitive routes. Database user roles are read on every authenticated request.
- Login rate limits use database-backed hashed keys: five attempts per account and twenty per connection IP in 15 minutes. Registration allows ten per connection IP. AI requests allow thirty per user and demo generation three per admin in 15 minutes. Current limits count successful attempts too. Reverse-proxied users share a connection-IP budget in the default setup; deploy trusted ingress rate limiting for larger teams.
- Pydantic rejects unknown request fields, invalid enums, malformed IPs, out-of-range ports, unbounded text, timezone-free event timestamps and timestamps more than five minutes ahead. Bodies are bounded to 2 MB including chunked requests. Sensor parsing errors return generic 422 responses.
- SQLAlchemy parameterization, escaped substring search, relational keys, indexed history, idempotent event IDs, transactionally consistent PostgreSQL ingestion, and unique alert deduplication keys.
- React renders untrusted text as text. No dangerouslySetInnerHTML, command execution, executable templates, eval, or unsafe YAML loading. Source messages are never treated as AI instructions.
- API no-store, nosniff, frame denial and referrer policy. Nginx adds same-origin CSP, object/frame restrictions and body size limits. HSTS is returned by the production API; also configure it at the TLS ingress.
- Audit records capture user actions and connection source IPs without request bodies, passwords, API keys or tokens. Validation responses omit Pydantic input values; generic server errors omit stack traces and SQL details.
- Private generated environment configuration, ignored secrets and databases, non-root application containers, loopback port exposure, private PostgreSQL networking, exact dependency locks and CI dependency audits.

## Trust boundaries

The server trusts deployment-owned rule files and environment configuration. Admins are privileged operators. Collector keys permit arbitrary supplied records, so protect them against event poisoning. The AI endpoint URL is deployment configuration, not user input. External responses may contain incorrect guidance, even when their JSON structure is valid; the UI labels external output unverified and the engine's evidence remains separate.

Original log messages can themselves contain sensitive data supplied by a collector. Redact secrets at collection, define retention policy, restrict account access, and encrypt database disks/backups. The system prevents its own authentication secrets from entering audit/error responses; it cannot guarantee that arbitrary imported log text is secret-free.

Default proxy headers are not trusted, preventing callers from inventing source IPs. Behind Nginx, audit source IP is the proxy connection address. For real client IP attribution, configure a known trusted proxy network and ingress limits explicitly; do not trust arbitrary forwarded headers.

## Before a production deployment

Set `ENVIRONMENT=production`, `DEMO_MODE=false`, `COOKIE_SECURE=true`, a strong persistent JWT secret, PostgreSQL and exact HTTPS CORS origins. Disable public registration if unnecessary. Terminate TLS, protect API ingress, restrict network access, rotate bootstrap/collector credentials, and use managed secret storage. Backup and recovery procedures, retention schedules, MFA/SSO and independent security review remain operator work.

PostgreSQL serializes each limiter key with an advisory lock. The database login limiter is not a replacement for a distributed edge limiter under high-volume adversarial traffic. SQLite provides no multi-worker correlation guarantee; use it only for local single-worker development. PostgreSQL ingestion serializes batches rather than scaling horizontally. Body limits do not replace ingress timeouts and connection limits.

Audit rows are not cryptographically chained or exported to write-once storage. There is no automated account recovery, email verification, tenant separation, antivirus, packet inspection engine, geolocation, external threat reputation feed, or automated incident response. This application is a defensive learning and investigation platform, not a substitute for production SIEM/EDR controls.
