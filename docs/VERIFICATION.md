# Verification report

## Pre-push verification — 2026-09-12

- Backend: 38 tests passed (2 upstream deprecation warnings); Ruff passed.
- Frontend: 4 tests passed; TypeScript/Vite build and Prettier passed.
- Chromium: 1 investigation workflow passed against the existing local Compose images (11.6 seconds); screenshots refreshed.
- PostgreSQL: Alembic reported no schema drift.
- npm audit and pip-audit: no known vulnerabilities reported.
- Git whitespace checks and a scan for local configured secrets passed. Generated TypeScript build metadata is no longer tracked.
- Backend tests required execution outside the restricted sandbox. Container images were reused for the browser check; the current frontend source was built separately.

Previous retest: **2026-09-11, 22:12 Asia/Kathmandu**. All **43 automated tests passed**. No application failures were found in this run.

| Check | Latest result |
| --- | --- |
| Backend pytest | 38 passed in 8.10 seconds; 2 upstream deprecation warnings |
| Frontend Vitest | 4 passed |
| Chromium workflow on Docker/PostgreSQL | 1 passed in 9.8 seconds |
| TypeScript / Vite production build | Passed |
| Ruff / Prettier / whitespace checks | Passed |
| Compose configuration / container readiness | Passed; backend and PostgreSQL healthy, frontend running |
| PostgreSQL Alembic schema drift | No new upgrade operations detected |
| npm audit / pip-audit | No known vulnerabilities reported |

The browser retest used existing simulated detections, added an investigation note and a resolved incident, and refreshed desktop/mobile screenshots. No application source changes were required. The initial migration/build verification and coverage details follow.

- Backend: 38 pytest cases passed against isolated SQLite, including authentication, permissions, JWT validation, token rotation/revocation, rate limits, malformed input, body bounds, ten detection behaviors, false-positive examples, scoring boundaries, ingestion replay, sensor imports, alert notes, incidents, analytics, local AI output, external fallback, invalid AI response handling, and evidence-integrity guarantees.
- Frontend: 4 Vitest/React Testing Library cases passed, covering failed mutations/retry, pagination boundaries, XSS-safe rendering and the empty feed.
- TypeScript and Vite production build: passed.
- Python dependency audit: no known vulnerabilities reported at verification time.
- Frontend dependency audit: the initial test-runner advisory was fixed by updating Vitest to 4.1.11; install audit reported no known vulnerabilities.
- SQLite Alembic migration upgrade and schema drift check: passed.
- Chromium end-to-end workflow: 1 passed (9.8 seconds) against the Compose frontend and PostgreSQL-backed API. Verified login, existing/demo detection feed, severity filtering, raw evidence, AI explanation, analyst note submission, incident creation and resolution, all administration/intelligence pages, session restoration across direct page loads, mobile navigation and absence of page errors. Mobile page width stayed within the viewport.
- Container verification: backend and frontend images built successfully; PostgreSQL and backend health checks passed; Nginx served the app at localhost:8080. The host uses Podman's Docker-compatible API with Docker Compose.
- PostgreSQL: Alembic initial migration and `alembic check` passed. The browser workflow exercised persisted ingestion, scoring, auth refresh, incident links and audit paths against PostgreSQL. The standalone pytest suite uses isolated SQLite.
- Formatting and static checks: Ruff, Prettier and `git diff --check` passed.
- Screenshots: `dashboard-desktop.png` and `dashboard-mobile.png` are actual Chromium captures with simulated data.

The browser checks found and prompted fixes for a status selector's accessible labeling and an Nginx `/assets` route collision. Static build files now live under `/static`, and direct application routes fall back to `index.html`.

Live Wazuh/Suricata sensor deployments and an external AI service were not provisioned. Adapter behavior is covered using supplied JSON fixtures; external AI behavior is covered with mocked responses, failure cases and evidence-integrity assertions. No external attack traffic was generated.

Tests use only simulated security records. Passing these checks is not an independent penetration test or a throughput certification. The test suite emits upstream Starlette/httpx and AnyIO deprecation warnings; they do not fail the checks.
