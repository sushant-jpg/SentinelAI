"""Import local sensor JSON using a collector key, without putting secrets in arguments."""

import argparse
import json
from pathlib import Path
import httpx
from dotenv import dotenv_values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", choices=["wazuh", "suricata"])
    parser.add_argument("file", type=Path)
    parser.add_argument("--url", default="http://localhost:8000")
    args = parser.parse_args()
    settings = dotenv_values(Path(__file__).resolve().parents[1] / ".env")
    key = settings.get("INGEST_API_KEY")
    if not key:
        parser.error("Set INGEST_API_KEY in your private .env")
    if not args.url.startswith(("https://", "http://localhost:", "http://127.0.0.1:")):
        parser.error("Remote ingestion requires HTTPS")
    raw = args.file.read_bytes()
    if len(raw) > 2_000_000:
        parser.error("Split files into batches below 2 MB and at most 500 records")
    with httpx.Client(timeout=60, follow_redirects=False) as client:
        response = client.post(
            args.url.rstrip("/") + "/api/events/import/" + args.source,
            content=raw,
            headers={"X-Ingest-Key": key, "Content-Type": "application/json"},
        )
        if response.status_code >= 400:
            raise SystemExit(
                f"Import failed: HTTP {response.status_code}; verify payload, configuration and access."
            )
        result = response.json()
        print(
            json.dumps(
                {k: result[k] for k in ("accepted", "duplicates", "alerts_created")},
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
