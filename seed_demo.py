"""
IntrusionX Demo Seed Script

Idempotent: stores the investigation ID in .demo_id after first successful run.
Subsequent runs simply print the existing URL without touching the database.

Run from the repository root:
    python seed_demo.py

To force a fresh investigation:
    rm .demo_id && python seed_demo.py
"""

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

API_URL = "http://localhost:8000/api/v1"
ANALYST_ID = "00000000-0000-0000-0000-000000000001"
DEMO_ID_FILE = Path(__file__).parent / ".demo_id"


def make_request(url: str, payload=None, method: str = "POST") -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else b""
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"HTTP {e.code} {e.reason}: {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection error: {e.reason}", file=sys.stderr)
        print(
            "Is the backend running?  Try:\n  cd backend && uvicorn app.main:app --reload",
            file=sys.stderr,
        )
        sys.exit(1)


def print_summary(inv_id: str) -> None:
    print()
    print("=" * 50)
    print("DEMO READY")
    print("=" * 50)
    print(f"\nExpected workspace contents:")
    print("  Evidence sources : 1  (phase3b_scenario.json)")
    print("  Observed events  : 5")
    print("  Relationships    : 2  (SPAWNED, CREATED)")
    print("  Reconstructions  : 1")
    print("  Unresolved events: 2  (USER_LOGIN, NETWORK_CONNECTION)")
    print()
    print(f"  WINWORD.EXE")
    print(f"    --SPAWNED--> powershell.exe")
    print(f"    --CREATED--> stage2.ps1")
    print()
    print(f"Demo URL:")
    print(f"  http://localhost:5173/?investigation={inv_id}")
    print()


def main() -> None:
    print("IntrusionX Demo Seed")
    print("=" * 50)

    # ── Check for cached investigation ID ────────────────────────────────────
    if DEMO_ID_FILE.exists():
        inv_id = DEMO_ID_FILE.read_text().strip()
        print(f"Found existing demo investigation: {inv_id}")
        print(f"(Delete .demo_id to create a fresh one)")
        print_summary(inv_id)
        return

    # ── 1. Create investigation ───────────────────────────────────────────────
    print("Creating investigation...")
    inv_res = make_request(
        f"{API_URL}/investigations",
        {
            "title": "IntrusionX Demo Investigation",
            "description": (
                "Phase 3B canonical scenario — "
                "WINWORD.EXE → powershell.exe → stage2.ps1"
            ),
            "created_by": ANALYST_ID,
        },
    )
    inv_id = inv_res["id"]
    print(f"  Investigation ID: {inv_id}")

    # ── 2. Ingest evidence ────────────────────────────────────────────────────
    scenario_path = Path(__file__).parent / "data" / "scenarios" / "phase3b_scenario.json"
    with open(scenario_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    print(f"Ingesting evidence ({len(events)} events from phase3b_scenario.json)...")
    ev_res = make_request(
        f"{API_URL}/evidence/ingest",
        {
            "investigation_id": inv_id,
            "source_identifier": "phase3b_scenario.json",
            "content": json.dumps(events),
        },
    )
    print(f"  Evidence ID: {ev_res.get('id', '?')}")
    print(f"  Normalized events: {ev_res.get('normalized_event_count', '?')}")

    # ── 3. Correlate ──────────────────────────────────────────────────────────
    print("Running correlation...")
    corr_res = make_request(f"{API_URL}/investigations/{inv_id}/correlate", {})
    print(
        f"  Relationships created : {corr_res.get('relationships_created', '?')}"
    )
    print(
        f"  Relationships skipped : {corr_res.get('relationships_skipped_duplicate', '?')}"
    )

    # ── 4. Reconstruct ────────────────────────────────────────────────────────
    print("Building reconstruction...")
    rec_res = make_request(f"{API_URL}/investigations/{inv_id}/reconstruct", {})
    print(f"  Reconstructions created: {rec_res.get('reconstructions_created', '?')}")
    print(f"  Steps created          : {rec_res.get('steps_created', '?')}")

    # ── 5. Persist ID for idempotency ─────────────────────────────────────────
    DEMO_ID_FILE.write_text(inv_id)
    print(f"\nSaved investigation ID to .demo_id for idempotent re-runs.")

    print_summary(inv_id)


if __name__ == "__main__":
    main()
