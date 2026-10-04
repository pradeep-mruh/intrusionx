import urllib.request
import json
import base64
import sys

API_URL = "http://localhost:8000/api/v1"
ANALYST_ID = "00000000-0000-0000-0000-000000000001"

print("Seeding Demo Data for IntrusionX...")

def make_request(url, payload=None, method="POST"):
    data = json.dumps(payload).encode('utf-8') if payload is not None else b''
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print(f"Error: {e.code} {e.reason}")
        print(e.read().decode('utf-8'))
        sys.exit(1)

# 1. Create Investigation
inv_data = {
    "title": "IntrusionX Demo Investigation",
    "description": "Smoke test demo investigation.",
    "created_by": ANALYST_ID
}
print("Creating Investigation...")
inv_res = make_request(f"{API_URL}/investigations", inv_data)
inv_id = inv_res["id"]
print(f"Investigation ID: {inv_id}")

import os

# 2. Ingest Evidence
scenario_path = os.path.join(os.path.dirname(__file__), "data", "scenarios", "phase3b_scenario.json")
with open(scenario_path, "r") as f:
    events = json.load(f)

content_str = json.dumps(events)

print("Ingesting Evidence...")
evidence_data = {
    "investigation_id": inv_id,
    "source_identifier": "phase3b_scenario.json",
    "content": content_str
}

ev_res = make_request(f"{API_URL}/evidence/ingest", evidence_data)
print(f"Evidence Ingested: {ev_res}")

# 3. Correlate
print("Correlating Events...")
corr_res = make_request(f"{API_URL}/investigations/{inv_id}/correlate", {})
print(f"Correlation: {corr_res}")

# 4. Reconstruct
print("Reconstructing...")
rec_res = make_request(f"{API_URL}/investigations/{inv_id}/reconstruct", {})
print(f"Reconstruction: {rec_res}")

print(f"\nSUCCESS! Open http://localhost:5173/?investigation={inv_id}")
