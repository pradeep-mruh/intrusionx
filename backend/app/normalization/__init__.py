"""
Normalization module.

Responsible for converting raw, heterogeneous security evidence into a
common NormalizedEvent representation that the rest of the pipeline can
reason about uniformly.

Future responsibilities:
- Define the NormalizedEvent schema (timestamp, event_type, source_host,
  target, process, user, raw_evidence_id, etc.).
- Implement source-specific parsers:
    - Syslog parser
    - Windows Event Log parser
    - EDR event parser
    - Zeek/Suricata log parser
- Map source-specific field names to canonical field names.
- Preserve a reference to the original raw evidence record (for traceability).

Normalization must be idempotent and deterministic.
"""
