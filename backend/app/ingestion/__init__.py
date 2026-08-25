"""
Ingestion module.

Responsible for receiving raw security evidence and persisting it in its
original, unmodified form.

Future responsibilities:
- Accept evidence from multiple sources: syslog, EDR agents, PCAP metadata,
  Windows Event Logs, etc.
- Validate that incoming evidence meets minimum schema requirements.
- Assign a unique evidence ID and a received-at timestamp.
- Store the raw payload alongside structured metadata.
- Guarantee immutability: once stored, raw evidence is never modified.

No business logic lives here.  Ingestion is a boundary layer.
"""
