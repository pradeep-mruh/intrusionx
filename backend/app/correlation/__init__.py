"""
Correlation module.

Responsible for discovering explainable, rule-based relationships between
normalized events.

Future responsibilities:
- Define the Relationship type (source_event_id, target_event_id,
  relationship_kind, confidence_reason, rule_id).
- Implement correlation rules, for example:
    - Same process spawned child process within a time window
    - Network connection from process matches subsequent remote execution event
    - File written by process A is later executed by process B
    - Authentication success followed by lateral movement from the same host
- All relationships must be explainable: every relationship stores which
  rule produced it and which evidence fields matched.
- No probabilistic scoring.  A relationship either satisfies a rule or it
  does not.

Correlation is deterministic and auditable.
"""
