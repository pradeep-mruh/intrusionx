"""
Correlation module.

Responsible for discovering explainable, rule-based relationships between
normalized events.

Phase 4A capabilities:
- Discover process parent/child relationships via PID matching.
- All relationships are explainable, deterministic, and auditable.
- No probabilistic scoring.  A relationship either satisfies a rule or it
  does not.

Future responsibilities:
- Network connection correlation.
- File-write/execute correlation.
- Authentication-to-lateral-movement correlation.
- All relationships must store which rule produced them and which evidence
  fields matched.

Correlation is deterministic and auditable.
"""

from app.correlation.service import CorrelationResult, correlate_process_parent_child

__all__ = [
    "CorrelationResult",
    "correlate_process_parent_child",
]
