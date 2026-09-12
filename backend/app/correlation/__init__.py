"""
Correlation module.

Responsible for discovering explainable, rule-based relationships between
normalized events.

Phase 4A / 4B capabilities:
- Discover process parent/child relationships via host + PID matching.
- All relationships are explainable, deterministic, and auditable.
- No probabilistic scoring.  A relationship either satisfies a rule or it
  does not.

Phase 4C capabilities:
- Discover process-to-file-activity relationships (CREATED / DELETED)
  via host + PID matching between PROCESS_START events and FILE_CREATE /
  FILE_DELETE events.

Future responsibilities:
- Network connection correlation.
- Authentication-to-lateral-movement correlation.
- All relationships must store which rule produced them and which evidence
  fields matched.

Correlation is deterministic and auditable.
"""

from app.correlation.service import (
    CorrelationResult,
    correlate_process_file_activity,
    correlate_process_parent_child,
)

__all__ = [
    "CorrelationResult",
    "correlate_process_file_activity",
    "correlate_process_parent_child",
]
