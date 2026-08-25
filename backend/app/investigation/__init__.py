"""
Investigation module.

Responsible for investigator-facing operations on the reconstructed attack
graph and its hypotheses.

Future responsibilities:
- Confirm a relationship (investigator validates that it is real).
- Reject a relationship (investigator marks it as a false positive).
- Connect two events manually with an investigator-supplied explanation.
- Disconnect a relationship that was created automatically.
- Record every analyst action with: analyst_id, timestamp, action_type,
  target (event or relationship), and a free-text justification.
- Expose the current investigation state as a read-only snapshot for UI
  rendering.

Every analyst action is an immutable audit record.  Actions are appended,
never overwritten.
"""
