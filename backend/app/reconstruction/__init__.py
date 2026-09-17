"""
Reconstruction module.

Responsible for assembling correlated events and their relationships into
candidate attack chains (attack graphs / hypotheses).

Future responsibilities:
- Traverse the relationship graph to identify contiguous sequences of events
  that form a plausible attack chain.
- Represent an attack chain as an ordered set of events connected by
  typed relationships.
- Produce one or more candidate hypotheses when the evidence is ambiguous.
- Annotate each hypothesis with the set of events and relationships it
  includes, so investigators can inspect the full evidence base.
- Never invent events or relationships that do not exist in the correlation
  output.

Reconstruction assembles; it does not invent.
"""

from app.reconstruction.service import ReconstructionResult, build_reconstruction

__all__ = ["ReconstructionResult", "build_reconstruction"]
