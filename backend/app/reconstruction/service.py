"""
Reconstruction service — Phase 5A.

PUBLIC API
----------
build_reconstruction(*, session, investigation_id) -> ReconstructionResult

    Assembles Reconstruction and ReconstructionStep rows from the
    Relationship rows that exist for one investigation.

    Phase 5A supports simple directed paths only: a sequence of events
    E₁ → E₂ → … → Eₙ (n ≥ 2) where every node has in_degree ≤ 1 and
    out_degree ≤ 1, exactly one root (in_degree == 0), exactly one
    terminal (out_degree == 0), and no directed cycle.

    One Reconstruction row is created per supported connected component.
    Branching, convergence, multi-root, and cyclic components are skipped
    and counted separately in the result.

    Does NOT commit the session.  The caller is responsible for
    commit/rollback.

──────────────────────────────────────────────────────────────────────────────
RELATIONSHIP INCLUSION POLICY
──────────────────────────────────────────────────────────────────────────────
Included in the graph:
    status IN ('SYSTEM_PROPOSED', 'ANALYST_CONFIRMED')
    source_event_id IS NOT NULL
    target_event_id IS NOT NULL

Excluded before graph construction:
    status == 'ANALYST_REJECTED'
    entity-to-entity relationships (source_entity_id / target_entity_id set)

An ANALYST_REJECTED edge is absent from the in-memory graph entirely.
It cannot disrupt, split, or erase any surviving path.  A surviving
segment (e.g., A→B where B→C is rejected) forms its own independent
connected component and is reconstructed normally.

──────────────────────────────────────────────────────────────────────────────
SEMANTIC ORDER
──────────────────────────────────────────────────────────────────────────────
Graph topology determines semantic and serialization order exclusively.
occurred_at is not consulted, not loaded, and not used anywhere in this
service.

A timestamp inversion (source.occurred_at > target.occurred_at) is not
detected and not rejected.  The Relationship's source/target direction
defines step order.

──────────────────────────────────────────────────────────────────────────────
TRUST BOUNDARY
──────────────────────────────────────────────────────────────────────────────
Phase 5A scopes Relationship rows by relationship.investigation_id and
trusts event endpoint ownership established by upstream domain services.

It does NOT independently validate that source_event.investigation_id
or target_event.investigation_id matches relationship.investigation_id.
The DB schema has no composite constraint enforcing this invariant (each
FK is validated independently).  Cross-investigation relationships cannot
be produced by the existing correlation service, which constructs
relationships using a scoped JOIN that enforces investigation_id equality
for both events before any match predicate is applied.

──────────────────────────────────────────────────────────────────────────────
IDEMPOTENCY
──────────────────────────────────────────────────────────────────────────────
Phase 5A makes no idempotency guarantee.  Each invocation creates new
Reconstruction and ReconstructionStep rows.  The Reconstruction table has
no creation_method or system_generated field to distinguish system-built
rows from analyst-created rows.

Callers are responsible for invocation timing.  A future migration adding
a creation_method column to reconstruction would enable the same
pre-insert SELECT guard that the correlation service uses.

──────────────────────────────────────────────────────────────────────────────
CYCLE DETECTION
──────────────────────────────────────────────────────────────────────────────
Cycle detection uses iterative DFS coloring (WHITE/GRAY/BLACK) over every
node in the connected component, regardless of whether a root exists.
A back-edge (edge into a GRAY node) proves a directed cycle.

Detection precedes linear-shape validation because a simple 2-cycle
(A→B→A) has in_degree=1 and out_degree=1 for every node; without the
prior cycle check it would be misclassified as "unsupported" (no unique
root) rather than "cycle".

──────────────────────────────────────────────────────────────────────────────
CALLER RESPONSIBILITY
──────────────────────────────────────────────────────────────────────────────
The caller owns the transaction.  This service:
    - calls session.flush() after each INSERT to surface DB errors early
    - never calls session.commit() or session.rollback()

──────────────────────────────────────────────────────────────────────────────
QUERY DESIGN
──────────────────────────────────────────────────────────────────────────────
One SELECT loads all included Relationship rows for the investigation.
All graph analysis occurs in Python after this bounded retrieval.

No additional SELECT on normalized_event is issued.  Event UUIDs for
ReconstructionStep.event_id are taken directly from the already-loaded
relationship.source_event_id / relationship.target_event_id values.

No N+1 queries.  No graph framework.  No recursion.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Iterator

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.reconstruction import Reconstruction, ReconstructionStep
from app.models.relationship import Relationship

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_STEP_ORDER_INCREMENT: int = 10

# DFS coloring for cycle detection
_WHITE: int = 0  # unvisited
_GRAY: int = 1   # on current DFS stack
_BLACK: int = 2  # fully processed

_INCLUDED_STATUSES: tuple[str, ...] = ("SYSTEM_PROPOSED", "ANALYST_CONFIRMED")

# ──────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ReconstructionResult:
    """
    Returned by build_reconstruction after processing one investigation.

    ``reconstructions_created`` is the number of new Reconstruction rows
    inserted (one per supported linear-path component).

    ``steps_created`` is the total number of ReconstructionStep rows
    inserted across all created reconstructions.

    ``components_skipped_unsupported`` is the number of relationship-
    connected components that could not be linearised (branching,
    convergence, or multiple roots).

    ``components_skipped_cycle`` is the number of components skipped
    because a directed cycle was detected.
    """

    investigation_id: uuid.UUID
    reconstructions_created: int
    steps_created: int
    components_skipped_unsupported: int
    components_skipped_cycle: int


# ──────────────────────────────────────────────────────────────────────────────
# Internal graph helpers  (pure Python, no DB calls)
# ──────────────────────────────────────────────────────────────────────────────

# Edge format throughout:
#   out_edges[source_event_id] = list of (relationship_id, target_event_id)
#   in_edges [target_event_id] = list of (relationship_id, source_event_id)
_OutEdges = dict[uuid.UUID, list[tuple[uuid.UUID, uuid.UUID]]]
_InEdges  = dict[uuid.UUID, list[tuple[uuid.UUID, uuid.UUID]]]


def _build_graph(
    relationships: list[Relationship],
) -> tuple[_OutEdges, _InEdges, dict[uuid.UUID, int], set[uuid.UUID]]:
    """
    Build in-memory directed graph structures from included Relationship rows.

    Returns
    -------
    out_edges   : event_id → [(rel_id, target_event_id)]
    in_edges    : event_id → [(rel_id, source_event_id)]
    in_degree   : event_id → number of incoming edges
    all_event_ids : every event UUID appearing as source or target
    """
    out_edges: _OutEdges = {}
    in_edges: _InEdges = {}
    in_degree: dict[uuid.UUID, int] = {}
    all_event_ids: set[uuid.UUID] = set()

    for rel in relationships:
        src = rel.source_event_id  # non-None; enforced by SELECT predicate
        tgt = rel.target_event_id  # non-None; enforced by SELECT predicate
        rid = rel.id

        all_event_ids.add(src)
        all_event_ids.add(tgt)

        out_edges.setdefault(src, []).append((rid, tgt))
        in_edges.setdefault(tgt, []).append((rid, src))

        in_degree.setdefault(src, 0)
        in_degree.setdefault(tgt, 0)
        in_degree[tgt] += 1

    return out_edges, in_edges, in_degree, all_event_ids


def _find_connected_components(
    all_event_ids: set[uuid.UUID],
    out_edges: _OutEdges,
    in_edges: _InEdges,
) -> list[set[uuid.UUID]]:
    """
    Partition all_event_ids into connected components using iterative BFS
    over the *undirected* view of the graph (both forward and backward edges
    are traversed to find reachable neighbours).

    Returns a list of non-overlapping, exhaustive sets of event UUIDs.
    """
    visited: set[uuid.UUID] = set()
    components: list[set[uuid.UUID]] = []

    for start in all_event_ids:
        if start in visited:
            continue

        component: set[uuid.UUID] = set()
        queue: list[uuid.UUID] = [start]

        while queue:
            node = queue.pop(0)
            if node in component:
                continue
            component.add(node)

            # Forward neighbours
            for _, tgt in out_edges.get(node, []):
                if tgt not in component:
                    queue.append(tgt)

            # Backward neighbours (for undirected connectivity)
            for _, src in in_edges.get(node, []):
                if src not in component:
                    queue.append(src)

        visited |= component
        components.append(component)

    return components


def _has_directed_cycle(
    component_nodes: set[uuid.UUID],
    out_edges: _OutEdges,
) -> bool:
    """
    Detect whether a directed cycle exists anywhere within component_nodes.

    Uses iterative DFS coloring (WHITE / GRAY / BLACK).  A back-edge —
    an edge from the current DFS node to a node already on the current
    stack (GRAY) — proves a directed cycle.

    This function does NOT require a root to exist in the component.
    It operates correctly for pure cycles (no in_degree-0 node) because
    it iterates over every node in component_nodes as a potential start.

    Complexity: O(V + E) where V = |component_nodes|, E = edges within
    the component.  No recursion.
    """
    color: dict[uuid.UUID, int] = {n: _WHITE for n in component_nodes}

    for start in component_nodes:
        if color[start] != _WHITE:
            continue

        # Iterative DFS: each frame is (node, iterator-over-successors)
        stack: list[tuple[uuid.UUID, Iterator[tuple[uuid.UUID, uuid.UUID]]]] = [
            (start, iter(out_edges.get(start, [])))
        ]
        color[start] = _GRAY

        while stack:
            node, children = stack[-1]
            try:
                _, child = next(children)  # (relationship_id, target_event_id)
                if child not in color:
                    # Edge leaves this component — skip (cannot happen in a
                    # fully partitioned component set, but guard defensively)
                    continue
                if color[child] == _GRAY:
                    return True  # back-edge → directed cycle found
                if color[child] == _WHITE:
                    color[child] = _GRAY
                    stack.append((child, iter(out_edges.get(child, []))))
            except StopIteration:
                color[node] = _BLACK
                stack.pop()

    return False


def _classify_component(
    component_nodes: set[uuid.UUID],
    out_edges: _OutEdges,
    in_degree: dict[uuid.UUID, int],
) -> str:
    """
    Classify one connected component as 'linear', 'unsupported', or 'cycle'.

    Classification order
    --------------------
    1. Directed cycle check (must precede linear-shape check because a
       simple 2-cycle A→B→A has in_degree=1 and out_degree=1 for every
       node, which would otherwise appear structurally valid until the
       root-finding step fails with the wrong classification).
    2. Linear shape validation:
         - every node has in_degree  ≤ 1
         - every node has out_degree ≤ 1
         - exactly one root   (in_degree  == 0)
         - exactly one terminal (out_degree == 0)
    3. If neither cycle nor valid linear shape: 'unsupported'.

    Returns
    -------
    'linear'      : exactly one supported simple directed path
    'unsupported' : branching, convergence, or multiple roots / terminals
    'cycle'       : one or more directed cycles detected
    """
    # Step 1 — directed cycle detection (component-wide, root-independent)
    if _has_directed_cycle(component_nodes, out_edges):
        return "cycle"

    # Step 2 — linear shape validation
    roots: list[uuid.UUID] = []
    for node in component_nodes:
        node_in = in_degree.get(node, 0)
        node_out = len(out_edges.get(node, []))

        if node_in > 1 or node_out > 1:
            return "unsupported"

        if node_in == 0:
            roots.append(node)

    if len(roots) != 1:
        # Zero roots impossible in an acyclic graph with ≥1 node, but guard
        # against it; multiple roots = unsupported.
        return "unsupported"

    terminals = [n for n in component_nodes if len(out_edges.get(n, [])) == 0]
    if len(terminals) != 1:
        return "unsupported"

    return "linear"


def _extract_linear_path(
    root: uuid.UUID,
    out_edges: _OutEdges,
) -> list[tuple[uuid.UUID, uuid.UUID | None]]:
    """
    Traverse the linear path starting from root and return an ordered list
    of (event_id, incoming_relationship_id | None) tuples.

    The first tuple always has relationship_id=None (the root has no
    incoming edge in the path).  Subsequent tuples carry the relationship_id
    of the edge that connects this event to its predecessor.

    Example for A→B→C:
        [(A, None), (B, rel_AB_id), (C, rel_BC_id)]

    This representation is used to generate the interleaved ReconstructionStep
    sequence:
        EVENT A, RELATIONSHIP rel_AB, EVENT B, RELATIONSHIP rel_BC, EVENT C
    """
    path: list[tuple[uuid.UUID, uuid.UUID | None]] = [(root, None)]
    current = root

    while True:
        edges = out_edges.get(current, [])
        if not edges:
            break
        rel_id, next_node = edges[0]
        path.append((next_node, rel_id))
        current = next_node

    return path


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────


async def build_reconstruction(
    *,
    session: AsyncSession,
    investigation_id: uuid.UUID,
) -> ReconstructionResult:
    """
    Assemble Reconstruction and ReconstructionStep rows for one investigation.

    Steps
    -----
    1. SELECT all included Relationship rows (one query, indexed by
       investigation_id; status filter applied at DB level).
    2. Build in-memory directed graph.
    3. Partition into connected components (undirected BFS).
    4. Classify each component: linear / unsupported / cycle.
    5. For each linear component:
       a. INSERT one Reconstruction row (status=DRAFT, flush).
       b. INSERT interleaved ReconstructionStep rows (flush).
    6. Return ReconstructionResult.

    Caller owns the transaction.  This service flushes but never commits
    or rolls back.

    Parameters
    ----------
    session:
        Active AsyncSession with an open transaction.
    investigation_id:
        UUID of the investigation to reconstruct.

    Returns
    -------
    ReconstructionResult with counts of reconstructions created, steps
    created, and components skipped.
    """
    # ── 1. Load included relationships ────────────────────────────────────────
    stmt = select(Relationship).where(
        Relationship.investigation_id == investigation_id,
        Relationship.status.in_(list(_INCLUDED_STATUSES)),
        Relationship.source_event_id.is_not(None),
        Relationship.target_event_id.is_not(None),
    )
    included: list[Relationship] = list(
        (await session.execute(stmt)).scalars().all()
    )

    logger.debug(
        "build_reconstruction: investigation=%s included_relationships=%d",
        investigation_id,
        len(included),
    )

    if not included:
        return ReconstructionResult(
            investigation_id=investigation_id,
            reconstructions_created=0,
            steps_created=0,
            components_skipped_unsupported=0,
            components_skipped_cycle=0,
        )

    # ── 2. Build in-memory graph ───────────────────────────────────────────────
    out_edges, in_edges, in_degree, all_event_ids = _build_graph(included)

    # ── 3. Find connected components ──────────────────────────────────────────
    components = _find_connected_components(all_event_ids, out_edges, in_edges)

    logger.debug(
        "build_reconstruction: investigation=%s components=%d",
        investigation_id,
        len(components),
    )

    # ── 4 & 5. Classify and reconstruct ───────────────────────────────────────
    reconstructions_created: int = 0
    steps_created: int = 0
    components_skipped_unsupported: int = 0
    components_skipped_cycle: int = 0

    for component in components:
        classification = _classify_component(component, out_edges, in_degree)

        if classification == "cycle":
            components_skipped_cycle += 1
            logger.debug(
                "build_reconstruction: skipping cyclic component "
                "investigation=%s nodes=%d",
                investigation_id,
                len(component),
            )
            continue

        if classification == "unsupported":
            components_skipped_unsupported += 1
            logger.debug(
                "build_reconstruction: skipping unsupported component "
                "investigation=%s nodes=%d",
                investigation_id,
                len(component),
            )
            continue

        # classification == "linear" — extract path and insert rows
        root = next(n for n in component if in_degree.get(n, 0) == 0)
        path = _extract_linear_path(root, out_edges)

        # ── 5a. INSERT Reconstruction ──────────────────────────────────────
        recon = Reconstruction(
            investigation_id=investigation_id,
            title="Relationship Reconstruction",
            description=None,
            status="DRAFT",
        )
        session.add(recon)
        await session.flush()  # materialise recon.id for FK in steps

        logger.info(
            "build_reconstruction: created Reconstruction id=%s "
            "investigation=%s path_length=%d",
            recon.id,
            investigation_id,
            len(path),
        )

        # ── 5b. INSERT ReconstructionStep rows ────────────────────────────
        step_order = _STEP_ORDER_INCREMENT
        local_steps = 0

        for event_id, incoming_rel_id in path:
            if incoming_rel_id is not None:
                # Emit the RELATIONSHIP step that connects the previous event
                # to this one, before the EVENT step for this event.
                session.add(
                    ReconstructionStep(
                        reconstruction_id=recon.id,
                        step_order=step_order,
                        step_type="RELATIONSHIP",
                        relationship_id=incoming_rel_id,
                        event_id=None,
                        gap_id=None,
                        analyst_note=None,
                    )
                )
                step_order += _STEP_ORDER_INCREMENT
                local_steps += 1

            session.add(
                ReconstructionStep(
                    reconstruction_id=recon.id,
                    step_order=step_order,
                    step_type="EVENT",
                    event_id=event_id,
                    relationship_id=None,
                    gap_id=None,
                    analyst_note=None,
                )
            )
            step_order += _STEP_ORDER_INCREMENT
            local_steps += 1

        await session.flush()  # surface constraint violations early

        steps_created += local_steps
        reconstructions_created += 1

        logger.debug(
            "build_reconstruction: steps inserted id=%s steps=%d",
            recon.id,
            local_steps,
        )

    logger.info(
        "build_reconstruction complete: investigation=%s "
        "reconstructions_created=%d steps_created=%d "
        "skipped_unsupported=%d skipped_cycle=%d",
        investigation_id,
        reconstructions_created,
        steps_created,
        components_skipped_unsupported,
        components_skipped_cycle,
    )

    return ReconstructionResult(
        investigation_id=investigation_id,
        reconstructions_created=reconstructions_created,
        steps_created=steps_created,
        components_skipped_unsupported=components_skipped_unsupported,
        components_skipped_cycle=components_skipped_cycle,
    )
