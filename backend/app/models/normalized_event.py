"""
NormalizedEvent model.

A NormalizedEvent is a structured, queryable representation of one
observable security event derived from an Evidence record.

Design decisions:
  - Common fields (host, user, process, IP) have dedicated typed columns
    to support efficient indexing and correlation queries.
  - Rare or source-specific fields go into extended_attributes (JSONB)
    with a GIN index for path queries.
  - occurred_at is the event's actual time from the source log, not the
    import time (normalized_at).
  - All IP columns use PostgreSQL INET type for subnet-level queries.
  - process_id and parent_process_id are stored as strings — PIDs can
    wrap and are not globally unique across reboots.
"""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.conflict import ConflictEvidence
    from app.models.entity import EventEntityRef
    from app.models.evidence import Evidence
    from app.models.gap import GapEvent
    from app.models.hypothesis import HypothesisElement
    from app.models.investigation import Investigation
    from app.models.reconstruction import ReconstructionStep
    from app.models.relationship import RelationshipSupport


class NormalizedEvent(UUIDPrimaryKeyMixin, Base):
    """
    A structured security event derived from raw Evidence.

    NormalizedEvents never replace or overwrite their source Evidence.
    The evidence_id foreign key preserves the lineage chain.
    """

    __tablename__ = "normalized_event"
    __table_args__ = (
        CheckConstraint(
            "source_port IS NULL OR (source_port >= 0 AND source_port <= 65535)",
            name="ck_normalized_event_source_port",
        ),
        CheckConstraint(
            "destination_port IS NULL OR (destination_port >= 0 AND destination_port <= 65535)",
            name="ck_normalized_event_destination_port",
        ),
        CheckConstraint(
            "action_result IS NULL OR action_result IN ('SUCCESS', 'FAILURE', 'UNKNOWN')",
            name="ck_normalized_event_action_result",
        ),
        # Primary query pattern: timeline within an investigation
        Index(
            "ix_normalized_event_investigation_occurred",
            "investigation_id",
            "occurred_at",
        ),
        Index("ix_normalized_event_evidence_id", "evidence_id"),
        Index("ix_normalized_event_event_type", "event_type"),
        Index("ix_normalized_event_event_category", "event_category"),
        Index("ix_normalized_event_source_host", "source_host"),
        Index("ix_normalized_event_source_user", "source_user"),
        Index("ix_normalized_event_source_ip", "source_ip"),
        Index("ix_normalized_event_destination_ip", "destination_ip"),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # Timing
    occurred_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    normalized_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Classification
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    event_category: Mapped[str] = mapped_column(String(50), nullable=False)

    # Host and identity
    source_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_account: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Process fields
    process_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    process_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    parent_process_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    parent_process_id: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Network fields — INET type validates and enables subnet queries
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # File and domain
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Action
    action: Mapped[str | None] = mapped_column(String(100), nullable=True)
    action_result: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Source-specific fields that don't map to a common column
    extended_attributes: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation", back_populates="events"
    )
    evidence: Mapped["Evidence"] = relationship(
        "Evidence", back_populates="normalized_events"
    )
    entity_refs: Mapped[list["EventEntityRef"]] = relationship(
        "EventEntityRef", back_populates="event", lazy="noload"
    )
    relationship_supports: Mapped[list["RelationshipSupport"]] = relationship(
        "RelationshipSupport", back_populates="event", lazy="noload"
    )
    reconstruction_steps: Mapped[list["ReconstructionStep"]] = relationship(
        "ReconstructionStep",
        primaryjoin="NormalizedEvent.id == ReconstructionStep.event_id",
        back_populates="event",
        lazy="noload",
    )
    gap_events: Mapped[list["GapEvent"]] = relationship(
        "GapEvent", back_populates="event", lazy="noload"
    )
    hypothesis_elements: Mapped[list["HypothesisElement"]] = relationship(
        "HypothesisElement", back_populates="event", lazy="noload"
    )
    conflict_references: Mapped[list["ConflictEvidence"]] = relationship(
        "ConflictEvidence", back_populates="event", lazy="noload"
    )
