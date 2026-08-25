"""
Relationship and RelationshipSupport models.

Relationship connects two events or entities and explains why they are
related.  The status field distinguishes system-proposed inferences from
analyst-confirmed or analyst-rejected decisions.

Explicit nullable foreign keys (source_event_id, source_entity_id,
target_event_id, target_entity_id) provide database-level referential
integrity.  CHECK constraints enforce that exactly one source FK and
exactly one target FK are populated.

RelationshipSupport links a Relationship to the specific NormalizedEvents
that justify it.  One relationship may be supported by multiple events.
"""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship as sa_relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.entity import Entity
    from app.models.hypothesis import HypothesisElement
    from app.models.investigation import Investigation
    from app.models.normalized_event import NormalizedEvent
    from app.models.reconstruction import ReconstructionStep


class Relationship(UUIDPrimaryKeyMixin, Base):
    """
    A typed, explainable connection between two events or entities.

    Status lifecycle:
      SYSTEM_PROPOSED → ANALYST_CONFIRMED
      SYSTEM_PROPOSED → ANALYST_REJECTED
      ANALYST_CONFIRMED → ANALYST_REJECTED  (analyst reverses decision)

    Every status change is recorded in AnalystAction (append-only).
    This table stores the current state; AnalystAction preserves history.
    """

    __tablename__ = "relationship"
    __table_args__ = (
        CheckConstraint(
            "status IN ('SYSTEM_PROPOSED', 'ANALYST_CONFIRMED', 'ANALYST_REJECTED')",
            name="ck_relationship_status",
        ),
        # Exactly one source FK populated
        CheckConstraint(
            "(source_event_id IS NOT NULL AND source_entity_id IS NULL) OR "
            "(source_event_id IS NULL AND source_entity_id IS NOT NULL)",
            name="ck_relationship_source_one_fk",
        ),
        # Exactly one target FK populated
        CheckConstraint(
            "(target_event_id IS NOT NULL AND target_entity_id IS NULL) OR "
            "(target_event_id IS NULL AND target_entity_id IS NOT NULL)",
            name="ck_relationship_target_one_fk",
        ),
        # Prevent self-references between identical events or entities
        CheckConstraint(
            "(source_event_id IS NULL OR target_event_id IS NULL OR source_event_id != target_event_id) AND "
            "(source_entity_id IS NULL OR target_entity_id IS NULL OR source_entity_id != target_entity_id)",
            name="ck_relationship_no_self_reference",
        ),
        Index("ix_relationship_investigation_id", "investigation_id"),
        Index("ix_relationship_type", "relationship_type"),
        Index("ix_relationship_status", "status"),
        Index("ix_relationship_source_event_id", "source_event_id"),
        Index("ix_relationship_source_entity_id", "source_entity_id"),
        Index("ix_relationship_target_event_id", "target_event_id"),
        Index("ix_relationship_target_entity_id", "target_entity_id"),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False)

    # Explicit typed foreign keys for source
    source_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_event.id", ondelete="RESTRICT"),
        nullable=True,
    )
    source_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("entity.id", ondelete="RESTRICT"),
        nullable=True,
    )

    # Explicit typed foreign keys for target
    target_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_event.id", ondelete="RESTRICT"),
        nullable=True,
    )
    target_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("entity.id", ondelete="RESTRICT"),
        nullable=True,
    )

    creation_method: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="SYSTEM_PROPOSED",
        server_default="SYSTEM_PROPOSED",
    )
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    status_changed_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    investigation: Mapped["Investigation"] = sa_relationship(
        "Investigation", back_populates="relationships"
    )
    source_event: Mapped["NormalizedEvent | None"] = sa_relationship(
        "NormalizedEvent",
        foreign_keys=[source_event_id],
        lazy="noload",
    )
    source_entity: Mapped["Entity | None"] = sa_relationship(
        "Entity",
        foreign_keys=[source_entity_id],
        lazy="noload",
    )
    target_event: Mapped["NormalizedEvent | None"] = sa_relationship(
        "NormalizedEvent",
        foreign_keys=[target_event_id],
        lazy="noload",
    )
    target_entity: Mapped["Entity | None"] = sa_relationship(
        "Entity",
        foreign_keys=[target_entity_id],
        lazy="noload",
    )

    support_records: Mapped[list["RelationshipSupport"]] = sa_relationship(
        "RelationshipSupport", back_populates="relationship", lazy="noload"
    )
    reconstruction_steps: Mapped[list["ReconstructionStep"]] = sa_relationship(
        "ReconstructionStep",
        primaryjoin="Relationship.id == ReconstructionStep.relationship_id",
        back_populates="relationship",
        lazy="noload",
    )
    hypothesis_elements: Mapped[list["HypothesisElement"]] = sa_relationship(
        "HypothesisElement",
        primaryjoin="Relationship.id == HypothesisElement.relationship_id",
        back_populates="relationship",
        lazy="noload",
    )


class RelationshipSupport(UUIDPrimaryKeyMixin, Base):
    """
    Links a Relationship to the NormalizedEvents that justify it.

    Answers: "Why does IntrusionX believe these two events/entities are related?"
    """

    __tablename__ = "relationship_support"
    __table_args__ = (
        UniqueConstraint(
            "relationship_id", "event_id", name="uq_relationship_support"
        ),
        Index("ix_relationship_support_relationship_id", "relationship_id"),
        Index("ix_relationship_support_event_id", "event_id"),
    )

    relationship_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("relationship.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_event.id", ondelete="RESTRICT"),
        nullable=False,
    )
    support_reason: Mapped[str] = mapped_column(String(200), nullable=False)

    # Relationships
    relationship: Mapped["Relationship"] = sa_relationship(
        "Relationship", back_populates="support_records"
    )
    event: Mapped["NormalizedEvent"] = sa_relationship(
        "NormalizedEvent", back_populates="relationship_supports"
    )
