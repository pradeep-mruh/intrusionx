"""
EvidenceConflict and ConflictEvidence models.

An EvidenceConflict is an explicit representation of contradictory
telemetry.  It forces the investigator to confront and resolve the
contradiction rather than silently ignoring it.

ConflictEvidence is the junction table linking an EvidenceConflict
to the specific Evidence records or NormalizedEvents involved.
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
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.evidence import Evidence
    from app.models.investigation import Investigation
    from app.models.normalized_event import NormalizedEvent


class EvidenceConflict(UUIDPrimaryKeyMixin, Base):
    """
    An explicit representation of contradictory security telemetry.

    Conflicts are never deleted.  Resolution is recorded in
    analyst_resolution with a status of RESOLVED or DISMISSED.
    """

    __tablename__ = "evidence_conflict"
    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'RESOLVED', 'DISMISSED')",
            name="ck_evidence_conflict_status",
        ),
        Index("ix_evidence_conflict_investigation_id", "investigation_id"),
        Index("ix_evidence_conflict_status", "status"),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    conflict_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="OPEN", server_default="OPEN"
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    analyst_resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    resolved_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation", back_populates="conflicts"
    )
    conflict_evidence: Mapped[list["ConflictEvidence"]] = relationship(
        "ConflictEvidence", back_populates="conflict", lazy="noload"
    )


class ConflictEvidence(UUIDPrimaryKeyMixin, Base):
    """
    Links an EvidenceConflict to the Evidence or NormalizedEvents involved.

    At least one of evidence_id or event_id must be set.
    Enforced by a CHECK constraint.
    """

    __tablename__ = "conflict_evidence"
    __table_args__ = (
        CheckConstraint(
            "evidence_id IS NOT NULL OR event_id IS NOT NULL",
            name="ck_conflict_evidence_has_reference",
        ),
        Index("ix_conflict_evidence_conflict_id", "conflict_id"),
        Index("ix_conflict_evidence_evidence_id", "evidence_id"),
        Index("ix_conflict_evidence_event_id", "event_id"),
    )

    conflict_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_conflict.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="RESTRICT"),
        nullable=True,
    )
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_event.id", ondelete="RESTRICT"),
        nullable=True,
    )

    # Relationships
    conflict: Mapped["EvidenceConflict"] = relationship(
        "EvidenceConflict", back_populates="conflict_evidence"
    )
    evidence: Mapped["Evidence | None"] = relationship(
        "Evidence", back_populates="conflict_references"
    )
    event: Mapped["NormalizedEvent | None"] = relationship(
        "NormalizedEvent", back_populates="conflict_references"
    )
