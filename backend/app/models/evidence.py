"""
Evidence model.

Evidence represents the preserved source record of raw telemetry.
Once an Evidence row is written it must never be modified.

Evidence is not automatically trusted ground truth — telemetry may be
incomplete, corrupted, duplicated, misleading, or contradictory.
However, the original preserved form is immutable.

Immutability is enforced by:
  1. A CHECK constraint: is_immutable must always be TRUE.
  2. Application-layer policy: no UPDATE endpoints for Evidence.

At least one of original_content or storage_reference must be non-null,
enforced by a CHECK constraint.
"""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.conflict import ConflictEvidence
    from app.models.hypothesis import HypothesisElement
    from app.models.investigation import Investigation
    from app.models.normalized_event import NormalizedEvent


class Evidence(UUIDPrimaryKeyMixin, Base):
    """
    Immutable original security evidence record.

    Original evidence is never modified after import.  Normalized events
    reference this record to preserve traceability.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id", "content_hash", name="uq_evidence_investigation_hash"
        ),
        CheckConstraint(
            "is_immutable = TRUE",
            name="ck_evidence_is_immutable",
        ),
        CheckConstraint(
            "original_content IS NOT NULL OR storage_reference IS NOT NULL",
            name="ck_evidence_content_or_reference",
        ),
        CheckConstraint(
            "hash_algorithm IN ('SHA-256')",
            name="ck_evidence_hash_algorithm",
        ),
        Index("ix_evidence_investigation_id", "investigation_id"),
        Index("ix_evidence_source_type", "source_type"),
        Index("ix_evidence_content_hash", "content_hash"),
        Index("ix_evidence_imported_at", "imported_at"),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source_identifier: Mapped[str] = mapped_column(String(1000), nullable=False)
    original_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_reference: Mapped[str | None] = mapped_column(
        String(2000), nullable=True
    )
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    hash_algorithm: Mapped[str] = mapped_column(
        String(20), nullable=False, default="SHA-256", server_default="SHA-256"
    )
    source_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    imported_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    is_immutable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="TRUE"
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation", back_populates="evidence"
    )
    normalized_events: Mapped[list["NormalizedEvent"]] = relationship(
        "NormalizedEvent", back_populates="evidence", lazy="noload"
    )
    conflict_references: Mapped[list["ConflictEvidence"]] = relationship(
        "ConflictEvidence", back_populates="evidence", lazy="noload"
    )
    hypothesis_elements: Mapped[list["HypothesisElement"]] = relationship(
        "HypothesisElement", back_populates="evidence", lazy="noload"
    )
