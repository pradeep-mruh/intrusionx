"""
Investigation model.

An Investigation is the top-level case container.  Every other entity
in the domain belongs to an investigation.
"""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.analyst_action import AnalystAction
    from app.models.conflict import EvidenceConflict
    from app.models.entity import Entity
    from app.models.evidence import Evidence
    from app.models.gap import EvidenceGap
    from app.models.hypothesis import Hypothesis
    from app.models.normalized_event import NormalizedEvent
    from app.models.reconstruction import Reconstruction
    from app.models.relationship import Relationship


class Investigation(UUIDPrimaryKeyMixin, Base):
    """Top-level case container for an IntrusionX investigation."""

    __tablename__ = "investigation"
    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'IN_PROGRESS', 'CLOSED', 'ARCHIVED')",
            name="ck_investigation_status",
        ),
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="OPEN", server_default="OPEN"
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    evidence: Mapped[list["Evidence"]] = relationship(
        "Evidence", back_populates="investigation", lazy="noload"
    )
    events: Mapped[list["NormalizedEvent"]] = relationship(
        "NormalizedEvent", back_populates="investigation", lazy="noload"
    )
    entities: Mapped[list["Entity"]] = relationship(
        "Entity", back_populates="investigation", lazy="noload"
    )
    relationships: Mapped[list["Relationship"]] = relationship(
        "Relationship", back_populates="investigation", lazy="noload"
    )
    reconstructions: Mapped[list["Reconstruction"]] = relationship(
        "Reconstruction", back_populates="investigation", lazy="noload"
    )
    hypotheses: Mapped[list["Hypothesis"]] = relationship(
        "Hypothesis", back_populates="investigation", lazy="noload"
    )
    gaps: Mapped[list["EvidenceGap"]] = relationship(
        "EvidenceGap", back_populates="investigation", lazy="noload"
    )
    conflicts: Mapped[list["EvidenceConflict"]] = relationship(
        "EvidenceConflict", back_populates="investigation", lazy="noload"
    )
    analyst_actions: Mapped[list["AnalystAction"]] = relationship(
        "AnalystAction", back_populates="investigation", lazy="noload"
    )
