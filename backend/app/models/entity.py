"""
Entity and EventEntityRef models.

Entity represents a real-world observable object — a host, user, process,
IP address, domain, file, or account — that appears across multiple events.

Design decision: single polymorphic Entity table with entity_type discriminator.
This avoids JOIN complexity in correlation queries and allows uniform
graph traversal across all entity types.

EventEntityRef is the junction table linking NormalizedEvents to Entities.
One event may involve multiple entities in different roles.
"""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.investigation import Investigation
    from app.models.normalized_event import NormalizedEvent

_ENTITY_TYPES = (
    "HOST",
    "USER",
    "PROCESS",
    "IP_ADDRESS",
    "DOMAIN",
    "FILE",
    "ACCOUNT",
)

_ENTITY_ROLES = (
    "SOURCE_HOST",
    "TARGET_HOST",
    "ACTING_USER",
    "ACTING_PROCESS",
    "PARENT_PROCESS",
    "SOURCE_IP",
    "DESTINATION_IP",
    "TARGET_FILE",
    "TARGET_DOMAIN",
)


class Entity(UUIDPrimaryKeyMixin, Base):
    """
    A real-world observable object referenced across multiple events.

    Entities are scoped to an investigation.  The same hostname in two
    different investigations produces two separate Entity records.

    Deduplication key: (investigation_id, entity_type, canonical_value).
    """

    __tablename__ = "entity"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "entity_type",
            "canonical_value",
            name="uq_entity_investigation_type_value",
        ),
        CheckConstraint(
            f"entity_type IN {_ENTITY_TYPES}",
            name="ck_entity_type",
        ),
        Index("ix_entity_investigation_id", "investigation_id"),
        Index("ix_entity_type", "entity_type"),
        Index("ix_entity_canonical_value", "canonical_value"),
        Index(
            "ix_entity_lookup",
            "investigation_id",
            "entity_type",
            "canonical_value",
        ),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    canonical_value: Mapped[str] = mapped_column(String(1000), nullable=False)
    attributes: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    first_seen_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation", back_populates="entities"
    )
    event_refs: Mapped[list["EventEntityRef"]] = relationship(
        "EventEntityRef", back_populates="entity", lazy="noload"
    )


class EventEntityRef(UUIDPrimaryKeyMixin, Base):
    """
    Junction table: links NormalizedEvents to Entities with a typed role.

    One event may reference multiple entities (e.g., a network event
    references both a source IP entity and a destination IP entity).
    """

    __tablename__ = "event_entity_ref"
    __table_args__ = (
        UniqueConstraint(
            "event_id", "entity_id", "role", name="uq_event_entity_ref"
        ),
        CheckConstraint(
            f"role IN {_ENTITY_ROLES}",
            name="ck_event_entity_ref_role",
        ),
        Index("ix_event_entity_ref_event_id", "event_id"),
        Index("ix_event_entity_ref_entity_id", "entity_id"),
        Index("ix_event_entity_ref_entity_role", "entity_id", "role"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_event.id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("entity.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(50), nullable=False)

    # Relationships
    event: Mapped["NormalizedEvent"] = relationship(
        "NormalizedEvent", back_populates="entity_refs"
    )
    entity: Mapped["Entity"] = relationship("Entity", back_populates="event_refs")
