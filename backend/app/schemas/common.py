"""
Common Pydantic base configuration and shared types.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ORMBase(BaseModel):
    """Base model configured for ORM compatibility."""

    model_config = ConfigDict(from_attributes=True)


class IdentifiableSchema(ORMBase):
    """Base schema with UUID primary key."""

    id: UUID


class TimestampedSchema(IdentifiableSchema):
    """Base schema with standard timestamps."""

    created_at: datetime
    updated_at: datetime
