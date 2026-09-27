import uuid

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column


def uuid_pk() -> Mapped[uuid.UUID]:
    """Primary-key column backed by the DB-side uuidv7() default (migrations/0001_init_schema.sql)."""
    return mapped_column(
        PgUUID(as_uuid=True), primary_key=True, server_default=text("uuidv7()")
    )


def pg_enum(name: str, *values: str, **kw):
    # create_type=False: der Typ wird bereits von der SQL-Migration angelegt.
    return PgEnum(*values, name=name, create_type=False, **kw)
