import datetime

from sqlalchemy import String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AppSetting(Base):
    """Operating settings that must be changeable at runtime (also through the
    GUI) and must NOT be fixed per deploy in the image.

    Currently the only key is 'llm_config' (OpenAI-compatible Vector Agent
    provider: base_url/model/api_key). Deliberately a generic key-value store
    (JSONB) so further switches can be added without a migration.

    Security note: the api_key is stored here in plaintext (like
    scope_signing_secret in local development) - in production it belongs in
    Vault/SOPS. GET endpoints mask it (only 'set: yes/no')."""

    __tablename__ = "app_setting"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
