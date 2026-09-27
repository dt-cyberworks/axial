import datetime

from sqlalchemy import String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AppSetting(Base):
    """Betriebs-Einstellungen, die zur Laufzeit (auch ueber die GUI) aenderbar
    sein muessen und NICHT je Deploy im Image festliegen sollen.

    Aktuell einziger Schluessel: 'llm_config' (OpenAI-kompatibler Vector-Agent-
    Provider: base_url/model/api_key). Bewusst generisches Key-Value (JSONB),
    damit weitere Betriebsschalter ohne Migration dazukommen koennen.

    Sicherheitshinweis: der api_key liegt hier im Klartext (wie
    scope_signing_secret im M1-Skeleton) - in Produktion gehoert er in
    Vault/SOPS. GET-Endpunkte maskieren ihn (nur 'gesetzt: ja/nein')."""

    __tablename__ = "app_setting"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
