from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.session import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    platform: Mapped[str] = mapped_column(String(128))
    sender: Mapped[str] = mapped_column(String(512))
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    threat_level: Mapped[str] = mapped_column(String(16), index=True)
    categories: Mapped[list] = mapped_column(JSON)
    tactics: Mapped[list] = mapped_column(JSON)
    triggers: Mapped[list] = mapped_column(JSON)
    recommended_action: Mapped[str] = mapped_column(String(16))
    provider: Mapped[str] = mapped_column(String(16))
    payload_json: Mapped[dict] = mapped_column(JSON)
    payment_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    raw_content: Mapped[str] = mapped_column(Text)
