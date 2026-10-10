from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, Index
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_time: Mapped[datetime] = mapped_column(DateTime, index=True)
    source: Mapped[str] = mapped_column(String(100), index=True, default="unknown")
    product: Mapped[str] = mapped_column(String(100), index=True, default="unknown")
    severity: Mapped[str] = mapped_column(String(20), index=True, default="info")
    category: Mapped[str] = mapped_column(String(100), index=True, default="other")

    src_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(150), nullable=True)

    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    raw_log: Mapped[str | None] = mapped_column(Text, nullable=True)


Index("ix_security_events_time_severity", SecurityEvent.event_time, SecurityEvent.severity)
Index("ix_security_events_time_product", SecurityEvent.event_time, SecurityEvent.product)
