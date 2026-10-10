from datetime import datetime
from pydantic import BaseModel, ConfigDict


class EventOut(BaseModel):
    id: int
    event_time: datetime
    source: str
    product: str
    severity: str
    category: str
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    rule_name: str | None = None
    message: str
    raw_log: str | None = None

    model_config = ConfigDict(from_attributes=True)


class StatItem(BaseModel):
    name: str
    count: int


class OverviewOut(BaseModel):
    total_events: int
    critical_events: int
    high_events: int
    unique_src_ips: int
    by_severity: list[StatItem]
    by_product: list[StatItem]
    by_category: list[StatItem]
    recent_events: list[EventOut]


class SiemLink(BaseModel):
    name: str
    url: str
    enabled: bool
