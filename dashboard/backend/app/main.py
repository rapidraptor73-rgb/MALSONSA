from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, distinct, func, select
from sqlalchemy.orm import Session

from .config import settings
from .database import Base, SessionLocal, engine, get_db
from .models import SecurityEvent
from .schemas import EventOut, OverviewOut, SiemLink, StatItem
from .seed import seed_demo_data


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    # 데모용. 실제 운영 DB에서는 DBA가 스키마를 관리하고 이 부분을 제거해도 됩니다.
    Base.metadata.create_all(bind=engine)

    if settings.database_url.startswith("sqlite"):
        with SessionLocal() as db:
            seed_demo_data(db)


def time_cutoff(hours: int) -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)


def grouped_stats(
    db: Session,
    column,
    cutoff: datetime,
    limit: int = 10,
) -> list[StatItem]:
    stmt = (
        select(column, func.count(SecurityEvent.id))
        .where(SecurityEvent.event_time >= cutoff)
        .group_by(column)
        .order_by(desc(func.count(SecurityEvent.id)))
        .limit(limit)
    )
    return [StatItem(name=str(name or "unknown"), count=count) for name, count in db.execute(stmt)]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get(f"{settings.api_prefix}/overview", response_model=OverviewOut)
def overview(
    hours: int = Query(default=24, ge=1, le=24 * 30),
    db: Session = Depends(get_db),
):
    cutoff = time_cutoff(hours)

    total = db.scalar(
        select(func.count(SecurityEvent.id))
        .where(SecurityEvent.event_time >= cutoff)
    ) or 0

    critical = db.scalar(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.event_time >= cutoff,
            func.lower(SecurityEvent.severity) == "critical",
        )
    ) or 0

    high = db.scalar(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.event_time >= cutoff,
            func.lower(SecurityEvent.severity) == "high",
        )
    ) or 0

    unique_src_ips = db.scalar(
        select(func.count(distinct(SecurityEvent.src_ip)))
        .where(
            SecurityEvent.event_time >= cutoff,
            SecurityEvent.src_ip.is_not(None),
        )
    ) or 0

    recent = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.event_time >= cutoff)
        .order_by(SecurityEvent.event_time.desc())
        .limit(12)
    ).all()

    return OverviewOut(
        total_events=total,
        critical_events=critical,
        high_events=high,
        unique_src_ips=unique_src_ips,
        by_severity=grouped_stats(db, SecurityEvent.severity, cutoff),
        by_product=grouped_stats(db, SecurityEvent.product, cutoff),
        by_category=grouped_stats(db, SecurityEvent.category, cutoff),
        recent_events=[EventOut.model_validate(x) for x in recent],
    )


@app.get(f"{settings.api_prefix}/events", response_model=list[EventOut])
def events(
    hours: int = Query(default=24, ge=1, le=24 * 30),
    severity: str | None = None,
    product: str | None = None,
    category: str | None = None,
    ip: str | None = None,
    q: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    stmt = select(SecurityEvent).where(
        SecurityEvent.event_time >= time_cutoff(hours)
    )

    if severity:
        stmt = stmt.where(func.lower(SecurityEvent.severity) == severity.lower())

    if product:
        stmt = stmt.where(SecurityEvent.product == product)

    if category:
        stmt = stmt.where(SecurityEvent.category == category)

    if ip:
        stmt = stmt.where(
            (SecurityEvent.src_ip == ip) | (SecurityEvent.dst_ip == ip)
        )

    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            SecurityEvent.message.ilike(like)
            | SecurityEvent.rule_name.ilike(like)
            | SecurityEvent.username.ilike(like)
        )

    stmt = (
        stmt.order_by(SecurityEvent.event_time.desc())
        .offset(offset)
        .limit(limit)
    )

    return [EventOut.model_validate(x) for x in db.scalars(stmt).all()]


@app.get(f"{settings.api_prefix}/sources")
def sources(db: Session = Depends(get_db)):
    products = [
        row[0]
        for row in db.execute(
            select(distinct(SecurityEvent.product))
            .where(SecurityEvent.product.is_not(None))
            .order_by(SecurityEvent.product)
        )
    ]

    categories = [
        row[0]
        for row in db.execute(
            select(distinct(SecurityEvent.category))
            .where(SecurityEvent.category.is_not(None))
            .order_by(SecurityEvent.category)
        )
    ]

    return {
        "products": products,
        "categories": categories,
        "severities": ["critical", "high", "medium", "low", "info"],
    }


@app.get(f"{settings.api_prefix}/siem-links", response_model=list[SiemLink])
def siem_links():
    data = [
        ("Wazuh", settings.wazuh_url),
        ("Kibana / ELK", settings.kibana_url),
        ("Splunk", settings.splunk_url),
        ("Zabbix", settings.zabbix_url),
        ("Prometheus", settings.prometheus_url),
        ("Grafana", settings.grafana_url),
        ("Snort", settings.snort_url),
        ("Suricata", settings.suricata_url),
        ("pfSense", settings.pfsense_url),
    ]

    return [
        SiemLink(name=name, url=url, enabled=bool(url.strip()))
        for name, url in data
    ]
