from datetime import datetime, timedelta, timezone
from random import choice, randint

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import SecurityEvent


def seed_demo_data(db: Session) -> None:
    exists = db.scalar(select(SecurityEvent.id).limit(1))
    if exists:
        return

    products = ["Wazuh", "Suricata", "Snort", "Windows", "Linux", "pfSense"]
    severities = ["info", "low", "medium", "high", "critical"]
    categories = [
        "authentication",
        "network",
        "malware",
        "web_attack",
        "scan",
        "policy",
    ]

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    rows = []
    for i in range(120):
        severity = choice(severities)
        product = choice(products)
        category = choice(categories)
        src = f"10.10.{randint(1, 4)}.{randint(10, 240)}"
        dst = f"172.16.{randint(10, 20)}.{randint(10, 240)}"

        rows.append(
            SecurityEvent(
                event_time=now - timedelta(minutes=randint(0, 1440)),
                source=f"{product.lower()}-collector",
                product=product,
                severity=severity,
                category=category,
                src_ip=src,
                dst_ip=dst,
                username=choice(["admin", "user1", "svc-web", None]),
                rule_name=f"{category.upper()}_{severity.upper()}",
                message=f"Demo {category} event detected from {src} to {dst}",
                raw_log=f'{{"demo":true,"product":"{product}","severity":"{severity}"}}',
            )
        )

    db.add_all(rows)
    db.commit()
