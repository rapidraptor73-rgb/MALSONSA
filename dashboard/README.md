# SIEM Unified Dashboard Starter

구조:

```text
SIEM / Agent / Collector
        |
        v
   Existing Log DB
        |
        v
 FastAPI Backend
        |
        +-- /api/overview
        +-- /api/events
        +-- /api/sources
        +-- /api/siem-links
        |
        v
 React Unified Dashboard
        |
        +-- Main Dashboard
        +-- Event Explorer
        +-- SIEM Sites
```

## 1. Backend 실행

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

기본값은 SQLite 데모 DB입니다.

PostgreSQL 예:

```env
DATABASE_URL=postgresql+psycopg://siem_reader:password@10.10.10.50:5432/siem
```

MySQL/MariaDB 예:

```env
DATABASE_URL=mysql+pymysql://siem_reader:password@10.10.10.50:3306/siem
```

> 실제 운영에서는 대시보드용 DB 계정에 SELECT 권한만 주는 것을 권장합니다.

## 2. Frontend 실행

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

## 3. DB 스키마가 이미 있는 경우

`backend/app/models.py`의 `SecurityEvent`를 실제 테이블/컬럼에 맞춰 수정하면 됩니다.

권장 공통 필드:

- id
- event_time
- source
- product
- severity
- category
- src_ip
- dst_ip
- username
- rule_name
- message
- raw_log

## 4. 외부 SIEM 사이트 주소

`backend/.env`의 URL만 수정합니다.

```env
WAZUH_URL=https://wazuh.example.local
KIBANA_URL=https://kibana.example.local
SPLUNK_URL=https://splunk.example.local
ZABBIX_URL=https://zabbix.example.local
PROMETHEUS_URL=https://prometheus.example.local
GRAFANA_URL=https://grafana.example.local
```

외부 관제 솔루션은 X-Frame-Options/CSP 때문에 iframe으로 안 열리는 경우가 많으므로
기본 구현은 새 탭으로 열도록 했습니다.
