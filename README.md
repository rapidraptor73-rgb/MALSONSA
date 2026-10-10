# MALSONSA — 자체 SIEM

2026-10-10 실행 중인 서버의 자체 SIEM 소스를 가져온 개발 저장소입니다.
운영 코드의 기능은 변경하지 않았습니다.

## 구성

- `backend/`: `/opt/soc/backend`의 운영 Flask + SQLite SIEM. rsyslog 수집, 이벤트 정규화, MITRE 태그, 앵커 Hold, 점수 기반 Similar 검색, 호스트 관리.
- `dashboard/frontend/`: Nginx 정적 대시보드, `rsyslog.html`, `hosts.html` 및 React 소스.
- `dashboard/backend/`: 서버에 함께 존재하는 FastAPI 시작 코드. 운영 Flask API와 별개이며 Docker Compose는 이 FastAPI 구성용입니다.
- `deploy/`: systemd, rsyslog, Nginx 설정 스냅샷. 인증서 파일은 제외합니다.
- `tests/`: 합성 로그와 임시 DB를 사용하는 통합 테스트.

DB, 실제 로그, 수집 offset, 비밀번호, 개인키, 가상환경과 백업은 Git에 포함하지 않습니다.

## 작업 흐름

```bash
git switch develop
git pull --ff-only
git switch -c feature/<기능명>
```

기능 완성과 테스트 후 `feature/* → develop` PR을 만듭니다.
통합 테스트와 수동 검증이 끝난 `develop`만 `main`에 PR로 병합합니다.
CI는 SIEM 테스트, Python 문법, React 빌드 및 main PR의 소스 브랜치를 검사합니다.
운영 배포는 main의 검증된 커밋을 대상으로 별도로 진행합니다.

```bash
python -m venv .venv
# Linux: source .venv/bin/activate
# PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
python -m unittest discover -s tests -v
python -m compileall -q backend dashboard/backend/app
```

React 빌드는 Node.js 22 및 pnpm 11.25.0을 사용합니다.

```bash
cd dashboard/frontend
pnpm install --frozen-lockfile
pnpm run build
```

Gunicorn은 Linux에서 실행합니다. 운영 Flask 코드는 import 시 스키마를 준비하고
수집 스레드를 시작합니다. 개발 테스트에 운영 DB를 지정하지 마세요.
테스트는 시작 동작을 격리하고 임시 DB에만 접근합니다.

## 프로젝트 맥락과 남은 검증

[기존 대화](https://chatgpt.com/share/6ac9f118-1f1c-83ec-b129-dae8a684d1f0)의
rsyslog 수집, 키/값 구조화, 앵커 Hold, 점수·시간·공격 단계 상관분석을 이어갑니다.
현재 검색은 SQLite 필드 인덱스와 SQL 검색입니다. 제안된 전용 인버티드 인덱스는 구현된 것으로 간주하지 않습니다.

운영 승격 전 확인할 사항:

- 실제 서비스 로그에서 SRC/DST 추출, 호스트별 이벤트·Similar 표시.
- 브라우저에서 마이크로초·시간대가 포함된 시각의 파싱과 최신 시간 필터.
- 로그 회전, 수집 offset, 재시작, 기존 DB 스키마와의 호환성.
- systemd 스냅샷의 `SOC_DB`, `SOC_LOG_FILE`은 현 앱에서 읽지 않습니다. 실제 앱의 `SOC_DB_PATH`, `SOC_RSYSLOG_LOG`, `SOC_STATE_DIR`와 일치 여부를 점검해야 합니다.
- `172.16.16.141 → 203.230.52.214` 변환이 하드코딩돼 있어 다른 환경 배포 전 설정화가 필요합니다.

[운영·배포 안내](docs/operations.md)를 참고하세요.

## 상관분석 화면

메인·상관분석·호스트 관리 화면은 공통 `theme.css`의 화이트 테마를 사용합니다.
상관분석 화면의 우선순위는 앵커와 비교한 `similar_score` 기준입니다:
Critical 120점 이상, High 90–119점, Medium 60–89점, Low 0–59점.
이 표시는 검토 우선순위이며 개별 로그의 확정된 공격 심각도와 구분합니다.
기존 점수 계산은 변경하지 않았습니다. 근거 펼침 영역에는 각 가점, 일치한 필드,
시간 차이와 분류 이유가 표시됩니다. 우선순위 건수는 현재 조회된 유사 로그 기준입니다.
