# MALSONSA — 자체 SIEM

## v1.1 자동 설치 패키지

[v1.1 릴리스](https://github.com/rapidraptor73-rgb/MALSONSA/releases/tag/v1.1)의
`malsonsa-v1.1.tar.gz`를 새 Linux 서버에 풀고 `sudo bash install.sh`로 구축할 수 있습니다.
기본 접속은 로컬로 제한됩니다. 관제망·도메인·HTTPS 설정과 업그레이드는
[설치 안내](docs/INSTALL.md)를 참고하세요.
패키지는 `python scripts/build_release.py`로 생성합니다.

2026-10-10 실행 중인 서버의 자체 SIEM 소스를 가져온 개발 저장소입니다.
DB 수집 보정, 화이트 테마 및 에이전트별 관제 룰 기능을 추가했습니다.

## 에이전트별 관제 룰셋

메인 메뉴의 **관제 룰셋 추가**에서 에이전트별 조건, 추정 공격명, 점수, 판단 이유를 등록합니다.
반복 발생 조건과 저장 전 테스트를 지원하며 상관분석에서 관찰값과 함께 표시합니다.
[룰 설정 안내](docs/RULES.md)를 참고하세요. v1.1에는 에이전트 룰, 사전 위험도,
저장한 로그, SRC IP 위험도와 중앙 MariaDB 저장·앵커 색인이 포함됩니다.
기존 v1.0 릴리스 파일은 변경하지 않습니다.

## 구성

- `backend/`: Flask SIEM. 기본 단일 서버 SQLite 모드와 중앙 MariaDB 모드를 지원하며 rsyslog 정규화, MITRE 태그, HOLD/Similar, 호스트와 룰을 관리합니다.
- `dashboard/frontend/`: Nginx 정적 대시보드, `rsyslog.html`, `hosts.html` 및 React 소스.
- `dashboard/backend/`: 서버에 함께 존재하는 FastAPI 시작 코드. 운영 Flask API와 별개이며 Docker Compose는 이 FastAPI 구성용입니다.
- `deploy/`: systemd, rsyslog, Nginx 설정 스냅샷. 인증서 파일은 제외합니다.
- `tests/`: 합성 로그와 임시 DB를 사용하는 통합 테스트.

DB, 실제 로그, 수집 offset, 비밀번호, 개인키, 가상환경과 백업은 Git에 포함하지 않습니다.

## 중앙 DB와 앵커 색인

관제 agent가 primary DB로 syslog를 보내면 MariaDB가 원본을 저장합니다. WAS는 원본을 읽어 메모리에서 분석하고 결과를 DB 서버에 반환합니다. DB 서버는 IP 최상위·앵커별 하위 디렉터리와 Similar 튜플 TXT/위치 TXT를 함께 만들어 HOLD에서 다시 참조합니다. 대상 호스트 로그·분석 파일은 WAS에 저장하지 않습니다.

[중앙 저장·이관·색인 운영 안내](docs/CENTRAL_STORAGE.md)를 참고하세요.
`install.sh`는 단일 서버 구축용입니다. 중앙 배치는 패키지의 `deploy/central/` 도구로
DB·agent·WAS를 역할별로 구성하며, 단일 서버 업그레이드 명령으로 덮어쓰지 않습니다.

## 작업 흐름

```bash
git switch develop
git pull --ff-only
git switch -c feature/<기능명>
```

기능 완성과 테스트 후 `feature/* → develop` PR을 만듭니다.
통합 테스트와 수동 검증이 끝난 `develop`만 `main`에 PR로 병합합니다.
main 병합과 릴리스 게시에는 사용자의 명시적인 게시 요청이 필요합니다.
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
단일 서버 검색은 SQLite 필드 인덱스를 사용합니다. 중앙 모드는 MariaDB SQL 인덱스와
DB 서버의 앵커 디렉터리·Similar 위치/튜플 파일을 함께 사용합니다.
전용 전문검색 인버티드 인덱스는 구현된 것으로 간주하지 않습니다.

운영 승격 전 확인할 사항:

- 실제 서비스 로그에서 SRC/DST 추출, 호스트별 이벤트·Similar 표시.
- 브라우저에서 마이크로초·시간대가 포함된 시각의 파싱과 최신 시간 필터.
- 로그 회전, 수집 offset, 재시작, 기존 DB 스키마와의 호환성.
- systemd 스냅샷의 `SOC_DB`, `SOC_LOG_FILE`은 현 앱에서 읽지 않습니다. 실제 앱의 `SOC_DB_PATH`, `SOC_RSYSLOG_LOG`, `SOC_STATE_DIR`와 일치 여부를 점검해야 합니다.
- 기존 설치의 IP 변환은 `SOC_IP_MAP`으로 설정할 수 있습니다. 자동 설치는 새 환경의 IP를 유지합니다.

[운영·배포 안내](docs/operations.md)를 참고하세요.

## 상관분석 화면

메인·상관분석·호스트 관리 화면은 공통 `theme.css`의 화이트 테마를 사용합니다.
상관분석 화면의 우선순위는 앵커와 비교한 `similar_score` 기준입니다:
Critical 120점 이상, High 90–119점, Medium 60–89점, Low 0–59점.
이 표시는 검토 우선순위이며 개별 로그의 확정된 공격 심각도와 구분합니다.
기존 점수 계산은 변경하지 않았습니다. 근거 펼침 영역에는 각 가점, 일치한 필드,
시간 차이와 분류 이유가 표시됩니다. 우선순위 건수는 현재 조회된 유사 로그 기준입니다.
