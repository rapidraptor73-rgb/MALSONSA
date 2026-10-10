# 운영 서버와 GitHub 작업

## 확인한 구조

- SSH: `root@172.16.16.141` (비밀번호는 저장하지 않음).
- Flask: `/opt/soc/backend`, Python 3.9 런타임 `/opt/soc/venv`.
- 정적 웹: `/usr/share/nginx/html/soc/frontend`.
- 서비스: `soc-siem`, `soc-event-enricher`, `nginx`, `rsyslog`.
- 2026-10-10 확인 당시 4개 서비스가 active이고 `/api/health`는 HTTP 200.

소스 수정은 로컬 `D:\project`에서 수행합니다. 운영 디렉터리를 Git checkout으로 덮어쓰지 않습니다.
가져오기 작업은 운영 코드, DB, 설정과 서비스 상태를 변경하지 않습니다.

## 서버의 직접 Git 연결

확인 당시 서버에는 Git이 없고 `api.github.com` DNS 조회가 실패했습니다.
직접 clone/pull하려면 패키지 저장소 접근, Git 설치, GitHub DNS/HTTPS 연결이 필요합니다.
서버 네트워크 설정은 이번 작업에서 변경하지 않았습니다.
조건을 해결한 뒤 별도 checkout을 사용합니다.

```bash
git clone --branch main https://github.com/rapidraptor73-rgb/MALSONSA.git /opt/malsonsa
```

서버는 검증된 main 릴리스를 읽는 용도로 사용합니다. 공개 저장소의 clone/pull에는 개인 토큰이 필요하지 않습니다.

## 배포 순서

1. feature PR의 CI와 기능 검증 후 develop에 병합합니다.
2. develop의 통합 테스트, 브라우저 UI, 테스트 로그 수신을 검증합니다.
3. develop → main PR을 병합하고 배포할 SHA를 기록합니다.
4. main 소스를 별도 staging 디렉터리에 전달합니다. GitHub 연결이 불가능하면 로컬 `git archive <검증된-main-SHA>` 결과를 SSH/SCP로 전달합니다.
5. 기존 코드·설정·DB를 서버 내부에 백업합니다.
6. 필요한 코드만 적용하고 DB, 로그, offset, 개인키를 덮어쓰지 않습니다.
7. 설정 변경 시 `nginx -t`, `rsyslogd -N1`을 검사하고 관련 서비스에만 적용합니다.
8. health, 서비스, 수집, Hold/Similar, 최신 시간 필터를 확인하고 실패하면 백업 코드로 복구합니다.

rsyslog 기본 설정 전체와 TLS 인증서는 포함하지 않습니다.
`deploy/`는 참고 스냅샷이며 일괄 설치 스크립트가 아닙니다.
자동 배포나 SSH 비밀번호 기반 GitHub Actions는 구성하지 않았습니다.
