# 중앙 MariaDB 수집과 앵커 색인

## 실제 배치

| 역할 | 관리 SSH | SIEM 통신 주소 |
|---|---|---|
| primary DB | 172.16.16.130 | 203.230.52.183 |
| 관제 agent | 172.16.12.20 | 203.230.52.185 |
| WAS | 172.16.16.141 | 203.230.52.214 |

SSH 암호나 생성된 DB 암호를 저장소에 넣지 않는다. main과 릴리스는 사용자 요청 전까지 게시하지 않는다.

agent rsyslog → primary TCP 514 → `ommysql` → MariaDB `malsonsa.raw_logs` → WAS `soc-central-worker`의 메모리 정규화·상관분석 → MariaDB `events`와 `analysis_results` → DB 서버의 `soc-central-exporter` → JSON과 TXT 색인 파일 순서이다. Wazuh 등 DB 서버의 기존 서비스는 별도로 유지한다.

WAS의 API도 중앙 MariaDB를 사용한다. HOLD·즐겨찾기·관제 호스트·룰을 중앙 DB에 보존하며, WAS에는 대상 agent 원본/분석 파일을 만들지 않는다. WAS 자신의 로컬 syslog 파일은 허용한다. 기존 SQLite enricher는 중앙 모드에서 중지한다. WAS의 옛 수신 포트로 들어온 외부 로그는 저장하지 않으므로 agent는 반드시 primary DB 주소로 전송해야 한다.

## 합친 거시적 / 미시적 색인

물리적인 디렉터리는 **DB 서버**의 `/var/lib/malsonsa/index`에 있으며 MariaDB datadir와는 분리한다. MariaDB 내부 저장 파일을 직접 건드리지 않는다.

```text
<관제 호스트 IP>/
  anchors/src/<SRC>/dst/<DST>/user/<USER>/time/YYYY/MM/DD/HH/<event-id>.json
  micro/src/<SRC>/YYYY/MM/DD/HH/<event-id>.json
  micro/event/<EVENT>/YYYY/MM/DD/HH/<event-id>.json
  micro/rule/<RULE-ID>/YYYY/MM/DD/HH/<event-id>.json
  micro/risk/<LEVEL>/YYYY/MM/DD/HH/<event-id>.json
  correlations/<anchor-id>/
    position.txt
    similar-tuples.txt
```

IP는 읽을 수 있는 그대로 표현하고, 사용자 등 디렉터리 값의 경로 구분자는 percent encoding으로 표현한다. `.`·`..` 특수 디렉터리 값도 인코딩하고 긴 값은 해시 접미사를 붙여 충돌을 방지한다. 시간 경로는 UTC 기준이다. 경로 이탈과 심볼릭 링크를 거부한다. JSON은 한 원본 파일만 쓰고 미시 색인은 같은 파일에 대한 하드 링크로 만들어 중복 데이터를 줄인다. 룰/위험도 변경 시 옛 링크를 제거하고 새 링크를 원자적으로 교체한다.

`position.txt`는 해당 앵커 JSON의 루트 기준 상대 경로 한 줄이다. `similar-tuples.txt`는 상관관계가 있는 로그만 `[anchor_id, similar_id, similar_score, delta_seconds]` JSON 배열 튜플로 한 줄씩 저장한다. 빈 파일은 저장된 연관 로그가 없다는 뜻이다. JSON에는 원본 `raw_id`, 정규화된 이벤트, 룰 근거, 위험도 합계, Similar 연결, 룰 버전과 후보 집합 버전을 저장한다.

HOLD 시 WAS는 DB 서버의 인증된 private archive API에 요청한다. DB 서버는 `position.txt`를 읽고 경로를 검증한 뒤 JSON과 튜플을 반환한다. Similar는 튜플의 ID로 중앙 DB의 인덱스/기본키를 사용해 관련 로그만 조회한다. 즉 WAS 파일시스템에 원격 DB 디렉터리를 마운트하거나 분석 파일을 복사하지 않는다.

새 로그가 해당 앵커의 Similar 조건에 일치하거나 룰·호스트 변경으로 스냅샷이 오래됐거나 export가 아직 끝나지 않았으면 현재 데이터를 WAS 메모리에서 다시 분석한다. 무관한 새 로그는 저장 색인을 계속 재사용한다. 파일은 비동기 작업으로 갱신된다. 저장 색인은 기본 60분/60점 이상/최대 500개 Similar를 대상으로 한다. 더 넓은 조회 조건도 메모리 재분석으로 처리한다. 저장된 점수는 분석 시점의 검토 우선순위이며 공격 확률이나 공격 확정 판정이 아니다.

## SQL 인덱스와 재참조 API

- 원본 처리: `(normalized_id,id)`와 `events.raw_id UNIQUE`. DB 트랜잭션 내 정규화/처리 표시로 재시도 때 같은 원본 ID를 이중 정규화하지 않는다. syslog TCP 재전송 자체의 중복 메시지까지 동일 이벤트로 판단하는 exactly-once 보장은 없다.
- 이벤트 조회: `(host_ip,id)`, `(src_ip,id)`, `(host_ip,time_jd)`. ISO 시간은 WAS에서 UTC Julian 숫자로 변환해 저장하고 기간 검색에서 인덱스를 쓴다.
- 분석 거시 조회: `(host_ip,hour_key,event_id)`.
- 분석 미시 조회: `(src_ip,time_jd,event_id)`, `(event,time_jd,event_id)`, 룰 연결 `(rule_id,time_jd,event_id)`.
- `/api/analysis?host_ip=203.230.52.185&hour_key=2026-10-11/03`, `src_ip`, `event`, `rule_id`, `before_id`, `limit`으로 저장 JSON을 재참조한다. 이것은 분석 시점 스냅샷이며 실시간 UI의 재평가 점수와 구분한다.
- `/api/similar/<id>` 응답의 `lookup=position-txt`는 저장 위치를 사용한 조회이다. 준비 중/버전 불일치/확장 범위이면 기존 분석 응답을 반환한다.

기존 후보 정책은 최근 최대 5,000건과 60분이며 무제한 과거 전체 상관분석은 아니다. SRC IP 탭의 건수는 선택 조건 DB 전체, 위험도는 최근 최대 20개 이벤트의 최고 점수다. 디렉터리 방식만으로 성능 향상을 단정하지 않으며 실행 계획과 실제 조회 시간을 확인한다.

## 설치·복구·운영

`deploy/central/central-rsyslog-forward.sh --db-ip <primary-address>`는 첨부 agent 스크립트를 바탕으로 RFC5424 TCP 전송, 디스크 큐, 자동 재시도, 설정 검증/롤백을 추가한 버전이다. 로컬 기록은 유지하고 네트워크 수신 로그를 재전송하지 않아 루프를 방지한다. 기존 전달 설정을 백업한다.

DB 서버에서 `deploy/central/install_primary.py --db-ip ... --was-ip ... --agent-ip ...`를 실행한다. MariaDB/ommysql/venv를 설치하고 전용 스키마·제한된 계정을 만든다. 원본 INSERT 계정, WAS 계정, export 계정을 분리하며 root 원격 로그인을 사용하지 않는다. DB 암호와 archive bearer token은 서버에서 무작위로 생성되어 root 전용 파일에 저장된다. WAS 설정은 root:socsiem 0640이다. TCP syslog와 private archive HTTP는 현재 실습망을 전제로 하며 외부망 배치에서는 TLS를 추가한다.

WAS 변경은 매번 사용자 승인을 받는다. `install_was.py prepare`는 API/enricher를 정지하고 코드·설정을 백업한 후 SQLite 스냅샷을 만든다. 스냅샷을 **DB 서버**에 전송하여 SHA256 검증을 끝내고 `backup-confirmed.json`을 작성한 다음 `apply`한다. 이벤트 ID와 내용·HOLD·즐겨찾기·룰을 검증하고 서비스를 전환한다. 이관에 실패하면 `rollback`으로 로컬 API와 설정을 복원한다. 원본 데이터는 검증 완료 전에 삭제하지 않는다.

운영 확인: DB의 `mariadb`, `rsyslog`, `soc-central-exporter`, `soc-central-archive`; WAS의 `soc-siem`, `soc-central-worker`, `nginx`, `rsyslog`; agent의 `rsyslog`. 미처리 원본과 `exported_revision<revision`의 분석 수로 지연을 점검한다. DB 장애 시 agent/DB 수신기의 디스크 큐와 worker 재시도로 복구하며 큐 용량/디스크 가용량을 모니터링한다.

업그레이드는 중앙 배치 코드를 검증해 적용한다. 기본 단일 서버 `install.sh --upgrade`로 중앙 서비스를 덮어쓰지 않는다. 새 agent는 receiver 허용 IP, IP 매핑과 관제 호스트 등록을 추가한 뒤 동일 전달 스크립트로 구성한다.

설계 근거: [rsyslog ommysql](https://docs.rsyslog.com/doc/configuration/modules/ommysql.html), [SQL 템플릿](https://docs.rsyslog.com/doc/reference/parameters/ommysql-template.html), [MariaDB 인덱스](https://mariadb.com/docs/server/reference/sql-statements/data-definition/create/create-index).

