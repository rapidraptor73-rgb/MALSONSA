# MALSONSA v1.1 자동 구축

이 패키지는 운영 Flask SIEM, 화이트 대시보드, TCP/UDP rsyslog 수신기,
SQLite DB, 로그 회전, Nginx와 두 systemd 서비스를 설치합니다.
별도의 FastAPI/React 데모 구성은 설치 대상이 아닙니다.

## 대상 서버

- systemd를 사용하는 Ubuntu 22.04/24.04, Debian 12/13, Rocky/Alma/RHEL 9/10.
- Python 3.9 이상과 root 권한. 패키지 저장소와 PyPI 접속이 필요합니다.
- 새 전용 서버 권장. 기존의 임의 Nginx/rsyslog 설정을 덮어쓰지 않습니다.
- 저장 공간은 수집량에 따라 확보하세요. 로그 파일은 일 단위로 7개 회전하지만 DB 이벤트는 자동 삭제하지 않습니다.

## 빠른 설치

```bash
tar -xzf malsonsa-v1.1.tar.gz
cd malsonsa-v1.1
sha256sum -c SHA256SUMS
sudo bash install.sh --check
sudo bash install.sh
```

기본값은 웹 `127.0.0.1:80`, API `127.0.0.1:8000`, syslog TCP/UDP `127.0.0.1:514`입니다.
원격에서 확인하려면 로컬 PC에서 `ssh -L 8080:127.0.0.1:80 사용자@서버`로 연결하고
`http://localhost:8080`을 여세요. 기본 설치는 방화벽을 변경하지 않습니다.

## 실제 관제망에서 설치

아래 주소·CIDR·인증서 경로를 환경에 맞게 바꿉니다.
`--allow-source`는 웹 접근 및 syslog 송신 허용 목록에 사용되며 반복 지정할 수 있습니다.

```bash
sudo bash install.sh \
  --hostname soc.example.local \
  --host-ip 192.0.2.10 \
  --bind 0.0.0.0 --syslog-bind 0.0.0.0 \
  --allow-source 192.0.2.0/24 \
  --tls-cert /경로/server.crt --tls-key /경로/server.key
```

HTTPS 인증서는 설치할 서버에서 제공해야 합니다. 인증서 개인키는 릴리스에 포함하지 않습니다.
TLS를 지정하면 기본 웹 포트는 443이 됩니다. TLS 없이 설치하면 HTTP입니다.
v1.1에는 사용자 로그인 기능이 없으므로 신뢰할 수 있는 관제망 또는 인증된 리버스 프록시에서 사용하세요.
도메인의 DNS 등록과 인증서 발급은 이 설치 프로그램의 범위 밖입니다.

외부 접속용 방화벽 규칙이 필요하면 이미 실행 중인 firewalld/ufw에 대해
`--open-firewall`을 추가하세요. 허용 CIDR에서 웹 TCP 및 syslog TCP/UDP 포트로 오는
규칙만 추가하며 방화벽을 초기화하거나 자동 활성화하지 않습니다.
SELinux Enforcing 환경에서는 Nginx의 API 연결을 위해 `httpd_can_network_connect`를 설정하고,
필요한 사용자 지정 웹 포트를 `http_port_t`에 추가합니다. SELinux를 비활성화하지 않습니다.

## 설치 옵션과 데이터

- `--web-port`, `--backend-port`, `--syslog-port`: 포트 지정. 서로 달라야 합니다.
- `--ip-map '{"관찰IP":"표시IP"}'`: 과거 IP 매핑이 필요한 환경에서만 지정.
  새 설치의 기본값은 `{}`이며 다른 서버의 IP로 자동 변환하지 않습니다.
- `--render-dir ./preview`: 설정 파일만 생성합니다. 시스템·서비스를 변경하지 않습니다.
- `--upgrade`: 이미 이 설치 프로그램으로 구축한 SIEM의 코드·설정을 백업 후 갱신합니다.
  DB·로그·수집 위치와 저장된 IP·포트·TLS 설정은 보존하며 명시한 옵션으로 변경할 수 있습니다. 원래 패치형 설치의 중복 수신기와 도메인 설정은
  충돌을 피하기 위해 먼저 별도로 검토·이관해야 합니다.
- `--skip-os-packages --wheel-dir /경로/wheels`: OS 필수 패키지가 사전 설치된 환경에서
  로컬 Python wheel만 사용합니다. wheel 디렉터리는 대상 Python/OS에 맞춰 별도로 준비합니다.
  릴리스 파일 자체에 OS 패키지나 wheel이 포함되어 있지는 않습니다.

소스는 `/opt/soc/backend`, 가상환경은 `/opt/soc/venv`, 웹은
`/usr/share/nginx/html/soc/frontend`에 설치합니다. 설정은 `/etc/malsonsa/siem.env`,
DB와 offset은 `/var/lib/soc-siem`, 수신 로그는 `/var/log/soc`에 저장합니다.
백업은 `/var/backups/malsonsa/install-*`에 보관합니다.
적용 실패 시 관리 대상 파일을 복구합니다. 설치된 OS/Python 패키지와 SELinux·방화벽의
추가 설정은 자동 제거하지 않으며, DB를 과거 백업으로 덮어쓰지 않습니다.

## 설치 확인

```bash
systemctl is-active nginx rsyslog soc-siem soc-event-enricher
curl http://127.0.0.1:8000/api/health
logger --server 127.0.0.1 --port 514 --tcp --tag MALSONSA-TEST \
  'failed password src=198.51.100.20 dst=192.0.2.10 user=analyst'
```

HTTP 설치의 전체 기능 검증은 `sudo python3 scripts/verify_install.py`로 실행합니다.
이 명령은 합성 TCP/UDP 로그 두 건을 남기고, 테스트 로그의 Hold를 저장·해제하며
시간·SRC/DST·Similar와 정적 화면 제공을 검사합니다.
사용자 지정 포트에는 `--web-port 번호 --syslog-port 번호`를 추가하세요.
HTTPS 설치는 신뢰한 CA를 사용해 웹 페이지를 열고 위 API와 logger 명령으로 검증합니다.

## 구축 검증과 업데이트

CI는 Ubuntu 24.04의 실제 systemd 환경에서 신규 설치, TCP/UDP 수신,
Nginx/API, Hold/Similar, 업그레이드 후 DB 보존, 로그 회전을 검증합니다.
다른 지원 배포판도 동일한 설치 구성을 사용하지만 모든 OS 조합을 CI에서 실행하는 것은 아닙니다.
현재 운영 서버를 설치 테스트 대상으로 자동 재구축하지 않습니다.

소스 변경은 feature → develop → main 검증 흐름을 유지합니다.
v1.1 태그와 릴리스 아카이브는 검증된 main 커밋에서 생성합니다.

설정 작성 시 참고한 공식 문서:
[rsyslog 파일 출력과 회전](https://docs.rsyslog.com/doc/configuration/modules/omfile.html),
[systemd 실행 환경과 파일 접근 제한](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml).
