# seoyun_pipeline — 자동화 점검 항목 정리

담당: 강서윤 | 담당 항목: 2.5.1 / 2.6.3 / 2.7.2 / 2.8.2 / 2.8.5 / 2.8.6 / 2.9.1

각 스크립트는 `base.py`의 `ISMSRule`을 상속하고, 실행하면 `results/{항목}/{시각}.json`에
결과를 스스로 저장한다. `judgment`가 아니라 `status` 필드를 쓰며 값은
`PASS` / `FAIL` / `MANUAL_REQUIRED` / `NOT_APPLICABLE` / `ERROR` 다섯 가지다.

- **PASS**: 결함 없음
- **FAIL**: 결함 확정 (자동 판정)
- **MANUAL_REQUIRED**: 자동으로 결함 단정은 못 하지만 사람이 봐야 하는 신호가 있음
- **NOT_APPLICABLE**: 점검할 대상 자체가 없음 (예: 라우트 파일이 없는 레포)
- **ERROR**: 스크립트가 점검을 수행하지 못함 (토큰 없음, API 실패 등) — 결함과는 다름

---

## 2.5.1 사용자 계정 관리
**막는 것**: 조직 구성원 계정 관리가 허술해서 생기는 문제 — 퇴직/휴면 계정 방치, 2FA 없는 계정,
관리자 권한 과다 부여.

| 조건 | 판정 |
|---|---|
| 멤버 계정에 2FA 미설정 | FAIL |
| 최근 90일간 감사 로그에 활동 없는 멤버가 조직에 잔류 | FAIL |
| Owner/Admin 권한자가 3명 초과 | MANUAL_REQUIRED |
| 감사 로그 API 자체에 접근 불가(Enterprise 아님/권한 부족) | MANUAL_REQUIRED |

- **입력**: GitHub `/orgs/{org}/members`, `/orgs/{org}/audit-log`
- **제외**: "계정 해지 시점과 접근권한 회수 시점 간 지연" — 이 구조에서는 조직 제거 = 접근권한 회수라
  별도로 측정할 데이터가 없어 구현하지 않음
- **환경변수**: `GITHUB_ORG`, `INACTIVE_DAYS`(기본 90), `ORG_ADMIN_THRESHOLD`(기본 3)

## 2.6.3 응용프로그램 접근
**막는 것**: 인증/인가 로직 없이 열려있는 API 라우트, 하드코딩된 관리자 우회 계정.

| 조건 | 판정 |
|---|---|
| 라우트 정의에 인증 미들웨어로 보이는 인자가 없음 (admin 경로면 HIGH, 그 외 MEDIUM) | FAIL |
| Flask admin 라우트 주변에 권한 체크 데코레이터 없음 | FAIL |
| `if user == "admin"` 류의 하드코딩 비교 패턴 발견 | FAIL |
| 대상 디렉토리(routes/controllers 등)에 소스 파일 자체가 없음 | NOT_APPLICABLE |

- **입력**: `routes/`, `controllers/`, `src/routes/`, `src/controllers/`, `api/` 등 소스 디렉토리
- **주의**: 정규식 기반 휴리스틱이라 오탐/누락 가능 → `category: semi-auto`로 표시해 결과를
  그대로 신뢰하지 않고 사람이 한 번 더 보게 설계함
- **제외**: "인증 로직이 프론트엔드에만 존재" 여부 — 정규식으로는 신뢰성 있게 판별 불가능해 제외
- **환경변수**: `APP_ACCESS_SCAN_DIRS`

## 2.7.2 암호키 관리
**막는 것**: git 커밋 이력(현재/과거 전부)에 남아있는 API 키·비밀번호·인증서, 민감 파일 커밋 이력.

| 조건 | 판정 |
|---|---|
| gitleaks가 커밋 이력에서 시크릿 패턴 탐지 | FAIL |
| `.env`/`.pem`/`credentials.json`이 커밋된 이력 존재 | FAIL |
| gitleaks 리포트 파일 자체가 없음(CI에서 스캔 안 됨) | ERROR |

- **입력**: `gitleaks detect --log-opts="--all"`로 만든 JSON 리포트 (CI에서 사전 생성), `git log --all`
- **제외**: "탐지된 시크릿이 아직 유효한지(로테이션 여부)" — gitleaks는 검증 기능이 없어 판정 불가.
  FAIL 메시지 안에 "로테이션 여부는 별도 확인 필요"라고 명시만 함
- **환경변수**: `GITLEAKS_REPORT_PATH`

## 2.8.2 보안 요구사항 검토 및 시험
**막는 것**: 배포 전 SAST 없이 넘어가거나, Critical/Blocker 취약점을 안고 배포하는 것.

| 조건 | 판정 |
|---|---|
| SonarQube에 해당 프로젝트 스캔 이력 자체가 없음 | FAIL |
| Quality Gate 상태가 OK가 아님 | FAIL |
| BLOCKER/CRITICAL 등급 미해결 취약점(Vulnerability) 존재 | FAIL |
| 코드 커버리지가 기준(기본 60%) 미달 | MANUAL_REQUIRED |
| Sonar 연동 정보(URL/프로젝트키/토큰) 미설정 | ERROR |

- **입력**: SonarQube API `/api/qualitygates/project_status`, `/api/issues/search`, `/api/measures/component`
- **환경변수**: `SONAR_HOST_URL`, `SONAR_PROJECT_KEY`, `SONAR_TOKEN`, `SONAR_COVERAGE_THRESHOLD`(기본 60)

## 2.8.5 소스 프로그램 관리
**막는 것**: 리뷰 없이, 또는 관리자 권한으로 우회해서 main 브랜치에 바로 반영되는 것.

| 조건 | 판정 |
|---|---|
| 브랜치 보호 규칙 자체가 없음 | FAIL |
| 최소 승인 리뷰어 수 미설정 | FAIL |
| 강제 push(force push) 허용 | FAIL |
| 관리자에게 규칙 강제 안 됨(enforce_admins=false) | FAIL |
| 브랜치 삭제 허용 | FAIL |

- **입력**: `/repos/{owner}/{repo}/branches/{branch}/protection`
- **환경변수**: `PROTECTED_BRANCH`(기본 main)

## 2.8.6 운영환경 이관
**막는 것**: 승인 절차 없이 production으로 자동 배포되는 것, 배포 이력이 추적 안 되는 것.

| 조건 | 판정 |
|---|---|
| production environment 자체가 정의 안 됨 | FAIL |
| production에 승인자(required reviewers) 규칙 없음 | FAIL |
| 배포에 상태(status) 기록이 없음 | FAIL |
| production 배포 이력 자체가 없음 | MANUAL_REQUIRED |

- **입력**: `/repos/{owner}/{repo}/environments/{env}`, `/repos/{owner}/{repo}/deployments`
- **제외**: "배포 실패 시 롤백 절차" — API로 확인할 근거 데이터가 없어 점검 범위에서 제외
- **환경변수**: `PROD_ENV_NAME`(기본 production)

## 2.9.1 변경관리
**막는 것**: 승인 없이, 또는 본인이 본인 PR을 셀프 승인해서 머지되는 것.

| 조건 | 판정 |
|---|---|
| 승인(APPROVED 리뷰) 없이 머지된 PR 존재 | FAIL |
| 작성자 본인이 자기 PR을 승인 후 머지(셀프 승인) | FAIL |
| PR 설명이 비어있어 변경 사유 확인 불가 | MANUAL_REQUIRED |

- **입력**: `/repos/{owner}/{repo}/pulls` (최근 병합 PR 최대 50건), `/repos/{owner}/{repo}/pulls/{n}/reviews`
- **제외**: "긴급 변경(hotfix)에 대한 사후 승인 절차 부재" — 어떤 PR이 hotfix인지 자동 식별할
  기준이 없어 제외 (라벨/브랜치명 규칙이 팀에서 정해지면 추가 가능)
- **환경변수**: `PR_LOOKBACK`(기본 50)
