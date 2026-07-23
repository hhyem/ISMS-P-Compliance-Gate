"""
2.8.2 보안 요구사항 검토 및 시험
SonarQube Quality Gate 통과 여부, 미해결 Critical/Blocker 취약점,
코드 커버리지를 SonarQube Web API로 확인한다.
"""
import os

import requests

from base import ISMSRule, finding

SONAR_HOST_URL = os.getenv("SONAR_HOST_URL", "").rstrip("/")
SONAR_PROJECT_KEY = os.getenv("SONAR_PROJECT_KEY", "")
SONAR_TOKEN = os.getenv("SONAR_TOKEN", "")
COVERAGE_THRESHOLD = float(os.getenv("SONAR_COVERAGE_THRESHOLD", "60"))


def sonar_session() -> requests.Session:
    session = requests.Session()
    session.auth = (SONAR_TOKEN, "")  # SonarQube 토큰 인증: username=token, password=빈 값
    return session


class SecurityRequirementsTestRule(ISMSRule):
    control_id = "2.8.2"
    control_name = "보안 요구사항 검토 및 시험"
    category = "auto"
    tool = "SonarQube API (SAST)"

    def check(self) -> dict:
        if not (SONAR_HOST_URL and SONAR_PROJECT_KEY and SONAR_TOKEN):
            return {
                "status": "ERROR",
                "findings": [finding(
                    "SONAR_HOST_URL / SONAR_PROJECT_KEY / SONAR_TOKEN 환경변수가 설정되지 않았습니다.",
                    severity="HIGH",
                )],
            }

        session = sonar_session()
        hard_findings = []
        soft_findings = []

        gate_resp = session.get(
            f"{SONAR_HOST_URL}/api/qualitygates/project_status",
            params={"projectKey": SONAR_PROJECT_KEY},
        )
        if gate_resp.status_code == 404:
            return {
                "status": "FAIL",
                "findings": [finding(
                    f"SonarQube 프로젝트 '{SONAR_PROJECT_KEY}'에 대한 스캔 이력이 없습니다. "
                    "배포 전 SAST 스캔이 수행되지 않았습니다.",
                    severity="HIGH",
                )],
            }
        gate_resp.raise_for_status()
        gate_status = gate_resp.json().get("projectStatus", {}).get("status")
        if gate_status != "OK":
            hard_findings.append(finding(
                f"SonarQube Quality Gate 상태가 '{gate_status}'입니다 "
                "(조건 실패 상태로 머지된 이력이 있는 것으로 추정).",
                severity="HIGH",
            ))

        issues_resp = session.get(
            f"{SONAR_HOST_URL}/api/issues/search",
            params={
                "componentKeys": SONAR_PROJECT_KEY,
                "severities": "BLOCKER,CRITICAL",
                "types": "VULNERABILITY",
                "resolved": "false",
                "ps": 100,
            },
        )
        issues_resp.raise_for_status()
        for issue in issues_resp.json().get("issues", []):
            component = issue.get("component", "")
            file_path = component.split(":", 1)[1] if ":" in component else component
            hard_findings.append(finding(
                f"{issue.get('severity')} 취약점 미해결: {issue.get('message')} (rule: {issue.get('rule')})",
                severity="HIGH",
                file=file_path,
                line=issue.get("line"),
            ))

        measures_resp = session.get(
            f"{SONAR_HOST_URL}/api/measures/component",
            params={"component": SONAR_PROJECT_KEY, "metricKeys": "coverage"},
        )
        measures_resp.raise_for_status()
        measures = {
            m["metric"]: m.get("value")
            for m in measures_resp.json().get("component", {}).get("measures", [])
        }
        coverage = measures.get("coverage")
        if coverage is not None and float(coverage) < COVERAGE_THRESHOLD:
            soft_findings.append(finding(
                f"코드 커버리지 {coverage}%가 기준({COVERAGE_THRESHOLD}%)에 미달합니다.",
                severity="LOW",
            ))

        if hard_findings:
            status = "FAIL"
        elif soft_findings:
            status = "MANUAL_REQUIRED"
        else:
            status = "PASS"

        return {"status": status, "findings": hard_findings + soft_findings}


if __name__ == "__main__":
    SecurityRequirementsTestRule().run()
