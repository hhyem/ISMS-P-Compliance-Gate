"""
2.7.2 암호키 관리
gitleaks가 git 히스토리 전체를 스캔해 만든 JSON 리포트를 읽어 노출된 시크릿이
있는지 확인한다. gitleaks 실행 자체는 CI(isms-p-gate.yml)에서 별도 스텝으로
캐싱하며, 이 스크립트는 결과 리포트 파싱/판정만 담당한다.
"""
import json
import os
import subprocess

from base import ISMSRule, finding

GITLEAKS_REPORT_PATH = os.getenv("GITLEAKS_REPORT_PATH", "gitleaks-report.json")

# gitleaks의 시크릿 패턴 탐지와는 별개로, 민감 파일명 자체가 커밋 이력에 존재하는지도 확인한다.
SENSITIVE_FILE_SUFFIXES = (".env", ".pem", "credentials.json")


class CryptoKeyManagementRule(ISMSRule):
    control_id = "2.7.2"
    control_name = "암호키 관리"
    category = "auto"
    tool = "Gitleaks"

    def check(self) -> dict:
        if not os.path.exists(GITLEAKS_REPORT_PATH):
            return {
                "status": "ERROR",
                "findings": [finding(
                    f"gitleaks 리포트 파일을 찾을 수 없습니다: {GITLEAKS_REPORT_PATH}. "
                    "CI에서 gitleaks 스캔 스텝이 먼저 실행되었는지 확인이 필요합니다.",
                    severity="HIGH",
                )],
            }

        with open(GITLEAKS_REPORT_PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()
        leaks = json.loads(content) if content else []

        findings = []
        for leak in leaks:
            findings.append(finding(
                f"{leak.get('RuleID', 'unknown-rule')} 패턴의 시크릿이 커밋 이력에 노출됨 "
                f"(commit {leak.get('Commit', '?')[:8]}, {leak.get('Date', '?')}). "
                "즉시 키 폐기/재발급 및 git 이력 정리(git-filter-repo)가 필요하며, "
                "로테이션 여부는 이 스캔만으로는 확인되지 않으므로 별도 확인이 필요합니다.",
                severity="HIGH",
                file=leak.get("File"),
                line=leak.get("StartLine"),
            ))

        findings.extend(self._check_sensitive_filenames())

        status = "FAIL" if findings else "PASS"
        return {"status": status, "findings": findings}

    def _check_sensitive_filenames(self) -> list:
        try:
            output = subprocess.run(
                ["git", "log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:"],
                capture_output=True, text=True, check=True,
            ).stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            return [finding(
                "git 명령 실행에 실패해 민감 파일명(.env/.pem/credentials.json) 커밋 이력을 "
                "확인하지 못했습니다.",
                severity="LOW",
            )]

        hits = sorted({
            line.strip() for line in output.splitlines()
            if line.strip() and line.strip().endswith(SENSITIVE_FILE_SUFFIXES)
        })
        return [
            finding(
                f"민감 파일 '{path}'이(가) 커밋 이력에 추가된 적이 있습니다. "
                "현재 삭제되었더라도 git 이력에는 남아있으므로 내용 노출 여부 확인이 필요합니다.",
                severity="MEDIUM",
                file=path,
            )
            for path in hits
        ]


if __name__ == "__main__":
    CryptoKeyManagementRule().run()
