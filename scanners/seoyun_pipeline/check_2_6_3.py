"""
2.6.3 응용프로그램 접근
routes/controllers 계열 디렉토리를 정규식 기반으로 훑어서
1) 인증 미들웨어가 안 걸린 것으로 보이는 라우트
2) admin 라우트인데 권한 체크 가드가 안 보이는 것
3) 하드코딩된 관리자 우회 패턴 (if user == "admin" 류)
을 탐지한다.

정규식 기반 휴리스틱이라 오탐/누락이 있을 수 있어 category를 "semi-auto"로 두고,
결과는 사람이 한 번 더 확인하는 걸 전제로 한다. "인증 로직이 프론트엔드에만 존재"
여부는 정규식으로는 신뢰성 있게 판별할 방법이 없어 이 스캐너의 점검 범위에서
제외했다 (수동 점검 필요).
"""
import os
import re
from pathlib import Path

from base import ISMSRule, finding

SCAN_DIRS = [
    d.strip() for d in os.getenv(
        "APP_ACCESS_SCAN_DIRS",
        "routes,controllers,src/routes,src/controllers,api,app/routes,app/controllers",
    ).split(",") if d.strip()
]
SOURCE_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".py")

AUTH_HINTS = ("auth", "Auth", "isAuthenticated", "requireAuth", "passport", "verifyToken", "protect", "authenticate", "jwt")
PUBLIC_PATH_HINTS = ("/health", "/login", "/register", "/public", "/status", "/ping")
FLASK_GUARD_HINTS = ("login_required", "admin_required", "permission_required", "jwt_required", "roles_required")

JS_ROUTE_RE = re.compile(r"\b(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*[\'\"`]([^\'\"`]+)[\'\"`]\s*,\s*([^)]*)\)")
FLASK_ROUTE_RE = re.compile(r"@\w+\.route\(\s*[\'\"]([^\'\"]+)[\'\"]")
BACKDOOR_RE = re.compile(
    r"\b(user(?:name)?|role)\s*==\s*[\'\"](admin|root|superuser|backdoor)[\'\"]", re.IGNORECASE
)


class ApplicationAccessControlRule(ISMSRule):
    control_id = "2.6.3"
    control_name = "응용프로그램 접근"
    category = "semi-auto"
    tool = "정적분석 스크립트 (정규식 기반 라우트/가드 탐지)"

    def check(self) -> dict:
        repo_root = Path(__file__).resolve().parents[2]
        scanned = [d for d in SCAN_DIRS if (repo_root / d).is_dir()]
        files = self._collect_files(repo_root, scanned)

        if not files:
            return {
                "status": "NOT_APPLICABLE",
                "scope": ", ".join(SCAN_DIRS),
                "findings": [finding(
                    f"설정된 디렉토리({', '.join(SCAN_DIRS)}) 안에서 라우트/컨트롤러 소스 파일을 "
                    "찾지 못해 점검 대상이 없습니다.",
                    severity="INFO",
                )],
            }

        findings = []
        for path in files:
            rel = str(path.relative_to(repo_root))
            text = path.read_text(encoding="utf-8", errors="ignore")
            findings.extend(self._check_js_routes(rel, text))
            findings.extend(self._check_flask_routes(rel, text))
            findings.extend(self._check_backdoor_patterns(rel, text))

        status = "FAIL" if findings else "PASS"
        return {"status": status, "scope": ", ".join(scanned), "findings": findings}

    def _collect_files(self, repo_root: Path, scanned_dirs: list) -> list:
        files = []
        for d in scanned_dirs:
            for ext in SOURCE_EXTENSIONS:
                files.extend((repo_root / d).rglob(f"*{ext}"))
        return files

    def _check_js_routes(self, rel_path: str, text: str) -> list:
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = JS_ROUTE_RE.search(line)
            if not match:
                continue
            route_path, handler_args = match.group(2), match.group(3)
            if any(p in route_path for p in PUBLIC_PATH_HINTS):
                continue
            if any(h in handler_args for h in AUTH_HINTS):
                continue
            severity = "HIGH" if "admin" in route_path.lower() else "MEDIUM"
            results.append(finding(
                f"'{route_path}' 라우트에 인증 미들웨어가 적용되지 않은 것으로 보입니다 "
                f"(핸들러 인자: {handler_args.strip() or '없음'}).",
                severity=severity, file=rel_path, line=lineno,
            ))
        return results

    def _check_flask_routes(self, rel_path: str, text: str) -> list:
        results = []
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            match = FLASK_ROUTE_RE.search(line)
            if not match:
                continue
            route_path = match.group(1)
            if "admin" not in route_path.lower():
                continue
            window = "\n".join(lines[max(0, lineno - 3):lineno + 3])
            if not any(h in window for h in FLASK_GUARD_HINTS):
                results.append(finding(
                    f"admin 라우트 '{route_path}'에 권한 체크 데코레이터"
                    f"({'/'.join(FLASK_GUARD_HINTS)})가 근처에 보이지 않습니다.",
                    severity="HIGH", file=rel_path, line=lineno,
                ))
        return results

    def _check_backdoor_patterns(self, rel_path: str, text: str) -> list:
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if BACKDOOR_RE.search(line):
                results.append(finding(
                    f"하드코딩된 관리자/우회 계정 비교 패턴으로 의심되는 코드가 있습니다: {line.strip()[:120]}",
                    severity="HIGH", file=rel_path, line=lineno,
                ))
        return results


if __name__ == "__main__":
    ApplicationAccessControlRule().run()
