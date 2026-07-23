"""
2.9.1 변경관리
최근 머지된 PR들이 승인 절차를 거쳤는지, 셀프 승인/승인 없는 머지가 없는지
GitHub REST API (Pull Requests, Reviews)로 확인한다.
"""
import os

from base import GITHUB_API, ISMSRule, finding, github_session, paginate, repo_full_name

# PR 설명이 비어있는 것은 자동으로 결함/정상을 단정하기 애매해 MANUAL_REQUIRED 사유로만 취급한다.
PR_LOOKBACK = int(os.getenv("PR_LOOKBACK", "50"))


class ChangeManagementRule(ISMSRule):
    control_id = "2.9.1"
    control_name = "변경관리"
    category = "auto"
    tool = "GitHub REST API (pull requests / reviews)"

    def check(self) -> dict:
        session = github_session()
        repo = repo_full_name()

        hard_findings = []  # 승인 없이 머지 / 셀프 승인 -> FAIL
        soft_findings = []  # PR 설명 비어있음 -> MANUAL_REQUIRED

        url = f"{GITHUB_API}/repos/{repo}/pulls"
        params = {"state": "closed", "sort": "updated", "direction": "desc", "per_page": 100}
        checked = 0

        for pr in paginate(session, url, params=params):
            if not pr.get("merged_at"):
                continue  # 머지 안 되고 닫힌 PR은 변경관리 대상 아님
            if checked >= PR_LOOKBACK:
                break
            checked += 1

            number = pr["number"]
            author = (pr.get("user") or {}).get("login")
            merged_by = (pr.get("merged_by") or {}).get("login")

            reviews = list(paginate(session, f"{GITHUB_API}/repos/{repo}/pulls/{number}/reviews"))
            approvals = [r for r in reviews if r.get("state") == "APPROVED"]

            if not approvals:
                hard_findings.append(finding(
                    f"PR #{number}: 승인 없이 머지됨 (merged_by: {merged_by}).",
                    severity="HIGH",
                ))
            elif any((a.get("user") or {}).get("login") == author for a in approvals):
                hard_findings.append(finding(
                    f"PR #{number}: 작성자({author})가 자신의 PR을 셀프 승인 후 머지함.",
                    severity="HIGH",
                ))

            if not (pr.get("body") or "").strip():
                soft_findings.append(finding(
                    f"PR #{number}: PR 설명이 비어있어 변경 사유를 확인할 수 없음 (수동 확인 필요).",
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
    ChangeManagementRule().run()
