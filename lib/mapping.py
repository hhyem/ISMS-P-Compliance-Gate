import json
from datetime import datetime, timezone
from pathlib import Path

VALID_OWNERS = {"민지", "서윤", "예원", "혜민", "정은"}

def to_isms_result(
    run_id: str,
    control_id: str,
    control_name: str,
    category: str,           # "auto" | "semi-auto" | "checklist"
    status: str,             # "PASS" | "FAIL" | "NOT_APPLICABLE" | "MANUAL_REQUIRED" | "ERROR"
    tool: str,
    owner: str,
    findings: list | None = None,
    checklist_items: list | None = None,
    scope: str | None = None,
    pr_number: int | None = None,
    commit_sha: str | None = None,
) -> dict:
    assert owner in VALID_OWNERS, f"owner는 {VALID_OWNERS} 중 하나여야 함"
    if category == "semi-auto" and not scope:
        raise ValueError("semi-auto 항목은 scope 필드가 필수입니다")
    if category == "checklist" and not checklist_items:
        raise ValueError("checklist 항목은 checklist_items가 필수입니다")

    control_dir = control_id.replace(".", "_")
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe_ts = timestamp.replace(":", "-")
    evidence_path = f"results/{control_dir}/{safe_ts}.json"

    result = {
        "schema_version": "1.0",
        "run_id": run_id,
        "control_id": control_id,
        "control_name": control_name,
        "category": category,
        "status": status,
        "tool": tool,
        "owner": owner,
        "timestamp": timestamp,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "findings": findings or [],
        "evidence_path": evidence_path,
    }
    if scope:
        result["scope"] = scope
    if checklist_items:
        result["checklist_items"] = checklist_items

    Path(f"results/{control_dir}").mkdir(parents=True, exist_ok=True)
    with open(evidence_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result
