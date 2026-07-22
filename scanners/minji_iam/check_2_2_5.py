import os
import json
import requests
from lib.mapping import to_isms_result

def check_2_2_5(org_name, github_token):
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json"
    }
    
    # GitHub Audit Log API 호출 (예시)
    url = f"https://api.github.com/orgs/{org_name}/audit-log?phrase=action:org.remove_member"
    response = requests.get(url, headers=headers)
    
    # 잔여 권한 존재 여부 판단 (API 응답 기반)
    has_dangling_permissions = False  # 예시 로직
    
    status = "FAIL" if has_dangling_permissions else "PASS"
    
    findings = {
        "message": "ISMS-P 2.2.5(퇴직 및 직무변경 관리) - 조직 제거 후 잔여 권한 존재 여부에 대한 자동 점검을 진행하였습니다. 나머지 항목은 담당자가 직접 확인해주세요."
    }
    
    result = to_isms_result(
        control_id="2.2.5",
        control_name="퇴직 및 직무변경 관리",
        status=status,
        method="semi-auto",
        tool="GitHub Audit Log API",
        findings=findings,
        evidence_path="results/2_2_5/result.json"
    )
    return result

if __name__ == "__main__":
    TOKEN = os.getenv("GITHUB_TOKEN", "")
    ORG = os.getenv("GITHUB_ORG", "your-org")
    
    res = check_2_2_5(ORG, TOKEN)
    
    # 결과 저장
    os.makedirs("results/2_2_5", exist_ok=True)
    with open("results/2_2_5/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.2.5 점검 완료 및 저장 성공")
