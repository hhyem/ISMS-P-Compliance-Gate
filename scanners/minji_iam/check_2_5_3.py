import os
import json
import requests
from lib.mapping import to_isms_result

def check_2_5_3(org_name, github_token):
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json"
    }
    
    url = f"https://api.github.com/orgs/{org_name}"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        org_data = response.json()
        # two_factor_requirement_enabled 필드 확인
        is_2fa_enabled = org_data.get("two_factor_requirement_enabled", False)
        status = "PASS" if is_2fa_enabled else "FAIL"
    else:
        status = "FAIL"
        
    findings = {
        "message": "ISMS-P 2.5.3(사용자 인증) - 2단계 인증 강제 설정 여부에 대한 자동 점검을 진행하였습니다. 나머지 항목은 담당자가 직접 확인해주세요."
    }
    
    result = to_isms_result(
        control_id="2.5.3",
        control_name="사용자 인증",
        status=status,
        method="semi-auto",
        tool="GitHub API",
        findings=findings,
        evidence_path="results/2_5_3/result.json"
    )
    return result

if __name__ == "__main__":
    TOKEN = os.getenv("GITHUB_TOKEN", "")
    ORG = os.getenv("GITHUB_ORG", "your-org")
    
    res = check_2_5_3(ORG, TOKEN)
    
    os.makedirs("results/2_5_3", exist_ok=True)
    with open("results/2_5_3/result.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print("✅ 2.5.3 점검 완료 및 저장 성공")
