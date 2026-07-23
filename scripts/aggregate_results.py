import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# --------------------------------------------------
# 경로 설정
# --------------------------------------------------

#github
# scripts 폴더
BASE_DIR = Path(__file__).resolve().parent

# 저장소 최상위 폴더
REPO_ROOT = BASE_DIR.parent

# 각 스캐너의 개별 결과가 저장되는 폴더
RESULTS_DIR = REPO_ROOT / "results"

# 통합 결과 저장 폴더
# results 안에 저장하면 validate.py가 통합 파일까지 검사할 수 있으므로
# 별도의 reports 폴더에 저장
REPORTS_DIR = REPO_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------
# 설정값
# --------------------------------------------------

VALID_STATUSES = {
    "PASS",
    "FAIL",
    "NOT_APPLICABLE",
    "MANUAL_REQUIRED",
    "ERROR",
}


# --------------------------------------------------
# 날짜 변환 함수
# --------------------------------------------------

def parse_timestamp(timestamp_value):
    """
    결과 JSON의 timestamp 문자열을 datetime으로 변환한다.

    예:
    2026-07-23T06:30:00Z
    """

    if not timestamp_value:
        return None

    try:
        return datetime.fromisoformat(
            timestamp_value.replace("Z", "+00:00")
        )

    except (ValueError, TypeError):
        return None


# --------------------------------------------------
# 전체 상태 결정
# --------------------------------------------------

def determine_overall_status(status_counts):
    """
    개별 점검 결과를 바탕으로 전체 상태를 결정한다.

    우선순위:
    ERROR > FAIL > MANUAL_REQUIRED > PASS > NOT_APPLICABLE
    """

    if status_counts["ERROR"] > 0:
        return "ERROR"

    if status_counts["FAIL"] > 0:
        return "FAIL"

    if status_counts["MANUAL_REQUIRED"] > 0:
        return "MANUAL_REQUIRED"

    if status_counts["PASS"] > 0:
        return "PASS"

    if status_counts["NOT_APPLICABLE"] > 0:
        return "NOT_APPLICABLE"

    return "ERROR"


# --------------------------------------------------
# 최신 결과 선택
# --------------------------------------------------

def get_latest_results():
    """
    results 폴더 아래의 JSON을 모두 읽고,
    control_id별 가장 최근 결과 하나만 반환한다.
    """

    latest_results = {}
    read_errors = []

    if not RESULTS_DIR.exists():
        raise FileNotFoundError(
            f"results 폴더를 찾을 수 없습니다: {RESULTS_DIR}"
        )

    result_files = sorted(RESULTS_DIR.rglob("*.json"))

    if not result_files:
        return {}, []

    #github
    for result_path in result_files:
         try:
             with result_path.open(
                 mode="r",
                 encoding="utf-8"
             ) as result_file:
                 result_data = json.load(result_file)

         except json.JSONDecodeError as error:
             read_errors.append({
                 "file": result_path.relative_to(REPO_ROOT).as_posix(),
                 "message": f"JSON 문법 오류: {error}"
             })
             continue

         except OSError as error:
             read_errors.append({
                 "file": result_path.relative_to(REPO_ROOT).as_posix(),
                 "message": f"파일 읽기 오류: {error}"
             })
             continue

         if not isinstance(result_data, dict):
             read_errors.append({
                 "file": result_path.relative_to(REPO_ROOT).as_posix(),
                 "message": "JSON 최상위 값이 객체가 아닙니다."
             })
             continue

         control_id = result_data.get("control_id")
         status = result_data.get("status")

         if not control_id:
             read_errors.append({
                 "file": result_path.relative_to(REPO_ROOT).as_posix(),
                 "message": "control_id가 없습니다."
             })
             continue

         if status not in VALID_STATUSES:
             read_errors.append({
                 "file": result_path.relative_to(REPO_ROOT).as_posix(),
                 "message": f"올바르지 않은 status입니다: {status}"
             })
             continue

         result_timestamp = parse_timestamp(
             result_data.get("timestamp")
         )

         # timestamp가 없거나 잘못된 경우 파일 수정 시간 사용
         if result_timestamp is None:
             result_timestamp = datetime.fromtimestamp(
                 result_path.stat().st_mtime,
                 tz=timezone.utc
             )

         current_result = latest_results.get(control_id)

         # 처음 발견한 control_id이면 저장
         if current_result is None:
             latest_results[control_id] = {
                 "data": result_data,
                 "path": result_path,
                 "timestamp": result_timestamp,
             }
             continue

         # 기존 결과보다 최신 결과이면 교체
         if result_timestamp > current_result["timestamp"]:
             latest_results[control_id] = {
                 "data": result_data,
                 "path": result_path,
                 "timestamp": result_timestamp,
             }

     return latest_results, read_errors


# --------------------------------------------------
# 결과 통합
# --------------------------------------------------

def aggregate_results():
    latest_results, read_errors = get_latest_results()

    if not latest_results:
        print(f"⚠️ 집계할 결과 JSON이 없습니다: {RESULTS_DIR}")
        return

    aggregated_items = []

    for control_id in sorted(latest_results):
        result_info = latest_results[control_id]
        data = result_info["data"]
        result_path = result_info["path"]

        #github
         aggregated_items.append({
             "control_id": data.get("control_id"),
             "control_name": data.get("control_name"),
             "category": data.get("category"),
             "status": data.get("status"),
             "tool": data.get("tool"),
             "owner": data.get("owner"),
             "timestamp": data.get("timestamp"),
             "evidence_path": data.get("evidence_path"),
             "source_file": (
                 result_path
                 .relative_to(REPO_ROOT)
                 .as_posix()
             )
         })

    # status별 개수 계산
    status_counts = Counter(
        item["status"]
        for item in aggregated_items
    )

    # 존재하지 않는 상태도 0으로 출력
    summary = {
        "total": len(aggregated_items),
        "PASS": status_counts["PASS"],
        "FAIL": status_counts["FAIL"],
        "NOT_APPLICABLE": status_counts["NOT_APPLICABLE"],
        "MANUAL_REQUIRED": status_counts["MANUAL_REQUIRED"],
        "ERROR": status_counts["ERROR"],
    }

    overall_status = determine_overall_status(status_counts)

    generated_at = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    aggregate_data = {
        "generated_at": generated_at,
        "overall_status": overall_status,
        "summary": summary,
        "results": aggregated_items,
        "read_errors": read_errors,
    }

    file_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_file = (
        REPORTS_DIR
        / f"aggregate_results_{file_timestamp}.json"
    )

    with output_file.open(
        mode="w",
        encoding="utf-8"
    ) as report_file:
        json.dump(
            aggregate_data,
            report_file,
            ensure_ascii=False,
            indent=2
        )

    # 터미널 출력
    print("\n================================")
    print("ISMS-P 전체 점검 결과")
    print("================================")

    print(f"전체 상태: {overall_status}")
    print(f"전체 항목: {summary['total']}개")
    print(f"PASS: {summary['PASS']}개")
    print(f"FAIL: {summary['FAIL']}개")
    print(
        f"NOT_APPLICABLE: "
        f"{summary['NOT_APPLICABLE']}개"
    )
    print(
        f"MANUAL_REQUIRED: "
        f"{summary['MANUAL_REQUIRED']}개"
    )
    print(f"ERROR: {summary['ERROR']}개")

    print("\n항목별 결과")

    for item in aggregated_items:
        print(
            f"- {item['control_id']} "
            f"{item['control_name']}: "
            f"{item['status']}"
        )

    if read_errors:
        print("\n⚠️ 읽지 못한 결과 파일")

        for error in read_errors:
            print(
                f"- {error['file']}: "
                f"{error['message']}"
            )

    #github
     print(
         "\n통합 결과 저장 위치: "
         f"{output_file.relative_to(REPO_ROOT).as_posix()}"
     )

if __name__ == "__main__":
    aggregate_results()
