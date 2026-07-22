import csv
from pathlib import Path
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.predefined_recognizers import PhoneRecognizer

# 현재 실행 코드가 저장된 폴더
BASE_DIR = Path(__file__).resolve().parent

# 실행 코드와 같은 폴더의 CSV
INPUT_FILE = BASE_DIR / "test_data.csv"

analyzer = AnalyzerEngine()

# 한국 전화번호 탐지기 추가
kr_phone_recognizer = PhoneRecognizer(
    supported_regions=["KR"],
    supported_entity="PHONE_NUMBER",
    supported_language="en",
)

analyzer.registry.add_recognizer(kr_phone_recognizer)

detected_count = 0

with open(INPUT_FILE, "r", encoding="cp949", newline="") as file:
    reader = csv.DictReader(file)

    print("CSV 헤더:", reader.fieldnames)

    for row_number, row in enumerate(reader, start=2):
        print(f"\n[CSV {row_number}행]")
        # print(row)

        for column_name, value in row.items():
            text = value or ""

            print(f"  {column_name}: {text!r}")

            results = analyzer.analyze(
                text=text,
                entities=["PHONE_NUMBER"],
                language="en",
            )

            if results:
                detected_count += len(results)

                for result in results:
                    detected_value = text[result.start:result.end]

                    print(
                        f"  → 탐지됨: {detected_value} "
                        f"/ 유형: {result.entity_type} "
                        f"/ 점수: {result.score}" #해당 문자열을 개인정보라고 판단한 신뢰도 점수
                    )

if detected_count > 0:
    print(f"\nFAIL: 평문 전화번호 {detected_count}건 발견")
else:
    print("\nPASS: 평문 전화번호가 발견되지 않음")
