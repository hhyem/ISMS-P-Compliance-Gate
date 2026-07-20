import json
import glob
from jsonschema import validate, ValidationError

def validate_all_results():
    with open("schema/isms-p-result.schema.json") as f:
        schema = json.load(f)

    errors = []
    for path in glob.glob("results/**/*.json", recursive=True):
        with open(path) as f:
            data = json.load(f)
        try:
            validate(instance=data, schema=schema)
        except ValidationError as e:
            errors.append(f"{path}: {e.message}")

    if errors:
        for e in errors:
            print(f"❌ {e}")
        raise SystemExit(1)
    print("✅ 모든 결과 파일이 스키마를 통과했습니다")

if __name__ == "__main__":
    validate_all_results()
