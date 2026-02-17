import argparse
import glob
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft7Validator, ValidationError, validate
from jsonschema.exceptions import SchemaError

DETECTION_CODE = "Detections/**/*.yml"
SCHEMA_CANDIDATES = (
    Path("Schemas/Schema1.yaml"),
    Path("Schemas/Schema1.yml"),
    Path("Schemas/Schema1.json"),
)
AI_VALIDATOR_PATH = Path(__file__).with_name("ai_validator.py")


def format_validation_error(exc):
    if isinstance(exc, ValidationError):
        location = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        return f"{location}: {exc.message}"
    if isinstance(exc, yaml.YAMLError):
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            return f"YAML parse error at line {mark.line + 1}, column {mark.column + 1}: {exc}"
        return f"YAML parse error: {exc}"
    return str(exc)


def load_schema():
    for schema_path in SCHEMA_CANDIDATES:
        if not schema_path.exists():
            continue

        with schema_path.open("r", encoding="utf-8") as schema_file:
            if schema_path.suffix == ".json":
                schema = json.load(schema_file)
            else:
                schema = yaml.safe_load(schema_file)

        if not isinstance(schema, dict):
            raise ValueError(f"Schema file is empty or not a mapping: {schema_path}")
        try:
            Draft7Validator.check_schema(schema)
        except SchemaError as exc:
            raise ValueError(
                f"Schema file is not a valid JSON Schema ({schema_path}): {exc.message}"
            ) from exc
        return schema, schema_path

    raise FileNotFoundError(
        "No schema file found. Expected one of: "
        + ", ".join(str(path) for path in SCHEMA_CANDIDATES)
    )


def collect_validation_errors(files, schema):
    errors = {}
    for rule_file in files:
        try:
            with open(rule_file, "r", encoding="utf-8") as handle:
                rule = yaml.safe_load(handle)
            if not isinstance(rule, dict):
                raise ValueError("Rule file is empty or not a mapping")
            validate(instance=rule, schema=schema)
        except (yaml.YAMLError, ValidationError, ValueError, TypeError) as exc:
            errors[rule_file] = format_validation_error(exc)
    return errors


def run_ai_validator(files, model, max_attempts, dry_run):
    cmd = [
        sys.executable,
        str(AI_VALIDATOR_PATH),
        "--files",
        *files,
        "--model",
        model,
        "--max-attempts",
        str(max_attempts),
    ]
    if dry_run:
        cmd.append("--dry-run")

    result = subprocess.run(cmd, check=False)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="Validate detection rules and auto-fix failing files with AI."
    )
    parser.add_argument(
        "--pattern",
        default=DETECTION_CODE,
        help=f"Glob pattern for detection rules (default: {DETECTION_CODE})",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="OpenAI model passed to ai_validator.py (default: env OPENAI_MODEL/MODEL or gpt-5.2)",
    )
    parser.add_argument(
        "--max-ai-attempts",
        type=int,
        default=2,
        help="Maximum AI fix attempts per file (default: 2)",
    )
    parser.add_argument(
        "--dry-run-ai",
        action="store_true",
        help="Run AI fixer in dry-run mode (no file writes).",
    )
    parser.add_argument(
        "--no-ai-fix",
        action="store_true",
        help="Disable AI fixer and fail immediately on validation errors.",
    )
    args = parser.parse_args()
    selected_model = (
        args.model
        or os.getenv("OPENAI_MODEL")
        or os.getenv("MODEL")
        or "gpt-5.2"
    )

    try:
        schema, schema_path = load_schema()
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to load schema: {exc}")
        return 1

    files = sorted(glob.glob(args.pattern, recursive=True))
    if not files:
        print(f"No detection files found for pattern: {args.pattern}")
        return 1

    initial_errors = collect_validation_errors(files, schema)
    if not initial_errors:
        print(f"All rules are valid against {schema_path}.")
        return 0

    print("Initial validation failures:")
    for rule_file, reason in initial_errors.items():
        print(f"- {rule_file}: {reason}")

    if args.no_ai_fix:
        return 1

    if not AI_VALIDATOR_PATH.exists():
        print(f"AI validator script not found: {AI_VALIDATOR_PATH}")
        return 1

    print("Running AI fixer for invalid files...")
    ai_exit_code = run_ai_validator(
        files=list(initial_errors.keys()),
        model=selected_model,
        max_attempts=max(1, args.max_ai_attempts),
        dry_run=args.dry_run_ai,
    )
    if ai_exit_code != 0:
        print(f"AI fixer exited with code {ai_exit_code}")

    final_errors = collect_validation_errors(files, schema)
    if final_errors:
        print("Validation failures after AI fixer:")
        for rule_file, reason in final_errors.items():
            print(f"- {rule_file}: {reason}")
        return 1

    print(f"All rules are valid against {schema_path}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
