import argparse
import glob
import json
import os
import sys
from pathlib import Path

import requests
import yaml
from jsonschema import Draft7Validator, ValidationError, validate
from jsonschema.exceptions import SchemaError

DEFAULT_DETECTION_GLOB = "Detections/**/*.yml"
SCHEMA_CANDIDATES = (
    Path("Schemas/Schema1.yaml"),
    Path("Schemas/Schema1.yml"),
    Path("Schemas/Schema1.json"),
)
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
DEFAULT_OPENAI_MODEL = "gpt-5.2"

SYSTEM_PROMPT = """You are a strict Elastic SIEM detection rule editor.
Return only corrected YAML with no markdown fences and no commentary.

Hard constraints:
- Output must be valid YAML mapping.
- Keep existing detection intent and query logic unless invalid syntax must be repaired.
- Keep field names exactly as provided by the schema and preserve unknown fields if valid.
- Ensure required fields exist and are non-empty: rule_id, name, description, type, language, query, index, severity, risk_score, enabled, tags, references, author, version.
- severity must be one of: low, medium, high, critical.
- risk_score must be an integer between 0 and 100.
- enabled must be a boolean.
- index/tags/references must be YAML lists with at least one non-empty string item.
- author must be either non-empty string or list of non-empty strings.
- version must be non-empty number or string.
- Keep YAML clean and deployment-safe for Elastic detection API payload usage."""


class PrettyDumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def dump_yaml(rule_obj):
    return yaml.dump(
        rule_obj,
        Dumper=PrettyDumper,
        sort_keys=False,
        allow_unicode=False,
        default_flow_style=False,
        indent=2,
        width=1000,
    )


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


def validate_rule_text(rule_text, schema):
    rule = yaml.safe_load(rule_text)
    if not isinstance(rule, dict):
        raise ValueError("Rule is empty or not a YAML object")
    validate(instance=rule, schema=schema)
    return rule


def collect_invalid_files(files, schema):
    invalid = {}
    for rule_file in files:
        try:
            with open(rule_file, "r", encoding="utf-8") as handle:
                validate_rule_text(handle.read(), schema)
        except (yaml.YAMLError, ValidationError, ValueError, TypeError) as exc:
            invalid[rule_file] = format_validation_error(exc)
    return invalid


def _strip_code_fences(text):
    cleaned = text.strip()
    if not cleaned.startswith("```"):
        return cleaned

    lines = cleaned.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _extract_response_text(response_json):
    output_text = response_json.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text

    chunks = []
    for output_item in response_json.get("output", []):
        for content_item in output_item.get("content", []):
            if content_item.get("type") in {"output_text", "text"}:
                text = content_item.get("text", "")
                if text:
                    chunks.append(text)
    return "\n".join(chunks).strip()


def request_ai_fix(
    *,
    api_key,
    model,
    schema,
    rule_file,
    rule_text,
    validation_error,
    timeout=120,
):
    prompt = (
        f"File path: {rule_file}\n"
        f"Schema (JSON):\n{json.dumps(schema, indent=2)}\n\n"
        f"Validation error:\n{validation_error}\n\n"
        f"Original YAML:\n{rule_text}"
    )

    payload = {
        "model": model,
        "instructions": SYSTEM_PROMPT,
        "input": prompt,
    }

    response = requests.post(
        OPENAI_RESPONSES_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=timeout,
    )
    if response.status_code >= 400:
        try:
            err_json = response.json()
            err_obj = err_json.get("error", {}) if isinstance(err_json, dict) else {}
            err_message = err_obj.get("message") or str(err_json)
        except ValueError:
            err_message = response.text.strip() or "Unknown error"
        raise RuntimeError(
            f"OpenAI API error {response.status_code} for model '{model}': {err_message}"
        )

    response_json = response.json()

    fixed_text = _extract_response_text(response_json)
    fixed_text = _strip_code_fences(fixed_text)
    if not fixed_text:
        raise ValueError("OpenAI returned an empty response")
    return fixed_text


def fix_file_with_ai(rule_file, schema, api_key, model, max_attempts, write_changes):
    with open(rule_file, "r", encoding="utf-8") as handle:
        current_text = handle.read()

    last_error = "Unknown validation failure"
    for attempt in range(1, max_attempts + 1):
        try:
            validate_rule_text(current_text, schema)
            return True, "already valid"
        except (yaml.YAMLError, ValidationError, ValueError, TypeError) as exc:
            last_error = format_validation_error(exc)

        fixed_text = request_ai_fix(
            api_key=api_key,
            model=model,
            schema=schema,
            rule_file=rule_file,
            rule_text=current_text,
            validation_error=last_error,
        )

        try:
            fixed_rule = validate_rule_text(fixed_text, schema)
        except (yaml.YAMLError, ValidationError, ValueError, TypeError) as exc:
            last_error = (
                f"attempt {attempt} produced invalid output: "
                f"{format_validation_error(exc)}"
            )
            current_text = fixed_text
            continue

        normalized_text = dump_yaml(fixed_rule)
        if write_changes:
            with open(rule_file, "w", encoding="utf-8") as handle:
                handle.write(normalized_text)
        changed = normalized_text != current_text
        return True, "updated" if changed else "normalized"

    return False, last_error


def run_ai_fixer(
    files,
    schema,
    *,
    model=DEFAULT_OPENAI_MODEL,
    api_key=None,
    max_attempts=2,
    dry_run=False,
):
    token = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API")
    if not token:
        raise RuntimeError("OPENAI_API_KEY/OPENAI_API is not set")

    invalid = collect_invalid_files(files, schema)
    if not invalid:
        return {"valid": len(files), "fixed": 0, "failed": 0, "failed_files": {}}

    fixed_count = 0
    failed_count = 0
    failed_files = {}

    for rule_file, reason in invalid.items():
        try:
            ok, detail = fix_file_with_ai(
                rule_file=rule_file,
                schema=schema,
                api_key=token,
                model=model,
                max_attempts=max_attempts,
                write_changes=not dry_run,
            )
            if ok:
                fixed_count += 1
                mode = "would fix" if dry_run else "fixed"
                print(f"{mode}: {rule_file} ({detail})")
            else:
                failed_count += 1
                failed_files[rule_file] = detail
                print(f"unable to fix: {rule_file} ({detail})")
        except Exception as exc:  # noqa: BLE001
            failed_count += 1
            failed_files[rule_file] = str(exc)
            print(f"unable to fix: {rule_file} ({exc})")
            print(f"original validation error: {reason}")

    return {
        "valid": len(files) - len(invalid),
        "fixed": fixed_count,
        "failed": failed_count,
        "failed_files": failed_files,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Fix invalid detection YAML files using OpenAI and schema validation."
    )
    parser.add_argument(
        "--pattern",
        default=DEFAULT_DETECTION_GLOB,
        help=f"Glob pattern for rule files (default: {DEFAULT_DETECTION_GLOB})",
    )
    parser.add_argument(
        "--files",
        nargs="+",
        help="Specific files to process. If set, --pattern is ignored.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "OpenAI model name "
            f"(default: env OPENAI_MODEL/MODEL or {DEFAULT_OPENAI_MODEL})"
        ),
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=2,
        help="Maximum AI fix attempts per file (default: 2)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be fixed without writing files.",
    )
    args = parser.parse_args()

    try:
        schema, schema_path = load_schema()
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to load schema: {exc}")
        return 1

    if args.files:
        files = sorted(set(args.files))
    else:
        files = sorted(glob.glob(args.pattern, recursive=True))

    if not files:
        print("No files found.")
        return 1

    selected_model = (
        args.model
        or os.getenv("OPENAI_MODEL")
        or os.getenv("MODEL")
        or DEFAULT_OPENAI_MODEL
    )

    print(f"Using schema: {schema_path}")
    try:
        result = run_ai_fixer(
            files,
            schema,
            model=selected_model,
            max_attempts=max(1, args.max_attempts),
            dry_run=args.dry_run,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"AI fixer failed: {exc}")
        return 1

    print(
        "Summary:"
        f" valid={result['valid']},"
        f" fixed={result['fixed']},"
        f" failed={result['failed']}"
    )
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
