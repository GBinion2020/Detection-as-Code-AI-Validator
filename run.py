import argparse
import glob
import os
import sys

import yaml
from jsonschema import ValidationError

from scripts.ai_validator import (
    DEFAULT_OPENAI_MODEL,
    dump_yaml,
    format_validation_error,
    load_schema,
    request_ai_fix,
    validate_rule_text,
)


def load_env_file(path=".env"):
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as env_file:
        for line in env_file:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue

            key, value = stripped.split("=", 1)
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export ") :].strip()
            value = value.strip().strip("'").strip('"')
            if key and key not in os.environ:
                os.environ[key] = value


def get_api_key():
    return os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API")


def get_model_name(explicit_model=None):
    return (
        explicit_model
        or os.getenv("OPENAI_MODEL")
        or os.getenv("MODEL")
        or DEFAULT_OPENAI_MODEL
    )


def validate_file(file_path, schema):
    try:
        with open(file_path, "r", encoding="utf-8") as rule_file:
            content = rule_file.read()
        validate_rule_text(content, schema)
        return True, ""
    except (yaml.YAMLError, ValidationError, ValueError, TypeError) as exc:
        return False, format_validation_error(exc)


def get_validation_error_for_text(yaml_text, schema):
    try:
        validate_rule_text(yaml_text, schema)
        return ""
    except (yaml.YAMLError, ValidationError, ValueError, TypeError) as exc:
        return format_validation_error(exc)


def collect_failures(files, schema):
    failures = {}
    for file_path in files:
        is_valid, error = validate_file(file_path, schema)
        if not is_valid:
            failures[file_path] = error
    return failures


def prompt_choice(prompt, valid_choices):
    allowed = {choice.lower() for choice in valid_choices}
    while True:
        answer = input(prompt).strip().lower()
        if answer in allowed:
            return answer
        print(f"Please enter one of: {', '.join(sorted(allowed))}")


def normalize_yaml_text(yaml_text):
    rule_obj = yaml.safe_load(yaml_text)
    if not isinstance(rule_obj, dict):
        raise ValueError("Generated YAML is not a mapping.")
    return dump_yaml(rule_obj)


def run_manual_loop(file_path, schema):
    print("okay please fix and type 'run again' to revalidate.")
    while True:
        command = input("> ").strip().lower()
        if command == "run again":
            is_valid, error = validate_file(file_path, schema)
            if is_valid:
                print(f"{file_path} now passes the authorized schema.")
                return True
            print(f"detection {file_path} still fails authorized schema: {error}")
            next_mode = prompt_choice(
                "do you want to continue manual fix or let AI do it? (manual/ai): ",
                {"manual", "ai"},
            )
            if next_mode == "manual":
                print("okay please fix and type 'run again' to revalidate.")
                continue
            return False
        if command == "ai":
            return False
        print("Type 'run again' after manual edits, or type 'ai' to switch.")


def run_ai_loop(file_path, schema, model, max_attempts):
    api_key = get_api_key()
    if not api_key:
        print("OPENAI_API_KEY/OPENAI_API is not set. Cannot run AI fixing.")
        return False

    with open(file_path, "r", encoding="utf-8") as rule_file:
        original_text = rule_file.read()

    working_text = original_text
    user_feedback = ""
    last_valid_candidate = None

    for attempt in range(1, max_attempts + 1):
        validation_error = get_validation_error_for_text(working_text, schema)
        if not validation_error:
            validation_error = "User requested revisions to an already schema-valid rule."
        full_error_context = validation_error
        if user_feedback:
            full_error_context = (
                f"{validation_error}\n\nUser feedback for next revision:\n{user_feedback}"
            )

        try:
            candidate = request_ai_fix(
                api_key=api_key,
                model=model,
                schema=schema,
                rule_file=file_path,
                rule_text=working_text,
                validation_error=full_error_context,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"AI request failed on attempt {attempt}: {exc}")
            continue

        try:
            normalized_candidate = normalize_yaml_text(candidate)
            validate_rule_text(normalized_candidate, schema)
        except Exception as exc:  # noqa: BLE001
            print(f"AI output failed schema on attempt {attempt}: {exc}")
            working_text = candidate
            user_feedback = (
                "Previous output was invalid. Fix schema/type issues and keep intent."
            )
            continue

        last_valid_candidate = normalized_candidate
        print("\nProposed detection (review this):")
        print("=" * 60)
        print(last_valid_candidate)
        print("=" * 60)
        print("Please validate this output.")

        approval = prompt_choice("Is this good? (yes/no): ", {"yes", "no"})
        if approval == "yes":
            with open(file_path, "w", encoding="utf-8") as rule_file:
                rule_file.write(last_valid_candidate)
            print("thank you")
            return True

        user_feedback = input(
            "What should be changed? (this will be sent to AI): "
        ).strip()
        if not user_feedback:
            user_feedback = "Improve wording and formatting while preserving detection logic."
        working_text = last_valid_candidate

    print(
        "you have run out of edit attempts, would you like to post this detection rule "
        "to the detection folders? if not the original detection remains "
        "(before ai touched it)"
    )
    final_post = prompt_choice("(yes/no): ", {"yes", "no"})
    if final_post == "yes":
        if last_valid_candidate is None:
            print("No valid AI candidate exists to post. Original detection remains.")
            return False
        with open(file_path, "w", encoding="utf-8") as rule_file:
            rule_file.write(last_valid_candidate)
        print(f"Posted latest AI candidate to {file_path}.")
        return True

    with open(file_path, "w", encoding="utf-8") as rule_file:
        rule_file.write(original_text)
    print("Original detection remains unchanged.")
    return False


def handle_failed_file(file_path, error, schema, model, max_attempts):
    print(f"\ndetection {file_path} failed the authorized schema.")
    print(f"reason: {error}")
    choice = prompt_choice(
        "do you want to fix manually ? or let AI do it for you? (manual/ai): ",
        {"manual", "ai"},
    )

    if choice == "manual":
        manual_success = run_manual_loop(file_path, schema)
        if manual_success:
            return True
        return run_ai_loop(file_path, schema, model, max_attempts)

    return run_ai_loop(file_path, schema, model, max_attempts)


def main():
    parser = argparse.ArgumentParser(description="Interactive detection validation CLI.")
    parser.add_argument(
        "--pattern",
        default="Detections/**/*.yml",
        help="Detection glob pattern (default: Detections/**/*.yml)",
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
        "--max-ai-attempts",
        type=int,
        default=3,
        help="Maximum interactive AI edit attempts per file (default: 3)",
    )
    args = parser.parse_args()

    load_env_file(".env")
    if "OPENAI_API_KEY" not in os.environ and "OPENAI_API" in os.environ:
        os.environ["OPENAI_API_KEY"] = os.environ["OPENAI_API"]
    if "OPENAI_MODEL" not in os.environ and "MODEL" in os.environ:
        os.environ["OPENAI_MODEL"] = os.environ["MODEL"]
    selected_model = get_model_name(args.model)

    files = sorted(glob.glob(args.pattern, recursive=True))
    if not files:
        print(f"No detection files found for pattern: {args.pattern}")
        return 1

    run_tests = prompt_choice("Do you want to test detections? (yes/no): ", {"yes", "no"})
    if run_tests != "yes":
        print("Exiting without validation.")
        return 0

    try:
        schema, schema_path = load_schema()
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to load schema: {exc}")
        return 1
    print(f"Loaded schema: {schema_path}")
    print(f"Using model: {selected_model}")

    failures = collect_failures(files, schema)
    if not failures:
        print("All detections pass schema validation.")
        return 0

    for file_path, error in failures.items():
        handle_failed_file(
            file_path=file_path,
            error=error,
            schema=schema,
            model=selected_model,
            max_attempts=max(1, args.max_ai_attempts),
        )

    final_failures = collect_failures(files, schema)
    if final_failures:
        print("\nFinal result: some detections are still invalid.")
        for file_path, error in final_failures.items():
            print(f"- {file_path}: {error}")
        return 1

    print("\nFinal result: all detections pass schema validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
