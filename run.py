import argparse
import glob
import os
import subprocess
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
from scripts.threat_intel_workflow import (
    DEFAULT_SCHEMA_CHOICE,
    DEFAULT_SCHEMA_LABEL,
    create_review_report,
    generate_detection_rule_from_report,
    normalize_and_validate_generated_rule,
    suggest_detection_output_path,
    write_detection_rule,
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


def prompt_non_empty(prompt):
    while True:
        answer = input(prompt).strip()
        if answer:
            return answer
        print("Please enter a value.")


def prompt_existing_file_path(prompt):
    while True:
        file_path = input(prompt).strip()
        if not file_path:
            print("Please enter a file path.")
            continue
        expanded_path = os.path.abspath(os.path.expanduser(file_path))
        if os.path.isfile(expanded_path):
            return expanded_path
        print(f"File not found: {expanded_path}")


def prompt_output_path(prompt):
    while True:
        file_path = input(prompt).strip()
        if not file_path:
            print("Please enter a file path.")
            continue
        return os.path.abspath(os.path.expanduser(file_path))


def prompt_threat_intel_file():
    if sys.platform == "darwin":
        apple_script = (
            'var app = Application.currentApplication();'
            'app.includeStandardAdditions = true;'
            'app.chooseFile({withPrompt: "Select threat intel file"}).toString();'
        )
        result = subprocess.run(
            ["osascript", "-l", "JavaScript", "-e", apple_script],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            selected_file = result.stdout.strip()
            if selected_file:
                return os.path.abspath(selected_file)
            print("No file was selected.")
        else:
            error_output = result.stderr.strip() or "unknown osascript error"
            print(f"Could not open macOS file picker: {error_output}")
        print("Falling back to manual file path entry.")
        return prompt_existing_file_path("Enter the local threat intel file path: ")

    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected_file = filedialog.askopenfilename(
            title="Select threat intel file",
            initialdir=os.getcwd(),
        )
        root.destroy()
        if selected_file:
            return os.path.abspath(selected_file)
        print("No file was selected.")
    except Exception as exc:  # noqa: BLE001
        print(f"Could not open file picker: {exc}")

    print("Falling back to manual file path entry.")
    return prompt_existing_file_path("Enter the local threat intel file path: ")


def review_generated_rule_loop(
    *,
    initial_candidate,
    schema,
    model,
    source_reference,
    allowed_query_fields,
    max_attempts=3,
):
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY/OPENAI_API is not set. Cannot revise rule.")

    working_text = initial_candidate

    for attempt in range(1, max_attempts + 1):
        try:
            normalized_candidate = normalize_and_validate_generated_rule(
                rule_text=working_text,
                schema=schema,
                source_reference=source_reference,
                allowed_query_fields=set(allowed_query_fields),
            )
        except Exception as exc:  # noqa: BLE001
            validation_error = str(exc)
            working_text = request_ai_fix(
                api_key=api_key,
                model=model,
                schema=schema,
                rule_file="generated:threat_intel_rule_review",
                rule_text=working_text,
                validation_error=validation_error,
            )
            continue

        print("\nProposed detection rule (review this):")
        print("=" * 60)
        print(normalized_candidate)
        print("=" * 60)

        approval = prompt_choice("Is this good? (yes/no): ", {"yes", "no"})
        if approval == "yes":
            return normalized_candidate

        user_feedback = input(
            "What should be changed? (this will be sent to AI): "
        ).strip()
        if not user_feedback:
            user_feedback = "Improve the rule while preserving the detection intent and house style."

        working_text = request_ai_fix(
            api_key=api_key,
            model=model,
            schema=schema,
            rule_file="generated:threat_intel_rule_review",
            rule_text=normalized_candidate,
            validation_error=(
                "User requested revisions to a generated detection rule.\n\n"
                f"User feedback:\n{user_feedback}"
            ),
        )

    raise RuntimeError(
        "You have run out of review attempts for the generated detection rule."
    )


def maybe_run_git_follow_up(file_path):
    should_add = prompt_choice(
        "Do you want to git add this detection file? (yes/no): ",
        {"yes", "no"},
    )
    if should_add != "yes":
        return

    add_result = subprocess.run(
        ["git", "add", file_path],
        check=False,
        capture_output=True,
        text=True,
    )
    if add_result.returncode != 0:
        print(add_result.stderr.strip() or "git add failed.")
        return
    print("Detection file staged.")

    should_commit = prompt_choice(
        "Do you want to create a git commit now? (yes/no): ",
        {"yes", "no"},
    )
    if should_commit != "yes":
        return

    commit_message = prompt_non_empty("Enter the git commit message: ")
    commit_result = subprocess.run(
        ["git", "commit", "-m", commit_message],
        check=False,
        capture_output=True,
        text=True,
    )
    if commit_result.returncode != 0:
        print(commit_result.stderr.strip() or "git commit failed.")
        return
    print(commit_result.stdout.strip() or "Commit created.")

    should_push = prompt_choice(
        "Do you want to git push now? (yes/no): ",
        {"yes", "no"},
    )
    if should_push != "yes":
        return

    push_result = subprocess.run(
        ["git", "push"],
        check=False,
        capture_output=True,
        text=True,
    )
    if push_result.returncode != 0:
        print(push_result.stderr.strip() or "git push failed.")
        return
    print(push_result.stdout.strip() or "Push completed.")


def run_threat_intel_intake(model):
    source_name = prompt_non_empty("Enter the threat intel source name: ")
    intake_mode = prompt_choice(
        "How do you want to provide the threat intel? (file/link): ",
        {"file", "link"},
    )

    if intake_mode == "link":
        source_value = prompt_non_empty("Paste the threat intel link: ")
    else:
        source_value = prompt_threat_intel_file()

    try:
        scan_result, report_path, opened = create_review_report(
            source_name=source_name,
            intake_mode=intake_mode,
            source_value=source_value,
            model=model,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Threat intel request failed: {exc}")
        return 1

    print("\nThreat intel intake captured.")
    print(f"Source: {source_name}")
    print(f"Mode: {intake_mode}")
    print(f"Value: {source_value}")
    print(f"Review report: {report_path}")
    print(
        "Existing detection coverage: "
        + ("yes" if scan_result["coverage_exists"] else "no")
    )
    if scan_result["matching_detections"]:
        print("Matching detections:")
        for match in scan_result["matching_detections"]:
            if isinstance(match, dict):
                path = match.get("path", "Unknown path")
                reason = match.get("reason", "")
                if reason:
                    print(f"- {path}: {reason}")
                else:
                    print(f"- {path}")
            else:
                print(f"- {match}")

    if opened:
        print("The markdown report was opened for review.")
    else:
        print("The markdown report could not be opened automatically.")

    input("Press Enter after reviewing the markdown report...")

    should_generate_rule = prompt_choice(
        "Do you want to create the detection query and rule? (yes/no): ",
        {"yes", "no"},
    )
    if should_generate_rule != "yes":
        print("Stopping after report review.")
        return 0

    system_name = prompt_non_empty("Which system should the rule target?: ")
    language = prompt_non_empty("Which query language should the detection use?: ")
    print("Schema options:")
    print(f"{DEFAULT_SCHEMA_CHOICE}. {DEFAULT_SCHEMA_LABEL}")
    schema_choice = prompt_choice(
        f"Choose a schema ({DEFAULT_SCHEMA_CHOICE}): ",
        {DEFAULT_SCHEMA_CHOICE},
    )

    try:
        generation_result = generate_detection_rule_from_report(
            report_path=report_path,
            scan_result=scan_result,
            source_name=source_name,
            system_name=system_name,
            language=language,
            schema_choice=schema_choice,
            model=model,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Rule generation failed: {exc}")
        return 1

    try:
        reviewed_rule_text = review_generated_rule_loop(
            initial_candidate=generation_result["rule_text"],
            schema=generation_result["schema"],
            model=model,
            source_reference=scan_result["source_value"],
            allowed_query_fields=generation_result["allowed_query_fields"],
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Rule review failed: {exc}")
        return 1

    path_suggestion = suggest_detection_output_path(
        scan_result=scan_result,
        system_name=system_name,
        language=language,
    )
    suggested_output_path = str(path_suggestion["output_path"])
    print(f"Suggested output path: {suggested_output_path}")
    if path_suggestion["requires_new_folder"]:
        print("This would create a new detection folder.")
    if not path_suggestion["file_exists"]:
        print("This would create a new detection file.")
    else:
        print("This would overwrite an existing detection file.")

    use_suggested_path = prompt_choice(
        "Do you want to save the rule to this path? (yes/no): ",
        {"yes", "no"},
    )
    if use_suggested_path == "yes":
        output_path = suggested_output_path
    else:
        output_path = prompt_output_path("Enter the detection output path: ")
        parent_dir = os.path.dirname(output_path)
        if parent_dir and not os.path.exists(parent_dir):
            create_folder = prompt_choice(
                "That folder does not exist. Create it? (yes/no): ",
                {"yes", "no"},
            )
            if create_folder != "yes":
                print("Stopping without writing a detection rule.")
                return 0
        if not os.path.exists(output_path):
            create_file = prompt_choice(
                "That file does not exist yet. Create it? (yes/no): ",
                {"yes", "no"},
            )
            if create_file != "yes":
                print("Stopping without writing a detection rule.")
                return 0
        else:
            overwrite_file = prompt_choice(
                "That file already exists. Overwrite it? (yes/no): ",
                {"yes", "no"},
            )
            if overwrite_file != "yes":
                print("Stopping without writing a detection rule.")
                return 0

    confirm_post = prompt_choice(
        "Do you want to post this detection rule to the detection folder now? (yes/no): ",
        {"yes", "no"},
    )
    if confirm_post != "yes":
        print("Stopping without writing a detection rule.")
        return 0

    saved_path = write_detection_rule(output_path, reviewed_rule_text)
    print(f"Detection rule saved to: {saved_path}")
    print(f"Schema used: {generation_result['schema_path']}")
    maybe_run_git_follow_up(str(saved_path))
    return 0


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

    print("Select a workflow:")
    print("1. Test current detection rules")
    print("2. Create a detection rule from threat intel")
    workflow = prompt_choice("Enter 1 or 2: ", {"1", "2"})

    if workflow == "2":
        return run_threat_intel_intake(selected_model)

    files = sorted(glob.glob(args.pattern, recursive=True))
    if not files:
        print(f"No detection files found for pattern: {args.pattern}")
        return 1

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
