import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import requests
import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from scripts.ai_validator import (  # noqa: E402
    DEFAULT_OPENAI_MODEL,
    OPENAI_RESPONSES_URL,
    dump_yaml,
    format_validation_error,
    load_schema,
    request_ai_fix,
    validate_rule_text,
)
from scripts.file_requests import analyze_threat_intel_file, get_api_key  # noqa: E402
from scripts.web_requests import analyze_threat_intel_link  # noqa: E402

DEFAULT_DETECTION_GLOB = "Detections/**/*.yml"
REPORTS_DIR = ROOT_DIR / "Reports"
KNOWLEDGE_BASE_DIR = ROOT_DIR / "KnowledgeBase"
KNOWLEDGE_BASE_SCHEMAS_DIR = KNOWLEDGE_BASE_DIR / "Schemas"
KNOWLEDGE_BASE_EXAMPLES_DIR = KNOWLEDGE_BASE_DIR / "DetectionExamples"
KNOWLEDGE_BASE_GUIDES_DIR = KNOWLEDGE_BASE_DIR / "Guides"
KNOWLEDGE_BASE_POLICIES_DIR = KNOWLEDGE_BASE_DIR / "Policies"
QUERY_STYLE_GUIDE_PATH = KNOWLEDGE_BASE_GUIDES_DIR / "Elastic_Query_Style_Guide.md"
QUERY_FIELD_ALLOWLIST_PATH = (
    KNOWLEDGE_BASE_POLICIES_DIR / "Elastic_Query_Field_Allowlist.txt"
)
WORKFLOW_POLICY_PATH = KNOWLEDGE_BASE_POLICIES_DIR / "ThreatIntelWorkflow.yaml"
PROMPTS_DIR = ROOT_DIR / "prompts"
INITIAL_SCAN_PROMPT_PATH = PROMPTS_DIR / "threat_intel_initial_scan_prompt.txt"
RULE_GENERATION_PROMPT_PATH = PROMPTS_DIR / "threat_intel_rule_generation_prompt.txt"
DEFAULT_SCHEMA_CHOICE = "1"
DEFAULT_SCHEMA_LABEL = "Default schema"
DEFAULT_MINIMUM_CONFIDENCE = "medium"
CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}


def load_prompt_text(prompt_path):
    return Path(prompt_path).read_text(encoding="utf-8")


def slugify(value):
    slug = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")
    return slug.lower() or "threat_intel"


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


def _extract_json_object(text):
    cleaned = _strip_code_fences(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("Threat intel scan did not return valid JSON.") from None
        return json.loads(cleaned[start : end + 1])


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


def load_workflow_policy():
    if not WORKFLOW_POLICY_PATH.exists():
        return {"minimum_confidence": DEFAULT_MINIMUM_CONFIDENCE}

    with open(WORKFLOW_POLICY_PATH, "r", encoding="utf-8") as handle:
        policy = yaml.safe_load(handle) or {}
    if not isinstance(policy, dict):
        raise ValueError(f"Workflow policy must be a mapping: {WORKFLOW_POLICY_PATH}")
    minimum_confidence = str(
        policy.get("minimum_confidence", DEFAULT_MINIMUM_CONFIDENCE)
    ).strip().lower()
    if minimum_confidence not in CONFIDENCE_ORDER:
        raise ValueError(
            f"Unsupported minimum_confidence '{minimum_confidence}' in {WORKFLOW_POLICY_PATH}"
        )
    return {"minimum_confidence": minimum_confidence}


def load_allowed_query_fields():
    if not QUERY_FIELD_ALLOWLIST_PATH.exists():
        return set()

    fields = set()
    for line in QUERY_FIELD_ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields.add(stripped)
    return fields


def _as_list(value):
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _as_string_list(value):
    normalized = []
    for item in _as_list(value):
        if item in (None, ""):
            continue
        normalized.append(str(item).strip())
    return normalized


def _as_ioc_list(value):
    normalized = []
    for item in _as_list(value):
        if isinstance(item, dict):
            normalized.append(
                {
                    "type": str(item.get("type", "")).strip(),
                    "value": str(item.get("value", "")).strip(),
                    "context": str(item.get("context", "")).strip(),
                }
            )
            continue
        item_str = str(item).strip()
        if item_str:
            normalized.append({"type": "", "value": item_str, "context": ""})
    return normalized


def collect_detection_catalog(pattern=DEFAULT_DETECTION_GLOB, query_char_limit=400):
    catalog = []
    for file_path in sorted(glob.glob(pattern, recursive=True)):
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                detection = yaml.safe_load(handle)
        except Exception:  # noqa: BLE001
            continue

        if not isinstance(detection, dict):
            continue

        query = str(detection.get("query", "")).strip()
        catalog.append(
            {
                "path": file_path,
                "name": str(detection.get("name", "")).strip(),
                "description": str(detection.get("description", "")).strip(),
                "language": str(detection.get("language", "")).strip(),
                "type": str(detection.get("type", "")).strip(),
                "severity": str(detection.get("severity", "")).strip(),
                "tags": _as_string_list(detection.get("tags"))[:12],
                "references": _as_string_list(detection.get("references"))[:5],
                "index": _as_string_list(detection.get("index"))[:5],
                "query_excerpt": query[:query_char_limit],
            }
        )
    return catalog


def _normalize_scan_result(scan_data, *, source_name, source_value, intake_mode):
    coverage = scan_data.get("existing_detection_coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}

    report_title = str(
        scan_data.get("report_title")
        or f"{source_name} threat intel review"
    ).strip()
    return {
        "report_title": report_title,
        "source_name": source_name,
        "source_value": source_value,
        "intake_mode": intake_mode,
        "executive_summary": str(scan_data.get("executive_summary", "")).strip(),
        "risk_level": str(scan_data.get("risk_level", "unknown")).strip(),
        "confidence": str(scan_data.get("confidence", "unknown")).strip().lower(),
        "attack_logic": _as_string_list(scan_data.get("attack_logic")),
        "impacted_systems": _as_string_list(scan_data.get("impacted_systems")),
        "targets": _as_string_list(scan_data.get("targets")),
        "ttps": _as_string_list(scan_data.get("ttps")),
        "tooling": _as_string_list(scan_data.get("tooling")),
        "recommendations": _as_string_list(scan_data.get("recommendations")),
        "references": _as_string_list(scan_data.get("references")),
        "iocs": _as_ioc_list(scan_data.get("iocs")),
        "coverage_exists": bool(
            coverage.get("coverage_exists", scan_data.get("coverage_exists", False))
        ),
        "coverage_summary": str(
            coverage.get("coverage_summary", scan_data.get("coverage_summary", ""))
        ).strip(),
        "matching_detections": _as_list(
            coverage.get("matching_detections", scan_data.get("matching_detections", []))
        ),
        "raw_scan": scan_data,
    }


def run_initial_scan(*, source_name, intake_mode, source_value, model=None):
    detection_catalog = collect_detection_catalog()
    context_sections = [
        "Current detection catalog JSON:",
        json.dumps(detection_catalog, indent=2),
    ]

    if intake_mode == "file":
        result = analyze_threat_intel_file(
            source_name=source_name,
            file_path=source_value,
            model=model or DEFAULT_OPENAI_MODEL,
            prompt_path=INITIAL_SCAN_PROMPT_PATH,
            context_sections=context_sections,
        )
    else:
        result = analyze_threat_intel_link(
            source_name=source_name,
            link=source_value,
            model=model or DEFAULT_OPENAI_MODEL,
            prompt_path=INITIAL_SCAN_PROMPT_PATH,
            context_sections=context_sections,
        )

    scan_data = _extract_json_object(result["output_text"])
    normalized = _normalize_scan_result(
        scan_data,
        source_name=source_name,
        source_value=source_value,
        intake_mode=intake_mode,
    )
    normalized["api_result"] = result
    return normalized


def _format_iocs_markdown(iocs):
    if not iocs:
        return "_No IOCs extracted._"

    lines = [
        "| Type | Value | Context |",
        "| --- | --- | --- |",
    ]
    for item in iocs:
        lines.append(
            "| "
            + " | ".join(
                [
                    item.get("type") or "-",
                    item.get("value") or "-",
                    item.get("context") or "-",
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def _format_string_bullets(values, empty_message):
    if not values:
        return empty_message
    return "\n".join(f"- {value}" for value in values)


def _format_matching_detections(values):
    if not values:
        return "_No matching detections were identified._"

    lines = []
    for item in values:
        if isinstance(item, dict):
            path = str(item.get("path", "")).strip() or "Unknown path"
            reason = str(item.get("reason", "")).strip()
            if reason:
                lines.append(f"- `{path}`: {reason}")
            else:
                lines.append(f"- `{path}`")
        else:
            lines.append(f"- {str(item).strip()}")
    return "\n".join(lines)


def _sanitize_mermaid_label(value):
    cleaned = re.sub(r"[^A-Za-z0-9 _/().:-]", "", value or "").strip()
    return cleaned or "Unknown"


def _build_mermaid_diagram(scan_result):
    steps = scan_result["attack_logic"] or scan_result["ttps"] or ["Threat activity observed"]
    node_ids = [f"N{index}" for index in range(len(steps))]
    lines = ["flowchart TD"]
    for node_id, step in zip(node_ids, steps):
        lines.append(f'  {node_id}["{_sanitize_mermaid_label(step)}"]')
    for first, second in zip(node_ids, node_ids[1:]):
        lines.append(f"  {first} --> {second}")
    return "\n".join(lines)


def render_report_markdown(scan_result):
    return "\n".join(
        [
            f"# {scan_result['report_title']}",
            "",
            f"- Source: {scan_result['source_name']}",
            f"- Intake mode: {scan_result['intake_mode']}",
            f"- Reference: {scan_result['source_value']}",
            f"- Risk level: {scan_result['risk_level']}",
            f"- Confidence: {scan_result['confidence']}",
            "",
            "## Executive Summary",
            scan_result["executive_summary"] or "_No summary returned._",
            "",
            "## Attack Diagram",
            "```mermaid",
            _build_mermaid_diagram(scan_result),
            "```",
            "",
            "## Existing Detection Coverage",
            f"- Coverage exists: {'yes' if scan_result['coverage_exists'] else 'no'}",
            f"- Coverage summary: {scan_result['coverage_summary'] or 'No coverage summary returned.'}",
            "",
            _format_matching_detections(scan_result["matching_detections"]),
            "",
            "## Attack Logic",
            _format_string_bullets(
                scan_result["attack_logic"],
                "_No attack logic returned._",
            ),
            "",
            "## Impacted Systems",
            _format_string_bullets(
                scan_result["impacted_systems"],
                "_No impacted systems returned._",
            ),
            "",
            "## Likely Targets",
            _format_string_bullets(
                scan_result["targets"],
                "_No likely targets returned._",
            ),
            "",
            "## TTPs",
            _format_string_bullets(scan_result["ttps"], "_No TTPs returned._"),
            "",
            "## Tooling And Malware",
            _format_string_bullets(scan_result["tooling"], "_No tooling returned._"),
            "",
            "## Indicators Of Compromise",
            _format_iocs_markdown(scan_result["iocs"]),
            "",
            "## Recommendations",
            _format_string_bullets(
                scan_result["recommendations"],
                "_No recommendations returned._",
            ),
            "",
            "## References",
            _format_string_bullets(
                scan_result["references"],
                "_No references returned._",
            ),
            "",
        ]
    )


def write_report_file(scan_result, reports_dir=REPORTS_DIR):
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"{slugify(scan_result['report_title'])}_{timestamp}.md"
    report_path = Path(reports_dir) / report_name
    report_path.write_text(render_report_markdown(scan_result), encoding="utf-8")
    return report_path


def open_review_file(file_path):
    file_path = str(file_path)
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", file_path], check=False)
            return True
        if sys.platform.startswith("win"):
            os.startfile(file_path)  # type: ignore[attr-defined]
            return True
        subprocess.run(["xdg-open", file_path], check=False)
        return True
    except Exception:  # noqa: BLE001
        return False


def create_review_report(*, source_name, intake_mode, source_value, model=None):
    scan_result = run_initial_scan(
        source_name=source_name,
        intake_mode=intake_mode,
        source_value=source_value,
        model=model,
    )
    report_path = write_report_file(scan_result)
    opened = open_review_file(report_path)
    return scan_result, report_path, opened


def get_schema_choice(choice):
    if choice != DEFAULT_SCHEMA_CHOICE:
        raise ValueError(f"Unsupported schema choice: {choice}")
    schema, schema_path = load_schema()
    return {
        "schema": schema,
        "schema_path": schema_path,
        "label": DEFAULT_SCHEMA_LABEL,
    }


def ensure_confidence_threshold(scan_result):
    confidence = str(scan_result.get("confidence", "")).strip().lower()
    policy = load_workflow_policy()
    minimum_confidence = policy["minimum_confidence"]
    if confidence not in CONFIDENCE_ORDER:
        raise ValueError(
            f"Threat intel scan confidence must be one of: {', '.join(CONFIDENCE_ORDER)}."
        )
    if CONFIDENCE_ORDER[confidence] < CONFIDENCE_ORDER[minimum_confidence]:
        raise ValueError(
            f"Threat intel confidence '{confidence}' is below the minimum "
            f"required threshold '{minimum_confidence}'."
        )


def _extract_query_fields(query_text):
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.]*)\s*(?::|==|!=|<=|>=|<|>)")
    return sorted({match.group(1) for match in pattern.finditer(query_text or "")})


def _apply_source_reference(rule_obj, source_reference):
    references = _as_string_list(rule_obj.get("references"))
    if source_reference not in references:
        references.append(source_reference)
    rule_obj["references"] = references
    return rule_obj


def normalize_and_validate_generated_rule(
    *, rule_text, schema, source_reference, allowed_query_fields
):
    cleaned_text = _strip_code_fences(rule_text)
    rule_obj = validate_rule_text(cleaned_text, schema)
    rule_obj = _apply_source_reference(rule_obj, source_reference)
    normalized_text = dump_yaml(rule_obj)
    validated_rule = validate_rule_text(normalized_text, schema)
    query = str(validated_rule.get("query", "")).strip()
    if allowed_query_fields:
        disallowed_fields = [
            field
            for field in _extract_query_fields(query)
            if field not in allowed_query_fields
        ]
        if disallowed_fields:
            raise ValueError(
                "Query uses fields outside the allowlist: "
                + ", ".join(sorted(disallowed_fields))
            )
    references = _as_string_list(validated_rule.get("references"))
    if source_reference not in references:
        raise ValueError(
            "Rule must include at least one reference back to the threat intel source."
        )
    return dump_yaml(validated_rule)


def _load_knowledge_base_examples():
    examples = []
    for file_path in sorted(KNOWLEDGE_BASE_EXAMPLES_DIR.rglob("*.yml")):
        try:
            content = file_path.read_text(encoding="utf-8").strip()
        except Exception:  # noqa: BLE001
            continue
        if content:
            examples.append({"path": str(file_path.relative_to(ROOT_DIR)), "content": content})
    return examples


def _load_knowledge_base_context():
    style_guide = ""
    if QUERY_STYLE_GUIDE_PATH.exists():
        style_guide = QUERY_STYLE_GUIDE_PATH.read_text(encoding="utf-8").strip()

    detection_folders = sorted(
        str(path.relative_to(ROOT_DIR))
        for path in (ROOT_DIR / "Detections").iterdir()
        if path.is_dir()
    )
    return {
        "style_guide": style_guide,
        "examples": _load_knowledge_base_examples(),
        "detection_folders": detection_folders,
    }


def _request_rule_candidate(
    *,
    api_key,
    model,
    prompt_text,
    report_markdown,
    source_name,
    system_name,
    language,
    schema_label,
    schema,
    timeout=120,
):
    input_text = "\n\n".join(
        [
            f"Threat intel source: {source_name}",
            f"Target system: {system_name}",
            f"Detection language: {language}",
            f"Schema label: {schema_label}",
            "Schema JSON:",
            json.dumps(schema, indent=2),
            "Threat intel report markdown:",
            report_markdown,
        ]
    )

    payload = {
        "model": model,
        "instructions": prompt_text,
        "input": input_text,
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
        raise RuntimeError(
            f"OpenAI rule generation failed with status {response.status_code}: "
            f"{response.text.strip() or 'Unknown error'}"
        )

    return _strip_code_fences(_extract_response_text(response.json()))


def generate_detection_rule_from_report(
    *,
    report_path,
    scan_result,
    source_name,
    system_name,
    language,
    schema_choice,
    model=None,
    max_fix_attempts=2,
):
    ensure_confidence_threshold(scan_result)
    schema_info = get_schema_choice(schema_choice)
    schema = schema_info["schema"]
    schema_path = schema_info["schema_path"]
    prompt_text = load_prompt_text(RULE_GENERATION_PROMPT_PATH)
    knowledge_base = _load_knowledge_base_context()
    allowed_query_fields = load_allowed_query_fields()
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY/OPENAI_API is not set")

    with open(report_path, "r", encoding="utf-8") as handle:
        report_markdown = handle.read()

    generation_context = "\n\n".join(
        [
            report_markdown,
            "Knowledge base query style guide:",
            knowledge_base["style_guide"],
            "Knowledge base example detections JSON:",
            json.dumps(knowledge_base["examples"], indent=2),
            "Existing detection folders:",
            json.dumps(knowledge_base["detection_folders"], indent=2),
        ]
    )

    model_name = model or DEFAULT_OPENAI_MODEL
    candidate = _request_rule_candidate(
        api_key=api_key,
        model=model_name,
        prompt_text=prompt_text,
        report_markdown=generation_context,
        source_name=source_name,
        system_name=system_name,
        language=language,
        schema_label=schema_info["label"],
        schema=schema,
    )

    try:
        candidate = normalize_and_validate_generated_rule(
            rule_text=candidate,
            schema=schema,
            source_reference=scan_result["source_value"],
            allowed_query_fields=allowed_query_fields,
        )
    except Exception as exc:  # noqa: BLE001
        last_error = format_validation_error(exc)
        working_text = candidate
        for _ in range(max_fix_attempts):
            working_text = request_ai_fix(
                api_key=api_key,
                model=model_name,
                schema=schema,
                rule_file=f"generated:{source_name}:{language}",
                rule_text=working_text,
                validation_error=last_error,
            )
            try:
                candidate = normalize_and_validate_generated_rule(
                    rule_text=working_text,
                    schema=schema,
                    source_reference=scan_result["source_value"],
                    allowed_query_fields=allowed_query_fields,
                )
                break
            except Exception as retry_exc:  # noqa: BLE001
                last_error = format_validation_error(retry_exc)
        else:
            raise RuntimeError(
                f"Generated rule could not be validated against {schema_path}: {last_error}"
            ) from exc

    return {
        "rule_text": candidate,
        "schema_path": schema_path,
        "model": model_name,
        "schema": schema,
        "allowed_query_fields": sorted(allowed_query_fields),
    }


def suggest_detection_output_path(*, scan_result, system_name, language):
    matching_detections = scan_result.get("matching_detections", [])
    for match in matching_detections:
        if isinstance(match, dict) and match.get("path"):
            existing_path = ROOT_DIR / str(match["path"])
            suggested_dir = existing_path.parent
            break
    else:
        detections_root = ROOT_DIR / "Detections"
        suggested_dir = None
        for folder in detections_root.iterdir():
            if not folder.is_dir():
                continue
            if folder.name.lower() == system_name.strip().lower():
                suggested_dir = folder
                break
        if suggested_dir is None:
            suggested_dir = detections_root / re.sub(r"[\\/]+", "_", system_name).strip()

    file_name = f"{slugify(scan_result['report_title'])}_{slugify(language)}.yml"
    output_path = suggested_dir / file_name
    return {
        "output_path": output_path,
        "requires_new_folder": not suggested_dir.exists(),
        "file_exists": output_path.exists(),
    }


def write_detection_rule(output_path, rule_text):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rule_text, encoding="utf-8")
    return output_path
