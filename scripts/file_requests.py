import argparse
import os
import sys
from pathlib import Path

import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from scripts.ai_validator import DEFAULT_OPENAI_MODEL

OPENAI_FILES_URL = "https://api.openai.com/v1/files"
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
PROMPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "prompts"
    / "threat_intel_initial_scan_prompt.txt"
)


def get_api_key(explicit_api_key=None):
    return explicit_api_key or os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API")


def get_model_name(explicit_model=None):
    return (
        explicit_model
        or os.getenv("OPENAI_MODEL")
        or os.getenv("MODEL")
        or DEFAULT_OPENAI_MODEL
    )


def load_prompt_text(prompt_path=PROMPT_PATH):
    return Path(prompt_path).read_text(encoding="utf-8")


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


def _build_input_text(source_name, file_path, context_sections=None):
    parts = [
        f"Threat intel source: {source_name}",
        f"Local file name: {os.path.basename(file_path)}",
    ]
    for section in context_sections or []:
        if section:
            parts.append(str(section))
    return "\n\n".join(parts)


def upload_threat_intel_file(file_path, *, api_key=None, timeout=120):
    token = get_api_key(api_key)
    if not token:
        raise RuntimeError("OPENAI_API_KEY/OPENAI_API is not set")

    with open(file_path, "rb") as file_handle:
        response = requests.post(
            OPENAI_FILES_URL,
            headers={"Authorization": f"Bearer {token}"},
            data={"purpose": "user_data"},
            files={"file": (os.path.basename(file_path), file_handle)},
            timeout=timeout,
        )

    if response.status_code >= 400:
        raise RuntimeError(
            f"OpenAI file upload failed with status {response.status_code}: "
            f"{response.text.strip() or 'Unknown error'}"
        )
    return response.json()


def analyze_threat_intel_file(
    *,
    source_name,
    file_path,
    model=None,
    api_key=None,
    prompt_path=PROMPT_PATH,
    context_sections=None,
    timeout=120,
):
    token = get_api_key(api_key)
    if not token:
        raise RuntimeError("OPENAI_API_KEY/OPENAI_API is not set")

    file_record = upload_threat_intel_file(file_path, api_key=token, timeout=timeout)
    prompt_text = load_prompt_text(prompt_path)

    payload = {
        "model": get_model_name(model),
        "input": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_file",
                        "file_id": file_record["id"],
                    },
                    {
                        "type": "input_text",
                        "text": _build_input_text(
                            source_name,
                            file_path,
                            context_sections=context_sections,
                        ),
                    },
                ],
            }
        ],
    }
    if prompt_text.strip():
        payload["instructions"] = prompt_text

    response = requests.post(
        OPENAI_RESPONSES_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=timeout,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"OpenAI file analysis failed with status {response.status_code}: "
            f"{response.text.strip() or 'Unknown error'}"
        )

    response_json = response.json()
    return {
        "file_id": file_record.get("id"),
        "filename": file_record.get("filename", os.path.basename(file_path)),
        "model": payload["model"],
        "prompt_path": str(prompt_path),
        "output_text": _extract_response_text(response_json),
        "response_json": response_json,
    }


def main():
    parser = argparse.ArgumentParser(description="Send a threat intel file to OpenAI.")
    parser.add_argument("--source", required=True, help="Threat intel source name")
    parser.add_argument("--file", required=True, help="Local file path")
    parser.add_argument("--model", default=None, help="OpenAI model name")
    parser.add_argument(
        "--prompt-path",
        default=str(PROMPT_PATH),
        help="Prompt file path for file-based threat intel requests",
    )
    args = parser.parse_args()

    try:
        result = analyze_threat_intel_file(
            source_name=args.source,
            file_path=os.path.abspath(os.path.expanduser(args.file)),
            model=args.model,
            prompt_path=args.prompt_path,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"File request failed: {exc}")
        raise SystemExit(1) from exc

    print(result["output_text"])


if __name__ == "__main__":
    main()
