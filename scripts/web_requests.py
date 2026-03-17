import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from scripts.ai_validator import DEFAULT_OPENAI_MODEL

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


def _extract_url_citations(response_json):
    citations = []
    for output_item in response_json.get("output", []):
        if output_item.get("type") != "message":
            continue
        for content_item in output_item.get("content", []):
            for annotation in content_item.get("annotations", []):
                if annotation.get("type") != "url_citation":
                    continue
                citations.append(
                    {
                        "title": annotation.get("title", ""),
                        "url": annotation.get("url", ""),
                    }
                )
    return citations


def _build_input_text(source_name, link, context_sections=None):
    parts = [
        f"Threat intel source: {source_name}",
        f"Reference URL: {link}",
    ]
    for section in context_sections or []:
        if section:
            parts.append(str(section))
    return "\n\n".join(parts)


def analyze_threat_intel_link(
    *,
    source_name,
    link,
    model=None,
    api_key=None,
    prompt_path=PROMPT_PATH,
    context_sections=None,
    timeout=120,
):
    token = get_api_key(api_key)
    if not token:
        raise RuntimeError("OPENAI_API_KEY/OPENAI_API is not set")

    prompt_text = load_prompt_text(prompt_path)
    parsed_url = urlparse(link)
    allowed_domains = [parsed_url.netloc] if parsed_url.netloc else []

    payload = {
        "model": get_model_name(model),
        "tools": [{"type": "web_search"}],
        "tool_choice": "auto",
        "include": ["web_search_call.action.sources"],
        "input": _build_input_text(
            source_name,
            link,
            context_sections=context_sections,
        ),
    }
    if allowed_domains:
        payload["tools"][0]["filters"] = {"allowed_domains": allowed_domains}
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
            f"OpenAI web search failed with status {response.status_code}: "
            f"{response.text.strip() or 'Unknown error'}"
        )

    response_json = response.json()
    return {
        "model": payload["model"],
        "prompt_path": str(prompt_path),
        "output_text": _extract_response_text(response_json),
        "citations": _extract_url_citations(response_json),
        "response_json": response_json,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Use OpenAI web search for a threat intel link."
    )
    parser.add_argument("--source", required=True, help="Threat intel source name")
    parser.add_argument("--link", required=True, help="Threat intel URL")
    parser.add_argument("--model", default=None, help="OpenAI model name")
    parser.add_argument(
        "--prompt-path",
        default=str(PROMPT_PATH),
        help="Prompt file path for web-based threat intel requests",
    )
    args = parser.parse_args()

    try:
        result = analyze_threat_intel_link(
            source_name=args.source,
            link=args.link,
            model=args.model,
            prompt_path=args.prompt_path,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Web request failed: {exc}")
        raise SystemExit(1) from exc

    print(result["output_text"])


if __name__ == "__main__":
    main()
