# Elastic Query Style Guide

Use the passing detections in this repository as the primary style reference when generating new Elastic detection rules.

## Rule structure

- Use `type: query`.
- Use `language: kuery` unless the user explicitly requests a different language.
- Keep the YAML compact and readable with a `query: |` block.
- Keep required metadata fields present and practical.

## Query style

- Prefer direct field matches with concise boolean logic.
- Match the current house tone: readable, focused, and implementation-oriented.
- Use lowercase boolean operators like `and` and `or`.
- Favor fields already used successfully in the passing rules, such as:
  - `message`
  - `process.args`
  - `event.category`
  - `event.code`
- Keep the query narrow enough to reflect the threat behavior described in the intel report.

## Metadata style

- Reuse the established index pattern style from the passing rules when it fits the requested platform.
- Match the existing tag style, including `attack.*` tags where justified.
- Keep severity and risk score aligned to the observed behavior and the repository's current convention.

## Examples

See the YAML files under `KnowledgeBase/DetectionExamples/Elastic_Query_Style_Examples/`.
