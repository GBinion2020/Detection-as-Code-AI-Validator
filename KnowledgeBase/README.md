# Knowledge Base

This folder contains reference material used to guide AI-assisted threat-intel review and detection generation.

## Contents

- `Schemas/`: the default validation schema used for generated detections.
- `DetectionExamples/`: known-good example detections that reflect the expected rule and query style.
- `Guides/`: human-readable guidance describing house style and query conventions.
- `Policies/`: workflow guardrails such as minimum-confidence and query-field allowlist rules.

The examples in `DetectionExamples/` are neutralized style references derived from the detections that already pass into the SIEM successfully.
