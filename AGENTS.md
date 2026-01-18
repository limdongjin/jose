# AGENTS.md

## Repository overview
- This repo contains the TypeScript `jose` implementation along with a parallel Python reimplementation under `python/`.
- Python work should stay aligned with the TypeScript behavior and document parity references.

## Working agreements
- When changing Python JWT behavior, update:
  - `python/doc/release-notes.md` (release-note style summary).
  - `python/doc/implementation-notes.md` (implementation detail summary).
  - `python/PLAN.md` if the plan changes or becomes more concrete.
  - `python/README.md` if usage or behaviors change.
- Include TypeScript parity references with code snippets and source paths when relevant.
- Keep Python code style consistent with the existing module layout in `python/src`.

## Tests
- Python unit tests live in `python/tests` and can be run with `python -m unittest` from the `python/` directory.
