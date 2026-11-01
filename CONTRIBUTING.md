# Contributing

Thanks for helping make AI agents safer.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
make install        # pip install -e ".[dev,llm]"
make check          # lint, types, SAST, hidden-character scan, tests, policy suite, eval gate
```

## Ground rules

1. **Every security feature ships with an adversarial test**: the bypass you are preventing, not
   just the happy path.
2. **Deny by default.** New checks fail closed; new detectors fail safe (`detector_error`).
3. **No invisible characters in the repository.** Build test payloads from code points
   (`chr(0xE0041)`) or with `agentwarden.evaluation.obfuscate`. `scripts/check_hidden_chars.py`
   enforces this in CI.
4. **No credential-shaped literals.** Assemble test secrets at runtime (`"AKIA" + "..."`) so secret
   scanners and push protection stay quiet.
5. **Detector changes need evidence.** Add samples to `src/agentwarden/data/injection_corpus.yaml`
   (keep known misses and hard negatives honest) and keep `agentwarden eval` green.
6. **Policy changes need cases** in `tests/policy/default_policy_cases.yaml`.
7. `ruff`, `ruff format` and `mypy --strict` must pass. Keep SQL static and parameterized.

## Commits & pull requests

- Conventional-style subjects (`feat(risk): …`, `fix(policy): …`, `docs: …`).
- Explain the *threat* a change addresses and how it was tested.
- Update docs (`README.md`, `docs/`) when behavior changes.
