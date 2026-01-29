# Repository Guidelines

## Work Language
You must answer in Chinese, but you could think in English.

## Project Structure & Module Organization
- `experiments/` contains the main entry points: `run_experiments.py` (orchestration) and `monitor_experiments.py` (live status view).
- `agents/` holds model-specific agent implementations (for example, `agents/openai-primitive-finder/openai-primitive-finder.py`).
- `evals-data/` stores target build/install scripts and verification harnesses used inside containers.
- `tools/` includes helper utilities (notably `tools/primitive-harness/`).
- `quickjs-bug/` contains the shared bug report and trigger inputs.
- `experiment-results/` and ad hoc output directories (for example, `test-output/`) can be large; avoid committing new results unless intentional.

## Build, Test, and Development Commands
- Set up credentials:
  - `cp .env.example .env` then add `OPENAI_API_KEY` and/or `ANTHROPIC_API_KEY`.
- Build Docker images:
  - `make build-docker-bugfinder` builds `evalrunner:bugfinder`.
  - `make build-docker-bugfinder-cet` builds the CET/Shadow Stack variant.
- Run a minimal experiment:
  - `python experiments/run_experiments.py -o ./results --experiment partial-relro-no-priors --model gpt-5.2 -n 1`
- Monitor progress:
  - `python experiments/monitor_experiments.py -o ./results`
- Enter a dev shell in the container:
  - `make docker-shell-bugfinder` (or `make docker-shell-bugfinder-cet`).

## Coding Style & Naming Conventions
- Python is the primary language; follow PEP 8 with 4-space indentation and explicit type hints where practical.
- Match existing patterns: `dataclass` configs, module-level constants in `UPPER_SNAKE_CASE`, and clear docstrings for public entry points.
- Prefer small, composable functions over deeply nested logic in orchestration code.
- Use descriptive filenames that mirror purpose (for example, `*_verify*.sh`, `*_checker.py`).

## Testing Guidelines
- There is no dedicated unit test suite in this repository.
- Treat a single-run experiment as a smoke test:
  - Run with `-n 1` and a fresh output directory, then monitor for errors.
- When editing harnesses or verification scripts, validate by running the closest related experiment and checking artifacts in the output directory.

## Commit & Pull Request Guidelines
- Follow the existing history: short, imperative commit subjects (for example, `Fix link`, `Update README`).
- Keep commits focused by concern (agents vs. harness vs. docs).
- PRs should include:
  - A clear description of what changed and why.
  - Exact reproduction commands used (build + run + monitor).
  - Notes on any new environment variables, Docker changes, or large outputs.

## Security & Configuration Tips
- Never commit real API keys or `.env`.
- Prefer writing outputs to dedicated, git-ignored directories like `./results/` or `./test-output/`.
- Treat `evals-data/` scripts as part of the trusted execution boundary; review changes there carefully.

