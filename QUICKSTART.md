# Quick Start

```bash
# 1. Configure API keys
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY and/or OPENAI_API_KEY

# 2. Build the Docker image
make build-docker-bugfinder

# 3. Run an experiment
python experiments/run_experiments.py \
    -o ./my-results \
    --experiment partial-relro-no-priors \
    --model claude-opus-4-5-20251101 \
    -n 1

# 4. Monitor progress (in another terminal)
python experiments/monitor_experiments.py -o ./my-results
```

**Note: To run the experiments with hardware-enforced shadowstack you need a processor that supports it, and you must use a docker image built from `Dockerfile.bugfinder-cet` (build via `make build-docker-bugfinder`)**

## Prerequisites

- Docker
- Python 3.10+
- API keys:
  - `ANTHROPIC_API_KEY` for Claude models
  - `OPENAI_API_KEY` for GPT models

---

## Repository Structure

### `experiments/`

Contains the experiment runner that orchestrates agent runs inside Docker containers.

| File | Purpose |
|------|---------|
| `run_experiments.py` | Main entry point. Configures experiments, launches Docker containers, collects results. |
| `monitor_experiments.py` | Live monitoring dashboard showing status of all runs. |

### `agents/`

LLM-powered exploit development agents. Each agent receives a bug report, trigger, and access to the target source/binary, then attempts to develop a working exploit.

| Directory | Purpose |
|-----------|---------|
| `claude-primitive-finder/` | Agent using Claude models via the Anthropic API |
| `openai-primitive-finder/` | Agent using GPT models via the OpenAI API |

### `tools/`

Utilities used by agents during exploitation and for verifying exploit success.

| File/Directory | Purpose |
|----------------|---------|
| `primitive-harness/shell_verify_callback.py` | Verifies shell spawning via network callback |
| `primitive-harness/offset_independence_checker.py` | Verifies exploits don't use hardcoded offsets |
| `get_definition.py` | Source code navigation tool used by agents |

### `evals-data/`

Target configurations including build scripts and verification harnesses.

| Directory | Purpose |
|-----------|---------|
| `evals-quickjs-latest/` | QuickJS build scripts (partial RELRO, full RELRO, CFI, CET) and verification scripts |
| `evals-quickjs-seccomp/` | QuickJS with seccomp sandbox blocking execve/fork |
| `evals-quickjs-connectback/` | QuickJS configured for network callback verification |

### `quickjs-bug/`

The vulnerability used in all experiments - a use-after-free in QuickJS's Atomics implementation.

| File | Purpose |
|------|---------|
| `report.md` | Vulnerability analysis provided to the agent |
| `trigger.js` | Proof-of-concept that triggers the bug |
| `asan_output.txt` | ASAN output showing the memory corruption |

### `experiment-results/`

Published results from our experiments. See `experiment-results/README.md` for a summary.

### Docker Images

| Image | Base | Purpose |
|-------|------|---------|
| `evalrunner:bugfinder` | Debian | Standard image for most experiments |
| `evalrunner:bugfinder-cet` | Ubuntu 24.04 | Required for Shadow Stack experiments |

---

## Experiments

| Experiment | Mitigations | Docker Image |
|------------|-------------|--------------|
| `partial-relro-no-priors` | Partial RELRO | bugfinder |
| `relro-no-priors` | Full RELRO | bugfinder |
| `cfi-no-priors` | Full RELRO + CFI | bugfinder |
| `cet-cfi-no-priors` | Full RELRO + CFI + Shadow Stack | bugfinder-cet |
| `partial-relro-offset-independent` | Partial RELRO | bugfinder |
| `filewrite-seccomp` | Full RELRO + CFI + CET + Seccomp | bugfinder-cet |
| `connectback` | Full RELRO + Seccomp | bugfinder |
| `connectback-offset-independent` | Full RELRO + Seccomp | bugfinder |

---

## Running Experiments

```bash
python experiments/run_experiments.py \
    -o ./results \
    --experiment <experiment-name> \
    --model <model-id> \
    -n <num-runs>
```

### Options

| Option | Description |
|--------|-------------|
| `-o, --output-dir` | Output directory for results |
| `--experiment` | Experiment name (see table above) |
| `--model` | Model ID (e.g., `claude-opus-4-5-20251101`, `gpt-5.2`) |
| `-n, --max-runs` | Number of runs (default: 10) |
| `-p, --parallel` | Parallel runs (default: 2) |
| `--reasoning-effort` | For OpenAI models: `low`, `medium`, or `high` |
| `--dry-run` | Show commands without executing |

### Monitoring Runs

Use the monitor script to watch experiment progress in real-time:

```bash
python experiments/monitor_experiments.py -o ./results
```

| Option | Description |
|--------|-------------|
| `-o, --output-dir` | Output directory to monitor (required) |
| `--refresh` | Refresh interval in seconds (default: 2) |
| `--no-logs` | Disable live log tailing section |
| `--log-lines` | Number of log lines to show per running experiment (default: 3) |

The monitor displays a live-updating table showing each run's status, token usage, and current activity. Press `q` to quit, or number keys to follow a specific run's log output.

---

## Output Structure

```
results/
|-- experiment_config.json
+-- run-001/
    |-- agent.log               # Full agent transcript
    |-- result.json             # Success/failure, tokens, cost
    +-- achieved_primitives/    # Only on success
        +-- exec-shell/
            |-- poc.js          # Working exploit
            +-- analysis.md     # Exploitation writeup
```

---

## Building Docker Images

```bash
# Standard image
make build-docker-bugfinder

# CET image (for Shadow Stack experiments)
make build-docker-bugfinder-cet
```

## Debug Shell

```bash
make docker-shell-bugfinder
make docker-shell-bugfinder-cet
```
