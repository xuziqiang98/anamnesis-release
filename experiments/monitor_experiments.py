#!/usr/bin/env python3
"""
Live monitoring for primitive-finder experiments.

Displays a continuously updating table showing status of all runs.

Usage:
    python monitor_experiments.py -o ./experiment-results/got-no-priors
"""

import argparse
import json
import re
import select
import shutil
import sys
import termios
import time
import tty
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# ANSI escape codes
CLEAR_SCREEN = "\033[2J\033[H"
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
RESET = "\033[0m"

# Alternating colors for log output (readable on light and dark terminals)
LOG_COLORS = [CYAN, MAGENTA]


@dataclass
class RateStats:
    """Track current and max rate statistics."""
    requests_per_min: float = 0.0
    input_per_min: float = 0.0
    output_per_min: float = 0.0

    max_requests_per_min: float = 0.0
    max_input_per_min: float = 0.0
    max_output_per_min: float = 0.0

    def update_maxes(self):
        """Update max values from current values."""
        self.max_requests_per_min = max(self.max_requests_per_min, self.requests_per_min)
        self.max_input_per_min = max(self.max_input_per_min, self.input_per_min)
        self.max_output_per_min = max(self.max_output_per_min, self.output_per_min)


@dataclass
class TokenDataPoint:
    """A single token usage data point from a log."""
    timestamp: datetime
    input_tokens: int
    output_tokens: int


def parse_token_data_points(log_path: Path, since: Optional[datetime] = None) -> list[TokenDataPoint]:
    """Parse log for token usage data points.

    Args:
        log_path: Path to agent.log
        since: Only return data points after this time (for efficiency)

    Returns:
        List of TokenDataPoint sorted by timestamp
    """
    if not log_path.exists():
        return []

    data_points = []

    try:
        with open(log_path, 'r') as f:
            for line in f:
                # Look for "Session total so far" lines (logged after each turn)
                # Format: "2026-01-06 10:45:28 - ... - Session total so far - Combined input: 682935"
                if 'Session total so far' not in line:
                    continue

                # Parse timestamp
                time_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if not time_match:
                    continue

                try:
                    timestamp = datetime.strptime(time_match.group(1), '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue

                # Skip if before 'since'
                if since and timestamp < since:
                    continue

                # Parse token count
                input_match = re.search(r'Combined input: (\d+)', line)

                if input_match:
                    data_points.append(TokenDataPoint(
                        timestamp=timestamp,
                        input_tokens=int(input_match.group(1)),
                        output_tokens=0,  # Not available per-turn in current logs
                    ))

    except IOError:
        return []

    return data_points


def calculate_rates_for_log(log_path: Path, window_seconds: int = 60) -> dict:
    """Calculate token rates for a single log over the given time window.

    Returns:
        {
            'requests': int (number of requests in window),
            'input_tokens': int (input tokens added in window),
            'output_tokens': int (output tokens added in window),
            'window_seconds': float (actual time window used),
        }
    """
    result = {'requests': 0, 'input_tokens': 0, 'output_tokens': 0, 'window_seconds': 0}

    # Get all recent data points (last 2x window to have enough data)
    # We'll calculate the window relative to the LAST entry, not "now",
    # because logs may lag behind real time
    all_points = parse_token_data_points(log_path)

    if len(all_points) < 2:
        return result

    # Use the last entry as "now" for window calculation
    latest = all_points[-1]
    window_start = latest.timestamp - timedelta(seconds=window_seconds)

    # Find data points within the window
    points_in_window = [dp for dp in all_points if dp.timestamp > window_start]

    if len(points_in_window) < 1:
        return result

    # Find the earliest point at or before window_start for delta calculation
    earliest = None
    for dp in all_points:
        if dp.timestamp <= window_start:
            earliest = dp
        else:
            break

    # If no point before window, use the first point in window
    if earliest is None:
        if len(points_in_window) < 2:
            return result
        earliest = points_in_window[0]
        points_in_window = points_in_window[1:]  # Don't count earliest as a request

    # Calculate deltas
    time_delta = (latest.timestamp - earliest.timestamp).total_seconds()
    if time_delta <= 0:
        return result

    result['requests'] = len(points_in_window)
    result['input_tokens'] = latest.input_tokens - earliest.input_tokens
    result['output_tokens'] = latest.output_tokens - earliest.output_tokens
    result['window_seconds'] = time_delta

    return result


def calculate_aggregate_rates(output_dir: Path, window_seconds: int = 60) -> dict:
    """Calculate aggregate token rates across all running experiments.

    Returns:
        {
            'requests_per_min': float,
            'input_per_min': float,
            'output_per_min': float,
        }
    """
    total_requests_per_min = 0.0
    total_input_per_min = 0.0
    total_output_per_min = 0.0

    for run_dir in output_dir.glob("run-*"):
        if not run_dir.is_dir():
            continue

        # Only count running experiments (no result.json yet)
        if (run_dir / 'result.json').exists():
            continue

        agent_log = run_dir / 'agent.log'
        if not agent_log.exists():
            continue

        rates = calculate_rates_for_log(agent_log, window_seconds)

        # Convert this log's rates to per-minute, then sum
        if rates['window_seconds'] > 0:
            scale = 60.0 / rates['window_seconds']
            total_requests_per_min += rates['requests'] * scale
            total_input_per_min += rates['input_tokens'] * scale
            total_output_per_min += rates['output_tokens'] * scale

    return {
        'requests_per_min': total_requests_per_min,
        'input_per_min': total_input_per_min,
        'output_per_min': total_output_per_min,
    }


def parse_agent_log(log_path: Path) -> dict:
    """Extract metrics from agent.log.

    Returns:
        {
            'start_time': datetime or None,
            'context_window': int or None,
            'total_tokens': int or None,
        }
    """
    result = {
        'start_time': None,
        'context_window': None,
        'total_tokens': None,
    }

    if not log_path.exists():
        return result

    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()
    except IOError:
        return result

    if not lines:
        return result

    # Parse start time from first line
    # Format: "2026-01-06 10:26:35 - claude-primitive-finder - INFO - ..."
    first_line = lines[0]
    time_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', first_line)
    if time_match:
        try:
            result['start_time'] = datetime.strptime(time_match.group(1), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass

    # Parse latest metrics from end of file (read last 100 lines for efficiency)
    recent_lines = lines[-100:] if len(lines) > 100 else lines

    for line in reversed(recent_lines):
        # Look for "Context window: N"
        if result['context_window'] is None and 'Context window:' in line:
            match = re.search(r'Context window: (\d+)', line)
            if match:
                result['context_window'] = int(match.group(1))

        # Look for "Combined input: N"
        if result['total_tokens'] is None and 'Combined input:' in line:
            match = re.search(r'Combined input: (\d+)', line)
            if match:
                result['total_tokens'] = int(match.group(1))

        # Stop early if we found both
        if result['context_window'] is not None and result['total_tokens'] is not None:
            break

    return result


def get_run_status(run_dir: Path) -> dict:
    """Get status of a single run directory.

    Returns:
        {
            'name': str,
            'status': 'running' | 'success' | 'failed',
            'start_time': datetime or None,
            'duration_seconds': float or None (for completed runs),
            'context_window': int or None,
            'total_tokens': int or None,
        }
    """
    result = {
        'name': run_dir.name,
        'status': 'running',
        'start_time': None,
        'duration_seconds': None,
        'context_window': None,
        'total_tokens': None,
    }

    result_json = run_dir / 'result.json'
    agent_log = run_dir / 'agent.log'

    # Check for completion
    if result_json.exists():
        try:
            with open(result_json) as f:
                data = json.load(f)
            result['status'] = 'success' if data.get('success') else 'failed'
            result['duration_seconds'] = data.get('duration_seconds')
            result['total_tokens'] = data.get('total_combined_input_tokens')
        except (json.JSONDecodeError, IOError):
            result['status'] = 'failed'
    elif not agent_log.exists() or agent_log.stat().st_size == 0:
        # No log yet - skip this run
        return None

    # Parse agent.log for metrics (start_time, and current metrics if still running)
    if agent_log.exists():
        metrics = parse_agent_log(agent_log)
        result['start_time'] = metrics.get('start_time')
        if result['status'] == 'running':
            result['context_window'] = metrics.get('context_window')
            result['total_tokens'] = metrics.get('total_tokens')

    return result


def format_duration_seconds(total_seconds: float) -> str:
    """Format duration in seconds as H:MM:SS."""
    total_seconds = int(total_seconds)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours}:{minutes:02d}:{seconds:02d}"


def format_duration(start_time: Optional[datetime], duration_seconds: Optional[float] = None) -> str:
    """Format duration as H:MM:SS.

    For completed runs, use duration_seconds.
    For running runs, calculate from start_time.
    """
    if duration_seconds is not None:
        return format_duration_seconds(duration_seconds)

    if start_time is None:
        return "-"

    delta = datetime.now() - start_time
    return format_duration_seconds(delta.total_seconds())


def format_tokens(tokens: Optional[int]) -> str:
    """Format token count with K/M suffix."""
    if tokens is None:
        return "-"

    if tokens >= 1_000_000:
        return f"{tokens / 1_000_000:.1f}M"
    elif tokens >= 1_000:
        return f"{tokens / 1_000:.0f}K"
    else:
        return str(tokens)


def format_status(status: str) -> str:
    """Format status with color."""
    if status == 'running':
        return f"{CYAN}RUNNING{RESET}"
    elif status == 'success':
        return f"{GREEN}SUCCESS{RESET}"
    else:
        return f"{RED}FAILED{RESET}"


def format_rate(value: float, suffix: str = "") -> str:
    """Format a rate value with K/M suffix."""
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M{suffix}"
    elif value >= 1_000:
        return f"{value / 1_000:.0f}K{suffix}"
    elif value >= 1:
        return f"{value:.0f}{suffix}"
    else:
        return f"0{suffix}"


def get_terminal_width() -> int:
    """Get terminal width, with fallback."""
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 120


def strip_log_timestamp(line: str) -> str:
    """Strip timestamp prefix from log line to save space.

    Converts: '2026-01-10 16:59:32,220 - INFO - Tool call: ...'
    To: 'Tool call: ...'
    """
    # Pattern: timestamp - level - message OR timestamp - name - level - message
    match = re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.\d]* - (?:\S+ - )?(?:INFO|DEBUG|WARNING|ERROR) - (.*)$', line)
    if match:
        return match.group(1)
    return line


def get_recent_log_lines(log_path: Path, n_lines: int, max_width: int) -> list[str]:
    """Get last N lines from a log file, truncated to max_width.

    Args:
        log_path: Path to agent.log
        n_lines: Number of lines to return
        max_width: Maximum width per line (will truncate with ...)

    Returns:
        List of formatted log lines (most recent last)
    """
    if not log_path.exists():
        return []

    try:
        with open(log_path, 'r') as f:
            # Read all lines and get the last n_lines
            lines = f.readlines()
            recent = lines[-n_lines:] if len(lines) >= n_lines else lines
    except IOError:
        return []

    result = []
    for line in recent:
        line = line.rstrip('\n\r')
        # Strip timestamp to save space
        line = strip_log_timestamp(line)
        # Truncate long lines
        if len(line) > max_width:
            line = line[:max_width - 3] + "..."
        result.append(line)

    return result


def get_keypress(timeout: float) -> Optional[str]:
    """Get a single keypress without waiting for Enter.

    Args:
        timeout: Maximum time to wait in seconds

    Returns:
        The key pressed, or None if timeout or no TTY available
    """
    # Check if stdin is a TTY
    if not sys.stdin.isatty():
        time.sleep(timeout)
        return None

    try:
        old_settings = termios.tcgetattr(sys.stdin)
    except termios.error:
        # No TTY available, fall back to sleep
        time.sleep(timeout)
        return None

    try:
        tty.setcbreak(sys.stdin.fileno())
        rlist, _, _ = select.select([sys.stdin], [], [], timeout)
        if rlist:
            return sys.stdin.read(1)
        return None
    except Exception:
        return None
    finally:
        try:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        except termios.error:
            pass


def print_table(output_dir: Path, runs: list[dict], rate_stats: RateStats,
                show_logs: bool = True, lines_per_run: int = 3):
    """Print the status table with optional live log tailing.

    Args:
        output_dir: Experiment output directory
        runs: List of run status dicts
        rate_stats: Rate statistics
        show_logs: Whether to show live log section
        lines_per_run: Number of log lines per running experiment
    """
    term_width = get_terminal_width()

    print(f"{BOLD}Experiment Monitor:{RESET} {output_dir}")
    print("Press 1-9 to view run details, 'q' to quit detail view. Ctrl+C to exit.\n")

    # Header
    header = f"{'Run':<10} {'Status':<10} {'Started':<10} {'Duration':<10} {'Tokens':<10} {'Context':<10}"
    print(f"{BOLD}{header}{RESET}")
    print("─" * 60)

    # Rows
    for run in runs:
        name = run['name']
        status = format_status(run['status'])
        started = run['start_time'].strftime('%H:%M:%S') if run['start_time'] else "-"
        duration = format_duration(run['start_time'], run.get('duration_seconds'))
        tokens = format_tokens(run['total_tokens'])
        context = format_tokens(run['context_window']) if run['status'] == 'running' else "-"

        # Status field has ANSI codes, so we need to account for that in padding
        status_display = f"{status:<19}"  # 10 + 9 for ANSI codes
        print(f"{name:<10} {status_display} {started:<10} {duration:<10} {tokens:<10} {context:<10}")

    # Summary
    running = sum(1 for r in runs if r['status'] == 'running')
    success = sum(1 for r in runs if r['status'] == 'success')
    failed = sum(1 for r in runs if r['status'] == 'failed')

    print()
    print(f"Summary: {CYAN}{running} running{RESET}, {GREEN}{success} success{RESET}, "
          f"{RED}{failed} failed{RESET}")

    # Rate statistics
    print()
    print(f"{BOLD}API Usage (per minute):{RESET}")
    print("─" * 60)
    print(f"{'Metric':<20} {'Current':<15} {'Max Seen':<15}")
    print(f"{'Requests':<20} {format_rate(rate_stats.requests_per_min):<15} {format_rate(rate_stats.max_requests_per_min):<15}")
    print(f"{'Input tokens':<20} {format_rate(rate_stats.input_per_min):<15} {format_rate(rate_stats.max_input_per_min):<15}")

    # Live logs section
    if show_logs:
        running_runs = [r for r in runs if r['status'] == 'running']
        if running_runs:
            print()
            print(f"{BOLD}Live Logs (running experiments):{RESET}")
            print("─" * 60)

            # Calculate max width for log content (leave room for prefix like "[run-001] ")
            prefix_len = 12  # "[run-NNN] "
            max_log_width = term_width - prefix_len

            for i, run in enumerate(running_runs):
                run_name = run['name']
                color = LOG_COLORS[i % len(LOG_COLORS)]
                log_path = output_dir / run_name / 'agent.log'
                lines = get_recent_log_lines(log_path, lines_per_run, max_log_width)

                for line in lines:
                    print(f"{color}[{run_name}]{RESET} {line}")

            # Show tail -f commands for easy copy-paste
            print()
            print(f"{BOLD}Tail commands (copy-paste to follow full logs):{RESET}")
            for run in running_runs:
                log_path = output_dir / run['name'] / 'agent.log'
                print(f"  tail -f {log_path}")


def print_detail_view(output_dir: Path, run_name: str, n_lines: int = 50):
    """Print detailed view of a single run's log.

    Args:
        output_dir: Experiment output directory
        run_name: Name of run (e.g., 'run-001')
        n_lines: Number of lines to show
    """
    term_width = get_terminal_width()
    log_path = output_dir / run_name / 'agent.log'

    print(f"{BOLD}Detail View: {run_name}{RESET}")
    print(f"Log: {log_path}")
    print(f"Press 'b' or 'q' to return to main view. Ctrl+C to exit.")
    print("─" * 60)

    lines = get_recent_log_lines(log_path, n_lines, term_width - 2)
    for line in lines:
        print(line)

    print()
    print(f"─" * 60)
    print(f"Showing last {len(lines)} lines. Full log: tail -f {log_path}")


def scan_runs(output_dir: Path) -> list[dict]:
    """Scan output directory for all runs."""
    if not output_dir.exists():
        return []

    runs = []
    for run_dir in sorted(output_dir.glob("run-*")):
        if run_dir.is_dir():
            status = get_run_status(run_dir)
            if status is not None:  # Skip dirs with no logs yet
                runs.append(status)

    return runs


def main():
    parser = argparse.ArgumentParser(
        description="Monitor running primitive-finder experiments"
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        required=True,
        help="Output directory to monitor",
    )
    parser.add_argument(
        "--refresh",
        type=float,
        default=2.0,
        help="Refresh interval in seconds (default: 2)",
    )
    parser.add_argument(
        "--no-logs",
        action="store_true",
        help="Disable live log tailing section",
    )
    parser.add_argument(
        "--log-lines",
        type=int,
        default=3,
        help="Number of log lines to show per running experiment (default: 3)",
    )

    args = parser.parse_args()

    if not args.output_dir.exists():
        print(f"Error: Directory does not exist: {args.output_dir}")
        sys.exit(1)

    # Track rate statistics across refreshes
    rate_stats = RateStats()

    # Detail view state: None = main view, "run-001" = detail view for that run
    detail_run = None

    try:
        while True:
            print(CLEAR_SCREEN, end="")
            runs = scan_runs(args.output_dir)

            if detail_run:
                # Detail view mode - show full log for one run
                print_detail_view(args.output_dir, detail_run)
            else:
                # Main view mode
                # Calculate current rates
                rates = calculate_aggregate_rates(args.output_dir)
                rate_stats.requests_per_min = rates['requests_per_min']
                rate_stats.input_per_min = rates['input_per_min']
                rate_stats.output_per_min = rates['output_per_min']
                rate_stats.update_maxes()

                if not runs:
                    print(f"No runs found in {args.output_dir}")
                    print("Waiting for runs to start...")
                else:
                    print_table(args.output_dir, runs, rate_stats,
                               show_logs=not args.no_logs,
                               lines_per_run=args.log_lines)

            # Wait for keypress or timeout
            key = get_keypress(args.refresh)

            if key:
                if key in '123456789' and detail_run is None:
                    # Switch to detail view for run-00N
                    run_num = int(key)
                    candidate = f"run-{run_num:03d}"
                    # Check if this run exists
                    if any(r['name'] == candidate for r in runs):
                        detail_run = candidate
                elif key in ('b', 'q', 'B', 'Q') and detail_run is not None:
                    # Return to main view
                    detail_run = None

    except KeyboardInterrupt:
        print("\n\nMonitoring stopped.")
        print(f"\n{BOLD}Final Max Rates:{RESET}")
        print(f"  Requests/min:     {format_rate(rate_stats.max_requests_per_min)}")
        print(f"  Input tokens/min: {format_rate(rate_stats.max_input_per_min)}")


if __name__ == "__main__":
    main()
