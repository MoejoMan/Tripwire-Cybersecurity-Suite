# Cybersecurity Suite

SSH Brute Force Log Analyzer that parses system authentication logs, aggregates attempts by IP, classifies threat levels, and prints a concise summary with optional detailed breakdown. Full results can be exported to CSV.

## Features

- **Brute-force detection**: Classifies short-burst and persistent attacks with severity levels (CRITICAL/HIGH/MEDIUM/LOW)
- **Auto-format parsing**: Supports common syslog and journald formats; auto-detects on first match
- **Event summaries**: Highlights invalid users and accepted login events
- **Configurable**: Tunable thresholds via `config.json`; color output can be disabled via environment
- **CSV export**: Export complete analysis results with timestamps and durations

## Requirements

- Python 3.8+ (built-in libraries only)
- Access to SSH auth logs (e.g., `/var/log/auth.log`, `/var/log/secure`)

## Installation

1. Clone this repository
2. Optional: create a virtual environment
3. No external dependencies required

## Configuration

Edit `config.json` to tune behavior:

- `max_attempts`: Threshold for short-window detection
- `time_window_minutes`: Rolling window size for short-burst detection
- `block_threshold`: Total failed attempts to recommend blocking
- `monitor_threshold`: Total failed attempts to recommend monitoring
- `summary_limit`: Max rows to show in terminal summary
- `verbose_limit`: Max IPs shown in detailed breakdown
- `color_enabled`: Enable ANSI colors (override with `NO_COLOR` env)

On first run, a default `config.json` is created if missing.

## Usage

Interactive run (opens a file picker if no path provided):

```bash
python main.py
```

Non-interactive (pass a log file and optional summary size):

```bash
python main.py --log-file "/var/log/auth.log" --summary-limit 50
```

Live monitoring (tail the log, refresh every 5s by default):

```bash
python main.py --log-file "/var/log/auth.log" --live --refresh 5
```

Start from top of file instead of tail:

```bash
python main.py --log-file "/var/log/auth.log" --live --follow-start
```

Reduce noise and condense output:

```bash
# Show only HIGH+ threats and skip event summaries
python main.py --log-file "/var/log/auth.log" --live --filter-severity HIGH --compact
```

Quick presets and shortcuts:

```bash
# Quiet SOC-style view: HIGH+ only, compact, 5s refresh
python main.py --log-file "/var/log/auth.log" --live --mode soc

# Verbose view: no filters, full summaries
python main.py --log-file "/var/log/auth.log" --live --mode verbose

# Short flag for filter
python main.py --log-file "/var/log/auth.log" --live -f HIGH --compact --refresh 10

# Presets without modes
python main.py --log-file "/var/log/auth.log" --live --quiet   # same as HIGH+ compact
python main.py --log-file "/var/log/auth.log" --live --noisy   # show everything
```

Disable color output (useful for CI or plain terminals):

```bash
NO_COLOR=1 python main.py --log-file "/var/log/auth.log"
```

On Windows PowerShell:

```powershell
$env:NO_COLOR = 1
python .\main.py --log-file "C:\\path\\to\\auth.log"
```

## Output

The analyzer prints:

- **Log Coverage**: Time window and total parsed attempts
- **Event Summaries**: Top invalid user and accepted login counts by IP
- **Threat Analysis Summary**: Severity, IP, attempts, rate, and recommended action
- **Detailed Breakdown** (optional): Per-IP statistics including window and targeted users

To export all results to CSV, answer `y` when prompted or set `export_csv` in code; the file is saved next to your log as `brute_force_analysis.csv`.

## Notes

- Supported formats are auto-detected; if detection fails, available formats are listed.
- The parser tracks basic stats: lines read, format matches, extract matches, and timestamp coverage.

## Roadmap

- Additional event types and heuristics
- Enrichment (GeoIP, ASN) via optional modules
- Batch processing and scheduling

## License

None yet, lol
