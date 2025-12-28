"""
SSH Brute Force Analysis CLI.

This script parses SSH authentication logs, aggregates login attempts by IP,
classifies threat levels, and prints a concise summary and optional detailed
breakdown. It can export full results to CSV for further analysis.

Usage:
- Non-interactive: provide a path with --log-file
- Interactive: if no path is provided, a file picker will open
"""
import re
import sys
import os
import csv
import shutil
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
from parser import SSHLogParser
from config import Config
from utils import follow_file

class BruteForceDetector:
    """
        Detects and summarizes brute-force behaviour in SSH authentication logs.

        Parameters:
        - max_attempts: Number of failed attempts within `time_window_minutes` to flag an IP.
        - time_window_minutes: Size of rolling window used for short-burst detection.
        - block_threshold: Total failed attempts to recommend blocking (persistent attacks).
        - monitor_threshold: Total failed attempts to recommend monitoring.
        - summary_limit: Maximum rows printed in the summary table.
        - verbose_limit: Maximum IPs included in the verbose breakdown.

        Attributes:
        - attempts_by_ip: Mapping of IP to list of parsed attempts with `username`,
            `timestamp`, `success`, and optional `event` label.
        - use_color: Whether to use ANSI colors in terminal output.
    """

    def __init__(self, max_attempts=5, time_window_minutes=10, block_threshold=50, monitor_threshold=20, summary_limit=20, verbose_limit=10):
        self.max_attempts = max_attempts
        self.time_window = timedelta(minutes=time_window_minutes)
        self.block_threshold = block_threshold
        self.monitor_threshold = monitor_threshold
        self.summary_limit = summary_limit
        self.verbose_limit = verbose_limit
        self.use_color = not os.environ.get('NO_COLOR')
        self.attempts_by_ip = defaultdict(list)

    def _color(self, text, fg=None, bold=False):
        """
        Return `text` decorated with ANSI color codes when enabled.

        Args:
        - text: String to colorize.
        - fg: Optional foreground color name (red, yellow, green, cyan, blue, magenta).
        - bold: Whether to apply bold styling.

        Returns:
        - The possibly colorized text, or the original text when color is disabled.
        """
        if not self.use_color:
            return text
        codes = []
        if bold:
            codes.append('1')
        fg_map = {
            'red': '31', 'yellow': '33', 'green': '32', 'cyan': '36', 'blue': '34', 'magenta': '35'
        }
        if fg and fg in fg_map:
            codes.append(fg_map[fg])
        if not codes:
            return text
        return f"\033[{';'.join(codes)}m{text}\033[0m"

    def add_attempt(self, ip_address, username, timestamp, success, event=None):
        """
        Record a single SSH auth attempt parsed from the logs.

        Args:
        - ip_address: Source IP address.
        - username: Target account name.
        - timestamp: Attempt time as `datetime`.
        - success: True if authentication succeeded; False otherwise.
        - event: Optional label describing the event type (e.g., 'invalid_user').
        """
        self.attempts_by_ip[ip_address].append({
            "username": username,
            "timestamp": timestamp,
            "success": success,
            "event": event
        })

    def classify_threat(self, total_attempts, attack_rate, duration):
        """
        Classify threat severity from aggregate metrics.

        Logic:
        - Short-burst attacks: high volume within `time_window` → CRITICAL/HIGH.
        - Persistent attacks: very high total volume regardless of rate → HIGH/MEDIUM.
        - Elevated rate with moderate volume → MEDIUM.
        - Otherwise → LOW.

        Args:
        - total_attempts: Total failed attempts for an IP.
        - attack_rate: Failed attempts per minute over the observed window.
        - duration: `timedelta` covering first to last attempt.

        Returns:
        - One of {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}.
        """
        # Rapid attacks - high rate in short window
        if total_attempts >= self.max_attempts and duration <= self.time_window and attack_rate >= 2.0:
            return "CRITICAL"
        elif total_attempts >= self.max_attempts and duration <= self.time_window:
            return "HIGH"
        
        # Persistent attacks - high volume even if slow
        elif total_attempts >= self.block_threshold:
            return "HIGH"
        elif total_attempts >= self.monitor_threshold:
            return "MEDIUM"
        
        # High-rate attacks even if lower volume
        elif attack_rate > 1.0:
            return "MEDIUM"
        
        elif total_attempts >= self.max_attempts:
            return "LOW"
        return "LOW"

    def format_duration(self, delta):
        """
        Format a `timedelta` as a compact human-readable string.

        Example: "2h 3m 15s" or "7m 04s".
        """
        total_seconds = int(delta.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        return f"{minutes}m {seconds}s"

    def analyze(self, verbose=False, export_csv=None):
        """
        Aggregate attempts, compute severity, and render summaries.

        Args:
        - verbose: If True, include a per-IP detailed breakdown.
        - export_csv: Optional path to export the full results table.

        Returns:
        - List of dict rows with keys: IP, Attempts, Attack_Rate, Severity,
          Action, Duration, Window_Start, Window_End.
        """
        THRESHOLD = self.max_attempts
        summary = defaultdict(lambda: defaultdict(int))

        for ip, attempts in self.attempts_by_ip.items():
            for attempt in attempts:
                # Count only failed attempts towards brute-force summary
                if not attempt.get('success', False):
                    username = attempt['username']
                    summary[ip][username] += 1

        sorted_ips = sorted(summary.items(), key=lambda x: sum(x[1].values()), reverse=True)
        
        # Pre-compute threat levels and scores for sorting
        threat_scores = {}
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        
        for ip, usernames in summary.items():
            total_attempts = sum(usernames.values())
            attempts = self.attempts_by_ip[ip]
            
            if attempts:
                timestamps = [att['timestamp'] for att in attempts]
                duration = max(timestamps) - min(timestamps)
                # Add 1 minute floor to prevent inflated rates from tiny time windows
                total_minutes = max(duration.total_seconds() / 60, 1.0)
                attack_rate = total_attempts / total_minutes
            else:
                attack_rate = 0
                duration = timedelta(0)
            
            threat_level = self.classify_threat(total_attempts, attack_rate, duration)
            threat_scores[ip] = (severity_order[threat_level], threat_level, total_attempts)
        
        # Sort by: severity first, then by attempt count
        sorted_ips = sorted(sorted_ips, key=lambda x: threat_scores[x[0]][:2])
        
        # Collect results for export
        results = []
        
        # Compute results for all IPs (for full CSV export)
        all_results = []
        for (ip, usernames) in sorted_ips:
            total_attempts = sum(usernames.values())
            attempts = self.attempts_by_ip[ip]
            if not attempts:
                continue
            timestamps = [att['timestamp'] for att in attempts]
            first = min(timestamps)
            last = max(timestamps)
            duration = last - first
            total_minutes = max(duration.total_seconds() / 60, 1.0)
            attack_rate = total_attempts / total_minutes
            threat_level = self.classify_threat(total_attempts, attack_rate, duration)
            if threat_level in ["CRITICAL", "HIGH"]:
                action = "BLOCK"
            elif threat_level == "MEDIUM":
                action = "MONITOR"
            else:
                action = "ALLOW"
            all_results.append({
                'IP': ip,
                'Attempts': total_attempts,
                'Attack_Rate': f"{attack_rate:.2f}",
                'Severity': threat_level,
                'Action': action,
                'Duration': self.format_duration(duration),
                'Window_Start': first.isoformat(),
                'Window_End': last.isoformat()
            })

        # Compute overall coverage stats
        all_timestamps = []
        total_parsed_attempts = 0
        for attempts in self.attempts_by_ip.values():
            total_parsed_attempts += len(attempts)
            all_timestamps.extend(att['timestamp'] for att in attempts)
        ip_count = len(self.attempts_by_ip)

        # Get terminal width for better formatting
        term_width = shutil.get_terminal_size((80, 20)).columns

        # Coverage summary header
        line_width = min(term_width, 100)
        print("\n" + "=" * line_width)
        print(self._color("LOG COVERAGE", bold=True))
        print("=" * line_width)
        # Prefer coverage from parser stats; fall back to attempts
        coverage_start = getattr(self, 'coverage_start', None)
        coverage_end = getattr(self, 'coverage_end', None)
        if not coverage_start or not coverage_end:
            if all_timestamps:
                coverage_start = min(all_timestamps)
                coverage_end = max(all_timestamps)

        if coverage_start and coverage_end:
            coverage_duration = coverage_end - coverage_start
            coverage_str = self.format_duration(coverage_duration)
            print(f"Window: {coverage_start.strftime('%Y-%m-%d %H:%M:%S')} to {coverage_end.strftime('%Y-%m-%d %H:%M:%S')} ({coverage_str})")
            print(f"Parsed IPs: {ip_count:,} | Attempts: {total_parsed_attempts:,}")
        else:
            print("No parsed attempts found.")

        # Compact event summaries to keep output concise
        print("\n" + "=" * line_width)
        print(self._color("EVENT SUMMARIES", bold=True))
        print("=" * line_width)
        
        # Invalid user summary (top N by count)
        invalid_counts = defaultdict(int)
        for ip, attempts in self.attempts_by_ip.items():
            for att in attempts:
                if att.get('event') == 'invalid_user':
                    invalid_counts[ip] += 1
        if invalid_counts:
            top_invalid = sorted(invalid_counts.items(), key=lambda x: x[1], reverse=True)[:max(1, self.summary_limit//2)]
            print(self._color(f"Invalid user attempts (top {len(top_invalid)}):", fg='cyan', bold=True))
            for ip, cnt in top_invalid:
                print(f"  {ip:<18} {cnt:>7,} events")
        else:
            print("No invalid user events detected.")

        # Accepted password summary (top N by count)
        accepted_counts = defaultdict(int)
        for ip, attempts in self.attempts_by_ip.items():
            for att in attempts:
                if att.get('success') is True:
                    accepted_counts[ip] += 1
        if accepted_counts:
            top_accepted = sorted(accepted_counts.items(), key=lambda x: x[1], reverse=True)[:max(1, self.summary_limit//2)]
            print(self._color(f"Accepted password events (top {len(top_accepted)}):", fg='green', bold=True))
            for ip, cnt in top_accepted:
                print(f"  {ip:<18} {cnt:>7,} events")
        else:
            print("No accepted password events detected.")

        # Threat summary header
        print("\n" + "=" * line_width)
        print(self._color("THREAT ANALYSIS SUMMARY", bold=True))
        print("=" * line_width)
        
        # Summary table header
        print(f"{'SEVERITY':<12} {'IP ADDRESS':<18} {'ATTEMPTS':<12} {'RATE':<12} {'ACTION':<12}")
        print("-" * line_width)

        for i, r in enumerate(all_results):
            sev = r['Severity']
            sev_col = {
                'CRITICAL': ('red', True),
                'HIGH': ('yellow', True),
                'MEDIUM': ('cyan', False),
                'LOW': (None, False)
            }
            fg, bold = sev_col.get(sev, (None, False))
            sev_text = self._color(sev, fg=fg, bold=bold)
            rate_val = float(r['Attack_Rate'])
            action = r['Action']
            action_col = {
                'BLOCK': 'red',
                'MONITOR': 'yellow',
                'ALLOW': 'green'
            }.get(action)
            action_text = self._color(action, fg=action_col, bold=True if action != 'ALLOW' else False)
            print(f"{sev_text:<12} {r['IP']:<18} {r['Attempts']:>12,} {rate_val:>6.2f}/min {action_text:<12}")
            # Limit summary output based on configured summary_limit
            if i >= (self.summary_limit - 1):
                remaining = len(all_results) - self.summary_limit
                if remaining > 0:
                    print("-" * line_width)
                    print(f"... and {remaining} more. Export to CSV to see all.")
                break

        print("=" * line_width)
        print(f"Total suspicious IPs: {len([r for r in all_results if r['Severity'] != 'LOW']):,}")
        print()
        
        # Verbose mode - detailed breakdown
        if verbose:
            print("\n" + "=" * line_width)
            print(self._color(f"DETAILED BREAKDOWN (Top {self.verbose_limit})", bold=True))
            print("=" * line_width)
            
            for i, (ip, usernames) in enumerate(sorted_ips):
                if i >= self.verbose_limit:
                    break
                    
                total_attempts = sum(usernames.values())
                attempts = self.attempts_by_ip[ip]
                
                if attempts:
                    timestamps = [att['timestamp'] for att in attempts]
                    first = min(timestamps)
                    last = max(timestamps)
                    duration = last - first
                    duration_str = self.format_duration(duration)
                    
                    total_minutes = max(duration.total_seconds() / 60, 1.0)
                    attack_rate = total_attempts / total_minutes
                    
                    print(f"\n[IP] {ip}")
                    print(f"  Attempts: {total_attempts:,}")
                    print(f"  Attack rate: {attack_rate:.2f} attempts/minute")
                    print(f"  Targeted users: {', '.join(usernames.keys())}")
                    print(f"  Window: {first.strftime('%Y-%m-%d %H:%M:%S')} to {last.strftime('%H:%M:%S')} ({duration_str})")
                    print("-" * line_width)
        
        # Export full results to CSV
        if export_csv and all_results:
            try:
                with open(export_csv, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
                    writer.writeheader()
                    writer.writerows(all_results)
                print(f"\nResults exported to: {export_csv}")
            except Exception as e:
                print(f"Error exporting CSV: {e}")
        
        return all_results  

def main():
    """
    Entry point: parse CLI args, read the log file, run analysis, and print
    results. Offers interactive prompts for verbosity and CSV export.
    """
    # CLI flags for non-interactive runs
    argp = argparse.ArgumentParser(description="SSH Brute Force Log Analyzer")
    argp.add_argument("--log-file", dest="log_file", help="Path to auth/secure log file")
    argp.add_argument("--summary-limit", dest="summary_limit", type=int, help="Max rows to show in terminal summary")
    argp.add_argument("--live", dest="live", action="store_true", help="Follow the log file and analyze in real-time")
    argp.add_argument("--follow-start", dest="follow_start", action="store_true", help="Start live mode from the beginning of the file")
    argp.add_argument("--refresh", dest="refresh", type=float, help="Seconds between summary refresh in live mode")
    args = argp.parse_args()
    print("SSH Brute Force Log Analyzer")
    print("=" * 40)
    
    # Only import tkinter and show GUI if not in live mode and no log-file provided
    if args.live or args.log_file:
        log_path = args.log_file
    else:
        import tkinter as tk
        from tkinter import filedialog
        tk.Tk().withdraw()
        log_path = filedialog.askopenfilename(
            title="Select your auth.log file",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )

    if not log_path:
        print("No file selected. Exiting.")
        sys.exit(1)

    possible_paths = [
        "/var/log/auth.log",        
        "/var/log/secure",           
        "auth.log",                  
        "C:\\Users\\jhg56\\Downloads\\auth.log",  
    ]

    if not os.path.exists(log_path):
        log_path = None
        for path in possible_paths:
            if os.path.exists(path):
                log_path = path
                print(f"Found log file at: {log_path}")
                confirm = input("Use this file? (y/n): ").strip().lower()
                if confirm == 'y':
                    break
                log_path = None

    if log_path is None:
        print("Error: No common auth.log file found.")
        print("Try placing it in the current folder or specify manually later.")
        sys.exit(1)
    
    print(f"Using log file: {log_path}")
    
    # Initialize config, parser and detector
    config = Config()
    parser = SSHLogParser()
    # Allow CLI override of summary_limit
    summary_limit_val = args.summary_limit if args.summary_limit else config["summary_limit"]

    detector = BruteForceDetector(
        max_attempts=config["max_attempts"],
        time_window_minutes=config["time_window_minutes"],
        block_threshold=config["block_threshold"],
        monitor_threshold=config["monitor_threshold"],
        summary_limit=summary_limit_val,
        verbose_limit=config["verbose_limit"]
    )
    # Apply color setting from config unless NO_COLOR env is set
    if os.environ.get('NO_COLOR'):
        detector.use_color = False
    else:
        detector.use_color = bool(config.get('color_enabled', True))

    # Live mode: follow file and periodically refresh summary
    if args.live:
        print("\nLive mode: following log for new entries...")
        refresh_interval = args.refresh if args.refresh else 5.0
        start_from_beginning = bool(args.follow_start)
        last_refresh = datetime.now()
        try:
            for line in follow_file(log_path, start_from_end=not start_from_beginning, poll_seconds=0.5):
                line_attempts = parser.parse_line(line, auto_detect=True)
                for item in line_attempts:
                    if len(item) == 5:
                        ip, username, timestamp, success, event = item
                    else:
                        ip, username, timestamp, success = item
                        event = None
                    detector.add_attempt(ip, username, timestamp, success, event)
                # Update coverage from parser stats
                detector.coverage_start = parser.stats.get('first_timestamp')
                detector.coverage_end = parser.stats.get('last_timestamp')
                now = datetime.now()
                if (now - last_refresh).total_seconds() >= refresh_interval:
                    detector.analyze(verbose=False, export_csv=None)
                    print("\n" + "=" * 100 + "\n")
                    last_refresh = now
        except KeyboardInterrupt:
            print("\nStopping live mode. Final summary:")
            detector.analyze(verbose=False, export_csv=None)
        return

    # Batch mode: parse the log file
    print("Parsing log file...")
    t_parse_start = datetime.now()
    attempts, stats = parser.parse_file(log_path, auto_detect=True)
    t_parse_end = datetime.now()
    
    print(f"\nProcessing stats:")
    print(f"Lines read: {stats['lines_read']}")
    print(f"Format matches: {stats['format_matches']}")
    print(f"Extract matches: {stats['extract_matches']}")
    print(f"Failed timestamps: {stats['failed_timestamps']}")
    if parser.get_detected_format():
        print(f"Detected format: {parser.get_detected_format()}")
    else:
        print("Warning: Could not auto-detect log format.")
        print("Available formats:")
        for fmt in parser.list_formats():
            print(f"  - {fmt}")
    parse_elapsed = t_parse_end - t_parse_start
    print(f"Parse time: {parse_elapsed.total_seconds():.2f}s")
    print()
    
    # Add attempts to detector (supports optional event field)
    for item in attempts:
        if len(item) == 5:
            ip, username, timestamp, success, event = item
        else:
            ip, username, timestamp, success = item
            event = None
        detector.add_attempt(ip, username, timestamp, success, event)
    
    # Pass coverage timestamps from parser to detector for accurate window
    detector.coverage_start = stats.get('first_timestamp')
    detector.coverage_end = stats.get('last_timestamp')
    
    # Ask for verbosity and export
    verbose_input = input("Show detailed breakdown? (y/n): ").strip().lower()
    verbose = verbose_input == 'y'
    
    export_input = input("Export to CSV? (y/n): ").strip().lower()
    export_csv = None
    if export_input == 'y':
        log_dir = os.path.dirname(log_path) or '.'
        export_csv = os.path.join(log_dir, 'brute_force_analysis.csv')
    
    t_analyze_start = datetime.now()
    detector.analyze(verbose=verbose, export_csv=export_csv)
    t_analyze_end = datetime.now()
    analyze_elapsed = t_analyze_end - t_analyze_start
    print(f"\nAnalysis time: {analyze_elapsed.total_seconds():.2f}s")

if __name__ == "__main__":
    main()