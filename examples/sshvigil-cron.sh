#!/bin/bash
# SSHVigil hourly cron job
# Install: sudo cp sshvigil-cron.sh /etc/cron.hourly/sshvigil-analysis && sudo chmod +x /etc/cron.hourly/sshvigil-analysis

# Configuration
SSHVIGIL_DIR="/opt/sshvigil"
LOG_FILE="/var/log/auth.log"
OUTPUT_DIR="/var/log/sshvigil"
BLOCKLIST="/var/lib/sshvigil/blocklist.txt"
WHITELIST="/etc/sshvigil/whitelist.txt"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$BLOCKLIST")"

# Run SSHVigil analysis
/usr/bin/python3 "$SSHVIGIL_DIR/main.py" \
  --log-file "$LOG_FILE" \
  --non-interactive \
  --export-csv "$OUTPUT_DIR/sshvigil_$(date +%Y%m%d_%H).csv" \
  --export-blocklist "$BLOCKLIST" \
  --whitelist "$WHITELIST" \
  --blocklist-threshold HIGH \
  >> "$OUTPUT_DIR/sshvigil.log" 2>&1

# Optional: Rotate old CSV files (keep last 7 days)
find "$OUTPUT_DIR" -name "sshvigil_*.csv" -mtime +7 -delete
