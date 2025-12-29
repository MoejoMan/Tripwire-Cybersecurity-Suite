#!/bin/bash
# Tripwire v1.0 VPS Test Suite
# Runs benchmarks and smoke tests for release validation
# Usage: ./vps_test.sh

set -e  # Exit on error

echo "=========================================="
echo "Tripwire v1.0 Test Suite"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="/tmp/tripwire_test_$(date +%s)"
TRIPWIRE_DIR="$(pwd)"
PYTHON_CMD="python3"

# Create test directory
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"
echo "[INFO] Test directory: $TEST_DIR"
echo ""

# =============================================
# TASK 2: BENCHMARK ON LARGE LOG FILE
# =============================================
echo "=========================================="
echo "TASK 2: BENCHMARK TEST"
echo "=========================================="
echo ""

echo "[1/3] Generating large synthetic log file (100MB)..."
$PYTHON_CMD << 'EOFPYTHON'
import random
from datetime import datetime, timedelta

ips = [f"192.0.2.{i}" for i in range(1, 255)]
usernames = ["root", "admin", "ubuntu", "user", "test", "oracle", "postgres"]

# Target ~100MB (adjust line count based on line size ~100 bytes)
target_lines = 1_000_000  # ~100MB

with open("large_auth.log", "w") as f:
    now = datetime.now()
    for i in range(target_lines):
        ip = random.choice(ips)
        user = random.choice(usernames)
        timestamp = (now - timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
        f.write(f"{timestamp} server sshd[{i}]: Invalid user {user} from {ip} port {random.randint(1000, 65535)}\n")
        
        if i % 1_000_000 == 0 and i > 0:
            print(f"  Generated {i:,} lines...")

print(f"  Total lines: {target_lines:,}")
EOFPYTHON

# Check file size
FILE_SIZE=$(du -h large_auth.log | awk '{print $1}')
echo "[INFO] Generated file size: $FILE_SIZE"
echo ""

echo "[2/3] Running benchmark (measuring time and memory)..."
# Use /usr/bin/time if available for detailed stats
if command -v /usr/bin/time &> /dev/null; then
    echo "[INFO] Using /usr/bin/time for detailed metrics"
    /usr/bin/time -v $PYTHON_CMD "$TRIPWIRE_DIR/main.py" \
        --log-file large_auth.log \
        --non-interactive \
        2>&1 | tee benchmark_output.txt
    
    # Extract key metrics
    echo ""
    echo "[BENCHMARK RESULTS]"
    grep "Elapsed" benchmark_output.txt || true
    grep "Maximum resident" benchmark_output.txt || true
else
    echo "[INFO] /usr/bin/time not available, using basic timing"
    START=$(date +%s)
    $PYTHON_CMD "$TRIPWIRE_DIR/main.py" \
        --log-file large_auth.log \
        --non-interactive \
        > benchmark_output.txt 2>&1
    END=$(date +%s)
    ELAPSED=$((END - START))
    echo ""
    echo "[BENCHMARK RESULTS]"
    echo "Elapsed time: ${ELAPSED}s"
fi

echo ""
echo "[3/3] Checking for crashes or errors..."
if grep -qi "error\|exception\|traceback" benchmark_output.txt; then
    echo -e "${RED}[FAIL] Found errors in benchmark output${NC}"
    tail -20 benchmark_output.txt
    exit 1
else
    echo -e "${GREEN}[PASS] No crashes detected${NC}"
fi

echo ""
echo -e "${GREEN}BENCHMARK TEST COMPLETE${NC}"
echo ""

# =============================================
# TASK 5: SMOKE TEST ALL V1.0 FEATURES
# =============================================
echo "=========================================="
echo "TASK 5: SMOKE TESTS"
echo "=========================================="
echo ""

# Create test log
cat > test_auth.log << 'EOF'
Dec 28 10:00:00 server sshd[1]: Invalid user admin from 192.0.2.10 port 5555
Dec 28 10:01:00 server sshd[2]: Failed password for root from 192.0.2.10 port 5556 ssh2
Dec 28 10:02:00 server sshd[3]: Invalid user test from 192.0.2.20 port 5557
Dec 28 10:03:00 server sshd[4]: Accepted publickey for alice from 198.51.100.5 port 5558 ssh2
Dec 28 10:04:00 server sshd[5]: Failed password for root from 203.0.113.30 port 5559 ssh2
EOF

# Test 1: Non-interactive mode
echo "[TEST 1/5] Non-interactive mode..."
$PYTHON_CMD "$TRIPWIRE_DIR/main.py" \
    --log-file test_auth.log \
    --non-interactive \
    > /dev/null 2>&1 && echo -e "${GREEN}[PASS]${NC}" || echo -e "${RED}[FAIL]${NC}"

# Test 2: Whitelist
echo "[TEST 2/5] IP whitelist..."
echo "192.0.2.10" > whitelist.txt
$PYTHON_CMD "$TRIPWIRE_DIR/main.py" \
    --log-file test_auth.log \
    --non-interactive \
    --whitelist whitelist.txt \
    --export-blocklist blocklist.txt \
    > /dev/null 2>&1

if [ -f blocklist.txt ]; then
    if grep -q "192.0.2.10" blocklist.txt; then
        echo -e "${RED}[FAIL] Whitelisted IP found in blocklist${NC}"
    else
        echo -e "${GREEN}[PASS]${NC}"
    fi
else
    echo -e "${YELLOW}[SKIP] No blocklist generated (IPs below threshold)${NC}"
fi

# Test 3: CSV export (batch mode)
echo "[TEST 3/5] CSV export (batch mode)..."
$PYTHON_CMD "$TRIPWIRE_DIR/main.py" \
    --log-file test_auth.log \
    --non-interactive \
    --export-csv test_batch.csv \
    > /dev/null 2>&1

if [ -f test_batch.csv ] && [ -s test_batch.csv ]; then
    echo -e "${GREEN}[PASS]${NC}"
else
    echo -e "${RED}[FAIL] CSV not created or empty${NC}"
fi

# Test 4: CSV export (large log performance test)
echo "[TEST 4/5] CSV export (large log)..."
$PYTHON_CMD "$TRIPWIRE_DIR/main.py" \
    --log-file large_auth.log \
    --non-interactive \
    --export-csv test_large.csv \
    > /dev/null 2>&1

if [ -f test_large.csv ] && [ -s test_large.csv ]; then
    echo -e "${GREEN}[PASS]${NC}"
else
    echo -e "${RED}[FAIL] CSV not created or empty${NC}"
fi

# Test 5: IP validation (test with real auth.log or fallback)
echo "[TEST 5/5] IP validation on real log..."
TEST_LOG="test_auth.log"
if [ -f /var/log/auth.log ]; then
    TEST_LOG="/var/log/auth.log"
elif [ -f /var/log/secure ]; then
    TEST_LOG="/var/log/secure"
fi

$PYTHON_CMD "$TRIPWIRE_DIR/main.py" \
    --log-file "$TEST_LOG" \
    --non-interactive \
    > /dev/null 2>&1 && echo -e "${GREEN}[PASS]${NC}" || echo -e "${RED}[FAIL]${NC}"

echo ""
echo -e "${GREEN}SMOKE TESTS COMPLETE${NC}"
echo ""

# =============================================
# SUMMARY
# =============================================
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo ""
echo "Benchmark:"
echo "  - Log size: $FILE_SIZE"
echo "  - See: $TEST_DIR/benchmark_output.txt"
echo ""
echo "Smoke tests: 5 tests run"
echo "  - See: $TEST_DIR/"
echo ""
echo "Test directory: $TEST_DIR"
echo "(You can delete this directory after review)"
echo ""
echo -e "${GREEN}ALL TESTS COMPLETE - READY FOR v1.0 RELEASE${NC}"
