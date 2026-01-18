#!/bin/bash
# Performance Testing Script

echo "======================================"
echo "VulnHunter Performance Test"
echo "======================================"
echo ""

# Default values
URL=${1:-"http://localhost:5000"}
OUTPUT_NAME=${2:-"performance_test"}
CONCURRENT=${3:-10}
REQUESTS=${4:-100}

echo "[*] Target URL: $URL"
echo "[*] Concurrent users: $CONCURRENT"
echo "[*] Total requests: $REQUESTS"
echo ""

# Check if server is running
echo "[*] Checking if server is accessible..."
HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" $URL)

if [ "$HTTP_CODE" != "200" ]; then
    echo "[!] Warning: Server returned HTTP $HTTP_CODE or is not accessible"
    echo "[!] Make sure the application is running at $URL"
    echo ""
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Create output directory
OUTPUT_DIR="analysis/performance_benchmarks"
mkdir -p $OUTPUT_DIR

# Run performance tests
echo ""
echo "[*] Starting performance tests..."
echo ""

python tools/performance_tester.py \
    --url $URL \
    --output $OUTPUT_DIR \
    --name $OUTPUT_NAME \
    --concurrent $CONCURRENT \
    --requests $REQUESTS

echo ""
echo "======================================"
echo "Performance Test Complete!"
echo "======================================"
echo ""
echo "Results saved to: $OUTPUT_DIR"
echo ""
echo "Files generated:"
echo "  - ${OUTPUT_NAME}_performance.json"
echo "  - ${OUTPUT_NAME}_performance_report.md"
echo ""
echo "View the report:"
echo "  cat $OUTPUT_DIR/${OUTPUT_NAME}_performance_report.md"
echo ""
