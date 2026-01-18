#!/bin/bash
# Security Scan Automation Script

echo "======================================"
echo "VulnHunter Security Scan"
echo "======================================"
echo ""

# Colors
RED='\033[0:31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if target is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target_directory> [output_name]"
    echo "Example: $0 original_code/vulnerable_app vulnerable"
    exit 1
fi

TARGET=$1
OUTPUT_NAME=${2:-"scan"}
OUTPUT_DIR="analysis/security_scan_results"

echo "[*] Target: $TARGET"
echo "[*] Output name: $OUTPUT_NAME"
echo ""

# Create output directory
mkdir -p $OUTPUT_DIR

# Run Bandit
echo -e "${YELLOW}[*] Running Bandit security scanner...${NC}"
bandit -r $TARGET -f json -o "$OUTPUT_DIR/bandit_$OUTPUT_NAME.json" 2>&1
if [ $? -eq 0 ] || [ $? -eq 1 ]; then
    echo -e "${GREEN}[+] Bandit scan complete${NC}"
else
    echo -e "${RED}[-] Bandit scan failed${NC}"
fi
echo ""

# Run Safety check if requirements.txt exists
if [ -f "$TARGET/requirements.txt" ]; then
    echo -e "${YELLOW}[*] Running Safety dependency check...${NC}"
    safety check --file "$TARGET/requirements.txt" --json > "$OUTPUT_DIR/safety_$OUTPUT_NAME.json" 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Safety check complete${NC}"
    else
        echo -e "${RED}[-] Safety check failed or vulnerabilities found${NC}"
    fi
    echo ""
fi

# Run custom security scanner
echo -e "${YELLOW}[*] Running custom security checks...${NC}"
python tools/security_scanner.py $TARGET --output $OUTPUT_DIR --name $OUTPUT_NAME --report
echo ""

# Run Pylint
echo -e "${YELLOW}[*] Running Pylint code quality check...${NC}"
pylint $TARGET --output-format=json > "$OUTPUT_DIR/pylint_$OUTPUT_NAME.json" 2>&1 || true
echo -e "${GREEN}[+] Pylint check complete${NC}"
echo ""

# Summary
echo "======================================"
echo "Scan Complete!"
echo "======================================"
echo ""
echo "Results saved to: $OUTPUT_DIR"
echo ""
echo "Files generated:"
echo "  - bandit_$OUTPUT_NAME.json"
echo "  - safety_$OUTPUT_NAME.json (if requirements.txt exists)"
echo "  - security_report_$OUTPUT_NAME.md"
echo "  - full_results_$OUTPUT_NAME.json"
echo ""
echo "View the security report:"
echo "  cat $OUTPUT_DIR/security_report_$OUTPUT_NAME.md"
echo ""
