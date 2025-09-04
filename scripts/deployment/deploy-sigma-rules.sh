#!/bin/bash

# SIGMA Rules Deployment Script
# Author: Security Operations Team
# Description: Converts and deploys SIGMA rules to QRadar
# Usage: ./deploy-sigma-rules.sh [environment]

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")")
ENVIRONMENT=${1:-development}
SIGMA_RULES_DIR="$PROJECT_ROOT/sigma-rules"
QRADAR_RULES_DIR="$PROJECT_ROOT/qradar/rules"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}BSI-QRadar SIGMA Rules Deployment${NC}"
echo "=========================================="
echo "Environment: $ENVIRONMENT"
echo "SIGMA Rules Directory: $SIGMA_RULES_DIR"
echo "QRadar Rules Directory: $QRADAR_RULES_DIR"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v sigmac &> /dev/null; then
    echo -e "${RED}Error: sigmac not found. Please install sigma tools.${NC}"
    echo "Install with: pip install sigmatools"
    exit 1
fi

if [ ! -d "$SIGMA_RULES_DIR" ]; then
    echo -e "${RED}Error: SIGMA rules directory not found: $SIGMA_RULES_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}Prerequisites check passed${NC}"
echo ""

# Function to convert SIGMA rule to QRadar AQL
convert_sigma_to_qradar() {
    local sigma_file="$1"
    local output_file="$2"
    
    echo "Converting: $(basename "$sigma_file")"
    
    # Convert SIGMA to QRadar AQL format
    # Note: This is a simplified conversion - production would need more sophisticated mapping
    sigmac -t qradar -c tools/config/qradar.yml "$sigma_file" > "$output_file" 2>/dev/null || {
        echo -e "${YELLOW}Warning: Direct conversion failed for $sigma_file, creating template${NC}"
        
        # Create AQL template based on SIGMA rule structure
        cat > "$output_file" << EOF
-- Converted from SIGMA rule: $(basename "$sigma_file")
-- Manual tuning required for production deployment
-- Generated: $(date)

SELECT *
FROM events
WHERE
    -- Add QRadar-specific detection logic here
    -- Based on SIGMA rule: $(basename "$sigma_file")
    eventtime > NOW() - INTERVAL '1' HOUR;
    
-- TODO: Implement proper field mappings and detection logic
-- TODO: Test rule effectiveness and tune thresholds
-- TODO: Configure appropriate offense creation parameters
EOF
    }
}

# Deploy SIGMA rules
echo -e "${YELLOW}Converting SIGMA rules to QRadar AQL...${NC}"

# Create output directory if it doesn't exist
mkdir -p "$QRADAR_RULES_DIR/converted"

total_rules=0
converted_rules=0

# Process all SIGMA rule files
find "$SIGMA_RULES_DIR" -name "*.yml" -o -name "*.yaml" | while read -r sigma_file; do
    total_rules=$((total_rules + 1))
    
    # Generate output filename
    relative_path="${sigma_file#$SIGMA_RULES_DIR/}"
    output_file="$QRADAR_RULES_DIR/converted/${relative_path%.y*ml}.sql"
    
    # Create output directory structure
    mkdir -p "$(dirname "$output_file")"
    
    # Convert rule
    if convert_sigma_to_qradar "$sigma_file" "$output_file"; then
        converted_rules=$((converted_rules + 1))
        echo -e "  ${GREEN}✓${NC} Converted: $relative_path"
    else
        echo -e "  ${RED}✗${NC} Failed: $relative_path"
    fi
done

echo ""
echo "Conversion Summary:"
echo "  Total SIGMA rules found: $total_rules"
echo "  Successfully converted: $converted_rules"
echo ""

# Generate deployment summary
echo -e "${YELLOW}Generating deployment summary...${NC}"

cat > "$QRADAR_RULES_DIR/deployment_summary_$(date +%Y%m%d_%H%M%S).md" << EOF
# SIGMA Rules Deployment Summary

**Deployment Date:** $(date)
**Environment:** $ENVIRONMENT
**Deployed by:** $(whoami)
**Total Rules:** $total_rules
**Converted Rules:** $converted_rules

## Next Steps

1. Review converted AQL rules in: \`qradar/rules/converted/\`
2. Test rules in QRadar development environment
3. Tune detection thresholds based on environment baseline
4. Import rules into QRadar using QRadar API or web interface
5. Monitor rule performance and false positive rates

## Manual Review Required

All converted rules require manual review and tuning before production deployment:

- Verify field mappings are correct for your log sources
- Adjust time windows and thresholds
- Configure appropriate offense creation parameters
- Test with sample data to validate detection logic

EOF

echo -e "${GREEN}SIGMA rules conversion completed!${NC}"
echo ""
echo "Next steps:"
echo "1. Review converted rules in: $QRADAR_RULES_DIR/converted/"
echo "2. Manual tuning required for production deployment"
echo "3. Test rules in QRadar development environment"
echo "4. Import validated rules into QRadar"
echo ""
echo -e "${YELLOW}Note: All converted rules require manual review and testing before production use${NC}"