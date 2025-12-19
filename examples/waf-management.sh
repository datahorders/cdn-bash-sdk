#!/usr/bin/env bash
#
# WAF Management Example
# Demonstrates configuring WAF rules, IP blocking, and geo-blocking
#

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the SDK
source "${SCRIPT_DIR}/../datahorders-cdn.sh"

# Check for API key
if [[ -z "${DATAHORDERS_API_KEY:-}" ]]; then
    echo "Please set DATAHORDERS_API_KEY environment variable"
    exit 1
fi

# Check for required argument
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <zone_id>"
    echo "Example: $0 zone_abc123"
    exit 1
fi

ZONE_ID="$1"

echo "=== WAF Management Example ==="
echo "Zone ID: ${ZONE_ID}"
echo

# ============================================================================
# Get current WAF configuration
# ============================================================================
echo "--- Current WAF Configuration ---"

waf_config=$(dh_waf_get_config "${ZONE_ID}") || {
    echo "Failed to get WAF config. Is the zone ID correct?"
    exit 1
}

if echo "${waf_config}" | jq -e '.data.config' > /dev/null 2>&1; then
    enabled=$(echo "${waf_config}" | jq -r '.data.config.enabled')
    mode=$(echo "${waf_config}" | jq -r '.data.config.mode')
    sqli=$(echo "${waf_config}" | jq -r '.data.config.sqliDetection // false')
    xss=$(echo "${waf_config}" | jq -r '.data.config.xssDetection // false')

    echo "WAF Enabled: ${enabled}"
    echo "Mode: ${mode}"
    echo "SQL Injection Detection: ${sqli}"
    echo "XSS Detection: ${xss}"
else
    echo "WAF config:"
    echo "${waf_config}" | jq '.'
fi
echo

# ============================================================================
# Enable WAF with blocking mode
# ============================================================================
echo "--- Enabling WAF ---"

update_result=$(dh_waf_update_config "${ZONE_ID}" \
    --enabled true \
    --mode "blocking" \
    --sqli-detection true \
    --xss-detection true) || {
    echo "Failed to update WAF config"
    echo "${update_result}"
}

if echo "${update_result}" | jq -e '.data' > /dev/null 2>&1; then
    echo "WAF enabled with blocking mode"
    echo "SQL injection and XSS detection enabled"
else
    echo "Update result:"
    echo "${update_result}" | jq '.'
fi
echo

# ============================================================================
# List existing WAF rules
# ============================================================================
echo "--- Existing WAF Rules ---"

rules=$(dh_waf_list_rules "${ZONE_ID}")

if echo "${rules}" | jq -e '.data' > /dev/null 2>&1; then
    rule_count=$(echo "${rules}" | jq '.data | length')
    echo "Found ${rule_count} rule(s)"

    if [[ "${rule_count}" -gt 0 ]]; then
        echo "${rules}" | jq -r '.data[] | "  - \(.name) [\(.action)] (priority: \(.priority))"'
    fi
else
    echo "No rules found"
fi
echo

# ============================================================================
# Create a sample WAF rule
# ============================================================================
echo "--- Creating Sample WAF Rule ---"

rule_result=$(dh_waf_create_rule "${ZONE_ID}" \
    "Block Admin Panel Access" \
    "pattern" \
    "uri" \
    "^/(admin|wp-admin|phpmyadmin)" \
    "block" \
    --description "Block common admin panel paths" \
    --severity "high" \
    --priority 100) || {
    echo "Failed to create rule (may already exist)"
}

if echo "${rule_result}" | jq -e '.data.id' > /dev/null 2>&1; then
    rule_id=$(echo "${rule_result}" | jq -r '.data.id')
    echo "Created rule: ${rule_id}"
else
    echo "Rule creation result:"
    echo "${rule_result}" | jq '.'
fi
echo

# ============================================================================
# List IP entries
# ============================================================================
echo "--- IP Block/Allow Lists ---"

ip_list=$(dh_waf_list_ips "${ZONE_ID}")

if echo "${ip_list}" | jq -e '.data' > /dev/null 2>&1; then
    ip_count=$(echo "${ip_list}" | jq '.data | length')
    echo "Found ${ip_count} IP entries"

    if [[ "${ip_count}" -gt 0 ]]; then
        echo
        echo "Blocked IPs:"
        echo "${ip_list}" | jq -r '.data[] | select(.listType == "block") | "  - \(.ipAddress) (\(.reason // "No reason"))"'

        echo
        echo "Allowed IPs:"
        echo "${ip_list}" | jq -r '.data[] | select(.listType == "allow") | "  - \(.ipAddress) (\(.reason // "No reason"))"'
    fi
else
    echo "No IP entries found"
fi
echo

# ============================================================================
# Block a sample IP
# ============================================================================
echo "--- Blocking Sample IP ---"

block_result=$(dh_waf_block_ip "${ZONE_ID}" "198.51.100.1" "Example malicious IP") || {
    echo "Failed to block IP (may already be blocked)"
}

if echo "${block_result}" | jq -e '.data.id' > /dev/null 2>&1; then
    ip_id=$(echo "${block_result}" | jq -r '.data.id')
    echo "Blocked IP 198.51.100.1 (ID: ${ip_id})"
else
    echo "Block result:"
    echo "${block_result}" | jq '.'
fi
echo

# ============================================================================
# Add to allowlist
# ============================================================================
echo "--- Adding to Allowlist ---"

allow_result=$(dh_waf_allow_ip "${ZONE_ID}" "203.0.113.0/24" "Office network") || {
    echo "Failed to add to allowlist (may already exist)"
}

if echo "${allow_result}" | jq -e '.data.id' > /dev/null 2>&1; then
    ip_id=$(echo "${allow_result}" | jq -r '.data.id')
    echo "Allowed network 203.0.113.0/24 (ID: ${ip_id})"
else
    echo "Allow result:"
    echo "${allow_result}" | jq '.'
fi
echo

# ============================================================================
# List country rules
# ============================================================================
echo "--- Country Rules ---"

countries=$(dh_waf_list_countries "${ZONE_ID}")

if echo "${countries}" | jq -e '.data' > /dev/null 2>&1; then
    country_count=$(echo "${countries}" | jq '.data | length')
    echo "Found ${country_count} country rule(s)"

    if [[ "${country_count}" -gt 0 ]]; then
        echo "${countries}" | jq -r '.data[] | "  - \(.countryCode): \(.action) (\(.reason // "No reason"))"'
    fi
else
    echo "No country rules found"
fi
echo

# ============================================================================
# List ASN rules
# ============================================================================
echo "--- ASN Rules ---"

asns=$(dh_waf_list_asns "${ZONE_ID}")

if echo "${asns}" | jq -e '.data' > /dev/null 2>&1; then
    asn_count=$(echo "${asns}" | jq '.data | length')
    echo "Found ${asn_count} ASN rule(s)"

    if [[ "${asn_count}" -gt 0 ]]; then
        echo "${asns}" | jq -r '.data[] | "  - AS\(.asn) \(.asnName // ""): \(.action) (\(.reason // "No reason"))"'
    fi
else
    echo "No ASN rules found"
fi
echo

echo "=== WAF Management Example Complete ==="
echo
echo "Summary:"
echo "- WAF is now enabled in blocking mode"
echo "- SQL injection and XSS detection are active"
echo "- Sample rule created to block admin panels"
echo "- Sample IP blocked and network allowed"
echo
echo "To disable WAF:"
echo "  dh_waf_update_config \"${ZONE_ID}\" --enabled false"
