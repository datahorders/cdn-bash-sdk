#!/usr/bin/env bash
#
# Basic Usage Example
# Demonstrates fundamental SDK operations
#

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the SDK
source "${SCRIPT_DIR}/../datahorders-cdn.sh"

# Check for API key
if [[ -z "${DATAHORDERS_API_KEY:-}" ]]; then
    echo "Please set DATAHORDERS_API_KEY environment variable"
    echo "Example: export DATAHORDERS_API_KEY='your-api-key'"
    exit 1
fi

echo "=== DataHorders CDN SDK Basic Usage Example ==="
echo

# ============================================================================
# List Domains
# ============================================================================
echo "--- Listing Domains ---"
domains_response=$(dh_domains_list 1 10)

# Check if we got data
if echo "${domains_response}" | jq -e '.data' > /dev/null 2>&1; then
    domain_count=$(echo "${domains_response}" | jq '.data | length')
    echo "Found ${domain_count} domain(s)"

    if [[ "${domain_count}" -gt 0 ]]; then
        echo
        echo "Domains:"
        echo "${domains_response}" | jq -r '.data[] | "  - \(.domain) (verified: \(.verified))"'
    fi
else
    echo "No domains found or error occurred"
fi
echo

# ============================================================================
# List Zones
# ============================================================================
echo "--- Listing Zones ---"
zones_response=$(dh_zones_list 1 10)

if echo "${zones_response}" | jq -e '.data' > /dev/null 2>&1; then
    zone_count=$(echo "${zones_response}" | jq '.data | length')
    echo "Found ${zone_count} zone(s)"

    if [[ "${zone_count}" -gt 0 ]]; then
        echo
        echo "Zones:"
        echo "${zones_response}" | jq -r '.data[] | "  - \(.name).\(.domain) (ID: \(.id))"'
    fi
else
    echo "No zones found or error occurred"
fi
echo

# ============================================================================
# List Certificates
# ============================================================================
echo "--- Listing Certificates ---"
certs_response=$(dh_certificates_list 1 10)

if echo "${certs_response}" | jq -e '.data' > /dev/null 2>&1; then
    cert_count=$(echo "${certs_response}" | jq '.data | length')
    echo "Found ${cert_count} certificate(s)"

    if [[ "${cert_count}" -gt 0 ]]; then
        echo
        echo "Certificates:"
        echo "${certs_response}" | jq -r '.data[] | "  - \(.name) (status: \(.status), expires: \(.expiresAt // "N/A"))"'
    fi
else
    echo "No certificates found or error occurred"
fi
echo

# ============================================================================
# Get Usage Analytics
# ============================================================================
echo "--- Usage Analytics ---"
usage_response=$(dh_analytics_get_usage)

if echo "${usage_response}" | jq -e '.total_traffic' > /dev/null 2>&1; then
    total_gb=$(echo "${usage_response}" | jq '.total_traffic.gigabytes // 0')
    total_zones=$(echo "${usage_response}" | jq '.total_zones // 0')

    echo "Total Bandwidth: ${total_gb} GB"
    echo "Total Zones: ${total_zones}"

    zone_usage=$(echo "${usage_response}" | jq '.zones // []')
    if [[ $(echo "${zone_usage}" | jq 'length') -gt 0 ]]; then
        echo
        echo "Per-Zone Usage:"
        echo "${zone_usage}" | jq -r '.[] | "  - \(.zone): \(.gigabytes_sent) GB, \(.requests) requests"'
    fi
else
    echo "Could not retrieve usage data"
fi
echo

# ============================================================================
# List CDN Nodes
# ============================================================================
echo "--- CDN Nodes ---"
nodes_response=$(dh_analytics_get_cdn_nodes)

if echo "${nodes_response}" | jq -e '.[0]' > /dev/null 2>&1; then
    node_count=$(echo "${nodes_response}" | jq 'length')
    echo "Found ${node_count} CDN node(s)"

    echo
    echo "Nodes:"
    echo "${nodes_response}" | jq -r '.[] | "  - \(.domain) (\(.ip_address))"'
else
    echo "No CDN nodes found or error occurred"
fi
echo

echo "=== Example Complete ==="
