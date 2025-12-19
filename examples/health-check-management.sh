#!/usr/bin/env bash
#
# Health Check Management Example
# Demonstrates managing health check profiles and server monitoring
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

echo "=== Health Check Management Example ==="
echo

# ============================================================================
# List health check profiles
# ============================================================================
echo "--- Health Check Profiles ---"

profiles=$(dh_health_checks_list_profiles 1 20)

if echo "${profiles}" | jq -e '.profiles' > /dev/null 2>&1; then
    profile_count=$(echo "${profiles}" | jq '.profiles | length')
    echo "Found ${profile_count} profile(s)"

    if [[ "${profile_count}" -gt 0 ]]; then
        echo
        echo "Profiles:"
        echo "${profiles}" | jq -r '.profiles[] | "  - \(.name) (\(.protocol)://:\(.port)\(.path))
    Method: \(.method), Interval: \(.checkInterval)s, Timeout: \(.timeout)s"'
    fi
else
    echo "No profiles found or different response format:"
    echo "${profiles}" | jq '.'
fi
echo

# ============================================================================
# List CDN nodes
# ============================================================================
echo "--- CDN Edge Nodes ---"

nodes=$(dh_health_checks_list_cdn_nodes)

if echo "${nodes}" | jq -e '.[0]' > /dev/null 2>&1; then
    node_count=$(echo "${nodes}" | jq 'length')
    echo "Found ${node_count} CDN node(s)"
    echo
    echo "Nodes:"
    echo "${nodes}" | jq -r '.[] | "  - \(.domain)
    IP: \(.ip_address)
    Location: \(.location // "Unknown")"'
else
    echo "No CDN nodes found or error:"
    echo "${nodes}" | jq '.'
fi
echo

# ============================================================================
# Create a health check profile
# ============================================================================
echo "--- Create Health Check Profile ---"
echo "Would you like to create a new health check profile? (y/n)"
read -r create_profile

if [[ "${create_profile}" =~ ^[Yy]$ ]]; then
    echo
    echo "Enter profile name:"
    read -r profile_name

    echo "Enter protocol (http/https/tcp):"
    read -r protocol
    protocol="${protocol:-http}"

    echo "Enter port:"
    read -r port
    port="${port:-80}"

    echo "Enter health check path (e.g., /health):"
    read -r path
    path="${path:-/}"

    echo "Enter check interval in seconds (default: 30):"
    read -r interval
    interval="${interval:-30}"

    echo "Creating health check profile..."

    profile_result=$(dh_health_checks_create_profile "${profile_name}" \
        --protocol "${protocol}" \
        --port "${port}" \
        --path "${path}" \
        --method "GET" \
        --expected-status-codes "200-399" \
        --check-interval "${interval}" \
        --timeout 10 \
        --retries 2) || {
        echo "Failed to create profile"
        echo "${profile_result}" | jq '.'
    }

    if echo "${profile_result}" | jq -e '.profile' > /dev/null 2>&1; then
        profile_id=$(echo "${profile_result}" | jq -r '.profile.id')
        echo "Profile created successfully!"
        echo "Profile ID: ${profile_id}"
        echo
        echo "${profile_result}" | jq '.profile'
    else
        echo "Profile creation result:"
        echo "${profile_result}" | jq '.'
    fi
fi
echo

# ============================================================================
# Server health check toggle
# ============================================================================
echo "--- Server Health Check Toggle ---"
echo "Enter a server ID to manage health checks (or press Enter to skip):"
read -r server_id

if [[ -n "${server_id}" ]]; then
    echo "Action: (e)nable or (d)isable?"
    read -r action

    if [[ "${action}" =~ ^[Dd]$ ]]; then
        echo "Enter reason for disabling (optional):"
        read -r reason

        echo "Disabling health checks for server ${server_id}..."
        toggle_result=$(dh_health_checks_disable_server "${server_id}" "${reason}") || {
            echo "Failed to disable"
        }

        if echo "${toggle_result}" | jq -e '.success' > /dev/null 2>&1; then
            echo "Health checks disabled for server"
        fi
        echo "${toggle_result}" | jq '.'

    elif [[ "${action}" =~ ^[Ee]$ ]]; then
        echo "Enabling health checks for server ${server_id}..."
        toggle_result=$(dh_health_checks_enable_server "${server_id}") || {
            echo "Failed to enable"
        }

        if echo "${toggle_result}" | jq -e '.success' > /dev/null 2>&1; then
            echo "Health checks enabled for server"
        fi
        echo "${toggle_result}" | jq '.'
    else
        echo "Invalid action"
    fi
fi
echo

echo "=== Health Check Management Example Complete ==="
echo
echo "Health Check Best Practices:"
echo "- Use /health or /healthz endpoints for health checks"
echo "- Set appropriate timeouts (backend response time + buffer)"
echo "- Configure retries to avoid false positives from network blips"
echo "- Monitor check intervals based on traffic patterns"
echo "- Disable checks during planned maintenance"
