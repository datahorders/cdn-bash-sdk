#!/usr/bin/env bash
#
# Domain Setup Example
# Demonstrates registering and verifying a domain, then creating a zone
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
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

DOMAIN="$1"

echo "=== Domain Setup Example ==="
echo "Domain: ${DOMAIN}"
echo

# ============================================================================
# Step 1: Register the domain
# ============================================================================
echo "--- Step 1: Registering Domain ---"

response=$(dh_domains_create "${DOMAIN}" false) || {
    error_msg=$(echo "${response}" | jq -r '.message // "Unknown error"')
    echo "Failed to create domain: ${error_msg}"

    # Check if domain already exists
    if [[ "${error_msg}" == *"already"* ]]; then
        echo "Domain may already be registered. Continuing..."
    else
        exit 1
    fi
}

# Extract verification details
if echo "${response}" | jq -e '.data.verification' > /dev/null 2>&1; then
    domain_id=$(echo "${response}" | jq -r '.data.id')
    verification_code=$(echo "${response}" | jq -r '.data.verification.code')
    verification_record=$(echo "${response}" | jq -r '.data.verification.record')

    echo "Domain registered successfully!"
    echo "Domain ID: ${domain_id}"
    echo
    echo "To verify your domain, add this DNS TXT record:"
    echo "  Record Name: ${verification_record}"
    echo "  Record Value: ${verification_code}"
    echo
    echo "Instructions:"
    echo "${response}" | jq -r '.data.verification.instructions'
else
    echo "Domain response:"
    echo "${response}" | jq '.'
fi
echo

# ============================================================================
# Step 2: Wait for DNS propagation
# ============================================================================
echo "--- Step 2: DNS Verification ---"
echo "Once you've added the TXT record, press Enter to verify..."
read -r

# ============================================================================
# Step 3: Verify domain ownership
# ============================================================================
echo "--- Step 3: Verifying Domain Ownership ---"

verify_response=$(dh_domains_verify "${DOMAIN}") || {
    echo "Verification failed. Please ensure the DNS TXT record is properly configured."
    echo "Response: ${verify_response}"
    exit 1
}

verified=$(echo "${verify_response}" | jq -r '.data.verified // false')

if [[ "${verified}" == "true" ]]; then
    echo "Domain verified successfully!"
    domain_id=$(echo "${verify_response}" | jq -r '.data.id')
else
    echo "Domain not yet verified. DNS propagation may take time."
    echo "Please try again later."
    exit 1
fi
echo

# ============================================================================
# Step 4: Create a zone (optional)
# ============================================================================
echo "--- Step 4: Create Zone (Optional) ---"
echo "Would you like to create a zone for this domain? (y/n)"
read -r create_zone

if [[ "${create_zone}" =~ ^[Yy]$ ]]; then
    echo "Enter the zone name (subdomain, or @ for apex):"
    read -r zone_name

    echo "Enter backend server address (e.g., 10.0.1.100):"
    read -r backend_address

    echo "Enter backend server port (default: 80):"
    read -r backend_port
    backend_port="${backend_port:-80}"

    # Build server configuration
    servers_json="[{\"address\":\"${backend_address}\",\"port\":${backend_port},\"protocol\":\"http\",\"healthCheckPath\":\"/\"}]"
    domains_json="[\"${domain_id}\"]"

    echo
    echo "Creating zone..."

    zone_response=$(dh_zones_create "${zone_name}" "${domains_json}" "${servers_json}" \
        --upgrade-insecure true \
        --health-check-enabled false) || {
        echo "Failed to create zone"
        echo "${zone_response}"
        exit 1
    }

    if echo "${zone_response}" | jq -e '.data.id' > /dev/null 2>&1; then
        zone_id=$(echo "${zone_response}" | jq -r '.data.id')
        fqdn=$(echo "${zone_response}" | jq -r '.data.fqdn // (.data.name + "." + .data.domain)')

        echo "Zone created successfully!"
        echo "Zone ID: ${zone_id}"
        echo "FQDN: ${fqdn}"
        echo
        echo "Next steps:"
        echo "1. Point your DNS ${fqdn} CNAME record to the CDN"
        echo "2. Configure SSL certificate (use ACME for automatic)"
        echo "3. Set up health checks and WAF as needed"
    else
        echo "Zone creation response:"
        echo "${zone_response}" | jq '.'
    fi
fi

echo
echo "=== Setup Complete ==="
