#!/usr/bin/env bash
#
# Certificate Management Example
# Demonstrates listing, creating, and managing SSL/TLS certificates
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

echo "=== Certificate Management Example ==="
echo

# ============================================================================
# List all certificates
# ============================================================================
echo "--- Listing Certificates ---"

certs=$(dh_certificates_list 1 20)

if echo "${certs}" | jq -e '.data' > /dev/null 2>&1; then
    cert_count=$(echo "${certs}" | jq '.data | length')
    echo "Found ${cert_count} certificate(s)"
    echo

    if [[ "${cert_count}" -gt 0 ]]; then
        echo "Certificates:"
        echo "${certs}" | jq -r '.data[] | "  ID: \(.id)
  Name: \(.name)
  Status: \(.status)
  Provider: \(.provider // "manual")
  Expires: \(.expiresAt // "N/A")
  Domains: \(.domains | map(.domain) | join(", "))
  ---"'
    fi
else
    echo "No certificates found or error occurred"
    echo "${certs}" | jq '.'
fi
echo

# ============================================================================
# List ACME certificates
# ============================================================================
echo "--- ACME Certificates ---"

acme_certs=$(dh_certificates_list_acme)

if echo "${acme_certs}" | jq -e '.data' > /dev/null 2>&1; then
    acme_count=$(echo "${acme_certs}" | jq '.data | length')
    echo "Found ${acme_count} ACME certificate(s)"

    if [[ "${acme_count}" -gt 0 ]]; then
        echo
        echo "${acme_certs}" | jq -r '.data[] | "  - \(.name): \(.status) (ID: \(.certificateId // .id))"'
    fi
else
    echo "No ACME certificates found"
fi
echo

# ============================================================================
# Interactive: Request ACME certificate
# ============================================================================
echo "--- Request New ACME Certificate ---"
echo "Would you like to request a new ACME certificate? (y/n)"
read -r create_cert

if [[ "${create_cert}" =~ ^[Yy]$ ]]; then
    echo
    echo "Enter a name for the certificate:"
    read -r cert_name

    echo "Enter the primary domain (e.g., example.com):"
    read -r primary_domain

    echo "Include wildcard (*.${primary_domain})? (y/n)"
    read -r include_wildcard

    echo "Enter contact email:"
    read -r email

    # Build domains array
    if [[ "${include_wildcard}" =~ ^[Yy]$ ]]; then
        domains_json="[\"${primary_domain}\", \"*.${primary_domain}\"]"
        echo
        echo "Requesting certificate for: ${primary_domain}, *.${primary_domain}"
    else
        domains_json="[\"${primary_domain}\"]"
        echo
        echo "Requesting certificate for: ${primary_domain}"
    fi

    echo "Creating ACME certificate request..."

    acme_result=$(dh_certificates_create_acme \
        "${cert_name}" \
        "${domains_json}" \
        "${email}" \
        --acme-provider "letsencrypt" \
        --auto-renew true) || {
        echo "Failed to create ACME certificate"
        echo "${acme_result}" | jq '.'
        exit 1
    }

    if echo "${acme_result}" | jq -e '.data.certificateId' > /dev/null 2>&1; then
        cert_id=$(echo "${acme_result}" | jq -r '.data.certificateId')
        status=$(echo "${acme_result}" | jq -r '.data.status')

        echo "ACME certificate request submitted!"
        echo "Certificate ID: ${cert_id}"
        echo "Status: ${status}"
        echo
        echo "The certificate will be issued automatically."
        echo "For wildcard certificates, you'll need to configure DNS challenges."
        echo
        echo "Check status with:"
        echo "  dh_certificates_get_acme_status \"${cert_id}\""
    else
        echo "ACME request result:"
        echo "${acme_result}" | jq '.'
    fi
fi
echo

# ============================================================================
# Interactive: Check certificate status
# ============================================================================
echo "--- Check Certificate Status ---"
echo "Enter a certificate ID to check (or press Enter to skip):"
read -r check_cert_id

if [[ -n "${check_cert_id}" ]]; then
    status_result=$(dh_certificates_get_acme_status "${check_cert_id}") || {
        echo "Failed to get status"
        echo "${status_result}" | jq '.'
    }

    if echo "${status_result}" | jq -e '.data' > /dev/null 2>&1; then
        echo
        echo "Certificate Status:"
        echo "${status_result}" | jq '.data'
    fi
fi
echo

# ============================================================================
# Interactive: Download certificate
# ============================================================================
echo "--- Download Certificate ---"
echo "Enter a certificate ID to download (or press Enter to skip):"
read -r download_cert_id

if [[ -n "${download_cert_id}" ]]; then
    output_file="certificate-${download_cert_id}.zip"

    echo "Downloading to ${output_file}..."

    if dh_certificates_download "${download_cert_id}" "${output_file}"; then
        echo "Certificate downloaded successfully!"
        echo "File: ${output_file}"
        echo
        echo "The ZIP contains:"
        echo "  - certificate.pem: SSL certificate and chain"
        echo "  - private-key.pem: Private key"
    else
        echo "Failed to download certificate"
    fi
fi
echo

echo "=== Certificate Management Example Complete ==="
echo
echo "Tips:"
echo "- ACME certificates auto-renew 30 days before expiry"
echo "- Wildcard certificates require DNS-01 challenges"
echo "- Manual certificates can be uploaded with dh_certificates_create"
