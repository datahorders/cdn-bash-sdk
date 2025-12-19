#!/usr/bin/env bash
#
# DataHorders CDN Bash SDK
# A comprehensive Bash SDK for the DataHorders CDN API
#
# Repository: https://github.com/datahorders/cdn-bash-sdk
# Documentation: https://wiki.datahorders.org/docs/api
#
# Copyright (c) 2024 DataHorders
# Licensed under the MIT License
#

set -euo pipefail

# ==============================================================================
# Configuration
# ==============================================================================

DH_BASE_URL="${DATAHORDERS_BASE_URL:-https://dashboard.datahorders.org/api/user/v1}"
DH_API_KEY="${DATAHORDERS_API_KEY:-}"
DH_DEBUG="${DATAHORDERS_DEBUG:-0}"
DH_TIMEOUT="${DATAHORDERS_TIMEOUT:-30}"

# Colors for output (can be disabled with DH_NO_COLOR=1)
if [[ "${DH_NO_COLOR:-0}" == "1" ]] || [[ ! -t 1 ]]; then
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    CYAN=""
    BOLD=""
    RESET=""
else
    RED="\033[0;31m"
    GREEN="\033[0;32m"
    YELLOW="\033[0;33m"
    BLUE="\033[0;34m"
    CYAN="\033[0;36m"
    BOLD="\033[1m"
    RESET="\033[0m"
fi

# ==============================================================================
# Utility Functions
# ==============================================================================

# Print debug messages if debug mode is enabled
dh_debug() {
    if [[ "${DH_DEBUG}" == "1" ]]; then
        echo -e "${CYAN}[DEBUG]${RESET} $*" >&2
    fi
}

# Print error messages
dh_error() {
    echo -e "${RED}[ERROR]${RESET} $*" >&2
}

# Print success messages
dh_success() {
    echo -e "${GREEN}[OK]${RESET} $*" >&2
}

# Print warning messages
dh_warn() {
    echo -e "${YELLOW}[WARN]${RESET} $*" >&2
}

# Print info messages
dh_info() {
    echo -e "${BLUE}[INFO]${RESET} $*" >&2
}

# Check if required dependencies are available
dh_check_deps() {
    local missing=()

    if ! command -v curl &>/dev/null; then
        missing+=("curl")
    fi

    if ! command -v jq &>/dev/null; then
        missing+=("jq")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        dh_error "Missing required dependencies: ${missing[*]}"
        dh_error "Please install them and try again."
        return 1
    fi

    return 0
}

# Check if API key is set
dh_check_api_key() {
    if [[ -z "${DH_API_KEY}" ]]; then
        dh_error "API key not set. Set DATAHORDERS_API_KEY environment variable or call dh_set_api_key."
        return 1
    fi
    return 0
}

# Set API key
dh_set_api_key() {
    DH_API_KEY="$1"
}

# Set base URL
dh_set_base_url() {
    DH_BASE_URL="$1"
}

# Enable debug mode
dh_enable_debug() {
    DH_DEBUG="1"
}

# Disable debug mode
dh_disable_debug() {
    DH_DEBUG="0"
}

# ==============================================================================
# HTTP Request Functions
# ==============================================================================

# Make an HTTP request to the API
# Usage: dh_request METHOD ENDPOINT [DATA]
# Returns: JSON response on stdout, exits with error code on failure
dh_request() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"
    local url="${DH_BASE_URL}${endpoint}"

    dh_check_api_key || return 1

    local curl_args=(
        -s
        -X "${method}"
        -H "Authorization: Bearer ${DH_API_KEY}"
        -H "Content-Type: application/json"
        -H "Accept: application/json"
        --max-time "${DH_TIMEOUT}"
        -w "\n%{http_code}"
    )

    if [[ -n "${data}" ]]; then
        curl_args+=(-d "${data}")
    fi

    curl_args+=("${url}")

    dh_debug "Request: ${method} ${url}"
    if [[ -n "${data}" ]]; then
        dh_debug "Body: ${data}"
    fi

    local response
    response=$(curl "${curl_args[@]}" 2>/dev/null) || {
        dh_error "Failed to connect to API"
        return 1
    }

    # Extract status code (last line) and body (everything else)
    local http_code
    http_code=$(echo "${response}" | tail -n1)
    local body
    body=$(echo "${response}" | sed '$d')

    dh_debug "Response code: ${http_code}"
    dh_debug "Response body: ${body}"

    # Handle error responses
    if [[ "${http_code}" -ge 400 ]]; then
        local error_msg
        error_msg=$(echo "${body}" | jq -r '.message // .error // "Unknown error"' 2>/dev/null || echo "Unknown error")

        case "${http_code}" in
            401)
                dh_error "Authentication failed: Invalid API key"
                ;;
            403)
                dh_error "Authorization failed: Insufficient permissions"
                ;;
            404)
                dh_error "Not found: ${error_msg}"
                ;;
            409)
                dh_error "Conflict: ${error_msg}"
                ;;
            422)
                dh_error "Validation error: ${error_msg}"
                ;;
            429)
                dh_error "Rate limit exceeded. Please retry later."
                ;;
            500|502|503|504)
                dh_error "Server error (${http_code}): ${error_msg}"
                ;;
            *)
                dh_error "API error (${http_code}): ${error_msg}"
                ;;
        esac

        # Output error response for further processing if needed
        echo "${body}"
        return 1
    fi

    echo "${body}"
    return 0
}

# GET request
dh_get() {
    local endpoint="$1"
    local params="${2:-}"

    if [[ -n "${params}" ]]; then
        endpoint="${endpoint}?${params}"
    fi

    dh_request "GET" "${endpoint}"
}

# POST request
dh_post() {
    local endpoint="$1"
    local data="${2:-{}}"

    dh_request "POST" "${endpoint}" "${data}"
}

# PUT request
dh_put() {
    local endpoint="$1"
    local data="${2:-{}}"

    dh_request "PUT" "${endpoint}" "${data}"
}

# PATCH request
dh_patch() {
    local endpoint="$1"
    local data="${2:-{}}"

    dh_request "PATCH" "${endpoint}" "${data}"
}

# DELETE request
dh_delete() {
    local endpoint="$1"
    local params="${2:-}"

    if [[ -n "${params}" ]]; then
        endpoint="${endpoint}?${params}"
    fi

    dh_request "DELETE" "${endpoint}"
}

# Download binary file
dh_download() {
    local endpoint="$1"
    local output_file="$2"
    local url="${DH_BASE_URL}${endpoint}"

    dh_check_api_key || return 1

    curl -s \
        -H "Authorization: Bearer ${DH_API_KEY}" \
        --max-time "${DH_TIMEOUT}" \
        -o "${output_file}" \
        "${url}" || {
        dh_error "Failed to download file"
        return 1
    }

    return 0
}

# ==============================================================================
# JSON Helper Functions
# ==============================================================================

# Build JSON object from key-value pairs
# Usage: dh_json_object key1 value1 key2 value2 ...
dh_json_object() {
    local json="{"
    local first=true

    while [[ $# -ge 2 ]]; do
        local key="$1"
        local value="$2"
        shift 2

        if [[ "${first}" == "true" ]]; then
            first=false
        else
            json+=","
        fi

        # Determine value type and format accordingly
        if [[ "${value}" == "true" ]] || [[ "${value}" == "false" ]]; then
            json+="\"${key}\":${value}"
        elif [[ "${value}" =~ ^[0-9]+$ ]]; then
            json+="\"${key}\":${value}"
        elif [[ "${value}" == "null" ]]; then
            json+="\"${key}\":null"
        elif [[ "${value}" == "["* ]] || [[ "${value}" == "{"* ]]; then
            # Already JSON array or object
            json+="\"${key}\":${value}"
        else
            # String value - escape special characters
            local escaped
            escaped=$(echo "${value}" | jq -Rs '.' | sed 's/^"//;s/"$//')
            json+="\"${key}\":\"${escaped}\""
        fi
    done

    json+="}"
    echo "${json}"
}

# Build JSON array
# Usage: dh_json_array elem1 elem2 ...
dh_json_array() {
    local json="["
    local first=true

    for elem in "$@"; do
        if [[ "${first}" == "true" ]]; then
            first=false
        else
            json+=","
        fi

        if [[ "${elem}" == "{"* ]] || [[ "${elem}" == "["* ]] || \
           [[ "${elem}" == "true" ]] || [[ "${elem}" == "false" ]] || \
           [[ "${elem}" =~ ^[0-9]+$ ]]; then
            json+="${elem}"
        else
            json+="\"${elem}\""
        fi
    done

    json+="]"
    echo "${json}"
}

# Extract value from JSON
# Usage: dh_json_get JSON_STRING PATH
dh_json_get() {
    local json="$1"
    local path="$2"

    echo "${json}" | jq -r "${path}" 2>/dev/null
}

# ==============================================================================
# DOMAINS
# ==============================================================================

# List all domains
# Usage: dh_domains_list [page] [per_page] [verified]
dh_domains_list() {
    local page="${1:-1}"
    local per_page="${2:-10}"
    local verified="${3:-}"

    local params="page=${page}&perPage=${per_page}"
    if [[ -n "${verified}" ]]; then
        params+="&verified=${verified}"
    fi

    dh_get "/domains" "${params}"
}

# Get a specific domain by ID
# Usage: dh_domains_get DOMAIN_ID
dh_domains_get() {
    local domain_id="$1"

    dh_get "/domains" "id=${domain_id}"
}

# Create a new domain
# Usage: dh_domains_create DOMAIN [health_check_enabled]
dh_domains_create() {
    local domain="$1"
    local health_check_enabled="${2:-false}"

    local data
    data=$(dh_json_object \
        "domain" "${domain}" \
        "healthCheckEnabled" "${health_check_enabled}"
    )

    dh_post "/domains" "${data}"
}

# Verify domain ownership
# Usage: dh_domains_verify [domain] [domain_id]
dh_domains_verify() {
    local domain="${1:-}"
    local domain_id="${2:-}"

    local data="{}"
    if [[ -n "${domain}" ]]; then
        data=$(dh_json_object "domain" "${domain}")
    elif [[ -n "${domain_id}" ]]; then
        data=$(dh_json_object "id" "${domain_id}")
    else
        dh_error "Either domain or domain_id must be provided"
        return 1
    fi

    dh_post "/domains/verify" "${data}"
}

# Delete a domain
# Usage: dh_domains_delete DOMAIN_ID
dh_domains_delete() {
    local domain_id="$1"

    dh_delete "/domains" "id=${domain_id}"
}

# ==============================================================================
# ZONES
# ==============================================================================

# List all zones
# Usage: dh_zones_list [page] [per_page] [domain]
dh_zones_list() {
    local page="${1:-1}"
    local per_page="${2:-10}"
    local domain="${3:-}"

    local params="page=${page}&perPage=${per_page}"
    if [[ -n "${domain}" ]]; then
        params+="&domain=${domain}"
    fi

    dh_get "/zones" "${params}"
}

# Get a zone by ID
# Usage: dh_zones_get ZONE_ID
dh_zones_get() {
    local zone_id="$1"

    dh_get "/zones/${zone_id}"
}

# Get a zone by FQDN
# Usage: dh_zones_get_by_fqdn FQDN
dh_zones_get_by_fqdn() {
    local fqdn="$1"

    dh_get "/zones" "fqdn=${fqdn}"
}

# Create a new zone
# Usage: dh_zones_create NAME DOMAINS_JSON SERVERS_JSON [options...]
# Options: --certificate-id ID --load-balance-method METHOD --upgrade-insecure BOOL
#          --four-k-fallback BOOL --health-check-enabled BOOL
dh_zones_create() {
    local name="$1"
    local domains_json="$2"
    local servers_json="$3"
    shift 3

    local certificate_id=""
    local load_balance_method="round_robin"
    local upgrade_insecure="true"
    local four_k_fallback="false"
    local health_check_enabled="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --certificate-id)
                certificate_id="$2"
                shift 2
                ;;
            --load-balance-method)
                load_balance_method="$2"
                shift 2
                ;;
            --upgrade-insecure)
                upgrade_insecure="$2"
                shift 2
                ;;
            --four-k-fallback)
                four_k_fallback="$2"
                shift 2
                ;;
            --health-check-enabled)
                health_check_enabled="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    local upstream_json
    upstream_json=$(cat <<EOF
{
    "loadBalanceMethod": "${load_balance_method}",
    "servers": ${servers_json}
}
EOF
)

    local data
    if [[ -n "${certificate_id}" ]]; then
        data=$(cat <<EOF
{
    "name": "${name}",
    "domains": ${domains_json},
    "upgradeInsecure": ${upgrade_insecure},
    "fourKFallback": ${four_k_fallback},
    "healthCheckEnabled": ${health_check_enabled},
    "certificateId": "${certificate_id}",
    "upstream": ${upstream_json}
}
EOF
)
    else
        data=$(cat <<EOF
{
    "name": "${name}",
    "domains": ${domains_json},
    "upgradeInsecure": ${upgrade_insecure},
    "fourKFallback": ${four_k_fallback},
    "healthCheckEnabled": ${health_check_enabled},
    "upstream": ${upstream_json}
}
EOF
)
    fi

    dh_post "/zones" "${data}"
}

# Update a zone
# Usage: dh_zones_update ZONE_ID DATA_JSON
dh_zones_update() {
    local zone_id="$1"
    local data="$2"

    dh_put "/zones/${zone_id}" "${data}"
}

# Update a zone by FQDN
# Usage: dh_zones_update_by_fqdn FQDN DATA_JSON
dh_zones_update_by_fqdn() {
    local fqdn="$1"
    local data="$2"

    dh_request "PATCH" "/zones?fqdn=${fqdn}" "${data}"
}

# Delete a zone by ID
# Usage: dh_zones_delete ZONE_ID
dh_zones_delete() {
    local zone_id="$1"

    dh_delete "/zones/${zone_id}"
}

# Delete a zone by FQDN
# Usage: dh_zones_delete_by_fqdn FQDN
dh_zones_delete_by_fqdn() {
    local fqdn="$1"

    dh_delete "/zones" "fqdn=${fqdn}"
}

# ==============================================================================
# CERTIFICATES
# ==============================================================================

# List all certificates
# Usage: dh_certificates_list [page] [per_page] [status]
dh_certificates_list() {
    local page="${1:-1}"
    local per_page="${2:-10}"
    local status="${3:-}"

    local params="page=${page}&perPage=${per_page}"
    if [[ -n "${status}" ]]; then
        params+="&status=${status}"
    fi

    dh_get "/certificates" "${params}"
}

# Get a certificate by domain
# Usage: dh_certificates_get DOMAIN [include_sensitive_data]
dh_certificates_get() {
    local domain="$1"
    local include_sensitive="${2:-false}"

    local params="domain=${domain}"
    if [[ "${include_sensitive}" == "true" ]]; then
        params+="&includeSensitiveData=true"
    fi

    dh_get "/certificates" "${params}"
}

# Create a manual certificate
# Usage: dh_certificates_create NAME CERT_FILE KEY_FILE [options...]
# Options: --domains DOMAINS_JSON --auto-renew BOOL --force BOOL
dh_certificates_create() {
    local name="$1"
    local cert_file="$2"
    local key_file="$3"
    shift 3

    local domains=""
    local auto_renew="false"
    local force="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domains)
                domains="$2"
                shift 2
                ;;
            --auto-renew)
                auto_renew="$2"
                shift 2
                ;;
            --force)
                force="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    local cert_content
    cert_content=$(cat "${cert_file}")
    local key_content
    key_content=$(cat "${key_file}")

    # Escape certificate content for JSON
    local cert_escaped
    cert_escaped=$(echo "${cert_content}" | jq -Rs '.')
    local key_escaped
    key_escaped=$(echo "${key_content}" | jq -Rs '.')

    local data
    if [[ -n "${domains}" ]]; then
        data=$(cat <<EOF
{
    "name": "${name}",
    "provider": "manual",
    "certContent": ${cert_escaped},
    "keyContent": ${key_escaped},
    "domains": ${domains},
    "autoRenew": ${auto_renew},
    "force": ${force}
}
EOF
)
    else
        data=$(cat <<EOF
{
    "name": "${name}",
    "provider": "manual",
    "certContent": ${cert_escaped},
    "keyContent": ${key_escaped},
    "autoRenew": ${auto_renew},
    "force": ${force}
}
EOF
)
    fi

    dh_post "/certificates" "${data}"
}

# Create an ACME certificate
# Usage: dh_certificates_create_acme NAME DOMAINS_JSON EMAIL [options...]
# Options: --acme-provider PROVIDER --auto-renew BOOL --force BOOL
dh_certificates_create_acme() {
    local name="$1"
    local domains_json="$2"
    local email="$3"
    shift 3

    local acme_provider="letsencrypt"
    local auto_renew="true"
    local force="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --acme-provider)
                acme_provider="$2"
                shift 2
                ;;
            --auto-renew)
                auto_renew="$2"
                shift 2
                ;;
            --force)
                force="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    local data
    data=$(cat <<EOF
{
    "name": "${name}",
    "domains": ${domains_json},
    "email": "${email}",
    "acmeProvider": "${acme_provider}",
    "autoRenew": ${auto_renew},
    "force": ${force}
}
EOF
)

    dh_post "/certificates/acme" "${data}"
}

# Get ACME certificate status
# Usage: dh_certificates_get_acme_status CERTIFICATE_ID
dh_certificates_get_acme_status() {
    local certificate_id="$1"

    dh_get "/certificates/acme" "certificateId=${certificate_id}"
}

# List all ACME certificates
# Usage: dh_certificates_list_acme
dh_certificates_list_acme() {
    dh_get "/certificates/acme"
}

# Download a certificate as ZIP
# Usage: dh_certificates_download CERTIFICATE_ID OUTPUT_FILE
dh_certificates_download() {
    local certificate_id="$1"
    local output_file="$2"

    dh_download "/certificates/${certificate_id}/download" "${output_file}"
}

# Delete a certificate
# Usage: dh_certificates_delete DOMAIN
dh_certificates_delete() {
    local domain="$1"

    dh_delete "/certificates" "domain=${domain}"
}

# ==============================================================================
# UPSTREAM SERVERS
# ==============================================================================

# List upstream servers for a zone
# Usage: dh_upstream_servers_list ZONE_ID
dh_upstream_servers_list() {
    local zone_id="$1"

    dh_get "/zones/${zone_id}/upstream/servers"
}

# Create an upstream server
# Usage: dh_upstream_servers_create ZONE_ID NAME ADDRESS PORT HEALTH_CHECK_PATH [options...]
# Options: --protocol PROTOCOL --weight WEIGHT --backup BOOL --region REGION --country COUNTRY
dh_upstream_servers_create() {
    local zone_id="$1"
    local name="$2"
    local address="$3"
    local port="$4"
    local health_check_path="$5"
    shift 5

    local protocol="http"
    local weight="1"
    local backup="false"
    local region=""
    local country=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --protocol)
                protocol="$2"
                shift 2
                ;;
            --weight)
                weight="$2"
                shift 2
                ;;
            --backup)
                backup="$2"
                shift 2
                ;;
            --region)
                region="$2"
                shift 2
                ;;
            --country)
                country="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    local data
    data=$(cat <<EOF
{
    "name": "${name}",
    "address": "${address}",
    "port": ${port},
    "protocol": "${protocol}",
    "weight": ${weight},
    "backup": ${backup},
    "healthCheckPath": "${health_check_path}"
EOF
)

    if [[ -n "${region}" ]]; then
        data+=",\"region\": \"${region}\""
    fi
    if [[ -n "${country}" ]]; then
        data+=",\"country\": \"${country}\""
    fi

    data+="}"

    dh_post "/zones/${zone_id}/upstream/servers" "${data}"
}

# Update an upstream server
# Usage: dh_upstream_servers_update ZONE_ID SERVER_ID DATA_JSON
dh_upstream_servers_update() {
    local zone_id="$1"
    local server_id="$2"
    local data="$3"

    dh_put "/zones/${zone_id}/upstream/servers/${server_id}" "${data}"
}

# Delete an upstream server
# Usage: dh_upstream_servers_delete ZONE_ID SERVER_ID
dh_upstream_servers_delete() {
    local zone_id="$1"
    local server_id="$2"

    dh_delete "/zones/${zone_id}/upstream/servers/${server_id}"
}

# ==============================================================================
# HEALTH CHECKS
# ==============================================================================

# List health check profiles
# Usage: dh_health_checks_list_profiles [page] [limit] [search]
dh_health_checks_list_profiles() {
    local page="${1:-1}"
    local limit="${2:-10}"
    local search="${3:-}"

    local params="page=${page}&limit=${limit}"
    if [[ -n "${search}" ]]; then
        params+="&search=${search}"
    fi

    dh_get "/healthcheck-profiles" "${params}"
}

# Get a specific health check profile
# Usage: dh_health_checks_get_profile PROFILE_ID
dh_health_checks_get_profile() {
    local profile_id="$1"

    dh_get "/healthcheck-profiles/${profile_id}"
}

# Create a health check profile
# Usage: dh_health_checks_create_profile NAME [options...]
# Options: --description DESC --protocol PROTO --port PORT --path PATH --method METHOD
#          --expected-status-codes CODES --check-interval SECS --timeout SECS
#          --retries NUM --follow-redirects BOOL --verify-ssl BOOL
dh_health_checks_create_profile() {
    local name="$1"
    shift

    local description=""
    local protocol="http"
    local port="80"
    local path="/"
    local method="HEAD"
    local expected_status_codes="200-399"
    local expected_response_text=""
    local check_interval="30"
    local timeout="10"
    local retries="2"
    local follow_redirects="false"
    local verify_ssl="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --description)
                description="$2"
                shift 2
                ;;
            --protocol)
                protocol="$2"
                shift 2
                ;;
            --port)
                port="$2"
                shift 2
                ;;
            --path)
                path="$2"
                shift 2
                ;;
            --method)
                method="$2"
                shift 2
                ;;
            --expected-status-codes)
                expected_status_codes="$2"
                shift 2
                ;;
            --expected-response-text)
                expected_response_text="$2"
                shift 2
                ;;
            --check-interval)
                check_interval="$2"
                shift 2
                ;;
            --timeout)
                timeout="$2"
                shift 2
                ;;
            --retries)
                retries="$2"
                shift 2
                ;;
            --follow-redirects)
                follow_redirects="$2"
                shift 2
                ;;
            --verify-ssl)
                verify_ssl="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    local data
    data=$(cat <<EOF
{
    "name": "${name}",
    "protocol": "${protocol}",
    "port": ${port},
    "path": "${path}",
    "method": "${method}",
    "expectedStatusCodes": "${expected_status_codes}",
    "checkInterval": ${check_interval},
    "timeout": ${timeout},
    "retries": ${retries},
    "followRedirects": ${follow_redirects},
    "verifySSL": ${verify_ssl}
EOF
)

    if [[ -n "${description}" ]]; then
        data+=",\"description\": \"${description}\""
    fi
    if [[ -n "${expected_response_text}" ]]; then
        data+=",\"expectedResponseText\": \"${expected_response_text}\""
    fi

    data+="}"

    dh_post "/healthcheck-profiles" "${data}"
}

# Update a health check profile
# Usage: dh_health_checks_update_profile PROFILE_ID DATA_JSON
dh_health_checks_update_profile() {
    local profile_id="$1"
    local data="$2"

    dh_put "/healthcheck-profiles/${profile_id}" "${data}"
}

# Delete a health check profile
# Usage: dh_health_checks_delete_profile PROFILE_ID
dh_health_checks_delete_profile() {
    local profile_id="$1"

    dh_delete "/healthcheck-profiles/${profile_id}"
}

# Enable health checks for a server
# Usage: dh_health_checks_enable_server SERVER_ID
dh_health_checks_enable_server() {
    local server_id="$1"

    local data
    data=$(dh_json_object \
        "serverId" "${server_id}" \
        "action" "enable"
    )

    dh_post "/monitoring/health-checks" "${data}"
}

# Disable health checks for a server
# Usage: dh_health_checks_disable_server SERVER_ID [reason]
dh_health_checks_disable_server() {
    local server_id="$1"
    local reason="${2:-}"

    local data
    if [[ -n "${reason}" ]]; then
        data=$(dh_json_object \
            "serverId" "${server_id}" \
            "action" "disable" \
            "reason" "${reason}"
        )
    else
        data=$(dh_json_object \
            "serverId" "${server_id}" \
            "action" "disable"
        )
    fi

    dh_post "/monitoring/health-checks" "${data}"
}

# List CDN nodes
# Usage: dh_health_checks_list_cdn_nodes
dh_health_checks_list_cdn_nodes() {
    dh_get "/cdn-nodes"
}

# ==============================================================================
# WAF (Web Application Firewall)
# ==============================================================================

# Get WAF configuration for a zone
# Usage: dh_waf_get_config ZONE_ID
dh_waf_get_config() {
    local zone_id="$1"

    dh_get "/zones/${zone_id}/waf"
}

# Update WAF configuration for a zone
# Usage: dh_waf_update_config ZONE_ID [options...]
# Options: --enabled BOOL --mode MODE --sqli-detection BOOL --xss-detection BOOL
dh_waf_update_config() {
    local zone_id="$1"
    shift

    local data="{"
    local first=true

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --enabled)
                [[ "${first}" != "true" ]] && data+=","
                data+="\"enabled\":$2"
                first=false
                shift 2
                ;;
            --mode)
                [[ "${first}" != "true" ]] && data+=","
                data+="\"mode\":\"$2\""
                first=false
                shift 2
                ;;
            --sqli-detection)
                [[ "${first}" != "true" ]] && data+=","
                data+="\"sqliDetection\":$2"
                first=false
                shift 2
                ;;
            --xss-detection)
                [[ "${first}" != "true" ]] && data+=","
                data+="\"xssDetection\":$2"
                first=false
                shift 2
                ;;
            --custom-block-page)
                [[ "${first}" != "true" ]] && data+=","
                local escaped
                escaped=$(echo "$2" | jq -Rs '.')
                data+="\"customBlockPage\":${escaped}"
                first=false
                shift 2
                ;;
            --inherit-global-rules)
                [[ "${first}" != "true" ]] && data+=","
                data+="\"inheritGlobalRules\":$2"
                first=false
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    data+="}"

    dh_put "/zones/${zone_id}/waf" "${data}"
}

# List WAF rules for a zone
# Usage: dh_waf_list_rules ZONE_ID [page] [per_page]
dh_waf_list_rules() {
    local zone_id="$1"
    local page="${2:-1}"
    local per_page="${3:-50}"

    dh_get "/zones/${zone_id}/waf/rules" "page=${page}&perPage=${per_page}"
}

# Get a specific WAF rule
# Usage: dh_waf_get_rule ZONE_ID RULE_ID
dh_waf_get_rule() {
    local zone_id="$1"
    local rule_id="$2"

    dh_get "/zones/${zone_id}/waf/rules/${rule_id}"
}

# Create a WAF rule
# Usage: dh_waf_create_rule ZONE_ID NAME RULE_TYPE MATCH_TARGET MATCH_PATTERN ACTION [options...]
# Options: --description DESC --severity SEV --enabled BOOL --priority NUM
dh_waf_create_rule() {
    local zone_id="$1"
    local name="$2"
    local rule_type="$3"
    local match_target="$4"
    local match_pattern="$5"
    local action="$6"
    shift 6

    local description=""
    local severity="medium"
    local enabled="true"
    local priority="500"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --description)
                description="$2"
                shift 2
                ;;
            --severity)
                severity="$2"
                shift 2
                ;;
            --enabled)
                enabled="$2"
                shift 2
                ;;
            --priority)
                priority="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    local pattern_escaped
    pattern_escaped=$(echo "${match_pattern}" | jq -Rs '.' | sed 's/^"//;s/"$//')

    local data
    data=$(cat <<EOF
{
    "name": "${name}",
    "ruleType": "${rule_type}",
    "matchTarget": "${match_target}",
    "matchPattern": "${pattern_escaped}",
    "action": "${action}",
    "severity": "${severity}",
    "enabled": ${enabled},
    "priority": ${priority}
EOF
)

    if [[ -n "${description}" ]]; then
        data+=",\"description\": \"${description}\""
    fi

    data+="}"

    dh_post "/zones/${zone_id}/waf/rules" "${data}"
}

# Update a WAF rule
# Usage: dh_waf_update_rule ZONE_ID RULE_ID DATA_JSON
dh_waf_update_rule() {
    local zone_id="$1"
    local rule_id="$2"
    local data="$3"

    dh_put "/zones/${zone_id}/waf/rules/${rule_id}" "${data}"
}

# Delete a WAF rule
# Usage: dh_waf_delete_rule ZONE_ID RULE_ID
dh_waf_delete_rule() {
    local zone_id="$1"
    local rule_id="$2"

    dh_delete "/zones/${zone_id}/waf/rules/${rule_id}"
}

# List IP entries in WAF
# Usage: dh_waf_list_ips ZONE_ID [list_type] [page] [per_page]
dh_waf_list_ips() {
    local zone_id="$1"
    local list_type="${2:-}"
    local page="${3:-1}"
    local per_page="${4:-20}"

    local params="page=${page}&perPage=${per_page}"
    if [[ -n "${list_type}" ]]; then
        params+="&listType=${list_type}"
    fi

    dh_get "/zones/${zone_id}/waf/ip-lists" "${params}"
}

# Add an IP to the WAF list
# Usage: dh_waf_add_ip ZONE_ID LIST_TYPE IP_ADDRESS [reason] [expires_at]
dh_waf_add_ip() {
    local zone_id="$1"
    local list_type="$2"
    local ip_address="$3"
    local reason="${4:-}"
    local expires_at="${5:-}"

    local data
    data=$(cat <<EOF
{
    "listType": "${list_type}",
    "ipAddress": "${ip_address}"
EOF
)

    if [[ -n "${reason}" ]]; then
        data+=",\"reason\": \"${reason}\""
    fi
    if [[ -n "${expires_at}" ]]; then
        data+=",\"expiresAt\": \"${expires_at}\""
    fi

    data+="}"

    dh_post "/zones/${zone_id}/waf/ip-lists" "${data}"
}

# Block an IP address
# Usage: dh_waf_block_ip ZONE_ID IP_ADDRESS [reason] [expires_at]
dh_waf_block_ip() {
    local zone_id="$1"
    local ip_address="$2"
    local reason="${3:-}"
    local expires_at="${4:-}"

    dh_waf_add_ip "${zone_id}" "block" "${ip_address}" "${reason}" "${expires_at}"
}

# Allow an IP address (whitelist)
# Usage: dh_waf_allow_ip ZONE_ID IP_ADDRESS [reason]
dh_waf_allow_ip() {
    local zone_id="$1"
    local ip_address="$2"
    local reason="${3:-}"

    dh_waf_add_ip "${zone_id}" "allow" "${ip_address}" "${reason}"
}

# Delete an IP from the WAF list
# Usage: dh_waf_delete_ip ZONE_ID IP_ID
dh_waf_delete_ip() {
    local zone_id="$1"
    local ip_id="$2"

    dh_delete "/zones/${zone_id}/waf/ip-lists/${ip_id}"
}

# List country rules
# Usage: dh_waf_list_countries ZONE_ID
dh_waf_list_countries() {
    local zone_id="$1"

    dh_get "/zones/${zone_id}/waf/countries"
}

# Add a country rule
# Usage: dh_waf_add_country ZONE_ID COUNTRY_CODE ACTION [reason] [enabled]
dh_waf_add_country() {
    local zone_id="$1"
    local country_code="$2"
    local action="$3"
    local reason="${4:-}"
    local enabled="${5:-true}"

    local data
    data=$(cat <<EOF
{
    "countryCode": "${country_code}",
    "action": "${action}",
    "enabled": ${enabled}
EOF
)

    if [[ -n "${reason}" ]]; then
        data+=",\"reason\": \"${reason}\""
    fi

    data+="}"

    dh_post "/zones/${zone_id}/waf/countries" "${data}"
}

# Delete a country rule
# Usage: dh_waf_delete_country ZONE_ID COUNTRY_ID
dh_waf_delete_country() {
    local zone_id="$1"
    local country_id="$2"

    dh_delete "/zones/${zone_id}/waf/countries/${country_id}"
}

# List ASN rules
# Usage: dh_waf_list_asns ZONE_ID
dh_waf_list_asns() {
    local zone_id="$1"

    dh_get "/zones/${zone_id}/waf/asn"
}

# Add an ASN rule
# Usage: dh_waf_add_asn ZONE_ID ASN ACTION [asn_name] [reason] [enabled]
dh_waf_add_asn() {
    local zone_id="$1"
    local asn="$2"
    local action="$3"
    local asn_name="${4:-}"
    local reason="${5:-}"
    local enabled="${6:-true}"

    local data
    data=$(cat <<EOF
{
    "asn": ${asn},
    "action": "${action}",
    "enabled": ${enabled}
EOF
)

    if [[ -n "${asn_name}" ]]; then
        data+=",\"asnName\": \"${asn_name}\""
    fi
    if [[ -n "${reason}" ]]; then
        data+=",\"reason\": \"${reason}\""
    fi

    data+="}"

    dh_post "/zones/${zone_id}/waf/asn" "${data}"
}

# Delete an ASN rule
# Usage: dh_waf_delete_asn ZONE_ID ASN_ID
dh_waf_delete_asn() {
    local zone_id="$1"
    local asn_id="$2"

    dh_delete "/zones/${zone_id}/waf/asn/${asn_id}"
}

# ==============================================================================
# ANALYTICS
# ==============================================================================

# Get usage metrics
# Usage: dh_analytics_get_usage [start_date] [end_date]
dh_analytics_get_usage() {
    local start_date="${1:-}"
    local end_date="${2:-}"

    local params=""
    if [[ -n "${start_date}" ]]; then
        params="start_date=${start_date}"
    fi
    if [[ -n "${end_date}" ]]; then
        [[ -n "${params}" ]] && params+="&"
        params+="end_date=${end_date}"
    fi

    dh_get "/usage" "${params}"
}

# Get CDN nodes status
# Usage: dh_analytics_get_cdn_nodes
dh_analytics_get_cdn_nodes() {
    dh_get "/cdn-nodes"
}

# ==============================================================================
# CLI Mode
# ==============================================================================

# Print usage information
dh_usage() {
    cat <<EOF
DataHorders CDN Bash SDK v1.0.0

Usage: datahorders-cdn.sh [command] [options]

Commands:
  domains list [page] [per_page] [verified]
  domains get <domain_id>
  domains create <domain> [health_check_enabled]
  domains verify <domain>
  domains delete <domain_id>

  zones list [page] [per_page] [domain]
  zones get <zone_id>
  zones get-by-fqdn <fqdn>
  zones delete <zone_id>
  zones delete-by-fqdn <fqdn>

  certificates list [page] [per_page] [status]
  certificates get <domain>
  certificates get-acme-status <certificate_id>
  certificates download <certificate_id> <output_file>
  certificates delete <domain>

  waf get-config <zone_id>
  waf list-rules <zone_id>
  waf list-ips <zone_id> [list_type]
  waf block-ip <zone_id> <ip_address> [reason]
  waf allow-ip <zone_id> <ip_address> [reason]
  waf list-countries <zone_id>
  waf list-asns <zone_id>

  analytics usage [start_date] [end_date]
  analytics cdn-nodes

  health-checks list-profiles [page] [limit]
  health-checks list-cdn-nodes
  health-checks enable-server <server_id>
  health-checks disable-server <server_id> [reason]

Options:
  -h, --help      Show this help message
  -v, --version   Show version
  --debug         Enable debug mode

Environment Variables:
  DATAHORDERS_API_KEY    API key for authentication (required)
  DATAHORDERS_BASE_URL   API base URL (default: https://dashboard.datahorders.org/api/user/v1)
  DATAHORDERS_DEBUG      Enable debug mode (1 = enabled)
  DATAHORDERS_TIMEOUT    Request timeout in seconds (default: 30)
  DH_NO_COLOR            Disable colored output (1 = disabled)

Examples:
  # List all domains
  DATAHORDERS_API_KEY="your-api-key" ./datahorders-cdn.sh domains list

  # Get usage analytics
  ./datahorders-cdn.sh analytics usage 2024-01-01 2024-01-31

  # Block an IP address
  ./datahorders-cdn.sh waf block-ip zone_abc123 198.51.100.50 "Malicious activity"

For more information, visit: https://wiki.datahorders.org/docs/api
EOF
}

# CLI entry point
dh_cli() {
    # Check for help or version flags
    case "${1:-}" in
        -h|--help)
            dh_usage
            return 0
            ;;
        -v|--version)
            echo "DataHorders CDN Bash SDK v1.0.0"
            return 0
            ;;
        --debug)
            dh_enable_debug
            shift
            ;;
    esac

    # Check dependencies
    dh_check_deps || return 1

    local command="${1:-}"
    local subcommand="${2:-}"

    if [[ -z "${command}" ]]; then
        dh_usage
        return 1
    fi

    shift
    [[ -n "${subcommand}" ]] && shift

    case "${command}" in
        domains)
            case "${subcommand}" in
                list)
                    dh_domains_list "$@"
                    ;;
                get)
                    dh_domains_get "$@"
                    ;;
                create)
                    dh_domains_create "$@"
                    ;;
                verify)
                    dh_domains_verify "$@"
                    ;;
                delete)
                    dh_domains_delete "$@"
                    ;;
                *)
                    dh_error "Unknown domains subcommand: ${subcommand}"
                    return 1
                    ;;
            esac
            ;;
        zones)
            case "${subcommand}" in
                list)
                    dh_zones_list "$@"
                    ;;
                get)
                    dh_zones_get "$@"
                    ;;
                get-by-fqdn)
                    dh_zones_get_by_fqdn "$@"
                    ;;
                delete)
                    dh_zones_delete "$@"
                    ;;
                delete-by-fqdn)
                    dh_zones_delete_by_fqdn "$@"
                    ;;
                *)
                    dh_error "Unknown zones subcommand: ${subcommand}"
                    return 1
                    ;;
            esac
            ;;
        certificates)
            case "${subcommand}" in
                list)
                    dh_certificates_list "$@"
                    ;;
                get)
                    dh_certificates_get "$@"
                    ;;
                get-acme-status)
                    dh_certificates_get_acme_status "$@"
                    ;;
                list-acme)
                    dh_certificates_list_acme
                    ;;
                download)
                    dh_certificates_download "$@"
                    ;;
                delete)
                    dh_certificates_delete "$@"
                    ;;
                *)
                    dh_error "Unknown certificates subcommand: ${subcommand}"
                    return 1
                    ;;
            esac
            ;;
        waf)
            case "${subcommand}" in
                get-config)
                    dh_waf_get_config "$@"
                    ;;
                update-config)
                    dh_waf_update_config "$@"
                    ;;
                list-rules)
                    dh_waf_list_rules "$@"
                    ;;
                get-rule)
                    dh_waf_get_rule "$@"
                    ;;
                delete-rule)
                    dh_waf_delete_rule "$@"
                    ;;
                list-ips)
                    dh_waf_list_ips "$@"
                    ;;
                block-ip)
                    dh_waf_block_ip "$@"
                    ;;
                allow-ip)
                    dh_waf_allow_ip "$@"
                    ;;
                delete-ip)
                    dh_waf_delete_ip "$@"
                    ;;
                list-countries)
                    dh_waf_list_countries "$@"
                    ;;
                add-country)
                    dh_waf_add_country "$@"
                    ;;
                delete-country)
                    dh_waf_delete_country "$@"
                    ;;
                list-asns)
                    dh_waf_list_asns "$@"
                    ;;
                add-asn)
                    dh_waf_add_asn "$@"
                    ;;
                delete-asn)
                    dh_waf_delete_asn "$@"
                    ;;
                *)
                    dh_error "Unknown waf subcommand: ${subcommand}"
                    return 1
                    ;;
            esac
            ;;
        analytics)
            case "${subcommand}" in
                usage)
                    dh_analytics_get_usage "$@"
                    ;;
                cdn-nodes)
                    dh_analytics_get_cdn_nodes
                    ;;
                *)
                    dh_error "Unknown analytics subcommand: ${subcommand}"
                    return 1
                    ;;
            esac
            ;;
        health-checks)
            case "${subcommand}" in
                list-profiles)
                    dh_health_checks_list_profiles "$@"
                    ;;
                get-profile)
                    dh_health_checks_get_profile "$@"
                    ;;
                delete-profile)
                    dh_health_checks_delete_profile "$@"
                    ;;
                list-cdn-nodes)
                    dh_health_checks_list_cdn_nodes
                    ;;
                enable-server)
                    dh_health_checks_enable_server "$@"
                    ;;
                disable-server)
                    dh_health_checks_disable_server "$@"
                    ;;
                *)
                    dh_error "Unknown health-checks subcommand: ${subcommand}"
                    return 1
                    ;;
            esac
            ;;
        upstream-servers)
            case "${subcommand}" in
                list)
                    dh_upstream_servers_list "$@"
                    ;;
                delete)
                    dh_upstream_servers_delete "$@"
                    ;;
                *)
                    dh_error "Unknown upstream-servers subcommand: ${subcommand}"
                    return 1
                    ;;
            esac
            ;;
        *)
            dh_error "Unknown command: ${command}"
            dh_usage
            return 1
            ;;
    esac
}

# Run CLI if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    dh_cli "$@"
fi
