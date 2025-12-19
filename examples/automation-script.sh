#!/usr/bin/env bash
#
# Automation Script Example
# Demonstrates non-interactive usage for CI/CD pipelines and cron jobs
#

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the SDK
source "${SCRIPT_DIR}/../datahorders-cdn.sh"

# Disable colors for non-interactive output
export DH_NO_COLOR=1

# ============================================================================
# Configuration
# ============================================================================

# These would typically come from environment variables or CI/CD secrets
: "${DATAHORDERS_API_KEY:?DATAHORDERS_API_KEY is required}"
: "${ZONE_ID:=}"
: "${ALERT_EMAIL:=}"

LOG_FILE="${LOG_FILE:-/tmp/datahorders-automation.log}"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# ============================================================================
# Logging functions
# ============================================================================

log() {
    echo "[${TIMESTAMP}] $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "[${TIMESTAMP}] ERROR: $*" | tee -a "${LOG_FILE}" >&2
}

log_success() {
    echo "[${TIMESTAMP}] SUCCESS: $*" | tee -a "${LOG_FILE}"
}

# ============================================================================
# Alert function (customize for your alerting system)
# ============================================================================

send_alert() {
    local subject="$1"
    local message="$2"

    if [[ -n "${ALERT_EMAIL}" ]]; then
        echo "${message}" | mail -s "[DataHorders CDN] ${subject}" "${ALERT_EMAIL}" 2>/dev/null || true
    fi

    # You could also integrate with:
    # - Slack: curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"${message}\"}" "${SLACK_WEBHOOK}"
    # - PagerDuty: curl with PD API
    # - Custom webhook
}

# ============================================================================
# Health check monitoring
# ============================================================================

check_cdn_health() {
    log "Checking CDN node health..."

    local nodes
    nodes=$(dh_health_checks_list_cdn_nodes 2>/dev/null) || {
        log_error "Failed to fetch CDN nodes"
        send_alert "CDN Health Check Failed" "Could not retrieve CDN node status"
        return 1
    }

    # Check if any nodes are down (customize based on actual response structure)
    local down_nodes
    down_nodes=$(echo "${nodes}" | jq '[.[] | select(.status == "down" or .status == "unhealthy")] | length' 2>/dev/null || echo "0")

    if [[ "${down_nodes}" -gt 0 ]]; then
        local details
        details=$(echo "${nodes}" | jq -r '.[] | select(.status == "down" or .status == "unhealthy") | "\(.domain) (\(.ip_address))"' 2>/dev/null)

        log_error "Found ${down_nodes} unhealthy CDN node(s)"
        send_alert "CDN Nodes Unhealthy" "The following CDN nodes are unhealthy:\n${details}"
        return 1
    fi

    log_success "All CDN nodes healthy"
    return 0
}

# ============================================================================
# Certificate expiration check
# ============================================================================

check_certificate_expiration() {
    local warning_days="${1:-30}"

    log "Checking certificate expiration (warning: ${warning_days} days)..."

    local certs
    certs=$(dh_certificates_list 1 100 2>/dev/null) || {
        log_error "Failed to fetch certificates"
        return 1
    }

    # Get current timestamp
    local now_epoch
    now_epoch=$(date +%s)
    local warning_epoch=$((now_epoch + warning_days * 86400))

    # Check each certificate
    local expiring_certs=""
    local expired_certs=""

    while IFS= read -r cert; do
        local name expires_at status
        name=$(echo "${cert}" | jq -r '.name')
        expires_at=$(echo "${cert}" | jq -r '.expiresAt // ""')
        status=$(echo "${cert}" | jq -r '.status')

        if [[ -z "${expires_at}" ]] || [[ "${expires_at}" == "null" ]]; then
            continue
        fi

        # Parse expiration date
        local expires_epoch
        expires_epoch=$(date -d "${expires_at}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "${expires_at%%.*}" +%s 2>/dev/null || echo "0")

        if [[ "${expires_epoch}" -lt "${now_epoch}" ]]; then
            expired_certs+="${name} (expired: ${expires_at})\n"
        elif [[ "${expires_epoch}" -lt "${warning_epoch}" ]]; then
            expiring_certs+="${name} (expires: ${expires_at})\n"
        fi
    done < <(echo "${certs}" | jq -c '.data[]' 2>/dev/null)

    if [[ -n "${expired_certs}" ]]; then
        log_error "Found expired certificates"
        send_alert "Expired Certificates" "The following certificates have expired:\n${expired_certs}"
    fi

    if [[ -n "${expiring_certs}" ]]; then
        log "Found certificates expiring soon"
        send_alert "Certificates Expiring Soon" "The following certificates expire within ${warning_days} days:\n${expiring_certs}"
    fi

    if [[ -z "${expired_certs}" ]] && [[ -z "${expiring_certs}" ]]; then
        log_success "All certificates valid"
    fi
}

# ============================================================================
# Usage report
# ============================================================================

generate_usage_report() {
    log "Generating usage report..."

    # Get last 7 days of usage
    local end_date start_date
    end_date=$(date +%Y-%m-%d)
    start_date=$(date -d "-7 days" +%Y-%m-%d 2>/dev/null || date -v-7d +%Y-%m-%d 2>/dev/null)

    local usage
    usage=$(dh_analytics_get_usage "${start_date}" "${end_date}" 2>/dev/null) || {
        log_error "Failed to fetch usage data"
        return 1
    }

    local total_gb total_requests
    total_gb=$(echo "${usage}" | jq '.total_traffic.gigabytes // 0' 2>/dev/null)
    total_requests=$(echo "${usage}" | jq '.total_requests // 0' 2>/dev/null)

    log "Usage Report (${start_date} to ${end_date}):"
    log "  Total Bandwidth: ${total_gb} GB"
    log "  Total Requests: ${total_requests}"

    # Per-zone breakdown
    echo "${usage}" | jq -r '.zones[] | "  \(.zone): \(.gigabytes_sent) GB, \(.requests) requests"' 2>/dev/null | while read -r line; do
        log "${line}"
    done

    log_success "Usage report generated"
}

# ============================================================================
# WAF event check
# ============================================================================

check_waf_events() {
    if [[ -z "${ZONE_ID}" ]]; then
        log "ZONE_ID not set, skipping WAF check"
        return 0
    fi

    log "Checking WAF configuration for zone ${ZONE_ID}..."

    local waf_config
    waf_config=$(dh_waf_get_config "${ZONE_ID}" 2>/dev/null) || {
        log_error "Failed to fetch WAF config"
        return 1
    }

    local waf_enabled
    waf_enabled=$(echo "${waf_config}" | jq -r '.data.config.enabled // false' 2>/dev/null)

    if [[ "${waf_enabled}" != "true" ]]; then
        log "WARNING: WAF is disabled for zone ${ZONE_ID}"
        send_alert "WAF Disabled" "WAF is disabled for zone ${ZONE_ID}. Consider enabling for security."
    else
        log_success "WAF is enabled for zone ${ZONE_ID}"
    fi
}

# ============================================================================
# Main execution
# ============================================================================

main() {
    log "Starting DataHorders CDN automation checks..."
    log "================================================"

    local exit_code=0

    # Run all checks
    check_cdn_health || exit_code=1
    check_certificate_expiration 30 || exit_code=1
    generate_usage_report || exit_code=1
    check_waf_events || exit_code=1

    log "================================================"

    if [[ "${exit_code}" -eq 0 ]]; then
        log_success "All checks completed successfully"
    else
        log_error "Some checks failed"
    fi

    return "${exit_code}"
}

# Run main function
main "$@"
