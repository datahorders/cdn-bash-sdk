# DataHorders CDN Bash SDK

A Bash SDK for the DataHorders CDN API, providing command-line access to manage domains, zones, SSL/TLS certificates, WAF configuration, health checks, and analytics.

## Features

- Full coverage of the DataHorders CDN API
- Both standalone CLI and sourceable library modes
- Colored output with helpful error messages
- Cross-platform support (macOS and Linux)
- Minimal dependencies (only curl and jq)
- Debug mode for troubleshooting

## Requirements

- Bash 4.0 or later
- curl
- jq (for JSON parsing)

### Installing Dependencies

**macOS (Homebrew):**
```bash
brew install jq
```

**Ubuntu/Debian:**
```bash
sudo apt-get install jq curl
```

**CentOS/RHEL:**
```bash
sudo yum install jq curl
```

**Arch Linux:**
```bash
sudo pacman -S jq curl
```

## Installation

### Option 1: Download directly

```bash
# Download the SDK
curl -o datahorders-cdn.sh https://raw.githubusercontent.com/datahorders/cdn-bash-sdk/main/datahorders-cdn.sh

# Make it executable
chmod +x datahorders-cdn.sh

# Optionally move to PATH
sudo mv datahorders-cdn.sh /usr/local/bin/datahorders-cdn
```

### Option 2: Clone the repository

```bash
git clone https://github.com/datahorders/cdn-bash-sdk.git
cd cdn-bash-sdk
chmod +x datahorders-cdn.sh
```

## Quick Start

### Set your API key

```bash
export DATAHORDERS_API_KEY="your-api-key"
```

### CLI Usage

```bash
# List all domains
./datahorders-cdn.sh domains list

# Get a specific domain
./datahorders-cdn.sh domains get dom_abc123

# Create a new domain
./datahorders-cdn.sh domains create example.com

# Verify domain ownership
./datahorders-cdn.sh domains verify example.com

# Get usage analytics
./datahorders-cdn.sh analytics usage 2024-01-01 2024-01-31
```

### Library Usage (Sourcing)

```bash
#!/usr/bin/env bash

# Source the SDK
source /path/to/datahorders-cdn.sh

# Set your API key
export DATAHORDERS_API_KEY="your-api-key"

# List domains and parse with jq
domains=$(dh_domains_list)
echo "${domains}" | jq -r '.data[] | "\(.domain) - verified: \(.verified)"'

# Create a domain
response=$(dh_domains_create "example.com")
verification_code=$(echo "${response}" | jq -r '.data.verification.code')
echo "Add this TXT record: ${verification_code}"
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATAHORDERS_API_KEY` | API key for authentication (required) | - |
| `DATAHORDERS_BASE_URL` | API base URL | `https://dashboard.datahorders.org/api/user/v1` |
| `DATAHORDERS_DEBUG` | Enable debug mode (`1` = enabled) | `0` |
| `DATAHORDERS_TIMEOUT` | Request timeout in seconds | `30` |
| `DH_NO_COLOR` | Disable colored output (`1` = disabled) | `0` |

### Programmatic Configuration

```bash
source datahorders-cdn.sh

# Set API key programmatically
dh_set_api_key "your-api-key"

# Set custom base URL
dh_set_base_url "https://custom-api.example.com/api/v1"

# Enable debug mode
dh_enable_debug
```

## API Reference

### Domains

```bash
# List domains with pagination
dh_domains_list [page] [per_page] [verified]

# Get a specific domain by ID
dh_domains_get <domain_id>

# Register a new domain
dh_domains_create <domain> [health_check_enabled]

# Verify domain ownership
dh_domains_verify <domain>
# or by ID:
dh_domains_verify "" <domain_id>

# Delete a domain
dh_domains_delete <domain_id>
```

**Example:**
```bash
# Create and verify a domain
response=$(dh_domains_create "example.com")
echo "${response}" | jq '.data.verification.instructions'

# Later, verify it
result=$(dh_domains_verify "example.com")
verified=$(echo "${result}" | jq -r '.data.verified')
if [[ "${verified}" == "true" ]]; then
    echo "Domain verified!"
fi
```

### Zones

```bash
# List zones
dh_zones_list [page] [per_page] [domain]

# Get zone by ID
dh_zones_get <zone_id>

# Get zone by FQDN
dh_zones_get_by_fqdn <fqdn>

# Create a zone
dh_zones_create <name> <domains_json> <servers_json> [options]
# Options: --certificate-id ID --load-balance-method METHOD
#          --upgrade-insecure BOOL --four-k-fallback BOOL
#          --health-check-enabled BOOL

# Update a zone
dh_zones_update <zone_id> <data_json>

# Delete a zone
dh_zones_delete <zone_id>
dh_zones_delete_by_fqdn <fqdn>
```

**Example:**
```bash
# Create a zone with servers
domains='["dom_abc123"]'
servers='[
  {"address": "10.0.1.100", "port": 8080, "protocol": "http", "healthCheckPath": "/health"},
  {"address": "10.0.1.101", "port": 8080, "protocol": "http", "weight": 2, "backup": true}
]'

zone=$(dh_zones_create "app" "${domains}" "${servers}" \
    --load-balance-method "round_robin" \
    --health-check-enabled true)

zone_id=$(echo "${zone}" | jq -r '.data.id')
echo "Created zone: ${zone_id}"
```

### Certificates

```bash
# List certificates
dh_certificates_list [page] [per_page] [status]

# Get certificate by domain
dh_certificates_get <domain> [include_sensitive_data]

# Create a manual certificate
dh_certificates_create <name> <cert_file> <key_file> [options]
# Options: --domains DOMAINS_JSON --auto-renew BOOL --force BOOL

# Request an ACME certificate
dh_certificates_create_acme <name> <domains_json> <email> [options]
# Options: --acme-provider PROVIDER --auto-renew BOOL --force BOOL

# Get ACME certificate status
dh_certificates_get_acme_status <certificate_id>

# Download certificate as ZIP
dh_certificates_download <certificate_id> <output_file>

# Delete a certificate
dh_certificates_delete <domain>
```

**Example:**
```bash
# Request a wildcard ACME certificate
domains='["example.com", "*.example.com"]'
status=$(dh_certificates_create_acme \
    "example.com Wildcard" \
    "${domains}" \
    "admin@example.com" \
    --acme-provider "letsencrypt")

cert_id=$(echo "${status}" | jq -r '.data.certificateId')
echo "Certificate ID: ${cert_id}"

# Check status later
status=$(dh_certificates_get_acme_status "${cert_id}")
echo "${status}" | jq '.data.status'
```

### Upstream Servers

```bash
# List servers in a zone
dh_upstream_servers_list <zone_id>

# Add a server
dh_upstream_servers_create <zone_id> <name> <address> <port> <health_check_path> [options]
# Options: --protocol PROTOCOL --weight WEIGHT --backup BOOL
#          --region REGION --country COUNTRY

# Update a server
dh_upstream_servers_update <zone_id> <server_id> <data_json>

# Remove a server
dh_upstream_servers_delete <zone_id> <server_id>
```

**Example:**
```bash
# Add a backend server
server=$(dh_upstream_servers_create \
    "zone_abc123" \
    "backend-3" \
    "10.0.1.102" \
    8080 \
    "/health" \
    --protocol "http" \
    --weight 2 \
    --backup false)

server_id=$(echo "${server}" | jq -r '.data.id')
echo "Added server: ${server_id}"
```

### Health Checks

```bash
# List health check profiles
dh_health_checks_list_profiles [page] [limit] [search]

# Get a specific profile
dh_health_checks_get_profile <profile_id>

# Create a profile
dh_health_checks_create_profile <name> [options]
# Options: --description DESC --protocol PROTO --port PORT --path PATH
#          --method METHOD --expected-status-codes CODES
#          --check-interval SECS --timeout SECS --retries NUM
#          --follow-redirects BOOL --verify-ssl BOOL

# Update a profile
dh_health_checks_update_profile <profile_id> <data_json>

# Delete a profile
dh_health_checks_delete_profile <profile_id>

# Disable health checks for a server
dh_health_checks_disable_server <server_id> [reason]

# Re-enable health checks
dh_health_checks_enable_server <server_id>

# List CDN nodes
dh_health_checks_list_cdn_nodes
```

**Example:**
```bash
# Create an API health check profile
profile=$(dh_health_checks_create_profile "API Health Check" \
    --protocol "https" \
    --port 443 \
    --path "/api/health" \
    --method "GET" \
    --expected-status-codes "200" \
    --check-interval 30 \
    --timeout 10 \
    --verify-ssl true)

echo "${profile}" | jq '.profile'

# Disable checks during maintenance
dh_health_checks_disable_server "srv_abc123" "Scheduled maintenance"

# Re-enable after maintenance
dh_health_checks_enable_server "srv_abc123"
```

### WAF (Web Application Firewall)

```bash
# Get WAF configuration
dh_waf_get_config <zone_id>

# Update WAF configuration
dh_waf_update_config <zone_id> [options]
# Options: --enabled BOOL --mode MODE --sqli-detection BOOL --xss-detection BOOL

# List WAF rules
dh_waf_list_rules <zone_id> [page] [per_page]

# Create a WAF rule
dh_waf_create_rule <zone_id> <name> <rule_type> <match_target> <match_pattern> <action> [options]
# Options: --description DESC --severity SEV --enabled BOOL --priority NUM

# Update a rule
dh_waf_update_rule <zone_id> <rule_id> <data_json>

# Delete a rule
dh_waf_delete_rule <zone_id> <rule_id>

# Block an IP address
dh_waf_block_ip <zone_id> <ip_address> [reason] [expires_at]

# Allow an IP (whitelist)
dh_waf_allow_ip <zone_id> <ip_address> [reason]

# List IP entries
dh_waf_list_ips <zone_id> [list_type] [page] [per_page]

# Delete an IP entry
dh_waf_delete_ip <zone_id> <ip_id>

# Country blocking
dh_waf_list_countries <zone_id>
dh_waf_add_country <zone_id> <country_code> <action> [reason] [enabled]
dh_waf_delete_country <zone_id> <country_id>

# ASN blocking
dh_waf_list_asns <zone_id>
dh_waf_add_asn <zone_id> <asn> <action> [asn_name] [reason] [enabled]
dh_waf_delete_asn <zone_id> <asn_id>
```

**Example:**
```bash
# Enable WAF with blocking mode
dh_waf_update_config "zone_abc123" \
    --enabled true \
    --mode "blocking" \
    --sqli-detection true \
    --xss-detection true

# Create a rule to block admin access
dh_waf_create_rule "zone_abc123" \
    "Block Admin Access" \
    "pattern" \
    "uri" \
    "^/admin" \
    "block" \
    --severity "high" \
    --priority 100

# Block a malicious IP
dh_waf_block_ip "zone_abc123" "198.51.100.50" "Malicious activity"

# Whitelist office network
dh_waf_allow_ip "zone_abc123" "203.0.113.0/24" "Office network"

# Block a high-risk country
dh_waf_add_country "zone_abc123" "XX" "block" "High risk region"

# Block a known bad ASN
dh_waf_add_asn "zone_abc123" 12345 "block" "Bad Hosting Provider" "Known abuse source"
```

### Analytics

```bash
# Get usage metrics
dh_analytics_get_usage [start_date] [end_date]

# Get CDN node status
dh_analytics_get_cdn_nodes
```

**Example:**
```bash
# Get current month usage
usage=$(dh_analytics_get_usage)
total_gb=$(echo "${usage}" | jq '.total_traffic.gigabytes')
echo "Total bandwidth: ${total_gb} GB"

# Per-zone breakdown
echo "${usage}" | jq -r '.zones[] | "\(.zone): \(.gigabytes_sent) GB, \(.requests) requests"'

# Get specific date range
usage=$(dh_analytics_get_usage "2024-01-01" "2024-01-31")
echo "${usage}" | jq '.total_traffic'

# List CDN nodes
nodes=$(dh_analytics_get_cdn_nodes)
echo "${nodes}" | jq -r '.[] | "\(.domain) (\(.ip_address))"'
```

## Error Handling

The SDK provides helpful error messages with colored output:

```bash
# Check exit status
if ! result=$(dh_domains_create "example.com"); then
    echo "Failed to create domain"
    exit 1
fi

# Parse error response
error_message=$(echo "${result}" | jq -r '.message // "Unknown error"')
```

### Error Types

| HTTP Code | Error Type | Description |
|-----------|------------|-------------|
| 401 | Authentication | Invalid API key |
| 403 | Authorization | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 422 | Validation | Invalid input data |
| 429 | Rate Limit | Too many requests |
| 5xx | Server Error | Internal server error |

## Debug Mode

Enable debug mode to see request/response details:

```bash
# Via environment variable
DATAHORDERS_DEBUG=1 ./datahorders-cdn.sh domains list

# Via CLI flag
./datahorders-cdn.sh --debug domains list

# Programmatically
dh_enable_debug
dh_domains_list
dh_disable_debug
```

## JSON Helpers

The SDK includes helper functions for building JSON:

```bash
# Build a JSON object
data=$(dh_json_object \
    "name" "my-zone" \
    "enabled" "true" \
    "port" "8080")
# Result: {"name":"my-zone","enabled":true,"port":8080}

# Build a JSON array
arr=$(dh_json_array "item1" "item2" "item3")
# Result: ["item1","item2","item3"]

# Extract value from JSON
value=$(dh_json_get "${json}" '.data.id')
```

## Output Control

```bash
# Disable colors (for piping/logging)
DH_NO_COLOR=1 ./datahorders-cdn.sh domains list

# Colors are automatically disabled when output is not a terminal
./datahorders-cdn.sh domains list | jq '.'
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- [Documentation](https://wiki.datahorders.org/docs/api/overview)
- [Issues](https://github.com/datahorders/cdn-bash-sdk/issues)
- [Repository](https://github.com/datahorders/cdn-bash-sdk)
