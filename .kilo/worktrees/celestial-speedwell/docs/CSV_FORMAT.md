# CSV Input Format - BBPTS v1.0

BBPTS supports enhanced CSV input for organizing, prioritizing, and tagging reconnaissance targets with rich metadata.

## Table of Contents

- [Basic Format](#basic-format)
- [Enhanced Format](#enhanced-format)
- [Column Reference](#column-reference)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Validation](#validation)

## Basic Format

The simplest CSV requires only the `url` column:

```csv
url
example.com
api.example.com
admin.example.com
```

## Enhanced Format

For maximum control, use all available columns:

```csv
url,scope,priority,tags,notes
example.com,in,high,api;critical,Main API target
api.example.com,in,critical,api;internal,Critical internal API
admin.example.com,in,high,admin,Administrative panel
staging.example.com,out,low,staging;test,Staging environment - out of scope
dev.example.com,out,medium,dev;internal,Development server
cdn.example.com,in,medium,cdn;infrastructure,CDN endpoint
```

## Column Reference

### url (Required)
- **Type:** String
- **Description:** Target domain, IP, or full URL
- **Examples:**
  - `example.com`
  - `192.168.1.1`
  - `https://api.example.com:443`
  - `subdomain.example.com`

### scope (Optional, default: "in")
- **Type:** Enum - `in`, `out`, `private`
- **Description:** Scope classification for testing
- **Values:**
  - `in` - Target is in scope for security testing
  - `out` - Target is out of scope (automatically excluded)
  - `private` - Private/internal system (affects tool selection)

### priority (Optional, default: "medium")
- **Type:** Enum - `critical`, `high`, `medium`, `low`
- **Description:** Scanning priority and resource allocation
- **Values:**
  - `critical` - Immediate testing with all tools
  - `high` - Full testing with all applicable tools
  - `medium` - Standard testing coverage
  - `low` - Basic testing only

### tags (Optional)
- **Type:** Semicolon-separated strings
- **Description:** Custom tags for organization and filtering
- **Examples:**
  - `api;rest;graphql`
  - `admin;login;auth`
  - `cdn;infrastructure;external`
  - `mobile;ios;android`

### notes (Optional)
- **Type:** String
- **Description:** Additional context and notes
- **Examples:**
  - `Main customer-facing API`
  - `Admin panel discovered via JS source`
  - `Out of scope per program rules`
  - `Requires special authentication`

## Examples

### Bug Bounty Program

```csv
url,scope,priority,tags,notes
api.example.com,in,critical,api;graphql;auth,Main GraphQL API endpoint
admin.example.com,in,high,admin;login,discovered via directory brute force
staging.example.com,out,low,staging;test,Staging environment - out of scope
dev.example.com,out,medium,dev;internal,Development server
cdn.example.com,in,medium,cdn;external,Cloudflare CDN endpoint
mobile.example.com,in,high,mobile;api,Mobile app API
```

### Infrastructure Assessment

```csv
url,scope,priority,tags,notes
web.example.com,in,high,web;nginx,Main web server
api.example.com,in,critical,api;microservice,User management service
db.example.com,private,high,database;internal,Internal database server
vpn.example.com,in,medium,vpn;remote,Remote access VPN
mail.example.com,in,low,email;smtp,Email server
```

### Red Team Engagement

```csv
url,scope,priority,tags,notes
portal.example.com,in,critical,portal;external,Customer portal
internal.example.com,private,high,internal;intranet,Internal company portal
dev.example.com,out,low,dev;staging,Development environment
api.example.com,in,high,api;rest,REST API for mobile apps
admin.example.com,in,medium,admin;management,Administrative interface
```

## Best Practices

### Organization
- Use consistent tag naming conventions
- Group related targets together
- Include discovery source in notes
- Document scope boundaries clearly

### Prioritization
- Reserve `critical` for high-impact targets
- Use `high` for primary attack surfaces
- Apply `medium` to most targets
- Use `low` for supplementary systems

### Scope Management
- Clearly mark out-of-scope targets
- Use `private` for internal systems
- Document scope decisions in notes
- Regularly review scope classifications

### Tagging Strategy
- Use hierarchical tags: `api;rest;auth`
- Include technology indicators: `nginx;php;mysql`
- Mark discovery methods: `bruteforce;js;dns`
- Indicate target types: `web;mobile;api`

## Validation

BBPTS validates CSV input and provides helpful error messages:

### Valid Headers
- `url` (required)
- `scope`, `priority`, `tags`, `notes` (optional)

### Data Validation
- URLs must be valid domains, IPs, or full URLs
- Scope values must be `in`, `out`, or `private`
- Priority values must be `critical`, `high`, `medium`, or `low`
- Tags are automatically trimmed and deduplicated

### Error Handling
- Invalid headers are reported with suggestions
- Malformed rows are skipped with warnings
- Empty required fields cause validation errors
- Encoding issues are detected and reported

## Integration with BBPTS

### Command Line Usage

```bash
# Basic CSV input
./bbpts -i targets.csv

# With scope filtering
./bbpts -i targets.csv -scope my-program

# Generate reports
./bbpts -i targets.csv -output report.md -summary summary.csv
```

### Scope Filtering

BBPTS automatically filters targets based on scope:

- `in` scope targets are included in scanning
- `out` scope targets are excluded
- `private` scope targets may use different methodologies

### Priority Handling

Priority affects tool selection and resource allocation:

- `critical`: All available tools, maximum concurrency
- `high`: Full tool suite, high concurrency
- `medium`: Standard tool selection
- `low`: Minimal tool set, low concurrency

### Tag-Based Analysis

Tags enhance analysis and reporting:

- Technology tags improve fingerprinting
- Function tags guide test selection
- Discovery tags track investigation sources
- Custom tags enable filtering and organization

This CSV format provides powerful organization and control over reconnaissance campaigns, enabling efficient and targeted security testing.
  - `medium` - Standard comprehensive testing
  - `low` - Basic testing only

### tags (Optional)
- **Type:** String (semicolon-separated)
- **Description:** Custom tags for organizing and filtering targets
- **Common Tags:**
  - `api` - REST/GraphQL API
  - `web` - Web application
  - `mobile` - Mobile app
  - `admin` - Admin panel
  - `auth` - Authentication system
  - `payment` - Payment processing
  - `database` - Database interface
  - `staging` - Staging environment
  - `dev` - Development environment
  - `sensitive` - Contains sensitive data
  - `internal` - Internal system
  - `critical` - Critical asset

### notes (Optional)
- **Type:** String
- **Description:** Additional context and notes about the target
- **Use Cases:**
  - Special testing requirements
  - Known vulnerabilities
  - Previous findings
  - Authentication requirements
  - Contact information

## Real-World Examples

### E-Commerce Platform

```csv
url,scope,priority,tags,notes
shop.example.com,in,critical,web;payment;auth,Main shopping platform - PCI scope
api.shop.example.com,in,critical,api;payment;internal,Payment API endpoint
admin.shop.example.com,in,high,admin;auth;sensitive,Admin dashboard
cdn.shop.example.com,in,medium,cdn;infrastructure,CDN for static assets
staging.shop.example.com,out,low,staging;dev,Staging - out of scope
backup.shop.example.com,out,medium,backup;infrastructure,Backup system - out of scope
```

### SaaS Application

```csv
url,scope,priority,tags,notes
app.example.com,in,critical,web;auth;internal,Main web app - user accounts
api.example.com,in,critical,api;auth;internal,REST API - authentication required
webhooks.example.com,in,high,api;infrastructure,Webhook endpoint
admin.example.com,in,high,admin;auth;sensitive,Admin interface - limited access
docs.example.com,in,medium,web;documentation,API documentation site
status.example.com,in,low,web;infrastructure,Status page - public info
beta.example.com,out,low,dev;staging,Beta environment - out of scope
```

### Financial Services

```csv
url,scope,priority,tags,notes
bank.example.com,in,critical,web;payment;auth;sensitive,Main web portal - PCI-DSS
api.bank.example.com,in,critical,api;payment;auth;sensitive,Banking API - tokenization required
mobile-api.example.com,in,critical,api;mobile;auth;sensitive,Mobile app API
admin.example.com,in,critical,admin;auth;sensitive;restricted,Restricted access - requires approval
backoffice.example.com,in,high,web;auth;internal;sensitive,Back office portal
compliance-reporting.example.com,in,high,web;sensitive,Compliance reporting system
```

## Usage Examples

### Using with BBPTS

```bash
# Scan all targets
./bbpts -input targets.csv

# Scan only critical priority targets
./bbpts -input targets.csv -input-filter "priority=critical"

# Scan only in-scope targets
./bbpts -input targets.csv -input-filter "scope=in"

# Scan specific tags
./bbpts -input targets.csv -input-filter "tags=api"

# Generate separate reports per priority
./bbpts -input targets.csv -report-by-priority
```

### Filtering and Reporting

```bash
# Critical targets only
./bbpts -input targets.csv \
  -input-filter "scope=in,priority=critical" \
  -report priority-critical.md

# API endpoints
./bbpts -input targets.csv \
  -input-filter "tags:api" \
  -output api-results/

# Staging excluded
./bbpts -input targets.csv \
  -input-filter "scope=in,!tags:staging" \
  -report in-scope.md
```

## Best Practices

### Organization
1. **Use descriptive names** - Include what service/component it is
2. **Group related targets** - Keep related services together
3. **Clear prioritization** - Be explicit about priority levels
4. **Consistent tagging** - Use standardized tag names
5. **Detailed notes** - Document why targets are scoped in/out

### Security
1. **Mark sensitive targets** - Use `sensitive` tag
2. **Restrict access targets** - Use `restricted` in notes
3. **Note authentication** - Document in notes if auth required
4. **Identify compliance scope** - Note PCI-DSS, HIPAA, etc.
5. **Track dependencies** - Note related systems

### Testing Strategy
1. **Start with high priority** - Focus effort on critical targets
2. **In-scope first** - Only test what's authorized
3. **Related targets together** - Test connected systems
4. **Document exclusions** - Explain why targets are out of scope
5. **Plan remediation** - Use notes for findings

## Advanced Features

### Conditional Scanning

```bash
# Scan with different tool sets by priority
./bbpts -input targets.csv \
  -tools-critical "subfinder,httpx,nuclei,ffuf" \
  -tools-high "subfinder,httpx,nuclei" \
  -tools-medium "httpx,nuclei" \
  -tools-low "httpx"
```

### Custom Wordlists by Tag

```bash
# Use specialized wordlists for API testing
./bbpts -input targets.csv \
  -wordlist-api custom_api_wordlist.txt \
  -wordlist-default common.txt
```

### Report Segmentation

```bash
# Generate separate reports per tag
./bbpts -input targets.csv \
  -report-by-tag \
  -output results/
```

This creates:
- `results/report-api.md`
- `results/report-web.md`
- `results/report-admin.md`
- etc.

## Migration Guide

### From Simple List

**Before:**
```
example.com
api.example.com
admin.example.com
```

**After:**
```csv
url,scope,priority,tags,notes
example.com,in,medium,web,Main website
api.example.com,in,high,api,REST API endpoint
admin.example.com,in,high,admin,Admin panel
```

### From Spreadsheet

If you have targets in Excel/Sheets:

1. Export as CSV
2. Ensure column names match: `url`, `scope`, `priority`, `tags`, `notes`
3. Fill in metadata
4. Use with BBPTS

---

**Note:** Comments in CSV files should start with `#` and will be automatically ignored.

Example with comments:
```csv
# Production Targets
url,scope,priority,tags,notes
example.com,in,critical,web,Main app

# Staging (Out of Scope)
staging.example.com,out,low,staging,Staging env - out of scope
```
