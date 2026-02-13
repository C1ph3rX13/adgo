# ADGO

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8E?logo=go)](https://go.dev/)

Active Directory reconnaissance and triage tool for Red Team operations.

A powerful Go-based CLI tool that performs LDAP queries against Active Directory environments for security assessments and penetration testing. Features 29 predefined queries across 6 categories, custom LDAP support, multiple output formats (including BloodHound), and advanced connection handling with automatic TLS fallback.

## Features

- **29 Predefined Queries** - Organized across 6 categories for common AD reconnaissance tasks
- **Custom LDAP Queries** - Flexible filter and attribute specification for targeted searches
- **4 Output Formats** - Text (card-based), JSON, CSV, and BloodHound v4
- **5 Security Modes** - LDAP connection security with automatic TLS version negotiation (1.3->1.0)
- **Streaming Architecture** - Memory-efficient pagination for large AD environments
- **Intelligent Scoring** - High-value targets (admins, DCs, SPNs) displayed first
- **Flexible Configuration** - File-based (YAML) with flag and environment variable override
- **Red Team Optimized** - Debug logging with no data sanitization for complete visibility

## Quick Start

### Prerequisites

- Go 1.24+ (for building from source)
- Access to an Active Directory environment
- Valid AD credentials

### Installation

#### Build from Source

```bash
# Clone the repository
git clone https://github.com/C1ph3rX13/adgo.git
cd adgo

# Build for your platform
go build -o adgo .

# Or cross-compile
GOOS=windows GOARCH=amd64 go build -o adgo.exe .
GOOS=linux GOARCH=amd64 go build -o adgo .
```

### First Run

```bash
# 1. Set up configuration (interactive wizard)
./adgo config init

# 2. List all available queries
./adgo quick --help

# 3. Run your first query
./adgo quick users

# 4. Check for Kerberoasting targets
./adgo quick kerberoasting

# 5. Export to BloodHound for analysis
./adgo quick users --output bloodhound --output-file bh_users.json
```

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Query Reference](#query-reference)
- [Usage](#usage)
- [Configuration](#configuration)
- [Security Modes](#security-modes)
- [Output Formats](#output-formats)
- [Logging](#logging)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)
- [Global Flags](#global-flags)
- [Development](#development)

## Architecture

### Package Structure

```
adgo/
├── cmd/              # Cobra CLI commands
│   ├── root.go      # Global flags and initialization
│   ├── quick.go      # 29 predefined query commands
│   ├── query.go      # Custom LDAP query support
│   ├── config.go     # Configuration management
│   └── runner.go     # Common execution logic
├── queries/          # Query registry (29 queries)
│   ├── basic.go      # 13 basic AD queries
│   ├── privileges.go  # Admin and permission queries
│   ├── kerberos.go   # Kerberos attack vectors
│   ├── delegation.go  # Delegation types
│   └── certificates.go # AD CS queries
├── connect/          # LDAP client
│   └── client.go    # 5 security modes, streaming, retry
├── output/           # Result formatters
│   ├── text.go       # Card-based color output
│   ├── json.go       # Raw LDAP entries
│   ├── csv.go        # Flattened spreadsheet format
│   └── bloodhound.go # BH v4 JSON export
├── analyze/          # AD constants and analysis
│   ├── attributes.go  # Standard AD names
│   ├── uac.go        # UAC flag definitions
│   └── defaults.go   # Default values
└── log/              # Zap logging wrapper
    └── log.go        # Debug default, no sanitization
```

## Query Reference

### Basic Queries

| Command | Description | Use Case |
|----------|-------------|-----------|
| `users` | All user accounts | User enumeration |
| `computers` | All computer accounts | Host discovery |
| `dc` | All domain controllers | DC identification |
| `ou` | All organizational units | OU mapping |
| `spn` | All service principal names | Kerberoasting targets |
| `gpo` | All group policy objects | GPO enumeration |
| `gpomachine` | GPOs with machine settings | GPO analysis |
| `gpouser` | GPOs with user settings | GPO analysis |
| `trustDomain` | Trusted domains | Trust mapping |
| `trustattributes` | Trusted domain attributes | Trust analysis |
| `machineAccountQuota` | Machine account quota for domain | Shadow credentials prep |

### Admin Queries

| Command | Description | Use Case |
|----------|-------------|-----------|
| `admin` | All admin accounts and groups | Admin enumeration |
| `domainadmins` | Domain admin group members | DA identification |
| `enterprise` | Enterprise related information | Forest-level admin discovery |
| `enterpriseadmins` | Enterprise admin group members | EA identification |
| `schemaadmins` | Schema admin group members | Schema admin discovery |
| `adminSDHolder` | Accounts with AdminSDHolder protection | Protected objects |
| `adminholders` | Admin account holders | Admin group membership |
| `sensitivegroups` | Sensitive AD groups | High-value group targeting |
| `disabled` | Disabled user accounts | Inactive account discovery |

### Kerberos Attacks

| Command | Description | Use Case |
|----------|-------------|-----------|
| `kerberoasting` | Accounts vulnerable to Kerberoasting | SPN targeting |
| `asreproast` | Accounts vulnerable to AS-REP roasting | Pre-auth targeting |

### Delegation

| Command | Description | Use Case |
|----------|-------------|-----------|
| `delegate` | Accounts with delegation rights | Delegation enumeration |
| `unconstraineddelegate` | Accounts with unconstrained delegation | Ticket theft |
| `constraineddelegate` | Accounts with constrained delegation | Constrained delegation abuse |
| `resourceconstraineddelegate` | Accounts with resource constrained delegation | RBCD exploitation |

### AD Certificate Services

| Command | Description | Use Case |
|----------|-------------|-----------|
| `cacomputer` | Certificate authorities | CA enumeration |
| `esc1` | ESC1 vulnerable certificate templates | ESC1 exploitation |
| `esc2` | ESC2 vulnerable certificate templates | ESC2 exploitation |

### Permissions

| Command | Description | Use Case |
|----------|-------------|-----------|
| `permissions` | Account permissions | Permission analysis |
| `highpriv` | High privilege accounts | Privilege escalation |
| `group` | Admin groups | Group membership analysis |
| `groupnested` | Nested groups | Group hierarchy mapping |
| `managedby` | Objects with managedBy attribute | Manager identification |
| `acl` | Objects with ACLs | ACL analysis |
| `sidhistory` | Accounts with SID history | SID tracking |

## Usage

### Quick Commands

#### Syntax

```bash
adgo quick <command> [flags]
```

#### Command Name Rules

Commands are auto-generated from query names:
- **Acronyms** (2-3 chars): `dc`, `gpo`, `spn` → UPPERCASE
- **Special cases**: `asreproast` → ASRepRoast, `cacomputer` → CaComputer
- **Underscore**: `machineAccountQuota` → MachineAccountQuota
- **camelCase**: `kerberoasting` → Kerberoasting

#### Examples

```bash
# Basic enumeration
./adgo quick users --server 192.168.1.10 --baseDN DC=example,DC=com
./adgo quick computers -s 192.168.1.10 -b DC=example,DC=com

# Admin discovery
./adgo quick domainadmins -s dc01.example.com -u admin@example.com -w P@ssw0rd
./adgo quick sensitivegroups -s dc01.example.com

# Attack scenarios
./adgo quick kerberoasting -s dc01.example.com
./adgo quick asreproast -s dc01.example.com
./adgo quick unconstraineddelegate -s dc01.example.com

# AD CS
./adgo quick esc1 -s dc01.example.com
./adgo quick cacomputer -s dc01.example.com
```

### Custom Queries

```bash
# Custom filter with specific attributes
./adgo query --filter "(objectClass=user)" --attrs "sAMAccountName,displayName" -s dc01

# Complex filters
./adgo query --filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -s dc01

# Output to file
./adgo query --filter "(objectClass=user)" -s dc01 --output json > users.json
```

## Configuration

### Config File Locations

ADGO searches for `adgo.yaml` in this order (first found wins):
1. `./adgo.yaml` (current directory)
2. `~/.adgo` (user home directory)
3. `/etc/adgo` (system-wide)

### Configuration Priority

Settings are merged in this order (later overrides earlier):
1. Default values
2. Config file values
3. Environment variables (`ADGO_LDAP_SERVER`, etc.)
4. Command line flags (highest priority)

### Example Config File

```yaml
# LDAP Connection Settings
ldap:
  server: "192.168.1.10"        # Domain Controller (required)
  port: 389                       # LDAP port (389/LDAP, 636/LDAPS)
  baseDN: "DC=example,DC=com"     # Base Distinguished Name (required)
  username: "admin@example.com"      # Bind username (required)
  password: "YourSecurePassword"     # Bind password (required)
  loginName: "userPrincipalName"    # Format: userPrincipalName or sAMAccountName
  security: 0                      # Security mode (0-4, see Security Modes section)
  timeout: 30                      # Connection timeout in seconds
  sizeLimit: 0                     # Max entries (0 = unlimited)

# Output Settings
output: "text"                    # Format: text, json, csv, bloodhound
```

### Config Management Commands

```bash
# Interactive setup (creates adgo.yaml)
./adgo config init

# Set specific config values
./adgo config set ldap.server 192.168.1.10
./adgo config set ldap.baseDN DC=example,DC=com
./adgo config set ldap.username admin@example.com

# Display current config
./adgo config show
```

## Security Modes

ADGO supports 5 LDAP connection security modes:

| Mode | Value | Description | Port | Use Case |
|-------|--------|-------------|--------|-----------|
| **None** | 0 | Plain LDAP (no encryption) | 389 | Testing, trusted networks |
| **TLS** | 1 | LDAPS with certificate verification | 636 | Production (recommended) |
| **StartTLS** | 2 | StartTLS with certificate verification | 389 | Production, LDAPS blocked |
| **InsecureTLS** | 3 | LDAPS without certificate verification | 636 | Self-signed certs |
| **InsecureStartTLS** | 4 | StartTLS without certificate verification | 389 | StartTLS, self-signed |

### TLS Version Negotiation

ADGO automatically negotiates TLS version for legacy DC compatibility:
1. **TLS 1.3** (modern DCs: Windows Server 2019+)
2. **TLS 1.2** (most common: Windows Server 2012 R2+)
3. **TLS 1.1** (legacy: Windows Server 2008 R2)
4. **TLS 1.0** (very old: Windows Server 2003)

A warning is displayed when falling back to TLS 1.0/1.1.

### Usage Examples

```bash
# Plain LDAP (testing only)
./adgo quick users --security 0 -s 192.168.1.10

# LDAPS with cert verification (recommended)
./adgo quick users --security 1 -s dc01.example.com -p 636

# LDAPS without cert verification (self-signed)
./adgo quick users --security 3 -s dc01.example.com -p 636

# StartTLS (port 389, upgrades to TLS)
./adgo quick users --security 2 -s dc01.example.com -p 389
```

## Output Formats

### Text Format (Default)

Card-based human-readable output with color-coded headers:
- **Color coding**: Object type headers (USER, DC, COMPUTER, GROUP, etc.)
- **Statistics**: Total entries, admin counts, enabled/disabled breakdown
- **Value sorting**: High-value targets displayed first

```
  ADGO REPORT  |  Search Results
--------------------------------------------------------------------------------
[USER] CN=Administrator,CN=Users,DC=example,DC=com
--------------------------------------------------------------------------------
  [*] sAMAccountName       : Administrator
  [*] userAccountControl   : 66048, Enabled
  [*] adminCount           : 1

--------------------------------------------------------------------------------
[DC] CN=DC01,OU=Domain Controllers,DC=example,DC=com
--------------------------------------------------------------------------------
  [*] sAMAccountName       : DC01$
  [*] userAccountControl   : 532480, Domain Controller
  [*] operatingSystem      : Windows Server 2019

Total Entries: 42
Admins: 8 | Enabled: 35 | Disabled: 7
```

### JSON Format

Raw LDAP entries with minimal processing:
```json
{
  "entries": [
    {
      "dn": "CN=Administrator,CN=Users,DC=example,DC=com",
      "attributes": {
        "sAMAccountName": ["Administrator"],
        "userAccountControl": ["66048"]
      }
    }
  ],
  "statistics": {
    "total": 42,
    "admins": 8
  }
}
```

### CSV Format

Flattened attributes for spreadsheet analysis:
```csv
dn,sAMAccountName,userAccountControl,adminCount
"CN=Administrator,...","Administrator","66048","1"
"CN=DC01,...","DC01$","532480",""
```

### BloodHound Format

BloodHound v4 compatible JSON for attack graph analysis:

**Object Types**: Users, Computers, Groups, Sessions, Aces

```bash
# Export users, computers, and groups
./adgo quick users --output bloodhound --output-file bh_users.json
./adgo quick computers --output bloodhound --output-file bh_computers.json
./adgo quick group --output bloodhound --output-file bh_groups.json

# Import into BloodHound GUI
# File → Import → Select all JSON files
```

## Logging

### Default Behavior

- **Log Level**: `debug` by default (shows all levels: debug, info, warn, error, fatal, panic)
- **No Sanitization**: All data logged in plaintext

### Security Warning

> ⚠️ **Warning**: ADGO displays all information in logs without sanitization. This includes:
> - Passwords in plaintext
> - Authentication tokens
> - NTLM hashes
> - Kerberos tickets
> - Security Identifiers (SIDs)
>
> Be cautious when sharing logs or screenshots, as they may contain sensitive credentials.

## Advanced Features

### Query Streaming

ADGO uses streaming with pagination for memory efficiency:
- Page size: 1000 entries per request
- Real-time output: Results displayed as they arrive
- Memory efficient: Suitable for AD environments with 100k+ objects

### Target Value Scoring

Results are automatically sorted by target value:

| Score | Criteria |
|--------|-----------|
| +50 | Domain Controllers |
| +40 | Enterprise/Domain/Schema Admins |
| +20 | Accounts with SPNs (Kerberoasting targets) |
| +15 | AS-REP roastable accounts |
| +10 | Recent logon timestamp |
| +5 | Group membership (10+ members) |

High-value targets are displayed first in text output.

### Retry Logic

Automatic connection retry with exponential backoff:
- **Attempt 1**: Immediate connection
- **Attempt 2**: 2 second delay
- **Attempt 3**: 4 second delay
- **Max retries**: 3 attempts

Useful for handling temporary network issues or DC load balancing.

### Username Auto-Formatting

Based on `loginName` config:

| Format | Input | Result |
|---------|--------|---------|
| `userPrincipalName` | `admin` | `admin@domain.com` |
| `sAMAccountName` | `admin` | `admin` (no change) |

The domain is automatically extracted from `baseDN` (e.g., `DC=example,DC=com` → `example.com`).

## Troubleshooting

### Connection Issues

**Problem**: "TLS handshake failure"
- **Solution**: Try `--security 3` (InsecureTLS) for self-signed certificates
- **Solution**: Try `--security 4` (InsecureStartTLS)

**Problem**: "Connection timeout"
- **Solution**: Increase timeout via config: `ldap.timeout: 60`
- **Solution**: Check firewall rules (ports 389/636)

**Problem**: "Failed to connect to LDAP server"
- **Solution**: Verify server is reachable: `ping dc01.example.com`
- **Solution**: Try security mode 0 (plain LDAP) for testing

### Authentication Issues

**Problem**: "Invalid credentials"
- **Solution**: Check `loginName` format (userPrincipalName vs sAMAccountName)
- **Solution**: Use UPN format: `username@domain.com`
- **Solution**: Verify password doesn't contain special characters needing quotes

**Problem**: "Bind DN not found"
- **Solution**: Ensure `baseDN` matches your domain structure
- **Solution**: Query the base DN first: `adgo query --filter "(objectClass=*)"`

### Query Errors

**Problem**: "Invalid filter syntax"
- **Solution**: Escape filters properly: `--filter "(objectClass=user)"`
- **Solution**: Use quotes for complex filters

**Problem**: "Size limit exceeded"
- **Solution**: Set `sizeLimit: 0` in config for unlimited results
- **Solution**: Use more specific filters to reduce result count

## Global Flags

| Flag | Short | Type | Default | Description |
|-------|--------|--------|----------|--------------|
| `--server` | `-s` | string | *required* | Domain Controller host/IP |
| `--port` | `-p` | int | 389 | LDAP port (389/LDAP, 636/LDAPS) |
| `--baseDN` | `-b` | string | *required* | Base DN (e.g., DC=example,DC=com) |
| `--username` | `-u` | string | *required* | Bind username |
| `--password` | `-w` | string | *required* | Bind password |
| `--login-name` | | string | userPrincipalName | Login format (userPrincipalName or sAMAccountName) |
| `--security` | | int | 0 | Security mode (0-4) |
| `--output` | `-o` | string | text | Output format (text, json, csv, bloodhound) |
| `--timeout` | | int | 30 | Connection timeout (seconds) |
| `--size-limit` | | int | 0 | Max entries to return (0 = unlimited) |

### Examples

```bash
# All flags specified
./adgo quick users -s 192.168.1.10 -p 389 -b DC=example,DC=com \
  -u admin@example.com -w Password123 --security 1 -o json

# Config-based (minimal flags)
./adgo config set ldap.server 192.168.1.10
./adgo config set ldap.baseDN DC=example,DC=com
./adgo quick users  # Uses config values
```

## Development

### Project Structure Recap

```
cmd/        → Cobra CLI (commands, flags, config)
queries/     → 29 predefined queries + registry
connect/     → LDAP client (5 security modes, streaming)
output/      → 4 formatters (text, json, csv, bloodhound)
analyze/      → AD constants (UAC, attributes, OIDs)
log/          → Zap logging (debug default, no sanitization)
```

### Adding New Queries

1. **Define the query** in `queries/<category>.go`:
```go
var myQueries = map[string]queries.Query{
    "MyNewQuery": {
        Filter:    "(objectClass=user)(someAttribute=value)",
        Attributes: []string{"sAMAccountName", "displayName"},
    },
}
```

2. **Register in `queries/queries.go` init()**:
```go
for name, q := range myQueries {
    queries.Register(name, q)
}
```

3. **Add metadata to `cmd/quick.go`**:
```go
{Name: "mynewquery", Description: "My new query", Category: CategoryBasic}
```

4. **Build and test**:
```bash
go build -o adgo .
./adgo quick mynewquery --help
```

## License

MIT License - see [LICENSE](LICENSE) file for details.
