# ADGO

Active Directory reconnaissance and triage tool for red team operators.

## Features

- **Quick Queries**: Predefined queries for common AD information gathering tasks
- **Custom Queries**: Run custom LDAP queries with flexible filter and attribute options
- **Multiple Output Formats**: Text, JSON, and CSV output options
- **Categorized Commands**: Organized by function for easy navigation
- **Configurable**: Supports configuration file for persistent settings

## Installation

### Prerequisites
- Go 1.24+
- Access to an Active Directory environment

### Build from Source

```bash
git clone https://github.com/C1ph3rX13/adgo.git
cd adgo
go build -o adgo .
```

## Usage

### Quick Start

```bash
# List all quick commands
./adgo quick --help

# Run a quick query
./adgo quick users --server 192.168.1.100 --username Administrator --password P@ssw0rd --baseDN DC=example,DC=com

# Run a custom query
./adgo query --filter "(objectClass=user)" --attrs "sAMAccountName,userPrincipalName"
```

### Command Categories

#### Basic Queries
- `Users` - All user accounts
- `Computers` - All computer accounts
- `DC` - All domain controllers
- `OU` - All organizational units
- `SPN` - All service principal names
- `GPO` - All group policy objects
- `MachineAccountQuota` - Machine account quota for the domain

#### Admin Queries
- `DomainAdmins` - Domain admin group members
- `EnterpriseAdmins` - Enterprise admin group members
- `SchemaAdmins` - Schema admin group members
- `SensitiveGroups` - Sensitive AD groups
- `Disabled` - Disabled user accounts

#### Kerberos Attacks
- `ASRepRoast` - Accounts vulnerable to AS-REP roasting
- `Kerberoasting` - Accounts vulnerable to Kerberoasting

#### Delegation
- `ConstrainedDelegate` - Accounts with constrained delegation
- `UnconstrainedDelegate` - Accounts with unconstrained delegation
- `ResourceConstrainedDelegate` - Accounts with resource constrained delegation

#### AD CS
- `CaComputer` - Certificate authorities
- `Esc1` - ESC1 vulnerable certificate templates
- `Esc2` - ESC2 vulnerable certificate templates

## Configuration

ADGO supports a configuration file for persistent settings. The config file is automatically created in the current directory as `adgo.yaml`.

### Example Config

```yaml
ldap:
  server: "192.168.1.100"
  port: 389
  baseDN: "DC=example,DC=com"
  username: "Administrator"
  password: "P@ssw0rd"
  security: 0
  loginName: "userPrincipalName"
output: "text"
```

## Flags

### Global Flags
- `-s, --server` - Domain controller host/IP
- `-p, --port` - LDAP port (389/LDAP, 636/LDAPS)
- `-b, --baseDN` - Base DN (e.g., DC=example,DC=com)
- `-u, --username` - Bind username
- `-w, --password` - Bind password
- `-o, --output` - Output format (text, json, csv)
- `--login-name` - Login name format (userPrincipalName or sAMAccountName)
- `--security` - Security mode (0=None, 1=TLS, 2=StartTLS, 3=InsecureTLS, 4=InsecureStartTLS)

## Output Examples

### Text Output
```
[+] Found 5 users

CN: Administrator
SAMAccountName: Administrator
UserPrincipalName: Administrator@example.com

CN: Guest
SAMAccountName: Guest
UserPrincipalName: Guest@example.com
```

### JSON Output
```json
[
  {
    "cn": "Administrator",
    "sAMAccountName": "Administrator",
    "userPrincipalName": "Administrator@example.com"
  },
  {
    "cn": "Guest",
    "sAMAccountName": "Guest",
    "userPrincipalName": "Guest@example.com"
  }
]
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
