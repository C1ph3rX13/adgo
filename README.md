# ADGO

Active Directory reconnaissance and triage tool for Red Team.

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

# Run a quick query for all users
./adgo quick users --server 192.168.111.100 --username Administrator --password pass1234!@#$ --baseDN DC=sec,DC=lab

# Check machine account quota
./adgo quick machineAccountQuota --server 192.168.111.100 --username Administrator --password pass1234!@#$ --baseDN DC=sec,DC=lab

# Run a custom query
./adgo query --filter "(objectClass=user)" --attrs "sAMAccountName,userPrincipalName" --server 192.168.111.100 --username Administrator --password pass1234!@#$ --baseDN DC=sec,DC=lab
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
  server: "192.168.111.100"
  port: 389
  baseDN: "DC=sec,DC=lab"
  username: "Administrator"
  password: "<your-password-here>"
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

### Text Output (Users Query)
```
  ADGO REPORT  |  Search Results

--------------------------------------------------------------------------------
[USER] CN=Administrator,CN=Users,DC=sec,DC=lab
--------------------------------------------------------------------------------
  [*] sAMAccountName       : Administrator
  [*] userAccountControl   : 66048, Unknown

--------------------------------------------------------------------------------
[USER] CN=Guest,CN=Users,DC=sec,DC=lab
--------------------------------------------------------------------------------
  [*] sAMAccountName       : Guest
  [*] userAccountControl   : 66082, Guest

--------------------------------------------------------------------------------
[DC] CN=AD,OU=Domain Controllers,DC=sec,DC=lab
--------------------------------------------------------------------------------
  [*] sAMAccountName       : AD$
  [*] userAccountControl   : 532480, Domain Controller

--------------------------------------------------------------------------------
[USER] CN=krbtgt,CN=Users,DC=sec,DC=lab
--------------------------------------------------------------------------------
  [*] sAMAccountName       : krbtgt
  [*] userAccountControl   : 514, Krbtgt

Total Entries: 8
```

### Text Output (Machine Account Quota)
```
  ADGO REPORT  |  Search Results

--------------------------------------------------------------------------------
[OTHER] DC=sec,DC=lab
--------------------------------------------------------------------------------
  [*] ms-DS-MachineAccountQuota : 10

Total Entries: 1
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
