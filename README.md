# PVE Manager

A comprehensive single-file Bash TUI application for managing Proxmox VE infrastructure, including LXC containers, Docker setup, SSH key management, certificate authority, and service deployment.

## Features

- **LXC Container Management**: Create, start, stop, delete containers with a wizard interface
- **Template Management**: Browse, download, and manage container templates
- **Docker Setup**: Automated Docker installation with LXC-specific configuration
- **SSH Key Management**: Generate and distribute SSH keys across containers
- **Certificate Authority**: Self-signed CA with automatic certificate generation, deployment, and renewal
- **Service Deployment**: 21 pre-configured services with Docker and native installation options
- **FreeIPA Setup Wizard**: Complete LDAP structure management for identity services

## Requirements

### Required Dependencies
- `bash` (version 4.0+)
- `dialog` or `whiptail` (TUI interface)
- `ssh` and `scp` (remote connections)
- `openssl` (certificate management)
- `curl` (downloading)

### Optional Dependencies
- `jq` (JSON parsing for advanced features)

## Installation

```bash
# Clone or download the script
git clone <repository> /opt/pve-manager
# Or just download the script
wget -O /opt/pve-manager/pve-manager.sh <url>

# Make executable
chmod +x /opt/pve-manager/pve-manager.sh

# Verify dependencies
/opt/pve-manager/pve-manager.sh --check
```

## Usage

### Starting the TUI

```bash
./pve-manager.sh
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-v, --version` | Show version information |
| `--check` | Check dependencies and exit |
| `--init` | Initialize configuration only |

## Configuration

Configuration is stored in `~/.pve-manager/`:

```
~/.pve-manager/
├── config.conf           # Main configuration
├── profiles.conf         # PVE connection profiles
├── ca/
│   ├── ca.key           # CA private key
│   ├── ca.crt           # CA certificate
│   ├── ca.info          # CA metadata (CN, Organization)
│   └── certs/           # Generated certificates
├── ssh/
│   ├── id_ed25519       # SSH private key
│   └── id_ed25519.pub   # SSH public key
└── plugins/             # Service plugins (future)
```

### Configuration Options

Edit `~/.pve-manager/config.conf`:

```bash
DEFAULT_PROFILE=""        # Default PVE profile
DEFAULT_STORAGE="local"   # Default storage for containers
DEFAULT_BRIDGE="vmbr0"    # Default network bridge
DEFAULT_CPU=2             # Default CPU cores
DEFAULT_RAM=2048          # Default RAM in MB
DEFAULT_DISK=8            # Default disk size in GB
CA_VALID_DAYS=3650        # CA certificate validity (10 years)
CERT_VALID_DAYS=365       # Container certificate validity (1 year)
SSH_KEY_TYPE="ed25519"    # SSH key type (ed25519, rsa, ecdsa)
LOG_LEVEL="INFO"          # Log level (INFO, DEBUG)
```

## Supported Services (21 Total)

### Monitoring Stack
| Service | Description | Ports |
|---------|-------------|-------|
| Prometheus | Metrics collection and alerting | 9090 |
| Grafana | Visualization and dashboards | 3000 |
| Loki | Log aggregation system | 3100 |
| Alloy | Telemetry collector (metrics/logs) | 12345 |
| Node Exporter | Hardware/OS metrics exporter | 9100 |
| Full Stack | All monitoring tools combined | Multiple |

### Development Tools
| Service | Description | Ports |
|---------|-------------|-------|
| SonarQube | Code quality and security analysis | 9000 |
| Nexus | Artifact repository manager | 8081 |
| Gitea | Lightweight Git server | 3000 |
| Jenkins | CI/CD automation server | 8080 |
| Harbor | Container image registry | 80, 5000 |
| Dependency-Track | SCA and SBOM vulnerability management | 8080, 8081 |

### Testing Tools
| Service | Description | Ports |
|---------|-------------|-------|
| Kiwi TCMS | Test case management system | 8080 |
| Selenium Grid | Browser automation testing | 4444 |
| TestLink | Test management and execution | 80 |

### Infrastructure Tools
| Service | Description | Ports |
|---------|-------------|-------|
| Pi-hole | Network-wide DNS ad blocker | 53, 80 |
| Keycloak | Identity and access management (IAM) | 8080 |
| FreeIPA | Identity management (LDAP/Kerberos/DNS) | 80, 443, 389, 636, 88 |
| Postfix Relay | SMTP mail relay server | 25, 587 |
| Traefik | Reverse proxy and load balancer | 80, 443, 8080 |

### Deployment Options
- **Docker**: All services support Docker-based deployment
- **Native**: Prometheus, Grafana, Gitea, Jenkins, Kiwi TCMS, TestLink, SonarQube, Pi-hole

## Main Menu

```
┌─────────────────────────────────────┐
│        PVE Manager v1.0.0           │
├─────────────────────────────────────┤
│  1. Connect to PVE Server           │
│  2. LXC Container Management        │
│  3. Docker Setup                    │
│  4. SSH Key Management              │
│  5. Service Deployment              │
│  6. Certificate Management          │
│  7. Settings                        │
│  0. Exit                            │
└─────────────────────────────────────┘
```

## Feature Details

### 1. PVE Connection Management

- **Local Mode**: Automatically detected when running on a PVE host
- **Remote Mode**: SSH-based connection to remote PVE servers
- **Profiles**: Save multiple connection profiles for different servers

### 2. LXC Container Management

Create containers with customizable settings:
- **Storage selection**: Choose from available storages (local-lvm, ZFS, etc.)
- **Template selection**: Pick from templates across all template storages
- **VMID**: Auto-suggested next available VMID
- **Resources**: CPU cores, RAM, disk size
- **Network**: Bridge selection, DHCP or static IP configuration

Template Management:
- View downloaded templates
- Browse available templates by category (system, turnkeylinux, mail)
- Download templates directly from the menu
- Automatic template index updates

Operations:
- List all containers with status
- Start/stop individual or bulk containers
- Delete containers (with confirmation)
- View detailed container configuration

### 3. Docker Setup

Pre-installation checks:
- Verifies container features (nesting, keyctl)
- Configures AppArmor profile to unconfined (required for Docker)
- Adds LXC cgroup permissions for Docker containers
- Offers to enable missing features automatically
- Restarts container if needed to apply changes

Supported distributions:
- **Debian/Ubuntu** (APT-based)
- **Alpine** (APK-based)
- **CentOS/RHEL/Rocky/AlmaLinux** (DNF/YUM-based)
- **Fedora** (DNF-based)

### 4. SSH Key Management

- Generate Ed25519/RSA/ECDSA keypairs
- Distribute public key to containers
- Setup passwordless inter-container SSH
- Test connectivity matrix across all containers

### 5. Certificate Authority

Self-signed CA for HTTPS:
- Initialize CA with custom Common Name and Organization
- Generate certificates with Subject Alternative Names (SAN)
- Deploy certificates to containers
- Renew certificates (single or batch)
- Update system trust stores
- Export CA certificate for client trust

Certificate locations in containers:
```
/etc/ssl/pve-manager/
├── <hostname>.key        # Private key
├── <hostname>.crt        # Certificate
├── <hostname>-chain.pem  # Certificate chain
└── ca.crt               # CA certificate
```

### 6. Service Deployment Menu

```
┌─────────────────────────────────────┐
│       Service Deployment            │
├─────────────────────────────────────┤
│  1. Monitoring Stack                │
│  2. Development Tools               │
│  3. Testing Tools                   │
│  4. Infrastructure Tools            │
│  5. Reverse Proxy (Traefik)         │
│  6. View deployed services          │
│  7. Update/Redeploy service         │
│  8. Stop service                    │
│  9. Remove service                  │
│ 10. Enable HTTPS for service        │
│ 11. View supported services list    │
│  0. Back                            │
└─────────────────────────────────────┘
```

### 7. FreeIPA Setup Wizard

Complete LDAP structure management:

- **Check FreeIPA Status**: View IPA services, Kerberos config, domain info
- **Create Organizational Units (OUs)**:
  - Standard Corporate (Users, Groups, Computers, Services)
  - Departmental (IT, HR, Finance, Sales, Engineering)
  - Custom OUs
- **Create User Groups**:
  - Role-based (admins, developers, operators, viewers)
  - Access-based (vpn-users, ssh-users, sudo-users)
  - Custom groups
- **Create Users**:
  - Single user with full details
  - Batch creation
  - Service accounts
- **Create Host Groups**:
  - Environment-based (production, staging, development)
  - Function-based (webservers, databases, appservers)
- **Configure Password Policy**:
  - Standard, Strong, Relaxed, or Custom settings
- **Configure Sudo Rules**:
  - Full admin sudo access
  - Limited sudo (specific commands)
- **View LDAP Structure**: Display all users, groups, host groups, sudo rules
- **Export LDAP Configuration**: Export settings to local files

### 8. DNS Management

Update DNS settings for containers when using Pi-hole:
- Auto-detect Pi-hole instances
- Update all or selected containers
- Configure custom DNS servers

## Progress Display

All long-running operations display real-time progress:
- Docker installation shows each step with live output
- Service deployment shows pull and container startup progress
- Certificate operations show generation and deployment status
- Bulk operations show per-container progress

## Timeout Protection

Commands that might hang have built-in timeouts:
- Container shutdown: 15 seconds graceful, then force stop
- Container start: 30 seconds
- Docker status checks: 5 seconds per container
- OS detection: 5 seconds
- Container IP retrieval: 5 seconds
- SSH connectivity tests: 5 seconds
- Docker test: 60 seconds

## Examples

### Create a Container and Install Docker

1. Start PVE Manager: `./pve-manager.sh`
2. Select "Connect to PVE Server" -> "Connect to local PVE"
3. Select "LXC Container Management" -> "Create new container"
4. Select storage, template, and configure settings
5. Start the container when prompted
6. Select "Docker Setup" -> "Install Docker in container"
7. Select the new container (features will be auto-configured if needed)

### Deploy Monitoring Stack

1. Create and start a container with Docker installed
2. Select "Service Deployment" -> "Monitoring Stack" -> "Full Monitoring Stack"
3. Select the target container
4. Access Grafana at http://<container-ip>:3000 (admin/admin)

### Setup FreeIPA Identity Management

1. Select "Service Deployment" -> "Infrastructure Tools" -> "FreeIPA"
2. Deploy to a container (first startup takes 5-10 minutes)
3. Select "FreeIPA Setup Wizard" to configure LDAP structure
4. Create OUs, groups, users, and policies through the wizard

### Setup HTTPS with Self-Signed Certificates

1. Select "Certificate Management" -> "Initialize Certificate Authority"
2. Enter Common Name and Organization for the CA
3. Select "Generate certificates for all containers"
4. Select "Deploy certificates to all containers"
5. Export CA certificate and import into your browser

## Troubleshooting

### Dialog/Whiptail Not Found
```bash
# Debian/Ubuntu
apt-get install dialog

# Alpine
apk add dialog

# RHEL/CentOS
yum install dialog
```

### SSH Connection Failed
- Verify SSH keys are set up: `ssh-copy-id root@<pve-host>`
- Check firewall allows port 22
- Verify the PVE host is reachable

### Docker Installation Failed
- Ensure container has nesting and keyctl features enabled
- Use "Check/fix container features" option in Docker menu
- Check container has internet access
- Verify container is running

### TestLink PHP 8 Errors
The installer automatically:
- Updates ADOdb library for PHP 8 compatibility
- Updates Smarty library to v4.x
- Applies PHP 8 compatibility patches
- Configures mysqli error suppression

### Certificate Errors
- Ensure CA is initialized before generating certificates
- Container must be running to deploy certificates
- Import CA certificate into browser/system trust store

## Log File

Logs are stored at `~/.pve-manager/pve-manager.log`

View logs:
```bash
tail -f ~/.pve-manager/pve-manager.log
```

Or use Settings -> View log file in the TUI.

## License

MIT License

## Contributing

Contributions are welcome. Please submit pull requests or open issues for bugs and feature requests.
