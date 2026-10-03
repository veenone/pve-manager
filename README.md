# PVE Manager

A comprehensive single-file Bash TUI application for managing Proxmox VE infrastructure, including LXC containers, Docker setup, SSH key management, certificate authority, and service deployment.

## Features

- **LXC Container Management**: Create, start, stop, delete containers with a wizard interface
- **VM Management**: Manage QEMU VMs via the guest agent, including HTTPS and service deployment
- **Template Management**: Browse, download, and manage container templates
- **Docker Setup**: Automated Docker installation with LXC-specific configuration
- **SSH Key Management**: Generate and distribute SSH keys across containers
- **Root SSH Access**: One-click install/enable of sshd and root login (key-only, password, or both) on any container, single or fleet-wide
- **User Provisioning**: Create a user with optional sudo/wheel membership and SSH key access, on either an LXC container or a VM
- **Certificate Authority**: Self-signed CA with automatic certificate generation, deployment, and renewal
- **Service Deployment**: 25 pre-configured services with Docker and native installation options
- **FreeIPA Setup Wizard**: Complete LDAP structure management for identity services
- **Publicly-trusted certificates** via ACME (Let's Encrypt) with Cloudflare DNS-01, deployable to LXC containers and VMs

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
| `--acme-status` | Show the ACME certificate and its deploy targets |
| `--acme-renew` | Renew the ACME certificate if due, then re-deploy (headless) |
| `--acme-redeploy` | Re-push the current certificate to recorded targets (no CA call) |
| `--acme-renew-force` | Force renewal even if not due (consumes rate-limit quota) |

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

## Supported Services (25 Total)

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
| Jenkins Inbound Agent | JNLP build agent that connects out to a controller | — (outbound) |
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
| Nginx | Reverse proxy and web server | 80, 443 |

### Databases
| Service | Description | Ports |
|---------|-------------|-------|
| MySQL | MySQL 8 relational database server | 3306 |
| PostgreSQL | PostgreSQL 16 relational database server | 5432 |
| MongoDB | MongoDB 7 NoSQL document database | 27017 |

### Deployment Options
- **Docker**: All services support Docker-based deployment
- **Native**: Prometheus, Grafana, Gitea, Jenkins, Kiwi TCMS, TestLink, SonarQube, Pi-hole, Nginx
- **Databases**: Docker-only; the deploy wizard prompts for credentials (blank = auto-generated) and stores them in `/opt/services/<db>/.env`

## Main Menu

```
┌─────────────────────────────────────┐
│        PVE Manager v2.1.0           │
├─────────────────────────────────────┤
│  1. Connect to PVE Server           │
│  2. LXC Container Management        │
│  3. VM Management                   │
│  4. Docker Setup                    │
│  5. SSH Key Management              │
│  6. Service Deployment              │
│  7. Certificate Management          │
│  8. Settings                        │
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

### 2b. VM Management

Manages QEMU VMs through the QEMU Guest Agent (`qm guest exec`), mirroring the
LXC workflow wherever the guest agent makes it possible:
- List VMs and view their configuration, including guest agent status and IP
- Execute arbitrary commands inside a running VM (requires the guest agent)
- Enable HTTPS for a detected service (Docker or native) the same way as LXC containers
- Deploy Jenkins or Nginx to a VM
- Create a user (see [2c. User Provisioning](#2c-user-provisioning-lxc--vm))

Operations that need guest access (command execution, user creation) are
disabled with a clear message if the QEMU Guest Agent isn't installed/running
in the VM.

### 2c. User Provisioning (LXC & VM)

Available from both **LXC Container Management → Create user** and
**VM Management → Create user** (same underlying logic for both guest types):

1. Pick a running container or VM
2. Enter a username (lowercase letters/digits/`-`/`_`, must not already exist)
3. Choose whether to grant sudo/wheel group membership
4. Choose whether to enable SSH key-based access for the new user

The wizard creates the account with a random password, adds it to `sudo`
(Debian/Ubuntu) or `wheel` (RHEL-family/Alpine) if requested — installing the
`sudo` package first if it's missing — and, if SSH access is requested,
installs/enables `sshd` and appends the pve-manager SSH public key to the
user's `~/.ssh/authorized_keys`. The generated password is shown once in a
results dialog; it is written to a private temp file and never passed through
stdout, so it never ends up in `~/.pve-manager/logs/operations.log`.

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
- **Enable root SSH** on one container or all running containers: installs/enables
  `sshd` if missing, sets `PermitRootLogin` (`prohibit-password` for key-only,
  `yes` for password/both), optionally copies the pve-manager SSH key, optionally
  sets a random root password (shown once), and opens the firewall (`ufw`/`firewalld`)
  if one is active. A high-precedence `sshd_config.d/00-pve-manager-root-ssh.conf`
  drop-in is written as well, since some distro images (e.g. Ubuntu cloud images)
  ship an `Include`'d config that would otherwise override the setting

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

### 5b. Cloudflare / Let's Encrypt Certificates (ACME)

Issues a **publicly-trusted** wildcard certificate and pushes it to guests,
replacing self-signed certificates. Browsers trust it with no CA import.

Reach it from **Certificate Management → C**.

#### Why a wildcard

One certificate covers every guest, which means:

- guests never hold the Cloudflare token — only the PVE host does
- a single issuance covers the whole fleet, so ACME rate limits are a non-issue
- renewal is one operation plus a re-push to recorded targets

#### Requirements

1. **A real, registrable domain on Cloudflare nameservers.** A reserved
   pseudo-TLD (`.lan`, `.local`, `.home`, `.internal`) can *never* be certified
   by a public CA — there is no way to prove ownership. The configuration menu
   rejects these outright.
2. **A scoped Cloudflare API token**:
   - `Zone → DNS → Edit`
   - `Zone → Zone → Read`
   - Zone Resources → Include → Specific zone → your domain
   - TTL blank (an expiring token silently breaks unattended renewal)

   Do **not** use a Global API Key. The token is stored `0600` at
   `~/.pve-manager/acme/cloudflare.env`, on the PVE host only.
3. **Split-horizon DNS.** DNS-01 validates against the *public* zone and creates
   no address records, so internal names must be pointed at LAN IPs on your own
   resolver (e.g. AdGuard Home DNS rewrites). Menu option `D` prints the details.

#### Naming

Guests are addressed as `<guest>.<ACME_SUBDOMAIN>.<ACME_DOMAIN>`, e.g.
`gitea.lan.example.com`. The issued SAN set is:

```
example.com
*.example.com
*.lan.example.com
```

Note that `lan.example.com` is deliberately **absent**. Let's Encrypt rejects an
order containing both a wildcard and a name that wildcard already covers:

```
Domain name "lan.example.com" is redundant with a wildcard
domain in the same request. Remove one or the other.
```

`*.example.com` already covers it, so nothing is lost.

#### Single-issuer model

Exactly **one** host should hold the Cloudflare token and run the ACME client.
Every other host deploys a certificate it did not issue.

Running an issuer per node looks convenient and fails quietly: each consumes
Let's Encrypt's 5-duplicate-certificates-per-week budget, each renews on its own
schedule (or none — a second issuer in testing had no timer at all, so its
certificate would simply have expired), and the same guest ends up recorded as a
renewal target on two hosts that overwrite each other.

Two settings control where a certificate comes from:

| Setting | Meaning |
|---|---|
| `ACME_ISSUER_HOST` | empty = **this host issues**. Set = fetch from that host over SSH and never issue locally. |
| `ACME_ISSUER_DIR` | path on the issuer holding `fullchain.pem` / `privkey.pem` / `chain.pem` |
| `ACME_CERT_SOURCE_DIR` | read the certificate from this local path instead of the tool's own acme.sh live directory — for when a standalone acme.sh already manages it |

On a deployer host:

- **Issuance is refused** with an explanation, not a silent duplicate certificate
- The deploy menu **fetches from the issuer first**, so a stale copy cannot be pushed
- `--acme-renew` **fetches and re-deploys** rather than renewing
- Only the three deployable files are fetched — never the account key or the token

The main menu shows the role (`ISSUER` / `DEPLOYER (issuer: …)`) and the resolved
certificate source, so it is never ambiguous which host is authoritative.

#### Integrating with an external issuer

If a standalone `acme.sh` already renews the certificate, point the tool at its
output with `ACME_CERT_SOURCE_DIR` and call the tool from that client's renew
hook so guests are refreshed in the same pass:

```bash
/root/pve-manager/pve-manager.sh --acme-redeploy
```

That re-pushes the current certificate to every recorded target **without
contacting the CA**. Without it, a renewal refreshes whatever the external hook
knows about and leaves every guest on the old certificate until it expires.

#### Proxmox products (PDM / PBS)

Proxmox Datacenter Manager and Proxmox Backup Server own their TLS and replace
it through their API, so they are deployed as target kind **`papi`** — no guest
agent and no SSH into the VM:

```
POST /api2/json/nodes/localhost/certificates/custom
     certificates=<chain> key=<key> force=1 restart=1
```

Register with menu option **P**. Credentials live in a 0600 env file, linked as
`~/.pve-manager/acme/api/<vmid>.env`:

```
PX_URL='https://10.88.20.200:8443'   # PBS: port 8007
PX_SCHEME='PDMAPIToken'              # PBS: PBSAPIToken
PX_TOKEN_ID='root@pam!certdeploy'    # quote it: contains '!'
PX_TOKEN_SECRET='<secret>'
```

The token needs `System.Modify` on `/`. **With Privilege Separation enabled,
grant it as an "API Token Permission"** — a permission on the user does not
reach the token, which then authenticates with every privilege `false`.

Before any key leaves the host the tool checks that the token authenticates and
holds `System.Modify`. Upload is skipped when the product already serves the
current certificate (it restarts the product's proxy), adoption is verified by a
real handshake, and a non-adoption prints the rollback
(`DELETE .../certificates/custom` regenerates the self-signed cert).

#### Consumers that pin certificates

Anything that **pins a fingerprint** breaks when the certificate changes — and a
renewal changes it every ~60 days. PDM pinned each PVE node's fingerprint and
every remote failed with `HTTP 400: Could not establish a TLS connection`.
Re-pinning only defers the failure; instead point such clients at a **name the
certificate covers** and drop the pin, so they validate against the public trust
store and renewals are invisible to them.

#### Cluster-wide deployment

Guests on **any node** are deployable. Proxmox's `pct`/`qm` only work for guests
the local node owns, so commands are routed to the owning node over the cluster's
existing root SSH trust. Node addresses come from `/etc/pve/.members` (replicated
by pmxcfs), and SSH uses the IP rather than the node name, which is frequently
absent from `known_hosts`.

The deploy picker lists every running guest in the cluster, labelled with its
node. If a node is unreachable you get a specific message naming it, not a
cryptic `Configuration file 'nodes/PDxxx/lxc/N.conf' does not exist`.

#### Supported application shapes

| Shape | Detected | Replaceable |
|---|---|---|
| nginx / apache2 / caddy installed in the guest | yes | yes (apache: cert only, no vhost rename) |
| caddy or nginx in a **Docker container** | yes | yes |
| traefik in a container | reported | no — cert paths not discoverable |
| cert path inside an image or named volume | reported as `NOTBOUND` | no — nothing to write |
| anything else | reported | `standard` mode only |

For containerised proxies the certificate path found in the config is a
*container* path; it is translated to the guest path through
`docker inspect .Mounts` before anything is written. Nginx's config file is
located by searching for `server_name` rather than assuming a path.

**Menu option `S` scans the whole cluster** and reports, per guest, which TLS
terminator it runs, where its certificate lives, what server names it answers to,
and whether those names are covered by your certificate.

#### Virtual host rename

Replacing a certificate is only half the job when the vhost is still named
`<app>.myhome.lan` — no public certificate can cover a reserved pseudo-TLD, so
the service loads the new cert and every client still sees a name mismatch. The
deploy therefore offers to repoint the vhost at `<guest>.<sub>.<domain>`.

It is **opt-in**, asked once per deployment, and never repeated on renewal (a
one-off migration should not be redone unattended every 60 days). The config is
backed up in the guest as `*.pvebak.<timestamp>`, validated after editing, and
restored automatically if validation fails.

Config edits are written with **truncate-and-write to preserve the inode**. This
matters: a Docker single-file bind mount is bound to the inode, so `sed -i`,
`install` or `mv` silently detach the mount and the container keeps reading stale
content — or sees the file disappear.

#### Verification

A reload reporting success does not mean the service adopted the certificate.
`caddy reload` with an unchanged config logs *"config is unchanged"*, keeps the
cert already in memory, and **exits 0** — so the deploy performs a real TLS
handshake from inside the guest and compares serial numbers. A mismatch is
reported as `NOT ADOPTED`, distinguishing "did not re-read the file" from "no
virtual host for that name, handshake aborted".

#### Deployment modes

| Mode | Behaviour |
|------|-----------|
| `inplace` (default) | Detects nginx / apache2 / caddy, finds the cert paths each already reads, backs them up in-guest as `*.pvebak.<stamp>`, overwrites them, then config-tests and gracefully reloads. No service config is edited, so it cannot break on a directive it did not expect. |
| `standard` | Installs to `/etc/ssl/pve-manager/<domain>/` only and changes nothing else. |

Both modes also install to the canonical path, and both are recorded as renewal
targets.

```
/etc/ssl/pve-manager/<domain>/
├── fullchain.pem   # leaf + intermediates (644)
├── privkey.pem     # private key (640)
└── chain.pem       # intermediates only (644)
```

#### Safety guards

Deployment is refused, with a reason, if the certificate and key are not a
matching pair, the certificate expires within 24h, or the chain does **not**
verify against the system trust store — the last of which stops a staging
certificate from ever reaching a real service.

#### Rate limits

Let's Encrypt permits 50 certificates per registered domain per week, but only
**5 duplicate certificates** (identical SAN set) per week. Use **option 4
(STAGING)** for dry runs; it has far higher limits. To debug *deployment*, re-run
a deploy against the already-issued certificate rather than re-issuing.

#### Renewal

Option `9` renews if due and re-pushes to every recorded target. For unattended
renewal, drive the same path from a timer:

```bash
# /etc/systemd/system/pve-manager-acme-renew.service
[Service]
Type=oneshot
ExecStart=/root/pve-manager/pve-manager.sh --acme-renew
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
│  5. Reverse Proxy (Nginx/Traefik)   │
│  6. Databases (MySQL/PgSQL/Mongo)   │
│  7. View deployed services          │
│  8. Update/Redeploy service         │
│  9. Stop service                    │
│ 10. Remove service                  │
│ 11. Enable HTTPS for service        │
│ 12. Auto-HTTPS via Nginx (proxy)    │
│ 13. View supported services list    │
│  0. Back                            │
└─────────────────────────────────────┘
```

### Databases

The **Databases** menu (Service Deployment → option 6) deploys a Docker-based
database engine and provisions its credentials:

1. Choose the engine — **MySQL**, **PostgreSQL**, or **MongoDB**.
2. Select a running container (Docker is installed if missing).
3. Enter the listening port and credentials (root/superuser password, database name,
   and — for MySQL — an application user). Leaving a password blank auto-generates a
   strong one via `openssl rand`.
4. The wizard writes `docker-compose.yml` plus a `.env` file (mode `600`) holding the
   credentials to `/opt/services/<engine>/`, then runs `docker compose up -d`.

Data persists in a named Docker volume, and the final screen shows a ready-to-use
connection command. Databases are intentionally excluded from the Auto-HTTPS wizard
(they are not HTTP services).

### Auto-HTTPS via Nginx

The **Auto-HTTPS via Nginx** wizard (Service Deployment → option 12) automatically
puts an Nginx reverse proxy with TLS in front of the plain-HTTP services already
running in a container:

1. Select a running container.
2. The wizard scans running Docker services and matches them to known HTTP ports
   (Grafana, Gitea, Jenkins, SonarQube, Nexus, Prometheus, Keycloak, …). Services
   that already serve HTTPS (Harbor, Kiwi TCMS, FreeIPA) and non-HTTP services are
   skipped automatically.
3. Pick which services to expose (all selected by default).
4. Nginx is installed natively if missing, a certificate for the container is issued
   by the PVE Manager CA and deployed, and one HTTPS reverse-proxy `server` block is
   generated per service (config is validated with `nginx -t` before reload).

Each service is published on a dedicated TLS port (`service port + 10000`, e.g.
Grafana `3000` → `https://<ip>:13000`); port collisions are resolved automatically.
Generated files live in `conf.d/pve-https-*.conf` (or `http.d/` on Alpine).

### Jenkins Inbound Agent

The **Jenkins Inbound Agent** wizard (Service Deployment → Development Tools →
option 5) deploys a Docker-based JNLP build agent
([`jenkins/inbound-agent`](https://hub.docker.com/r/jenkins/inbound-agent/)) that
connects **out** to an existing Jenkins controller:

1. Select a running container (Docker is installed if missing).
2. Provide the controller URL, the agent (node) name, and the agent secret from the
   Jenkins node's connection page. Optionally choose the work directory and whether
   to use WebSocket transport (recommended behind an HTTPS reverse proxy).
3. If the controller URL is **HTTPS**, the wizard offers to make the agent trust the
   controller's certificate:
   - **Fetch from controller** — retrieves the certificate chain via `openssl
     s_client` from `host:port`.
   - **Reuse PVE Manager CA** — uses the local CA cert (ideal when the controller was
     fronted by the Auto-HTTPS wizard).
   - **Skip** — for publicly-trusted certs.

The chosen chain is split into individual certificates and each is passed **inline**
to the agent via its built-in, repeatable `-cert` option (`hudson.remoting`), embedded
directly in the compose file's `command:`. This is the officially-supported way to
trust a self-signed or private-CA controller and covers both the initial HTTPS resolve
and the WebSocket connection — no JVM trust-store surgery required. Each agent is
deployed with `restart: unless-stopped`, so multiple agents can coexist in one
container.

> **Why inline and not `-cert @file`?** The remoting option parser (args4j) treats any
> argument beginning with `@` as a *command file* and splices its lines in as
> arguments before option parsing. Passing `-cert @/path/cert.pem` therefore expands
> the PEM's body lines into bogus options and fails with
> `'-----END CERTIFICATE-----' is not a valid option`. An inline PEM value is a single
> argument and is parsed correctly.

When you choose **Fetch from controller**, the wizard also inspects the certificate's
SAN/CN and warns if it does **not** cover the host in your Controller URL. The agent
still verifies the hostname (trusting a cert does not disable that check), so a
mismatch fails with `No name matching <host> found` even though the cert is trusted.
Fix it by pointing the Controller URL at a name the cert covers, or reissuing the
controller cert with the right SAN.

> If you still see `unable to find valid certification path to requested target`,
> re-run the wizard and choose **Fetch from controller** so the exact certificate the
> controller presents (including any intermediates) is the one that gets trusted.

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

Operation output (install/config steps, errors) is also mirrored to
`~/.pve-manager/logs/operations.log`. Generated passwords (root SSH, user
provisioning) are deliberately kept out of both logs — they're written to a
private, caller-owned temp file and shown once in a results dialog instead of
being printed to stdout.

## License

MIT License

## Contributing

Contributions are welcome. Please submit pull requests or open issues for bugs and feature requests.
