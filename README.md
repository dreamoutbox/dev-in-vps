# dev-vps

`dev-vps` is a command-line tool written in Go to quickly spin up, connect to, and destroy high-resource development cloud servers for remote development workflows.

DigitalOcean is the initial cloud provider implemented behind an extensible provider interface, allowing future support for additional providers.

---

## Features

- **Interactive & Headless Creation**: Choose region and server size interactively from live DigitalOcean API slugs or pass flags (`--region`, `--size`, `--name`) for scripting.
- **Dedicated SSH Key Management**: Automatically generates an Ed25519 key pair in `~/.dev-vps/.ssh/`, uploads it to DigitalOcean via API, and configures permissions (`0700`/`0600`).
- **Automated Server Bootstrap**: Automatically provisions instances with cloud-init user-data from `~/.dev-vps/auto-setup/init.sh`.
- **Per-Droplet Cloud Firewalls**: Automatically creates a DigitalOcean Cloud Firewall (`dev-vps-<name>`) on `create`, removes it on `destroy`, and manages inbound rules via `dev-vps firewall`.
- **Seamless SSH Terminal**: One-command terminal connection (`dev-vps ssh [name]`) with auto-selection when only one server is active.
- **Local State Tracking**: Tracks provisioned instances in `~/.dev-vps/state.json`.

---

## Prerequisites & Configuration

### DigitalOcean API Token
`dev-vps` resolves the DigitalOcean Personal Access Token using the following order of precedence:
1. `DEV_VPS_DO_TOKEN` environment variable
2. `DIGITALOCEAN_TOKEN` environment variable
3. `digitalocean_token` field in `~/.dev-vps/config.json`

Example:
```bash
export DIGITALOCEAN_TOKEN="dop_v1_your_token_here"
```

To manage per-droplet cloud firewalls, ensure your DigitalOcean API token includes firewall write scope (otherwise `dev-vps create` warns and leaves the droplet without a managed firewall).

### Firewall Defaults (`~/.dev-vps/config.json`)
New installations write a `firewall` section into `~/.dev-vps/config.json`:
```json
{
  "firewall": {
    "default_rules": ["22", "80", "443", "8080", "8081", "3000", "8000"],
    "default_sources": ["0.0.0.0/0", "::/0"]
  }
}
```
- `default_rules` uses the same rule spec syntax as the CLI (`9000`, `9000/tcp`, `9001/udp`, `9000-9010`, `9000-9010/udp`, `icmp`). Port `5432` is not included in the built-in defaults.
- If the `firewall` block or either key is omitted, `dev-vps` falls back to the built-in defaults shown above without rewriting existing config files.
- Setting `"default_rules": []` opens only `22/tcp`. `dev-vps create` always includes `22/tcp` even if `default_rules` omits `22`, and validates the firewall config before creating a droplet.

---

## Installation

### Quick Install (GitHub Release)
Install the latest release binary directly into `~/.local/bin/dev-vps`:
```bash
curl -fsSL https://raw.githubusercontent.com/dreamoutbox/dev-in-vps/main/install.sh | sh
```

Alternatively, download the target binary manually from GitHub Releases:
```bash
# Linux (x86_64 / amd64)
curl -fsSL https://github.com/dreamoutbox/dev-in-vps/releases/latest/download/dev-vps-linux-amd64 -o ~/.local/bin/dev-vps && chmod +x ~/.local/bin/dev-vps

# macOS (Apple Silicon arm64)
curl -fsSL https://github.com/dreamoutbox/dev-in-vps/releases/latest/download/dev-vps-darwin-arm64 -o ~/.local/bin/dev-vps && chmod +x ~/.local/bin/dev-vps
```

### Build From Source
Install into `~/.local/bin/dev-vps`:
```bash
./local-install.sh
```

Or build binary in the current directory:
```bash
./build.sh
```

---

## Command Reference

### 1. Create a Dev Server
Interactive mode (prompts for region, size slug, and server name):
```bash
dev-vps create
```

Non-interactive / scriptable mode:
```bash
dev-vps create --name my-devbox --region nyc1 --size s-2vcpu-4gb
```

Custom init script:
```bash
dev-vps create --name my-devbox --init-script ./custom-init.sh
```

### 2. List Servers
Tabular format:
```bash
dev-vps list
dev-vps ls
```

JSON format:
```bash
dev-vps list --json
```

### 3. SSH into a Server
Connect to a specific server by name or ID:
```bash
dev-vps ssh my-devbox
```

Execute a remote command and exit:
```bash
dev-vps ssh my-devbox echo 1
```

Auto-selects if only one active server exists, or opens an interactive picker if multiple exist:
```bash
dev-vps ssh
```

### 4. Manage SSH Keys
Manually generate local Ed25519 key pair and register it with DigitalOcean:
```bash
dev-vps ssh create
```

### 5. Destroy a Server
With interactive confirmation:
```bash
dev-vps destroy my-devbox
```

Skip confirmation:
```bash
dev-vps destroy my-devbox --force
dev-vps destroy my-devbox -y
```
Destroying a server automatically deletes its managed `dev-vps-<name>` firewall before removing the droplet.

### 6. Manage Firewall Rules
Every droplet created with `dev-vps create` gets a DigitalOcean Cloud Firewall named `dev-vps-<droplet_name>` with allow-all outbound rules (TCP, UDP, ICMP) and the configured default inbound rules. Firewalls you created manually without the `dev-vps-` prefix are never touched.

List inbound rules as a table or JSON:
```bash
dev-vps firewall list my-droplet
dev-vps firewall ls my-droplet
dev-vps firewall list my-droplet --json
```

Allow rules (merges sources into existing rules; creates a firewall with `22/tcp` plus the requested rules if the droplet does not have one yet):
```bash
dev-vps firewall allow my-droplet 9000 icmp 9001/udp 9100-9110
dev-vps firewall allow my-droplet 5432 --source 203.0.113.7
dev-vps firewall allow my-droplet 9000-9010/udp icmp -s 10.0.0.0/8,2001:db8::/32
```

Deny rules (without `--source`, removes the whole rule; with `--source`, removes only those sources and deletes the rule if no sources remain; ranges match exactly and are never split):
```bash
dev-vps firewall deny my-droplet 9000 icmp
dev-vps firewall deny my-droplet 5432 --source 203.0.113.7
dev-vps firewall deny my-droplet 22 -s any
```

Rule spec syntax (case-insensitive):

| Arg | Meaning |
|---|---|
| `9000` | TCP port 9000 (bare port or range defaults to TCP) |
| `9000/tcp`, `9001/udp` | Single port with explicit protocol |
| `9000-9010`, `9000-9010/udp` | Inclusive port range |
| `icmp` | ICMP (ping) |

Accepted `--source` / `-s` values (repeatable or comma-separated; omitted on `allow` uses `firewall.default_sources` or `0.0.0.0/0, ::/0`):
- Bare IPv4 or IPv6 address (normalized to `/32` or `/128`), e.g. `203.0.113.7`
- IPv4 or IPv6 CIDR with no host bits set, e.g. `10.0.0.0/8`, `2001:db8::/32`
- `any` (expands to `0.0.0.0/0` and `::/0`)

SSH protection (`22/tcp`):
- `dev-vps firewall deny <droplet> 22` without `--source` is refused.
- `dev-vps firewall deny <droplet> 22 -s <sources>` is allowed only if at least one source remains.
- To restrict SSH to your IP only:
```bash
dev-vps firewall allow my-droplet 22 -s <your-ip>
dev-vps firewall deny my-droplet 22 -s any
```
Warning: verify `<your-ip>` matches your actual public IP before removing broad sources, or you can lock yourself out of SSH access.

---

## Storage Layout

All persistent files are stored in `~/.dev-vps` (or overridden by the `DEV_VPS_HOME` environment variable):

```
~/.dev-vps/
├── config.json            # Default provider, region, size, firewall defaults, and optional API token
├── state.json             # Local registry of active dev servers
├── .ssh/
│   ├── id_ed25519         # Private Ed25519 key (0600)
│   └── id_ed25519.pub     # Public Ed25519 key (0644)
└── auto-setup/
    └── init.sh            # Bootstrap shell script executed on first boot (0755)
```

---

## Automated First-Boot Setup

When a server is created, `~/.dev-vps/auto-setup/init.sh` is passed directly as cloud-init `user_data`. Customize this file to install packages, clone repositories, or configure development environments automatically on boot.

All stdout and stderr output from the startup script is automatically piped to `/dev-vps/startup.log` inside the provisioned VPS for easy inspection. You can review the logs after connecting via SSH:
```bash
dev-vps ssh <server-name> cat /dev-vps/startup.log
```

---

## Release Workflow

To bump version, create a release commit, and tag:
```bash
# Bump patch (e.g. 0.1.0 -> 0.1.1)
./release.sh patch

# Bump minor (e.g. 0.1.1 -> 0.2.0)
./release.sh minor

# Bump major (e.g. 0.2.0 -> 1.0.0)
./release.sh major

# Optionally push release and tags immediately to remote
./release.sh patch --push
```

Pushing a `v*` tag triggers the GitHub Actions CI workflow to test, cross-compile binaries for Linux and macOS (`amd64` and `arm64`), generate SHA256 checksums, and publish a GitHub Release.

