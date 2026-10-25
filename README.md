# dev-vps

`dev-vps` is a command-line tool written in Go to quickly spin up, connect to, and destroy high-resource development cloud servers for remote development workflows.

DigitalOcean is the initial cloud provider implemented behind an extensible provider interface, allowing future support for additional providers.

---

## Features

- **Interactive & Headless Creation**: Choose region and server size interactively from live DigitalOcean API slugs or pass flags (`--region`, `--size`, `--name`) for scripting.
- **Dedicated SSH Key Management**: Automatically generates an Ed25519 key pair in `~/.dev-vps/.ssh/`, uploads it to DigitalOcean via API, and configures permissions (`0700`/`0600`).
- **Automated Server Bootstrap**: Automatically provisions instances with cloud-init user-data from `~/.dev-vps/auto-setup/init.sh`.
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

---

## Storage Layout

All persistent files are stored in `~/.dev-vps` (or overridden by the `DEV_VPS_HOME` environment variable):

```
~/.dev-vps/
├── config.json            # Default provider, region, size, and optional API token
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

