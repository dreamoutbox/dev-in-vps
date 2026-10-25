# Implementation Plan: Dev Server VPS CLI

## Overview
A lightweight Go CLI tool (`dev-vps`) to provision, manage, SSH into, and destroy development VPS instances. DigitalOcean is implemented as the initial provider behind a pluggable cloud provider interface. Persistent state, SSH keys, and startup scripts are stored in `~/.dev-vps`.

---

### Phase 1: CLI scaffold, configuration, and local storage [STATUS: DONE]
- Goal: Set up project structure, CLI command routing, and `~/.dev-vps` configuration/state/SSH directory handling.
- Tasks:
  - [x] Initialize CLI router (`cobra`) with root command and global flags.
  - [x] Define typed enums for provider types (`ProviderDigitalOcean`, etc.).
  - [x] Implement storage package managing `~/.dev-vps/`:
    - `~/.dev-vps/config.json`: stores default provider, default region, DO API token reference.
    - `~/.dev-vps/state.json`: tracks provisioned dev servers locally.
    - `~/.dev-vps/.ssh/`: dedicated directory for CLI-managed SSH keys (permissions `0700`).
    - `~/.dev-vps/auto-setup/init.sh`: auto-creates default bootstrap shell script if not present.
  - [x] Add unit tests for storage and directory initialization.
- Done when: `go test ./...` passes; running `./dev-vps --help` displays command usage; directory structure at `~/.dev-vps/` (including `~/.dev-vps/.ssh/`) is automatically scaffolded on first execution.

---

### Phase 2: Cloud provider abstraction and DigitalOcean client [STATUS: DONE]
- Goal: Define provider interface and implement DigitalOcean region/size fetching, droplet creation, SSH key synchronization, listing, and deletion.
- Tasks:
  - [x] Define `Provider` interface:
    - `ListRegions(ctx)`: returns available VPS regions (slug, name, availability).
    - `ListSizes(ctx, regionSlug)`: returns available VPS size slugs, vCPUs, RAM, disk, and price, filtered by region availability.
    - `EnsureSSHKey(ctx, name, publicKey)`: finds existing SSH key by fingerprint or creates a new key on DO via API, returning the key identifier.
    - `CreateServer(ctx, req)`: creates droplet with region, size, registered SSH key, and `init.sh` user-data.
    - `ListServers(ctx)`: lists droplets matching dev-vps tag.
    - `GetServer(ctx, id)`: retrieves droplet status and public IPv4.
    - `DeleteServer(ctx, id)`: deletes droplet by ID.
  - [x] Implement DigitalOcean provider using DO API client.
  - [x] Implement token resolution: precedence order `DEV_VPS_DO_TOKEN` > `DIGITALOCEAN_TOKEN` > config file.
  - [x] Add unit tests with mock HTTP transport for DigitalOcean API interactions (region listing, size listing, SSH key check, droplet creation, and deletion).
- Done when: Provider tests pass with mock responses covering region and size queries, SSH key synchronization, droplet creation, and deletion.

---

### Phase 3: Interactive & flag-driven creation, SSH key management, and provisioning [STATUS: DONE]
- Goal: Implement `dev-vps create` supporting both non-interactive flags and interactive selection for region and size, plus SSH key auto-generation and droplet provisioning.
- Tasks:
  - [x] Implement SSH key helper package:
    - Generate Ed25519 key pair and save to `~/.dev-vps/.ssh/id_ed25519` (`0600`) and `~/.dev-vps/.ssh/id_ed25519.pub` (`0644`).
    - Compute SSH public key fingerprint.
  - [x] Implement `dev-vps ssh create`:
    - Manually generates the SSH key pair under `~/.dev-vps/.ssh/` if not present.
    - Synchronizes the public key to DigitalOcean via `EnsureSSHKey`.
  - [x] Implement selection UI helper for interactive mode (e.g., using `charmbracelet/huh` or terminal selector):
    - Region picker: displays formatted regions (e.g. `nyc1 - New York 1`, `sfo3 - San Francisco 3`).
    - Size picker: displays formatted specs and price (e.g. `s-2vcpu-4gb - 2 vCPU, 4GB RAM, 80GB Disk ($24/mo)`).
  - [x] Implement `dev-vps create`:
    - Flags: `--name`, `--region`, `--size`, `--init-script`.
    - Region resolution:
      - If `--region` flag is provided: validate against available DO regions.
      - If `--region` flag is omitted: fetch DO regions and prompt with interactive picker.
    - Size resolution:
      - If `--size` flag is provided: validate against available sizes in the selected region.
      - If `--size` flag is omitted: fetch DO sizes for the selected region and prompt with interactive picker.
    - Name resolution: prompt interactively if not provided via `--name`.
    - SSH key auto-setup: check `~/.dev-vps/.ssh/id_ed25519`, auto-create if missing, and sync to DO via `EnsureSSHKey`.
    - User-data script: read `~/.dev-vps/auto-setup/init.sh` (or `--init-script`) and embed into droplet request.
    - Provision droplet with selected region, size, and SSH key.
  - [x] Poll until server status is active and public IP is assigned.
  - [x] Save instance record (ID, name, region, size, IP, provider, created date) to `~/.dev-vps/state.json`.
- Done when:
  - Non-interactive creation works: `dev-vps create --name box1 --region nyc1 --size s-2vcpu-4gb` provisions immediately without prompts.
  - Interactive creation works: running `dev-vps create` presents an interactive region picker, followed by an interactive size picker, creates the droplet, and records state.

---

### Phase 4: Server listing and SSH connectivity commands [STATUS: DONE]
- Goal: Implement `dev-vps list` and `dev-vps ssh` commands using the managed SSH key.
- Tasks:
  - [x] Implement `dev-vps list`:
    - Display tabular output with Name, Provider, Server ID, Region, Size, IP Address, Status, Created At.
    - Support `--json` flag for machine-readable output.
  - [x] Implement `dev-vps ssh <name-or-id>`:
    - Resolve target server IP from local state or provider lookup.
    - If no target specified and only one server exists, auto-select it; if multiple exist, prompt for selection.
    - Hand off terminal to `ssh -i ~/.dev-vps/.ssh/id_ed25519 -o StrictHostKeyChecking=accept-new root@<ip>` via `os/exec` with `Stdin`, `Stdout`, `Stderr` attached.
- Done when: `dev-vps list` renders server table; `dev-vps ssh <name>` successfully connects using `~/.dev-vps/.ssh/id_ed25519` in an interactive terminal session.

---

### Phase 5: Server destruction command and lifecycle cleanup [STATUS: DONE]
- Goal: Implement `dev-vps destroy` command to delete VPS and clean up local tracking.
- Tasks:
  - [x] Implement `dev-vps destroy <name-or-id>`:
    - Flags: `--force` / `-y` to skip confirmation prompt.
    - Resolve server by name or ID.
    - Prompt for confirmation before destruction when running interactively.
    - Call provider `DeleteServer` API.
    - Remove destroyed server from `~/.dev-vps/state.json`.
  - [x] Add unit test verifying state cleanup upon successful deletion.
- Done when: `dev-vps destroy test-box -y` deletes the DO droplet and removes it from `~/.dev-vps/state.json`.

---

### Phase 6: End-to-end polish, error handling, and documentation [STATUS: DONE]
- Goal: Add validation, graceful error messages, and documentation.
- Tasks:
  - [x] Handle missing API tokens, rate limits, and network failure modes with actionable error messages.
  - [x] Validate `~/.dev-vps/auto-setup/init.sh` and SSH key file permissions before operations.
  - [x] Write `README.md` covering prerequisites, setup, token configuration, interactive vs flag usage, and command reference.
  - [x] Run full test suite: `go test -v ./...`.
- Done when: All tests pass, build succeeds via `go build -o dev-vps ./cmd/dev-vps`, and CLI handles edge cases cleanly.

---

## Unknowns, risks, assumptions
- Assumption: Storage root will default to `~/.dev-vps` (overrideable with `DEV_VPS_HOME` environment variable).
- Assumption: SSH key pair will default to Ed25519 (`~/.dev-vps/.ssh/id_ed25519` and `.pub`).
- Assumption: SSH key registration on DigitalOcean will name the key (e.g. `dev-vps-default` or based on hostname/key fingerprint) and skip creation if the fingerprint already exists on the DO account.
- Assumption: Both `--region` and `--size` are optional on the command line; if omitted, the CLI defaults to interactive selection prompts; if provided via flags, the CLI runs headlessly without prompts.
- Assumption: `auto-setup/init.sh` will be passed as cloud-init `user_data` during creation so execution begins immediately on first boot.
- Risk: Cloud-init execution time varies depending on commands inside `init.sh`; SSH command can connect before `init.sh` finishes running. (Mitigation: Provide a message indicating cloud-init runs in background or add an optional wait flag).

