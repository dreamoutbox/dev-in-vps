# Implementation Plan: Internal IP Tracking and Startup Script Logging

## Overview
Add private/internal IPv4 tracking across the cloud provider layer, local state storage, `dev-vps create` output, and `dev-vps list` table/JSON output. Additionally, configure VPS bootstrap (`user_data`) execution so all startup script stdout and stderr are piped to `/dev-vps/startup.log` on the provisioned VPS.

---

### Phase 1: Provider and State Internal IP Support [STATUS: DONE]
- Goal: Extend provider models, DigitalOcean adapter, and local state persistence to capture and store the server's private/internal IPv4 address.
- Tasks:
  - [x] Add `PrivateIPAddress string` (`json:"private_ip_address"`) to `provider.ServerInfo` in `pkg/provider/provider.go` and `config.ServerRecord` in `pkg/config/state.go`.
  - [x] Extract a helper function in `pkg/provider/digitalocean/digitalocean.go` to map a `godo.Droplet` to `provider.ServerInfo` (eliminating duplicate mapping code across `CreateServer`, `ListServers`, and `GetServer`) and populate `PrivateIPAddress` via `droplet.PrivateIPv4()`.
  - [x] Update unit tests in `pkg/provider/digitalocean/digitalocean_test.go` and `pkg/config/config_test.go` to verify private IPv4 extraction and state serialization.
- Done when: `go test ./pkg/...` passes and both public and private IPv4 addresses are populated from DigitalOcean API responses and persisted in `state.json`.

---

### Phase 2: Internal IP Display in `create` and `list` Commands [STATUS: DONE]
- Goal: Surface the internal IP address in `dev-vps create` summary output and as a column in `dev-vps list`.
- Tasks:
  - [x] Update `runCreateServer` in `cmd/dev-vps/create.go` to copy `activeInfo.PrivateIPAddress` into `config.ServerRecord` and print `Internal IP` alongside `IP Address` in the creation summary.
  - [x] Update `runListServers` in `cmd/dev-vps/list.go` to include the `INTERNAL IP` column in the tabular output (displaying `-` when empty for backward compatibility with older state entries).
  - [x] Update `mockProvider` and CLI tests in `cmd/dev-vps/commands_test.go` to assert `Internal IP` output in `dev-vps create` and `INTERNAL IP` column / JSON field in `dev-vps list`.
- Done when: `go test ./cmd/...` passes; `dev-vps create` prints the internal IP and `dev-vps list` displays the `INTERNAL IP` column.

---

### Phase 3: Pipe Startup Script Output to `/dev-vps/startup.log` [STATUS: DONE]
- Goal: Ensure startup script execution redirects both stdout and stderr to `/dev-vps/startup.log` inside the VPS.
- Tasks:
  - [x] Implement a user-data formatting helper that ensures `/dev-vps` exists (`mkdir -p /dev-vps`) and redirects stdout and stderr (`exec > /dev-vps/startup.log 2>&1`) for both default `init.sh` in `pkg/config/config.go` and custom `--init-script` scripts loaded in `cmd/dev-vps/create.go`.
  - [x] Add unit tests in `pkg/config/config_test.go` and `cmd/dev-vps/commands_test.go` verifying the startup script redirection to `/dev-vps/startup.log` is present in generated/submitted `UserData`.
  - [x] Update `README.md` to document `/dev-vps/startup.log` for inspecting first-boot setup logs and mark completed items in `TODO.md`.
- Done when: `go test -v ./...` and `./build.sh` succeed, and any provisioned server's `UserData` logs all stdout/stderr to `/dev-vps/startup.log`.

---

## Unknowns, risks, assumptions
- Assumption: DigitalOcean's VPC networking is enabled by default on modern regions, so `droplet.PrivateIPv4()` returns the internal VPC IP without needing changes to `DropletCreateRequest`.
- Assumption: Existing records in `~/.dev-vps/state.json` created prior to this change may have an empty `private_ip_address`; `dev-vps list` will render `-` in the `INTERNAL IP` column when empty.
- Assumption: Wrapping or preamble injection (`mkdir -p /dev-vps && exec > /dev-vps/startup.log 2>&1`) is applied to shell user-data scripts so both newly generated `init.sh` files and pre-existing `~/.dev-vps/auto-setup/init.sh` files log to `/dev-vps/startup.log`.

