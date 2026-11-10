# Implementation Plan: ssh exit bug, SSH key copy/import, API-backed list

Build/test: `go build ./...` and `go test ./...`.

Sorted by dependency: bug fix, then key commands (share a key-file helper), then the list/API change, which is the largest behavior change.

### Phase 1: Fix `dev-vps ssh` printing usage after remote exit [STATUS: DONE]
- Goal: A non-zero ssh exit (e.g. Ctrl+D after a failed last command) must not print cobra usage/help.
- Tasks:
  - [x] Reproduce with a test in `cmd/dev-vps/commands_test.go`: `sshExecutor` returns an `*exec.ExitError`; assert no usage text in output.
  - [x] Set `cmd.SilenceUsage = true` in `runSSHConnect` once args and state are validated, just before `sshExecutor` runs. Early errors such as an unknown server keep their usage output.
  - [x] Check `main.go` propagates the ssh exit code as the process exit code.
- Done when: the new test passes and `go test ./cmd/...` is green. Manual check: `dev-vps ssh`, then `exit 3` or Ctrl+D, prints no usage text.

### Phase 2: Shared SSH key file helper plus `ssh copy` command [STATUS: DONE]
- Goal: `dev-vps ssh copy [path]` copies the managed key pair to `path` (default: current dir).
- Tasks:
  - [x] Add a helper in `pkg/sshutil/keys.go` that copies a key pair between directories. It sets perms 0600 for the private key and 0644 for the public key, and refuses to overwrite existing files unless `--force` is given. Phase 3 reuses it.
  - [x] Add `newSSHCopyCmd` in `cmd/dev-vps/ssh.go` and register it in `newSSHCmd`. It takes an optional path arg and a `--force` flag, fails if the managed key is missing (hint: `dev-vps ssh create`), and prints the destination paths.
  - [x] Unit tests for the helper in `pkg/sshutil/keys_test.go`: perms, default dir, overwrite refusal, missing source. CLI test in `commands_test.go`.
  - [x] Verify cobra routing: `ssh` uses `DisableFlagParsing`, so check that `ssh copy` and `ssh create` still dispatch to their subcommands.
- Done when: tests pass and `dev-vps ssh copy /tmp/x` yields `id_ed25519` (0600) and `id_ed25519.pub` (0644) there.

### Phase 3: `ssh import` command (from `~/.ssh` to `~/.dev-vps/.ssh`) [STATUS: DONE]
- Goal: `dev-vps ssh import [key-path]` imports an existing user key as the managed key.
- Tasks:
  - [x] Add `newSSHImportCmd`. The source defaults to `~/.ssh/id_ed25519`. The user can pass another private key path, and the matching `.pub` is expected next to it.
  - [x] Reuse the Phase 2 copy helper, targeting `config.SSHPrivateKeyPath` and `config.SSHPublicKeyPath` (respecting `customBaseDir`). The destination names are fixed, so an imported RSA key is saved under the `id_ed25519` names. Decide in Phase 3 whether to support only ed25519 or to generalize the key filenames.
  - [x] Refuse to overwrite an existing managed key without `--force`. Validate that the source key parses with `golang.org/x/crypto/ssh`.
  - [x] Print a reminder to run `dev-vps ssh create` to register the key with the provider.
  - [x] Tests using temp dirs: success, missing source, existing destination, `--force`, invalid key.
- Done when: tests pass and an imported key is used by `dev-vps ssh` (`-i` path matches).

### Phase 4: `list` fetches from the provider API [STATUS: TODO]
- Goal: `dev-vps list` shows live provider data, so state from another machine is not stale.
- Tasks:
  - [ ] Extract a shared function (e.g. in `cmd/dev-vps/provider.go`) that loads config, builds the provider via `providerFactory`, and calls `ListServers`. `ListServers` already filters by `DevVPSTag`.
  - [ ] Convert `provider.ServerInfo` to `config.ServerRecord` through one shared mapper. Reuse it in `create.go` if the mapping is duplicated there.
  - [ ] Make `runListServers` use the API result for display. Show the same columns and keep `--json`.
  - [ ] Reconcile local state with the API result: add servers seen only in the API, and drop local entries that no longer exist remotely. Then save, so `ssh` and `destroy` also work on servers created from another machine. Decide the final semantics for this step.
  - [ ] Add an offline fallback: if the API call fails, warn and show the cached state.
  - [ ] Update `mockProvider` and the list tests in `commands_test.go`: API-only server shown, stale local server removed, API error fallback, JSON output.
- Done when: `go test ./...` passes and `dev-vps list` on a machine with empty state shows existing tagged droplets.

## Unknowns, risks, assumptions
- Assumption: "copy keys" means the managed key pair (`~/.dev-vps/.ssh`), and "import" supports a single key pair (default `id_ed25519`), not the whole `~/.ssh` directory.
- Risk: the Phase 4 reconcile writes state and deletes local records. The conservative option is for `list` to display API data without mutating state, which is simpler. Tell me if you want that instead.
- Risk: the `ssh` command has `DisableFlagParsing`, so `--force` on `ssh copy` and `ssh import` needs verification (Phase 2). The subcommands themselves still parse flags.
- Risk: servers created from another machine may have been created with a different SSH key. Importing or copying keys (Phases 2-3) is the intended workaround.
- Phase 4 needs a valid provider token even for `list`, and `list` was previously offline-capable. The fallback covers this.

