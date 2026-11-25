# Implementation Plan: per-droplet firewalls and `dev-vps firewall` commands

Build/test: `go build ./...` and `go test ./...`.

Sorted by dependency: pure rule logic, then config, then the provider layer, then the create/destroy lifecycle, then the `firewall` command group, then docs.

## Design

### Model
- One DigitalOcean Cloud Firewall per droplet, named `dev-vps-<droplet_name>`, attached by droplet ID.
- A rule is `(protocol, port range, sources)`. The rule's identity is `(protocol, port range)`, and its sources form a set.
  - Example: `9000/tcp` from `0.0.0.0/0, ::/0`
  - Example: `5432/tcp` from `203.0.113.7/32`
  - Example: `icmp` from `10.0.0.0/8`
- A single port is a range with equal ends (`9000` is `9000-9000`). ICMP has no port range.
- Outbound rules: all TCP/UDP/ICMP to anywhere. A DO firewall with no outbound rules blocks all egress, which would break apt, git and the startup script.
- To find a droplet's firewall, call `Firewalls.ListByDroplet` and pick the entry whose name starts with `dev-vps-`. Firewalls the user made by hand are never touched.

### Rule spec syntax (positional args, case-insensitive)

| Arg | Meaning |
|---|---|
| `9000` | TCP 9000 (a bare port or range defaults to TCP) |
| `9000/tcp`, `9001/udp` | single port, explicit protocol |
| `9000-9010`, `9000-9010/udp` | inclusive port range |
| `icmp` | ICMP (ping) |

The following are rejected before any API call, and every invalid arg is reported in one error: `0`, `65536`, `9010-9000` (reversed), `9000-`, `9000/icmp`, `icmp/tcp`, `9000/sctp`, `9000/`.

### Custom sources
- Flag: `--source` / `-s` on `allow` and `deny`. It can be repeated or comma-separated (cobra `StringSlice`), and applies to every rule spec in that command.
  - `dev-vps firewall allow my-droplet 5432 --source 203.0.113.7`
  - `dev-vps firewall allow my-droplet 9000-9010/udp icmp -s 10.0.0.0/8,2001:db8::/32`
- Accepted values:
  - IPv4 or IPv6 CIDR, parsed with `net/netip.ParsePrefix`.
  - A bare IP, which becomes `/32` (IPv4) or `/128` (IPv6).
  - The keyword `any`, which expands to `0.0.0.0/0` and `::/0`.
- Rejected values:
  - A CIDR with host bits set, e.g. `10.0.0.1/8`. The error suggests the masked form `10.0.0.0/8`, so a typo is never silently widened.
  - Hostnames.
  - DO-specific sources (droplet IDs, tags, load balancers): out of scope.
- If `--source` is omitted, `firewall.default_sources` from config is used. If that is not set, the built-in default is `0.0.0.0/0, ::/0`.
- Sources are stored normalized and de-duplicated, so `1.2.3.4` and `1.2.3.4/32` count as one source.

### Semantics of `allow` / `deny`
- `allow <specs> [-s S]`: if a rule with the same protocol and range exists, add S to its sources. Otherwise create the rule with S. Sources that are already present are reported as skipped.
- `deny <specs>` without `-s`: remove the whole rule, with all its sources.
- `deny <specs> -s S`: remove only S from the rule. If no sources remain, remove the rule.
- Ranges match exactly; overlapping ranges are not split or merged.
  - `deny 9005` while `9000-9010/tcp` is open reports "not open (covered by 9000-9010/tcp)" and changes nothing.
  - `allow 9005-9020` while `9000-9010/tcp` is open adds a separate rule.
- SSH protection for the exact rule `22/tcp`:
  - `create` always adds it, even if config omits it.
  - `deny 22` without `-s` is refused.
  - `deny 22 -s S` is allowed only if at least one source remains. This allows restricting SSH, e.g. `allow 22 -s <my-ip>` then `deny 22 -s any`.
- Changes are read-modify-write. dev-vps reads the firewall, computes the new inbound rule set locally with pure functions, and writes it back with `Firewalls.Update`. All merge logic is therefore unit-testable without the API.

### Config (`~/.dev-vps/config.json`)
```json
"firewall": {
  "default_rules": ["22", "80", "443", "8080", "8081", "3000", "8000"],
  "default_sources": ["0.0.0.0/0", "::/0"]
}
```
- `default_rules` uses the same spec syntax as the CLI, so ranges, `/udp` and `icmp` work there too. 5432 is no longer in the defaults.
- A missing `firewall` block or missing key falls back to the built-in values above. Existing users' configs keep working, and config files are never rewritten.
- New installs get the block written by `DefaultConfig()`, so the setting is easy to find.
- Validation runs in `create` **before** the droplet is provisioned. An invalid config fails fast and creates no droplet.

## Phases

### Phase 1: Pure firewall rule logic in a new `pkg/firewall` package [STATUS: DONE]
- Goal: parsing, normalizing, formatting and merging rules, with no IO and fully unit-tested.
- Tasks:
  - [x] Add a `NetworkProtocol` enum (`tcp`, `udp`, `icmp`) in `pkg/types/enums.go` with tests in `enums_test.go`.
  - [x] `pkg/firewall/port_range.go`: `PortRange{From, To int}` with validation and `String()`, which renders `9000` or `9000-9010`.
  - [x] `pkg/firewall/rule.go`: `Rule{Protocol, Ports PortRange, Sources []string}`, plus `Key()` for identity and `Spec()`, which renders `9000-9010/tcp` or `icmp`.
  - [x] `pkg/firewall/spec.go`: `ParseRuleSpecs(args []string) ([]Rule, error)` implements the syntax table. It removes duplicates (`9000` and `9000/tcp` count as one rule) and reports all invalid args together.
  - [x] `pkg/firewall/source.go`: `ParseSources(values []string) ([]string, error)` handles CIDR, bare IP and `any`, rejects host bits, and normalizes and de-duplicates.
  - [x] `pkg/firewall/ruleset.go`:
    - `Allow(current, specs, sources)` and `Deny(current, specs, sources)` return the new rule set plus a change report (added, skipped, covered-by).
    - Both apply the SSH protection rules. `Deny` returns a typed `ErrSSHRuleProtected`.
  - [x] `pkg/firewall/defaults.go`: the built-in default specs and sources, plus `BuildDefaultRules(specs, sources []string) ([]Rule, error)`, which parses both and makes sure `22/tcp` is present.
  - [x] A `_test.go` file per source file, covering every row of the syntax table, every source case, every allow/deny semantics bullet, and the SSH protection cases.
- Done when: `go test ./pkg/firewall/... ./pkg/types/...` is green. Nothing else uses the package yet.

### Phase 2: `firewall` section in `config.json` [STATUS: TODO]
- Goal: default rules and default sources are configurable, with a fallback to the built-in values.
- Tasks:
  - [ ] `pkg/config/firewall_config.go`: `FirewallConfig{DefaultRules []string, DefaultSources []string}` with json tags `default_rules` and `default_sources`. Add `Firewall *FirewallConfig` (json tag `firewall,omitempty`) to `Config`.
  - [ ] Populate the block in `DefaultConfig()` from the `pkg/firewall` built-in defaults, so the values live in one place.
  - [ ] A helper in `cmd/dev-vps` (e.g. `firewall_defaults.go`) resolves config to `[]firewall.Rule` and the default sources. A nil block or nil field means built-in defaults; an explicit empty `default_rules` means `22/tcp` only.
  - [ ] Tests in `pkg/config/config_test.go` and `cmd/dev-vps`:
    - an old config without the block loads and resolves to the built-in values;
    - a custom block with ranges, UDP and ICMP resolves correctly;
    - an invalid spec or source in config gives a clear error naming the config key;
    - a config without `22` still gets `22/tcp`.
- Done when: `go test ./...` is green and a fresh `--home-dir` produces `config.json` with the `firewall` block.

### Phase 3: Firewall support in the provider layer [STATUS: TODO]
- Goal: `provider.Provider` can create, read, replace and delete a droplet's inbound rules.
- Tasks:
  - [ ] Add `provider.FirewallInfo{ID, Name, ServerID, InboundRules []firewall.Rule}`, the typed `ErrFirewallNotFound` and the `FirewallNamePrefix = "dev-vps-"` constant in `pkg/provider/provider.go`.
  - [ ] Add these interface methods to `Provider`:
    - `CreateFirewall(ctx, serverID, name, rules)`
    - `GetFirewall(ctx, serverID)`
    - `UpdateFirewallRules(ctx, serverID, rules)`: replaces the inbound rules and keeps the name, droplets and outbound rules.
    - `DeleteFirewall(ctx, serverID)`: a no-op when no firewall exists.
  - [ ] Implement them in `pkg/provider/digitalocean/digitalocean.go` with godo `Firewalls.Create/ListByDroplet/Update/Delete`. Use two shared mappers:
    - `firewall.Rule` to `godo.InboundRule`: ICMP gets an empty `PortRange`, a single port gets `"9000"`, a range gets `"9000-9010"`, and sources go in `Sources.Addresses`.
    - `godo.InboundRule` to `firewall.Rule`: DO's `"all"` or `"0"` port range becomes `1-65535`. Non-address sources (tags, droplet IDs) are kept as-is when writing back, so console-made sources are not erased.
  - [ ] Add httptest handlers for `/v2/firewalls` and `/v2/firewalls/{id}` in `digitalocean_test.go`. Assert that:
    - create includes outbound rules;
    - ICMP is sent without `ports`;
    - a range is sent as `"9000-9010"`;
    - update keeps outbound rules and droplet IDs;
    - the lookup skips firewalls without the `dev-vps-` prefix.
  - [ ] Add the new methods to `mockProvider` in `cmd/dev-vps/commands_test.go`, backed by an in-memory map keyed by server ID.
- Done when: `go test ./...` is green and the provider tests cover create, get (found and not found), update and delete.

### Phase 4: Create the firewall on `create`, delete it on `destroy` [STATUS: TODO]
- Goal: every new droplet gets the configured default firewall, and destroying the droplet removes it.
- Tasks:
  - [ ] In `runCreateServer`, resolve the firewall defaults (Phase 2) right after `LoadConfig`, before any provider call, so a bad config fails without creating a droplet.
  - [ ] After `pollServerActive`, call `CreateFirewall`. If it fails, warn and keep the droplet: the droplet still works, and `firewall allow` (Phase 6) can create the missing firewall. Print the open rules in the success summary.
  - [ ] In `runDestroyServer`, call `DeleteFirewall` before `DeleteServer`, because `ListByDroplet` cannot find the firewall once the droplet is gone. If it fails, warn and continue with the droplet deletion.
  - [ ] Tests in `commands_test.go`:
    - create uses the config rules and sources;
    - create with no firewall block uses the built-in defaults (5432 absent);
    - an invalid firewall config makes create fail with no `CreateServer` call;
    - a firewall API error still finishes create with a warning;
    - destroy removes the firewall, and destroying a droplet without a firewall succeeds.
- Done when: the tests pass. Manual check: `dev-vps create` shows a firewall `dev-vps-<name>` in the DO console with the configured rules, and `dev-vps destroy` removes it.

### Phase 5: `dev-vps firewall list <droplet_name>` [STATUS: TODO]
- Goal: show a droplet's inbound rules as a table, with `--json` support like `list`.
- Tasks:
  - [ ] Add `cmd/dev-vps/firewall.go` with `newFirewallCmd` (group command) and `newFirewallListCmd`. Register the group in `main.go`.
  - [ ] Table columns: `RULE` (`9000-9010/tcp`), `PROTOCOL`, `PORTS` (`-` for ICMP), `SOURCES` (comma-joined). Sort TCP, then UDP, then ICMP, and by start port within each protocol. Use one rendering function, which Phase 6 reuses.
  - [ ] Shared helper `resolveServerID(ctx, prov, nameOrID)`: look in local state first, then fall back to `ListServers`. Reuse it in `destroy.go` only if it actually removes duplicated code there.
  - [ ] If the droplet has no firewall, print a hint: `dev-vps firewall allow <name> <rule>` creates one.
  - [ ] Tests: table output (single port, range, ICMP, multiple sources), JSON output, unknown droplet, and a droplet without a firewall.
- Done when: the tests pass and `dev-vps firewall list my-droplet` shows the default rules.

### Phase 6: `dev-vps firewall allow` and `deny` with `--source` [STATUS: TODO]
- Goal: `dev-vps firewall allow|deny <droplet_name> <rule...> [--source S...]` changes the rules as described in the Design section.
- Tasks:
  - [ ] Both commands take `cobra.MinimumNArgs(2)` and a `--source/-s` `StringSlice` flag. They parse specs and sources first, so invalid input causes no API call.
  - [ ] `allow`:
    - Use `GetFirewall`, then `firewall.Allow`, then `UpdateFirewallRules`.
    - On `ErrFirewallNotFound`, create the firewall with `22/tcp` (default sources) plus the requested rules. This also covers droplets that existed before this feature.
  - [ ] `deny`: use `GetFirewall`, then `firewall.Deny`, then `UpdateFirewallRules`. Surface `ErrSSHRuleProtected` with a hint on how to restrict SSH instead.
  - [ ] Skip the API write when the change report is empty, i.e. nothing changed.
  - [ ] Print the change report (added, removed, skipped, covered-by), then the resulting rule table.
  - [ ] Show the syntax table, the `--source` values and examples in `Long` help for both commands.
  - [ ] Tests in `commands_test.go`:
    - allow `9000 icmp 9001/udp 9100-9110`;
    - allow with `-s` merging into an existing rule;
    - allow when the droplet has no firewall;
    - deny a whole rule; deny with `-s` (partial, and last source removing the rule);
    - deny `22` refused; deny `22 -s any` refused when it would empty the rule and allowed when another source remains;
    - deny `9005` when a range covers it;
    - invalid spec or source (no API call);
    - no-op change (no update call).
- Done when: the tests pass. Manual check: `allow my-droplet 9000-9002 icmp -s <my-ip>`, then `list` shows them with `<my-ip>/32`, `ping` works from your machine only, and `deny` removes them.

### Phase 7: Docs [STATUS: TODO]
- Goal: users can find the feature in the docs.
- Tasks:
  - [ ] Document the following in `README.md`:
    - the `firewall` config block and its fallback behavior;
    - the subcommands, the rule spec syntax (ports, ranges, `/tcp`, `/udp`, `icmp`) and the `--source` values;
    - the SSH protection rules, including the "restrict SSH to my IP" recipe.
  - [ ] Tick the firewall items in `TODO.md`.
- Done when: the README examples match the actual CLI `--help` output.

## Unknowns, risks, assumptions
- Assumption: `--source` applies to all specs in one command. Per-spec sources (e.g. `5432@1.2.3.4`) are not supported; run the command twice instead.
- Assumption: a `me` keyword (auto-detecting your public IP) is out of scope, because it needs an external IP-echo service. It is a cheap later addition on top of `ParseSources`.
- Assumption: ICMP is not in the built-in defaults. Add `"icmp"` to `default_rules` in config if you want ping.
- Assumption: ranges match exactly, with no splitting or merging of overlaps. This keeps `deny` predictable.
- Risk: read-modify-write means two concurrent `allow`/`deny` runs on the same droplet can lose one change. This is acceptable for a single-user dev tool.
- Risk: `deny 22 -s ...` can lock you out if the remaining sources don't include your IP. dev-vps cannot know your IP without the `me` lookup, so the help text and README must warn about this.
- Risk: the DO token needs firewall write scope. A token scoped only to droplets makes `create` warn and skip the firewall.
- Risk: DO limits firewalls to 50 inbound rules each. Each protocol/range pair counts as one rule. Ranges help stay under the limit.
- Firewall names derive from the droplet name. Two droplets with the same name get firewalls with the same name, which is safe because lookup goes by droplet ID, not by name.
