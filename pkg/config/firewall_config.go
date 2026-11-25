package config

// FirewallConfig represents default inbound firewall rules and sources stored under
// the "firewall" key in config.json.
type FirewallConfig struct {
	DefaultRules   []string `json:"default_rules"`
	DefaultSources []string `json:"default_sources"`
}
