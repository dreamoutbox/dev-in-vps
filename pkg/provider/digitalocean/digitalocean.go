// Package digitalocean implements the cloud provider interface for DigitalOcean.
package digitalocean

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/digitalocean/godo"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

const (
	// DefaultImage is the base OS distribution used for dev VPS instances.
	DefaultImage = "ubuntu-24-04-x64"
)

// Client provides an adapter to interact with the DigitalOcean API.
type Client struct {
	client *godo.Client
}

// Option configures a Client instance.
type Option func(*Client)

// WithHTTPClient overrides the default HTTP client (useful for unit testing with httptest).
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.client = godo.NewClient(httpClient)
	}
}

// WithBaseURL overrides the API base URL (useful for mock servers in tests).
func WithBaseURL(rawURL string) Option {
	return func(c *Client) {
		if c.client != nil {
			if parsed, err := url.Parse(rawURL); err == nil {
				c.client.BaseURL = parsed
			}
		}
	}
}

// New creates a new DigitalOcean provider client using the supplied token.
//
// Input args:
//   - token: Personal Access Token for DigitalOcean API.
//   - opts: optional functional configuration options.
//
// Returns:
//   - *Client: initialized provider client.
//
// Example:
//
//	doClient := digitalocean.New("do-token-here")
func New(token string, opts ...Option) *Client {
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauthClient := oauth2.NewClient(context.Background(), tokenSource)
	c := &Client{
		client: godo.NewClient(oauthClient),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Type returns the ProviderDigitalOcean enumeration identifier.
func (c *Client) Type() types.ProviderType {
	return types.ProviderDigitalOcean
}

// ListRegions fetches all available DigitalOcean datacenter regions.
//
// Input args:
//   - ctx: execution context.
//
// Returns:
//   - []provider.Region: list of datacenter regions.
//   - error: non-nil if API query fails.
//
// Example:
//
//	regions, err := client.ListRegions(ctx)
func (c *Client) ListRegions(ctx context.Context) ([]provider.Region, error) {
	opts := &godo.ListOptions{PerPage: 100}
	regions, _, err := c.client.Regions.List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list DigitalOcean regions: %w", err)
	}

	result := make([]provider.Region, 0, len(regions))
	for _, r := range regions {
		result = append(result, provider.Region{
			Slug:      r.Slug,
			Name:      r.Name,
			Available: r.Available,
		})
	}
	return result, nil
}

// ListSizes fetches all compute droplet sizes, optionally filtering by region availability.
//
// Input args:
//   - ctx: execution context.
//   - regionSlug: optional region slug to filter (if empty, all sizes returned).
//
// Returns:
//   - []provider.Size: list of available hardware specifications.
//   - error: non-nil if API query fails.
//
// Example:
//
//	sizes, err := client.ListSizes(ctx, "nyc1")
func (c *Client) ListSizes(ctx context.Context, regionSlug string) ([]provider.Size, error) {
	opts := &godo.ListOptions{PerPage: 200}
	sizes, _, err := c.client.Sizes.List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list DigitalOcean sizes: %w", err)
	}

	result := make([]provider.Size, 0, len(sizes))
	for _, s := range sizes {
		if !s.Available {
			continue
		}
		if regionSlug != "" {
			regionSupported := false
			for _, r := range s.Regions {
				if r == regionSlug {
					regionSupported = true
					break
				}
			}
			if !regionSupported {
				continue
			}
		}

		result = append(result, provider.Size{
			Slug:         s.Slug,
			VCPUs:        s.Vcpus,
			MemoryMB:     s.Memory,
			DiskGB:       s.Disk,
			PriceMonthly: s.PriceMonthly,
			PriceHourly:  s.PriceHourly,
			Regions:      s.Regions,
		})
	}
	return result, nil
}

// computeMD5Fingerprint calculates MD5 fingerprint formatted as hex colons for DigitalOcean API.
func computeMD5Fingerprint(pubKeyStr string) (string, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		return "", fmt.Errorf("invalid ssh public key: %w", err)
	}
	hash := md5.Sum(pubKey.Marshal())
	hexStr := hex.EncodeToString(hash[:])
	var formatted strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			formatted.WriteByte(':')
		}
		formatted.WriteString(hexStr[i : i+2])
	}
	return formatted.String(), nil
}

// EnsureSSHKey verifies if the specified SSH key already exists on DigitalOcean, uploading it if missing.
//
// Input args:
//   - ctx: execution context.
//   - name: label identifier to name the key on DigitalOcean.
//   - publicKey: raw authorized_keys formatted public key string.
//
// Returns:
//   - string: stringified key ID or fingerprint.
//   - error: non-nil if verification or creation fails.
//
// Example:
//
//	keyID, err := client.EnsureSSHKey(ctx, "dev-vps-key", pubKeyData)
func (c *Client) EnsureSSHKey(ctx context.Context, name string, publicKey string) (string, error) {
	trimmedKey := strings.TrimSpace(publicKey)
	fingerprint, err := computeMD5Fingerprint(trimmedKey)
	if err != nil {
		return "", err
	}

	// Check if key exists by fingerprint
	existingKey, resp, err := c.client.Keys.GetByFingerprint(ctx, fingerprint)
	if err == nil && existingKey != nil {
		return strconv.Itoa(existingKey.ID), nil
	}
	if resp != nil && resp.StatusCode != http.StatusNotFound && err != nil {
		return "", fmt.Errorf("failed to lookup ssh key by fingerprint: %w", err)
	}

	// Key not found on DO, create it
	keyReq := &godo.KeyCreateRequest{
		Name:      name,
		PublicKey: trimmedKey,
	}
	newKey, _, err := c.client.Keys.Create(ctx, keyReq)
	if err != nil {
		return "", fmt.Errorf("failed to upload ssh key to DigitalOcean: %w", err)
	}

	return strconv.Itoa(newKey.ID), nil
}

// CreateServer provisions a new Droplet with user-data, SSH key, and dev-vps tag.
//
// Input args:
//   - ctx: execution context.
//   - req: server creation parameters.
//
// Returns:
//   - *provider.ServerInfo: provisioned server metadata.
//   - error: non-nil if droplet creation fails.
//
// Example:
//
//	info, err := client.CreateServer(ctx, req)
func (c *Client) CreateServer(ctx context.Context, req provider.CreateServerRequest) (*provider.ServerInfo, error) {
	image := req.Image
	if image == "" {
		image = DefaultImage
	}

	tags := append([]string{provider.DevVPSTag}, req.Tags...)

	var sshKeys []godo.DropletCreateSSHKey
	if req.SSHKeyID != "" {
		if id, err := strconv.Atoi(req.SSHKeyID); err == nil {
			sshKeys = append(sshKeys, godo.DropletCreateSSHKey{ID: id})
		} else {
			sshKeys = append(sshKeys, godo.DropletCreateSSHKey{Fingerprint: req.SSHKeyID})
		}
	}

	createReq := &godo.DropletCreateRequest{
		Name:     req.Name,
		Region:   req.Region,
		Size:     req.Size,
		Image:    godo.DropletCreateImage{Slug: image},
		SSHKeys:  sshKeys,
		UserData: req.UserData,
		Tags:     tags,
	}

	droplet, _, err := c.client.Droplets.Create(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create DigitalOcean droplet: %w", err)
	}

	ip, _ := droplet.PublicIPv4()
	createdAt, _ := time.Parse(time.RFC3339, droplet.Created)
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	return &provider.ServerInfo{
		ID:        strconv.Itoa(droplet.ID),
		Name:      droplet.Name,
		Provider:  types.ProviderDigitalOcean,
		Region:    droplet.Region.Slug,
		Size:      droplet.SizeSlug,
		IPAddress: ip,
		Status:    mapDropletStatus(droplet.Status),
		CreatedAt: createdAt,
	}, nil
}

// ListServers returns all droplets tagged with dev-vps.
//
// Input args:
//   - ctx: execution context.
//
// Returns:
//   - []provider.ServerInfo: list of active server instances.
//   - error: non-nil if query fails.
//
// Example:
//
//	servers, err := client.ListServers(ctx)
func (c *Client) ListServers(ctx context.Context) ([]provider.ServerInfo, error) {
	opts := &godo.ListOptions{PerPage: 100}
	droplets, _, err := c.client.Droplets.ListByTag(ctx, provider.DevVPSTag, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list droplets by tag %s: %w", provider.DevVPSTag, err)
	}

	result := make([]provider.ServerInfo, 0, len(droplets))
	for _, d := range droplets {
		ip, _ := d.PublicIPv4()
		createdAt, _ := time.Parse(time.RFC3339, d.Created)
		if createdAt.IsZero() {
			createdAt = time.Now()
		}
		result = append(result, provider.ServerInfo{
			ID:        strconv.Itoa(d.ID),
			Name:      d.Name,
			Provider:  types.ProviderDigitalOcean,
			Region:    d.Region.Slug,
			Size:      d.SizeSlug,
			IPAddress: ip,
			Status:    mapDropletStatus(d.Status),
			CreatedAt: createdAt,
		})
	}

	return result, nil
}

// GetServer retrieves details and network status of a droplet by its ID.
//
// Input args:
//   - ctx: execution context.
//   - id: droplet ID string.
//
// Returns:
//   - *provider.ServerInfo: updated droplet info.
//   - error: non-nil if lookup fails.
//
// Example:
//
//	info, err := client.GetServer(ctx, "123456")
func (c *Client) GetServer(ctx context.Context, id string) (*provider.ServerInfo, error) {
	dropletID, err := strconv.Atoi(id)
	if err != nil {
		return nil, fmt.Errorf("invalid droplet id %s: %w", id, err)
	}

	droplet, _, err := c.client.Droplets.Get(ctx, dropletID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch droplet %d: %w", dropletID, err)
	}

	ip, _ := droplet.PublicIPv4()
	createdAt, _ := time.Parse(time.RFC3339, droplet.Created)
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	return &provider.ServerInfo{
		ID:        strconv.Itoa(droplet.ID),
		Name:      droplet.Name,
		Provider:  types.ProviderDigitalOcean,
		Region:    droplet.Region.Slug,
		Size:      droplet.SizeSlug,
		IPAddress: ip,
		Status:    mapDropletStatus(droplet.Status),
		CreatedAt: createdAt,
	}, nil
}

// DeleteServer destroys a droplet by its ID.
//
// Input args:
//   - ctx: execution context.
//   - id: droplet ID string.
//
// Returns:
//   - error: non-nil if deletion fails.
//
// Example:
//
//	err := client.DeleteServer(ctx, "123456")
func (c *Client) DeleteServer(ctx context.Context, id string) error {
	dropletID, err := strconv.Atoi(id)
	if err != nil {
		return fmt.Errorf("invalid droplet id %s: %w", id, err)
	}

	_, err = c.client.Droplets.Delete(ctx, dropletID)
	if err != nil {
		return fmt.Errorf("failed to delete droplet %d: %w", dropletID, err)
	}

	return nil
}

// mapDropletStatus converts DigitalOcean droplet status strings to typed ServerStatus enum.
func mapDropletStatus(raw string) types.ServerStatus {
	switch raw {
	case "active":
		return types.StatusActive
	case "off":
		return types.StatusOff
	case "archive":
		return types.StatusDestroyed
	case "new":
		return types.StatusPending
	default:
		return types.StatusPending
	}
}
