package digitalocean_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider/digitalocean"
)

func TestAPIErrorIncludesHTTPStatusAndJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"id":"forbidden","message":"You do not have access for the attempted action."}`))
	}))
	defer server.Close()

	client := digitalocean.New(
		"secret-token-value",
		digitalocean.WithHTTPClient(server.Client()),
		digitalocean.WithBaseURL(server.URL),
	)

	_, err := client.ListSizes(context.Background(), "sgp1")
	if err == nil {
		t.Fatalf("expected error on 403 response, got nil")
	}

	msg := err.Error()
	for _, want := range []string{
		"HTTP 403 Forbidden",
		"GET " + server.URL + "/v2/sizes?per_page=200",
		`"id": "forbidden"`,
		`"message": "You do not have access for the attempted action."`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected error to contain %q, got:\n%s", want, msg)
		}
	}

	var apiErr *digitalocean.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected error to unwrap as *digitalocean.APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("expected StatusCode 403, got %d", apiErr.StatusCode)
	}

	var godoErr *godo.ErrorResponse
	if !errors.As(err, &godoErr) {
		t.Errorf("expected error to still unwrap as *godo.ErrorResponse")
	}
}

func TestListSizesEmptyDiagnostics(t *testing.T) {
	t.Run("200 OK with empty sizes array includes status and JSON body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sizes":[],"links":{},"meta":{"total":0}}`))
		}))
		defer server.Close()

		client := digitalocean.New(
			"fake-token",
			digitalocean.WithHTTPClient(server.Client()),
			digitalocean.WithBaseURL(server.URL),
		)

		_, err := client.ListSizes(context.Background(), "sgp1")
		if err == nil {
			t.Fatalf("expected diagnostic error when sizes array is empty, got nil")
		}
		msg := err.Error()
		for _, want := range []string{
			`no sizes available for region "sgp1"`,
			"HTTP 200 OK",
			"returned 0 sizes, 0 available, 0 in region \"sgp1\"",
			"meta.total=0",
			`"sizes": []`,
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("expected error to contain %q, got:\n%s", want, msg)
			}
		}
	})

	t.Run("200 OK with non-matching sizes reports counts and pagination", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sizes":[{"slug":"s-1vcpu-1gb","available":true,"regions":["nyc1"]}],"links":{"pages":{"next":"https://api.digitalocean.com/v2/sizes?page=2&per_page=200"}},"meta":{"total":250}}`))
		}))
		defer server.Close()

		client := digitalocean.New(
			"fake-token",
			digitalocean.WithHTTPClient(server.Client()),
			digitalocean.WithBaseURL(server.URL),
		)

		_, err := client.ListSizes(context.Background(), "sgp1")
		if err == nil {
			t.Fatalf("expected diagnostic error when no sizes match region, got nil")
		}
		msg := err.Error()
		for _, want := range []string{
			`no sizes available for region "sgp1"`,
			"HTTP 200 OK",
			`returned 1 sizes, 1 available, 0 in region "sgp1"`,
			"meta.total=250",
			"has_next_page=true",
			"--debug",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("expected error to contain %q, got:\n%s", want, msg)
			}
		}
	})
}

func TestWithDebugWriterLogsStatusAndJSONWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"regions":[{"slug":"sgp1","name":"Singapore 1","available":true}]}`))
	}))
	defer server.Close()

	var debugBuf bytes.Buffer
	client := digitalocean.New(
		"super-secret-token",
		digitalocean.WithDebugWriter(&debugBuf),
		digitalocean.WithHTTPClient(server.Client()),
		digitalocean.WithBaseURL(server.URL),
	)

	regions, err := client.ListRegions(context.Background())
	if err != nil {
		t.Fatalf("ListRegions failed: %v", err)
	}
	if len(regions) != 1 || regions[0].Slug != "sgp1" {
		t.Fatalf("unexpected regions: %+v", regions)
	}

	out := debugBuf.String()
	for _, want := range []string{
		"[HTTP] GET " + server.URL + "/v2/regions?per_page=100 -> 200 OK",
		`"slug": "sgp1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected debug output to contain %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "super-secret-token") {
		t.Errorf("debug output must not leak token, got:\n%s", out)
	}
}
