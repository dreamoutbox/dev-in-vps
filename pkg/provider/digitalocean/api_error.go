package digitalocean

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/digitalocean/godo"
)

// APIError wraps a DigitalOcean API failure with HTTP request details, status, and raw JSON body.
type APIError struct {
	Action     string
	Method     string
	URL        string
	StatusCode int
	Status     string
	Body       string
	Err        error
}

// Error formats the API failure including HTTP status, request target, and raw response body.
func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString(e.Action)
	b.WriteString(": HTTP ")
	if e.Status != "" {
		b.WriteString(e.Status)
	} else {
		b.WriteString(fmt.Sprintf("%d", e.StatusCode))
	}
	if e.Method != "" || e.URL != "" {
		b.WriteString(fmt.Sprintf(" (%s %s)", e.Method, e.URL))
	}
	if e.Body != "" {
		b.WriteString("\n")
		b.WriteString(e.Body)
	}
	return b.String()
}

// Unwrap returns the underlying error so errors.Is and errors.As continue to work.
func (e *APIError) Unwrap() error {
	return e.Err
}

// wrapAPIError enriches a godo API error with HTTP status and raw response JSON when available.
//
// Input args:
//   - action: human-readable description of the failed operation.
//   - resp: optional godo response returned by the API call.
//   - err: error returned by godo.
//
// Returns:
//   - error: *APIError if an HTTP response was received, otherwise a wrapped error.
//
// Example:
//
//	if err != nil {
//		return nil, wrapAPIError("failed to list DigitalOcean sizes", resp, err)
//	}
func wrapAPIError(action string, resp *godo.Response, err error) error {
	if err == nil {
		return nil
	}

	httpResp := resolveHTTPResponse(resp, err)
	if httpResp == nil {
		return fmt.Errorf("%s: %w", action, err)
	}

	method, reqURL := requestSummary(httpResp)
	return &APIError{
		Action:     action,
		Method:     method,
		URL:        reqURL,
		StatusCode: httpResp.StatusCode,
		Status:     httpResp.Status,
		Body:       formatResponseBody(extractCapturedBody(httpResp)),
		Err:        err,
	}
}

// formatEmptySizesError builds a diagnostic error when DigitalOcean returns 2xx but no sizes match.
func formatEmptySizesError(regionSlug string, resp *godo.Response, sizes []godo.Size, availableCount int) error {
	var httpResp *http.Response
	if resp != nil {
		httpResp = resp.Response
	}

	var details []string
	if httpResp != nil {
		method, reqURL := requestSummary(httpResp)
		details = append(details, fmt.Sprintf("HTTP %s, %s %s", httpResp.Status, method, reqURL))
	}

	countSummary := fmt.Sprintf("returned %d sizes, %d available", len(sizes), availableCount)
	if regionSlug != "" {
		countSummary = fmt.Sprintf("%s, 0 in region %q", countSummary, regionSlug)
	}
	details = append(details, countSummary)

	if resp != nil && resp.Meta != nil {
		details = append(details, fmt.Sprintf("meta.total=%d", resp.Meta.Total))
	}
	if resp != nil && resp.Links != nil && resp.Links.Pages != nil && resp.Links.Pages.Next != "" {
		details = append(details, "has_next_page=true")
	}

	header := "no sizes available"
	if regionSlug != "" {
		header = fmt.Sprintf("no sizes available for region %q", regionSlug)
	}

	// Include full response body when empty so unexpected payloads are visible immediately;
	// for non-empty pages, avoid flooding the terminal and point to --debug.
	if len(sizes) == 0 {
		body := formatResponseBody(extractCapturedBody(httpResp))
		if body != "" {
			return fmt.Errorf("%s (%s)\n%s", header, strings.Join(details, "; "), body)
		}
		return fmt.Errorf("%s (%s)", header, strings.Join(details, "; "))
	}

	details = append(details, "re-run with --debug to inspect full response JSON")
	return fmt.Errorf("%s (%s)", header, strings.Join(details, "; "))
}

// resolveHTTPResponse extracts the underlying *http.Response from godo's Response or ErrorResponse.
func resolveHTTPResponse(resp *godo.Response, err error) *http.Response {
	if resp != nil && resp.Response != nil {
		return resp.Response
	}
	var godoErr *godo.ErrorResponse
	if errors.As(err, &godoErr) && godoErr.Response != nil {
		return godoErr.Response
	}
	return nil
}

// requestSummary extracts the HTTP method and URL string from a response's originating request.
func requestSummary(resp *http.Response) (string, string) {
	if resp == nil || resp.Request == nil {
		return "", ""
	}
	reqURL := ""
	if resp.Request.URL != nil {
		reqURL = resp.Request.URL.String()
	}
	return resp.Request.Method, reqURL
}
