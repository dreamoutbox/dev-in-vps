package digitalocean

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// capturedBody wraps an HTTP response body so the raw bytes remain readable after
// godo finishes decoding or draining the response stream.
type capturedBody struct {
	raw    []byte
	reader *bytes.Reader
}

// newCapturedBody constructs a capturedBody backed by a copy of raw.
//
// Input args:
//   - raw: raw HTTP response body bytes.
//
// Returns:
//   - *capturedBody: ReadCloser retaining raw bytes for later inspection.
//
// Example:
//
//	resp.Body = newCapturedBody(bodyBytes)
func newCapturedBody(raw []byte) *capturedBody {
	return &capturedBody{
		raw:    raw,
		reader: bytes.NewReader(raw),
	}
}

// Read reads response bytes from the buffered reader.
func (c *capturedBody) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// Close is a no-op so the captured raw bytes remain intact for error reporting.
func (c *capturedBody) Close() error {
	return nil
}

// extractCapturedBody returns the captured raw response bytes from resp if present.
func extractCapturedBody(resp *http.Response) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	cb, ok := resp.Body.(*capturedBody)
	if !ok {
		return nil
	}
	return cb.raw
}

// formatResponseBody pretty-prints JSON payloads and falls back to trimmed raw text.
func formatResponseBody(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, trimmed, "", "  "); err == nil {
		return pretty.String()
	}
	return string(trimmed)
}
