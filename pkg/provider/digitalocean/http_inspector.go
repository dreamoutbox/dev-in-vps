package digitalocean

import (
	"fmt"
	"io"
	"net/http"
)

// httpInspector wraps an http.RoundTripper to capture response bodies for rich API
// errors and optionally stream HTTP request/response diagnostics to a debug writer.
type httpInspector struct {
	base        http.RoundTripper
	debugWriter io.Writer
}

// RoundTrip executes the HTTP request, buffers the response body into a capturedBody,
// and writes request/response status and body details when debug logging is enabled.
//
// Input args:
//   - req: outgoing HTTP request.
//
// Returns:
//   - *http.Response: HTTP response with a replayable capturedBody.
//   - error: non-nil if transport execution or body reading fails.
//
// Example:
//
//	httpClient.Transport = &httpInspector{base: http.DefaultTransport, debugWriter: os.Stderr}
func (i *httpInspector) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := i.base.RoundTrip(req)
	if err != nil {
		if i.debugWriter != nil {
			_, _ = fmt.Fprintf(i.debugWriter, "[HTTP] %s %s -> error: %v\n", req.Method, req.URL.String(), err)
		}
		return nil, err
	}

	var rawBody []byte
	if resp.Body != nil {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("failed to read HTTP response body: %w", readErr)
		}
		rawBody = bodyBytes
		resp.Body = newCapturedBody(rawBody)
	}

	if i.debugWriter != nil {
		writeHTTPDebug(i.debugWriter, req, resp, rawBody)
	}

	return resp, nil
}

// writeHTTPDebug writes HTTP method, URL, status, and formatted body without exposing headers.
func writeHTTPDebug(w io.Writer, req *http.Request, resp *http.Response, rawBody []byte) {
	_, _ = fmt.Fprintf(w, "[HTTP] %s %s -> %s\n", req.Method, req.URL.String(), resp.Status)
	formatted := formatResponseBody(rawBody)
	if formatted != "" {
		_, _ = fmt.Fprintf(w, "%s\n", formatted)
	}
}
