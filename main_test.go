package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRewritePortalAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		dialIP  string
		want    string
	}{
		{
			name:    "portal host is replaced",
			address: "w.xidian.edu.cn:443",
			dialIP:  "10.255.44.33",
			want:    "10.255.44.33:443",
		},
		{
			name:    "unrelated host is unchanged",
			address: "example.com:443",
			dialIP:  "10.255.44.33",
			want:    "example.com:443",
		},
		{
			name:    "malformed address is unchanged",
			address: "w.xidian.edu.cn",
			dialIP:  "10.255.44.33",
			want:    "w.xidian.edu.cn",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rewritePortalAddress(test.address, test.dialIP); got != test.want {
				t.Fatalf("rewritePortalAddress() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestClientKeepsTLSVerificationEnabled(t *testing.T) {
	client := createClient(portalDirectIP)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLS configuration is missing")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS certificate verification must remain enabled")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %d, want TLS 1.2 or newer", transport.TLSClientConfig.MinVersion)
	}
}

func TestPasswordModesCannotBeCombined(t *testing.T) {
	if _, err := readPassword("not-a-real-password", true); err == nil {
		t.Fatal("readPassword() should reject -p together with --password-stdin")
	}
}

func TestReadPasswordFromStdin(t *testing.T) {
	password, err := readPasswordFrom("", true, strings.NewReader("not-a-real-password\r\n"))
	if err != nil {
		t.Fatalf("readPasswordFrom() returned an error: %v", err)
	}
	if password != "not-a-real-password" {
		t.Fatalf("readPasswordFrom() = %q, want the line ending removed", password)
	}
}

func TestReadPasswordRejectsOversizedInput(t *testing.T) {
	input := strings.NewReader(strings.Repeat("x", maxPasswordBytes+1))
	if _, err := readPasswordFrom("", true, input); err == nil {
		t.Fatal("readPasswordFrom() should reject oversized input")
	}
}

func TestMakeRequestRedactsSensitiveURL(t *testing.T) {
	const secret = "do-not-log-this"
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, &url.Error{
				Op:  "Get",
				URL: req.URL.String(),
				Err: errors.New("dial failed"),
			}
		}),
	}

	_, err := makeRequest(context.Background(), client, "https://example.com/?password="+secret)
	if err == nil {
		t.Fatal("makeRequest() unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("makeRequest() leaked a sensitive URL: %v", err)
	}
	if !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("makeRequest() removed the useful network cause: %v", err)
	}
}

func TestFinalLoginRedactsServerResponse(t *testing.T) {
	const secret = "server-secret-material"
	client := &http.Client{
		Transport: roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"error":"fail","error_msg":"` + secret + `"}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	err := finalLogin(context.Background(), client, portalBaseURL, "192.0.2.1", "hash", "info", "checksum", "example-user")
	if err == nil {
		t.Fatal("finalLogin() unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("finalLogin() leaked the server response: %v", err)
	}
}
