package main

import (
	"crypto/tls"
	"net/http"
	"testing"
)

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
