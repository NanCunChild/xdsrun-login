package main

import (
	"net/http"
	"testing"
)

func TestParsePortalURL(t *testing.T) {
	portalURL, host, err := parsePortalURL("https://w.xidian.edu.cn/")
	if err != nil {
		t.Fatalf("parsePortalURL() returned an error: %v", err)
	}
	if portalURL != defaultPortalURL || host != "w.xidian.edu.cn" {
		t.Fatalf("parsePortalURL() = %q, %q", portalURL, host)
	}
}

func TestParsePortalURLRejectsUnsupportedScheme(t *testing.T) {
	if _, _, err := parsePortalURL("ftp://w.xidian.edu.cn"); err == nil {
		t.Fatal("parsePortalURL() should reject unsupported schemes")
	}
}

func TestClientVerifiesCertificatesByDefault(t *testing.T) {
	client := createClient("w.xidian.edu.cn", defaultPortalDirectIP, false)
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("certificate verification should be enabled by default")
	}
	if transport.DialContext == nil {
		t.Fatal("direct-IP client should override DialContext")
	}
}

func TestClientAllowsExplicitlyInsecureTLS(t *testing.T) {
	client := createClient("w.xidian.edu.cn", "", true)
	transport := client.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("explicit insecure mode should disable certificate verification")
	}
	if transport.DialContext != nil {
		t.Fatal("domain client should use the default dialer")
	}
}

func TestRewritePortalAddress(t *testing.T) {
	if got := rewritePortalAddress("w.xidian.edu.cn:443", "w.xidian.edu.cn", defaultPortalDirectIP); got != "10.255.44.33:443" {
		t.Fatalf("rewritePortalAddress() = %q", got)
	}
	if got := rewritePortalAddress("example.com:443", "w.xidian.edu.cn", defaultPortalDirectIP); got != "example.com:443" {
		t.Fatalf("rewritePortalAddress() changed an unrelated address to %q", got)
	}
}
