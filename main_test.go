package main

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
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

func TestAcquirePasswordUsesProvidedValue(t *testing.T) {
	password, err := acquirePassword("secret", 0, func(int) bool { return false }, nil, nil)
	if err != nil || password != "secret" {
		t.Fatalf("acquirePassword() = %q, %v", password, err)
	}
}

func TestAcquirePasswordReadsFromTerminalWithoutEcho(t *testing.T) {
	var prompt bytes.Buffer
	password, err := acquirePassword("", 42, func(fd int) bool { return fd == 42 }, func(fd int) ([]byte, error) {
		return []byte("secret"), nil
	}, &prompt)
	if err != nil || password != "secret" {
		t.Fatalf("acquirePassword() = %q, %v", password, err)
	}
	if got := prompt.String(); got != "请输入校园网密码: \n" {
		t.Fatalf("prompt = %q", got)
	}
}

func TestAcquirePasswordRejectsNonTerminal(t *testing.T) {
	_, err := acquirePassword("", 0, func(int) bool { return false }, nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), envPassword) {
		t.Fatalf("acquirePassword() error = %v", err)
	}
}

func TestAcquirePasswordReportsReadError(t *testing.T) {
	want := errors.New("read failed")
	_, err := acquirePassword("", 0, func(int) bool { return true }, func(int) ([]byte, error) {
		return nil, want
	}, &bytes.Buffer{})
	if !errors.Is(err, want) {
		t.Fatalf("acquirePassword() error = %v", err)
	}
}
