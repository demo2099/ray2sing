package ray2sing

// ECH regression tests.
//
// These exercise the exact code paths behind the four production incidents:
//   #74  literal "+" in share links being decoded to a space
//   #75  ECH colliding with Reality, and the DoH "+https://" detection
//   #76  a failed DoH refresh dropping a working (stale) ECH config list
//
// They are internal tests (package ray2sing) so they can drive the unexported
// helpers directly. No network is required: the stale-serving test forces a
// fetch failure with an unreachable DoH URL, and the inline/reality paths
// never touch the network.

import (
	"strings"
	"testing"
	"time"
)

// inlineECH is a harmless base64 blob standing in for an inline ECH config list.
const inlineECH = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"

// TestSplitECHParam covers #74: the v2rayN/v2rayNG separator must be accepted
// as a literal "+", a space (HTML-form-decoded links), and "%2B" (double
// encoded). Anything that is not one of those forms is not a DoH ECH param.
func TestSplitECHParam(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantOk   bool
		wantDom  string
		wantDoH  string
	}{
		{"plus", "example.com+https://dns.google/dns-query", true, "example.com", "https://dns.google/dns-query"},
		{"space", "example.com https://dns.google/dns-query", true, "example.com", "https://dns.google/dns-query"},
		{"percent2B", "example.com%2Bhttps://dns.google/dns-query", true, "example.com", "https://dns.google/dns-query"},
		{"inline-base64", inlineECH, false, "", ""},
		{"plus-no-doh", "example.com+", false, "", ""},
		{"garbage", "just-a-plain-string", false, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dom, doh, ok := splitECHParam(c.in)
			if ok != c.wantOk {
				t.Fatalf("splitECHParam(%q) ok = %v, want %v", c.in, ok, c.wantOk)
			}
			if ok {
				if dom != c.wantDom || doh != c.wantDoH {
					t.Fatalf("splitECHParam(%q) = (%q,%q), want (%q,%q)", c.in, dom, doh, c.wantDom, c.wantDoH)
				}
			}
		})
	}
}

// TestGetTLSOptionsInlineECH covers the inline (base64) ECH path: it must be
// wrapped in a PEM block and attached, without ever hitting the network.
func TestGetTLSOptionsInlineECH(t *testing.T) {
	decoded := map[string]string{
		"tls": "tls",
		"sni": "host.example.com",
		"ech": inlineECH,
	}
	res := getTLSOptions(decoded)
	if res.TLS == nil || res.TLS.ECH == nil {
		t.Fatalf("inline ECH not enabled: TLS=%v ECH=%v", res.TLS, res.TLS)
	}
	if !res.TLS.ECH.Enabled {
		t.Errorf("ECH.Enabled = false, want true")
	}
	if len(res.TLS.ECH.Config) != 1 {
		t.Fatalf("ECH.Config len = %d, want 1", len(res.TLS.ECH.Config))
	}
	if !strings.Contains(res.TLS.ECH.Config[0], "-----BEGIN ECH CONFIGS-----") {
		t.Errorf("ECH.Config not wrapped as PEM: %q", res.TLS.ECH.Config[0])
	}
	// Inline form has no query server name to publish.
	if res.TLS.ECH.QueryServerName != "" {
		t.Errorf("inline ECH QueryServerName = %q, want empty", res.TLS.ECH.QueryServerName)
	}
}

// TestGetTLSOptionsRealityConflict covers #75: when the node already uses
// Reality, ECH must be dropped (sing-box rejects the combination), not attached.
func TestGetTLSOptionsRealityConflict(t *testing.T) {
	decoded := map[string]string{
		"security": "reality",
		"sni":      "host.example.com",
		"ech":      inlineECH,
	}
	res := getTLSOptions(decoded)
	if res.TLS == nil {
		t.Fatalf("TLS options unexpectedly nil for a reality node")
	}
	if res.TLS.ECH != nil {
		t.Errorf("ECH should be nil when Reality is in use, got %+v", res.TLS.ECH)
	}
}

// TestClampECHTTL covers #76: negative/zero and absurd TTLs must be pinned to
// the sane [echMinimumTTL, echMaximumTTL] window so a broken record cannot
// disable ECH forever nor hammer the DoH server every second.
func TestClampECHTTL(t *testing.T) {
	cases := []struct {
		in   uint32
		want time.Duration
	}{
		{0, echMinimumTTL},
		{30, echMinimumTTL},            // below minimum -> minimum
		{300, 300 * time.Second},       // inside window -> unchanged
		{5000, echMaximumTTL},          // above maximum -> maximum
		{99999, echMaximumTTL},         // above maximum -> maximum
	}
	for _, c := range cases {
		if got := clampECHTTL(c.in); got != c.want {
			t.Errorf("clampECHTTL(%d) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestCachedECHConfigStaleServing covers #76's heart: if the cache already
// holds a working config list but a refresh fails (DoH down, proxy toggled),
// the node must keep serving the stale value instead of dropping to empty and
// becoming unconnectable.
func TestCachedECHConfigStaleServing(t *testing.T) {
	const (
		domain = "stale.example.com"
		dohURL = "https://127.0.0.1:1/dns-query" // unreachable -> fetch always fails
		stale  = "-----BEGIN ECH CONFIGS-----\nstale-config-list\n-----END ECH CONFIGS-----"
	)
	key := domain + "|" + dohURL

	echCacheLock.Lock()
	echCacheValues[key] = echCacheEntry{
		configPEM: stale,
		expires:   time.Now().Add(-time.Hour), // expired -> triggers a refresh attempt
	}
	echCacheLock.Unlock()
	defer func() {
		echCacheLock.Lock()
		delete(echCacheValues, key)
		echCacheLock.Unlock()
	}()

	got := cachedECHConfigFromDoH(domain, dohURL)
	if got != stale {
		t.Errorf("stale ECH not served on failed refresh: got %q, want %q", got, stale)
	}
}

// TestCachedECHConfigHit covers the happy path: a still-fresh entry is returned
// without paying for a DoH round trip.
func TestCachedECHConfigHit(t *testing.T) {
	const (
		domain = "fresh.example.com"
		dohURL = "https://127.0.0.1:1/dns-query"
		fresh  = "-----BEGIN ECH CONFIGS-----\nfresh-config-list\n-----END ECH CONFIGS-----"
	)
	key := domain + "|" + dohURL

	echCacheLock.Lock()
	echCacheValues[key] = echCacheEntry{
		configPEM: fresh,
		expires:   time.Now().Add(time.Hour),
	}
	echCacheLock.Unlock()
	defer func() {
		echCacheLock.Lock()
		delete(echCacheValues, key)
		echCacheLock.Unlock()
	}()

	if got := cachedECHConfigFromDoH(domain, dohURL); got != fresh {
		t.Errorf("cached ECH not returned: got %q, want %q", got, fresh)
	}
}
