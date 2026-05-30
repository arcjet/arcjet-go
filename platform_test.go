package arcjet

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectPlatformFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want hostingPlatform
	}{
		{"none", nil, platformNone},
		{"firebase", map[string]string{"FIREBASE_CONFIG": `{"projectId":"x"}`}, platformFirebase},
		{"firebase empty value is none", map[string]string{"FIREBASE_CONFIG": ""}, platformNone},
		{"fly-io", map[string]string{"FLY_APP_NAME": "myapp"}, platformFlyIo},
		{"vercel exact value 1", map[string]string{"VERCEL": "1"}, platformVercel},
		{"vercel wrong value", map[string]string{"VERCEL": "true"}, platformNone},
		{"render exact value true", map[string]string{"RENDER": "true"}, platformRender},
		{"render wrong value", map[string]string{"RENDER": "1"}, platformNone},
		{"cloudflare pages exact value 1", map[string]string{"CF_PAGES": "1"}, platformCloudflare},
		{"cloudflare pages wrong value", map[string]string{"CF_PAGES": "true"}, platformNone},
		{"railway", map[string]string{"RAILWAY_PROJECT_ID": "00000000-0000-0000-0000-000000000000"}, platformRailway},
		{"railway empty value is none", map[string]string{"RAILWAY_PROJECT_ID": ""}, platformNone},
		{
			"precedence firebase beats fly",
			map[string]string{"FIREBASE_CONFIG": "x", "FLY_APP_NAME": "x"},
			platformFirebase,
		},
		{
			"precedence vercel beats render",
			map[string]string{"VERCEL": "1", "RENDER": "true"},
			platformVercel,
		},
		{
			"precedence render beats cloudflare",
			map[string]string{"RENDER": "true", "CF_PAGES": "1"},
			platformRender,
		},
		{
			"precedence cloudflare beats railway",
			map[string]string{"CF_PAGES": "1", "RAILWAY_PROJECT_ID": "p"},
			platformCloudflare,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string { return tt.env[key] }
			if got := detectPlatform(getenv); got != tt.want {
				t.Fatalf("detectPlatform = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDetectPlatformReadsOsEnv(t *testing.T) {
	// Other vars may be set in the host environment; clear the higher-precedence
	// ones so this test deterministically observes RENDER.
	t.Setenv("FIREBASE_CONFIG", "")
	t.Setenv("FLY_APP_NAME", "")
	t.Setenv("VERCEL", "")
	t.Setenv("RENDER", "true")
	t.Setenv("RAILWAY_PROJECT_ID", "")

	client, err := NewClient(Config{Key: "ajkey_test"})
	if err != nil {
		t.Fatal(err)
	}
	if client.platform != platformRender {
		t.Fatalf("client platform = %d, want render (%d)", client.platform, platformRender)
	}
}

func TestPlatformIP(t *testing.T) {
	tests := []struct {
		name     string
		platform hostingPlatform
		headers  map[string]string
		want     string
	}{
		{
			name:     "firebase x-fah-client-ip",
			platform: platformFirebase,
			headers:  map[string]string{"X-Fah-Client-Ip": "203.0.113.5"},
			want:     "203.0.113.5",
		},
		{
			name:     "firebase falls through to xff",
			platform: platformFirebase,
			headers:  map[string]string{"X-Forwarded-For": "203.0.113.5, 198.51.100.7"},
			want:     "198.51.100.7",
		},
		{
			name:     "fly-io",
			platform: platformFlyIo,
			headers:  map[string]string{"Fly-Client-Ip": "203.0.113.10"},
			want:     "203.0.113.10",
		},
		{
			name:     "vercel x-real-ip wins",
			platform: platformVercel,
			headers: map[string]string{
				"X-Real-Ip":              "203.0.113.20",
				"X-Vercel-Forwarded-For": "198.51.100.30",
				"X-Forwarded-For":        "198.51.100.40",
			},
			want: "203.0.113.20",
		},
		{
			name:     "vercel falls through to x-vercel-forwarded-for",
			platform: platformVercel,
			headers: map[string]string{
				"X-Vercel-Forwarded-For": "1.1.1.1, 203.0.113.20",
				"X-Forwarded-For":        "198.51.100.40",
			},
			want: "203.0.113.20",
		},
		{
			name:     "vercel falls through to x-forwarded-for",
			platform: platformVercel,
			headers:  map[string]string{"X-Forwarded-For": "1.1.1.1, 203.0.113.50"},
			want:     "203.0.113.50",
		},
		{
			name:     "render true-client-ip",
			platform: platformRender,
			headers:  map[string]string{"True-Client-Ip": "203.0.113.60"},
			want:     "203.0.113.60",
		},
		{
			name:     "cloudflare cf-connecting-ip",
			platform: platformCloudflare,
			headers:  map[string]string{"CF-Connecting-IP": "203.0.113.65"},
			want:     "203.0.113.65",
		},
		{
			name:     "cloudflare prefers ipv6",
			platform: platformCloudflare,
			headers: map[string]string{
				"CF-Connecting-IPv6": "2001:db8::1",
				"CF-Connecting-IP":   "203.0.113.65",
			},
			want: "2001:db8::1",
		},
		{
			name:     "railway x-real-ip",
			platform: platformRailway,
			headers:  map[string]string{"X-Real-Ip": "203.0.113.70"},
			want:     "203.0.113.70",
		},
		{
			name:     "missing platform header returns empty",
			platform: platformFlyIo,
			headers:  map[string]string{"X-Forwarded-For": "203.0.113.5"},
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if got := platformIP(req, tt.platform, nil); got != tt.want {
				t.Fatalf("platformIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPlatformIPSkipsTrustedProxiesInXFF(t *testing.T) {
	proxies, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.44, 10.0.0.5")

	if got := platformIP(req, platformVercel, proxies); got != "198.51.100.44" {
		t.Fatalf("vercel XFF rightmost-untrusted = %q", got)
	}
}

func TestClientIPUsesPlatformHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.99.0.1:443"
	req.Header.Set("Fly-Client-Ip", "203.0.113.10")
	req.Header.Set("X-Forwarded-For", "198.51.100.99")

	if got := clientIP(req, nil, platformFlyIo); got != "203.0.113.10" {
		t.Fatalf("fly client ip = %q", got)
	}
}

func TestClientIPFallsBackToRemoteWhenPlatformHeaderMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.99.0.1:443"
	// Fly is detected but no Fly-Client-Ip was sent. Falling back to XFF here
	// would defeat the platform-trust signal, so we use RemoteAddr instead.
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := clientIP(req, nil, platformFlyIo); got != "10.99.0.1" {
		t.Fatalf("fallback ip = %q, want remote", got)
	}
}

func TestProtectUsesPlatformHeaderWhenEnvSet(t *testing.T) {
	t.Setenv("FIREBASE_CONFIG", "")
	t.Setenv("FLY_APP_NAME", "")
	t.Setenv("VERCEL", "")
	t.Setenv("RENDER", "")
	t.Setenv("RAILWAY_PROJECT_ID", "proj_test")

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Real-Ip", "203.0.113.42")

	client, err := NewClient(Config{Key: "ajkey_test"})
	if err != nil {
		t.Fatal(err)
	}
	details := detailsFromRequest(req, client.proxies, client.platform)
	if details.IP != "203.0.113.42" {
		t.Fatalf("railway X-Real-Ip = %q", details.IP)
	}
}
