package arcjet

import (
	"net/http"
	"slices"
	"strings"
)

// hostingPlatform identifies a managed hosting provider whose proxy headers
// the SDK can trust without an explicit Config.Proxies entry. It is set either
// by environment auto-detection (detectPlatform) or explicitly via
// Config.Platform.
type hostingPlatform int

const (
	platformNone hostingPlatform = iota
	platformFirebase
	platformFlyIo
	platformVercel
	platformRender
	platformCloudflare
	platformRailway
)

// Platform names a managed hosting platform whose proxy headers Arcjet can
// trust to determine the client IP. Set Config.Platform to one of these to
// select a platform explicitly when its environment isn't auto-detected — most
// importantly a Go service behind the Cloudflare CDN, which does not set the
// CF_PAGES variable detectPlatform looks for. The names mirror the platform
// values accepted by arcjet-js's @arcjet/ip.
type Platform string

const (
	PlatformFirebase   Platform = "firebase"
	PlatformFlyIo      Platform = "fly-io"
	PlatformVercel     Platform = "vercel"
	PlatformRender     Platform = "render"
	PlatformCloudflare Platform = "cloudflare"
	PlatformRailway    Platform = "railway"
)

// toHostingPlatform maps a public Platform to its internal value, reporting
// false when p is not a recognized Platform.
func (p Platform) toHostingPlatform() (hostingPlatform, bool) {
	switch p {
	case PlatformFirebase:
		return platformFirebase, true
	case PlatformFlyIo:
		return platformFlyIo, true
	case PlatformVercel:
		return platformVercel, true
	case PlatformRender:
		return platformRender, true
	case PlatformCloudflare:
		return platformCloudflare, true
	case PlatformRailway:
		return platformRailway, true
	default:
		return platformNone, false
	}
}

// detectPlatform infers the hosting platform from environment variables.
//
// The detection order matches @arcjet/env so the Go and JS SDKs pick the
// same platform when more than one signature is present (e.g. a Firebase
// function deployed on Cloud Run with FLY_APP_NAME also set in error).
// Railway is appended last: Railway is not detected by the JS SDK and
// Railway runtimes don't set any of the prior signals.
func detectPlatform(getenv func(string) string) hostingPlatform {
	if getenv("FIREBASE_CONFIG") != "" {
		return platformFirebase
	}
	if getenv("FLY_APP_NAME") != "" {
		return platformFlyIo
	}
	if getenv("VERCEL") == "1" {
		return platformVercel
	}
	if getenv("RENDER") == "true" {
		return platformRender
	}
	// Cloudflare Pages sets CF_PAGES=1 in its build and Functions runtime.
	// https://developers.cloudflare.com/pages/configuration/build-configuration/#environment-variables
	if getenv("CF_PAGES") == "1" {
		return platformCloudflare
	}
	if getenv("RAILWAY_PROJECT_ID") != "" {
		return platformRailway
	}
	return platformNone
}

// platformIP returns the source IP read from the detected platform's signed
// headers, or "" when no platform header carries a value. Header order per
// platform matches @arcjet/ip's findIp. Comma-separated lists are walked
// right-to-left so spoofed left-most entries are ignored, skipping any
// configured trusted proxies along the way.
func platformIP(r *http.Request, platform hostingPlatform, proxies []trustedProxy) string {
	switch platform {
	case platformNone:
		return ""
	case platformFirebase:
		if ip := strings.TrimSpace(r.Header.Get("X-Fah-Client-Ip")); ip != "" {
			return ip
		}
		return rightmostUntrustedXFF(r.Header.Get("X-Forwarded-For"), proxies)
	case platformFlyIo:
		return strings.TrimSpace(r.Header.Get("Fly-Client-Ip"))
	case platformVercel:
		if ip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); ip != "" {
			return ip
		}
		if ip := rightmostUntrustedXFF(r.Header.Get("X-Vercel-Forwarded-For"), proxies); ip != "" {
			return ip
		}
		return rightmostUntrustedXFF(r.Header.Get("X-Forwarded-For"), proxies)
	case platformRender:
		return strings.TrimSpace(r.Header.Get("True-Client-Ip"))
	case platformCloudflare:
		// Cloudflare signs CF-Connecting-IP(v6) on every proxied request and
		// strips client-supplied copies, so they can be trusted directly.
		// IPv6 is preferred when present, matching @arcjet/ip.
		// https://developers.cloudflare.com/fundamentals/reference/http-request-headers/#cf-connecting-ip
		if ip := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ipv6")); ip != "" {
			return ip
		}
		return strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip"))
	case platformRailway:
		// Railway sets X-Real-IP to the original client IP.
		// https://docs.railway.com/networking/public-networking/specs-and-limits#technical-specifications
		return strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	}
	return ""
}

func rightmostUntrustedXFF(value string, proxies []trustedProxy) string {
	if value == "" {
		return ""
	}
	for _, part := range slices.Backward(strings.Split(value, ",")) {
		ip := strings.TrimSpace(part)
		if ip == "" {
			continue
		}
		if isTrustedProxy(ip, proxies) {
			continue
		}
		return ip
	}
	return ""
}
