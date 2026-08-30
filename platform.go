package arcjet

import (
	"net"
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
	return platformIPDetails(r, platform, proxies).IP
}

func platformIPDetails(r *http.Request, platform hostingPlatform, proxies []trustedProxy) ClientIPDetails {
	details := func(value, header string) ClientIPDetails {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			return ClientIPDetails{Provenance: ClientIPProvenanceNone}
		}
		return ClientIPDetails{
			IP:         ip.String(),
			Provenance: ClientIPProvenancePlatform,
			Verified:   true,
			Header:     header,
		}
	}
	switch platform {
	case platformNone:
		return ClientIPDetails{Provenance: ClientIPProvenanceNone}
	case platformFirebase:
		if found := details(r.Header.Get("X-Fah-Client-Ip"), "x-fah-client-ip"); found.IP != "" {
			return found
		}
		return details(rightmostUntrustedXFF(r.Header.Get("X-Forwarded-For"), proxies), "x-forwarded-for")
	case platformFlyIo:
		return details(r.Header.Get("Fly-Client-Ip"), "fly-client-ip")
	case platformVercel:
		if found := details(r.Header.Get("X-Real-Ip"), "x-real-ip"); found.IP != "" {
			return found
		}
		if ip := rightmostUntrustedXFF(r.Header.Get("X-Vercel-Forwarded-For"), proxies); ip != "" {
			return details(ip, "x-vercel-forwarded-for")
		}
		return details(rightmostUntrustedXFF(r.Header.Get("X-Forwarded-For"), proxies), "x-forwarded-for")
	case platformRender:
		return details(r.Header.Get("True-Client-Ip"), "true-client-ip")
	case platformCloudflare:
		// Cloudflare signs CF-Connecting-IP(v6) on every proxied request and
		// strips client-supplied copies, so they can be trusted directly.
		// IPv6 is preferred when present, matching @arcjet/ip.
		// https://developers.cloudflare.com/fundamentals/reference/http-request-headers/#cf-connecting-ip
		if found := details(r.Header.Get("Cf-Connecting-Ipv6"), "cf-connecting-ipv6"); found.IP != "" {
			return found
		}
		return details(r.Header.Get("Cf-Connecting-Ip"), "cf-connecting-ip")
	case platformRailway:
		// Railway sets X-Real-IP to the original client IP.
		// https://docs.railway.com/networking/public-networking/specs-and-limits#technical-specifications
		return details(r.Header.Get("X-Real-Ip"), "x-real-ip")
	}
	return ClientIPDetails{Provenance: ClientIPProvenanceNone}
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
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if isTrustedProxy(ip, proxies) {
			continue
		}
		return parsed.String()
	}
	return ""
}
