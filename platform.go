package arcjet

import (
	"net/http"
	"slices"
	"strings"
)

// hostingPlatform identifies a managed hosting provider whose proxy headers
// the SDK can trust without an explicit Config.Proxies entry. Detection
// mirrors the JS SDK's @arcjet/env package so request IPs are extracted
// consistently across stacks.
type hostingPlatform int

const (
	platformNone hostingPlatform = iota
	platformFirebase
	platformFlyIo
	platformVercel
	platformRender
	platformRailway
)

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
