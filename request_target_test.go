package arcjet

import "testing"

func TestRawPathFromOriginFormTarget(t *testing.T) {
	for _, test := range []struct{ target, want string }{
		{"/a/%2E%2e/../b?x=1", "/a/%2E%2e/../b"},
		{"/", "/"},
		{"/a??b", "/a"},
		{"", ""},
		{"https://example.com/a", ""},
		{"a/b", ""},
		{"/bad#fragment", ""},
		{"/bad path", ""},
		{"/bad\x1fpath", ""},
		{"/caf\xc3\xa9", ""},
	} {
		if got := rawPathFromOriginFormTarget(test.target); got != test.want {
			t.Errorf("target %q: raw path = %q, want %q", test.target, got, test.want)
		}
	}
}

func TestRawPathIsDecideOnly(t *testing.T) {
	details := ProtectDetails{RawPath: "/signed/%2F"}
	if got := details.toDecideProto().GetRawPath(); got != "/signed/%2F" {
		t.Errorf("Decide raw path = %q", got)
	}
	if got := details.toProto().GetRawPath(); got != "" {
		t.Errorf("Report raw path = %q", got)
	}
	details.RawPath = "/bad path"
	if got := details.toDecideProto().GetRawPath(); got != "" {
		t.Errorf("invalid raw path forwarded as %q", got)
	}
}
