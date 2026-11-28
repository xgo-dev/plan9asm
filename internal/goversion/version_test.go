package goversion

import "testing"

func TestParseMinor(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"go1.20.14", 20}, {"devel go1.20-1234567", 20}, {"devel go1.28-abcdef Sat Nov 28 12:00:00 2026 +0000", 28}, {"go1.21rc1", 21}, {"go1.20.14-vendor", 20},
		{"", -1}, {"go1.20junk", -1}, {"go1.020", -1}, {"go1.20.", -1}, {"devel unknown", -1}, {"go1.20.1 other", -1},
	} {
		got, ok := ParseMinor(tc.in)
		if ok != (tc.want >= 0) || ok && got != tc.want {
			t.Errorf("ParseMinor(%q) = %d,%t", tc.in, got, ok)
		}
	}
}
