package main

import "testing"

func TestModuleNodeVersionPacketLineEndings(t *testing.T) {
	for _, version := range []string{"v22.20.0\n", "v22.20.0\r\n", "v22.20.0-test.1\n"} {
		if !ciNodeVersion.MatchString(version) {
			t.Fatalf("complete Node version line rejected: %q", version)
		}
	}
	for _, version := range []string{
		"", "v22.20.0", "v22.20.0\r", "v22.\r20.0\n", "v22.20.0\n\n",
		"v22.20.0\r\r\n", "v22.20.0\x00\n", " v22.20.0\n", "v22.20.0\r\nv22.20.0\r\n",
	} {
		if ciNodeVersion.MatchString(version) {
			t.Fatalf("partial/multiple/control Node packet accepted: %q", version)
		}
	}
}
