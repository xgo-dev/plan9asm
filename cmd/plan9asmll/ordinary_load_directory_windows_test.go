//go:build windows

package main

import (
	"context"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func ordinaryLoadDirectoryAlias(t *testing.T, alias, actual string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, "", nil, "cmd", "/c", "mklink", "/J", alias, actual)
	if err != nil {
		t.Fatalf("create actual Windows SDK junction: %v; %s; %s", err, stdout, stderr)
	}
}
