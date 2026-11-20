//go:build windows

package sdkfrontend

import (
	"context"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func sdkEnvironmentAlias(t *testing.T, alias, actual string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, "", nil, "cmd", "/c", "mklink", "/J", alias, actual)
	if err != nil {
		t.Fatalf("create required actual Windows junction: %v; %s; %s", err, stdout, stderr)
	}
}
