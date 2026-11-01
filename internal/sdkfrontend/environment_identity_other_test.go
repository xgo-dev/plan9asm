//go:build !windows

package sdkfrontend

import (
	"os"
	"testing"
)

func sdkEnvironmentAlias(t *testing.T, alias, actual string) {
	t.Helper()
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
}
