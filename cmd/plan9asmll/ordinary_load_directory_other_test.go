//go:build !windows

package main

import (
	"os"
	"testing"
)

func ordinaryLoadDirectoryAlias(t *testing.T, alias, actual string) {
	t.Helper()
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
}
