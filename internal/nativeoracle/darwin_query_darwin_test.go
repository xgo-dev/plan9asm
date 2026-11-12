package nativeoracle

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDarwinClangFlagsMissingDeveloperSelectionNeverUsesSDKROOT(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	environment := append(os.Environ(),
		"DEVELOPER_DIR="+filepath.Join(t.TempDir(), "missing-developer-tools"),
		"SDKROOT="+t.TempDir())
	if flags, err := DarwinClangFlags(ctx, environment); err == nil || flags != nil {
		t.Fatalf("missing actual developer SDK fell back to SDKROOT: flags=%q err=%v", flags, err)
	}
}

func TestDarwinClangFlagsResolveActualDirectoryAlias(t *testing.T) {
	root := filepath.Join(t.TempDir(), "owned SDK")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "SDK alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	flags, err := darwinClangFlagsFromSDKOutput([]byte(alias + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := os.Stat(flags[2])
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(root)
	if err != nil || !os.SameFile(selected, original) {
		t.Fatalf("SDK flags invented a directory identity: %v", err)
	}
}
