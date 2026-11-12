package nativeoracle

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestDarwinClangFlagsRequireCompleteExistingDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "actual SDK with spaces")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	physical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := darwinClangFlagsFromSDKOutput([]byte(root + "\n"))
	want := []string{"--no-default-config", "-isysroot", physical}
	if err != nil || !reflect.DeepEqual(flags, want) {
		t.Fatalf("actual SDK arguments=%q want=%q error=%v", flags, want, err)
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("not an SDK"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{
		"", root, root + "\n\n", root + "\r\n", root + "\n/other\n",
		"relative/SDK\n", root + "\x00\n", file + "\n",
		filepath.Join(root, "missing") + "\n",
	} {
		if flags, err := darwinClangFlagsFromSDKOutput([]byte(output)); err == nil || flags != nil {
			t.Fatalf("malformed/missing SDK selection accepted: output=%q flags=%q err=%v", output, flags, err)
		}
	}
}

func TestDarwinClangFlagsRejectUnboundedAndExpiredQueries(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for _, ctx := range []context.Context{nil, context.Background(), expired} {
		if flags, err := DarwinClangFlags(ctx, nil); err == nil || flags != nil {
			t.Fatalf("unbounded/expired SDK query accepted: flags=%q err=%v", flags, err)
		}
	}
}
