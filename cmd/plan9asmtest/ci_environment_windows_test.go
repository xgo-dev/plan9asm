package main

import "testing"

func TestWindowsCIAbsolutePathSeparatorEquivalence(t *testing.T) {
	for _, path := range []string{`C:\tools\go`, `C:/tools/go`, `C:\tools/go`, `\\server\share\go`} {
		if !ciAbsolutePath(path) {
			t.Fatal("absolute native/Go separator spelling rejected", path)
		}
	}
	for _, path := range []string{
		`C:tools\go`, `\tools\go`, `C:\tools\..\go`, `C:/tools/./go`,
		`C:/tools//go`, `C:\tools\\go`, `C:\tools\go\`, "C:\\go\x00", "C:\\go\n",
	} {
		if ciAbsolutePath(path) {
			t.Fatal("relative/unclean/control path acquired source identity", path)
		}
	}
	for _, path := range []string{`C:\llvm\lib\LLVM.dll`, `C:/llvm/lib/LLVM.dll`} {
		files, err := moduleSharedLibraries([]byte(path + "\n"))
		if err != nil || len(files) != 1 || files[0] != path {
			t.Fatalf("actual configured spelling was changed or rejected: %q %v", files, err)
		}
	}
	if _, err := moduleSharedLibraries([]byte("C:\\llvm\\lib\\LLVM.dll C:/llvm/lib/LLVM.dll\n")); err == nil {
		t.Fatal("separator aliases became two independent library origins")
	}
}
