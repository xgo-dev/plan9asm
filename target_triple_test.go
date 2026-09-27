package plan9asm

// testTargetTriple returns a practical LLVM target triple for tests.
// We only need a small set for current coverage.
func testTargetTriple(goos, goarch string) string {
	switch goos {
	case "darwin":
		switch goarch {
		case "amd64":
			return "x86_64-apple-macosx"
		case "arm64":
			return "arm64-apple-macosx"
		}
	case "linux":
		switch goarch {
		case "amd64":
			return "x86_64-unknown-linux-gnu"
		case "arm64":
			return "aarch64-unknown-linux-gnu"
		}
	case "windows":
		// Runtime fixtures link with MSYS2/MinGW clang, not the MSVC CRT.
		// In particular, their large frames need ___chkstk_ms on amd64.
		// Explicit MSVC object-compile tests keep their separate triples.
		switch goarch {
		case "amd64":
			return "x86_64-w64-windows-gnu"
		case "arm64":
			return "aarch64-w64-windows-gnu"
		}
	}

	// Fallback for unsupported combos in tests.
	return goarch + "-unknown-" + goos
}
