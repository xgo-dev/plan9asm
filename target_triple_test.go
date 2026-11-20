package plan9asm

// testTargetTriple returns a practical LLVM target triple for tests.
// Go's architecture names are not interchangeable with LLVM architecture names.
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
		case "386":
			return "i386-unknown-linux-gnu"
		case "amd64":
			return "x86_64-unknown-linux-gnu"
		case "arm":
			return "armv7-unknown-linux-gnueabihf"
		case "arm64":
			return "aarch64-unknown-linux-gnu"
		}
	case "windows":
		// Runtime fixtures link with MSYS2/MinGW clang, not the MSVC CRT.
		// In particular, their large frames need ___chkstk_ms on amd64.
		// Explicit MSVC object-compile tests keep their separate triples.
		switch goarch {
		case "386":
			return "i686-w64-windows-gnu"
		case "amd64":
			return "x86_64-w64-windows-gnu"
		case "arm64":
			return "aarch64-w64-windows-gnu"
		}
	case "js":
		if goarch == "wasm" {
			return "wasm32-unknown-unknown"
		}
	case "wasip1":
		if goarch == "wasm" {
			return "wasm32-unknown-wasi"
		}
	}

	// An invented or empty triple could silently select the host LLVM backend.
	panic("unsupported test target " + goos + "/" + goarch)
}
