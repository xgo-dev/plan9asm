package plan9asm

// These exact triples join the selected SDK source profile to the translator.
// A target spelling alone never creates a numerical source or native ABI lease.
func numericalSDKTargetTriple(target string) string {
	switch target {
	case "linux/386":
		return "i386-unknown-linux-gnu"
	case "linux/amd64":
		return "x86_64-unknown-linux-gnu"
	case "darwin/amd64":
		return "x86_64-apple-macosx"
	case "windows/386":
		return "i686-pc-windows-msvc"
	case "windows/amd64":
		return "x86_64-pc-windows-msvc"
	}
	return ""
}
