package gostaticstorage

import "strings"

// ObserveX86TLSAssemblyText retains complete standalone tool-asm TEXT bytes,
// source positions and relocations, including the exact Shared object flag.
// This offline observation grants no native entry, thread or TLS address role.
// The ordinary Linux numerical-read observer keeps its separate admission.
func ObserveX86TLSAssemblyText(data, builtin []byte, target string, shared bool) ([]TextRecord, error) {
	goos, arch, valid := strings.Cut(target, "/")
	if !valid || arch != "386" && arch != "amd64" ||
		goos != "linux" && goos != "android" && goos != "darwin" && goos != "windows" && goos != "freebsd" &&
			goos != "openbsd" && goos != "netbsd" && goos != "dragonfly" && goos != "solaris" && goos != "plan9" {
		return nil, contextError("unobserved x86 TLS assembler target")
	}
	builtins, err := textBuiltins(builtin)
	if err != nil {
		return nil, err
	}
	body, err := objectBody(data, target)
	if err != nil {
		return nil, err
	}
	flags := uint32(4) // FromAssembly, with the explicit -p linkable role.
	if shared {
		flags |= 1
	}
	return readTextObject(body, target, flags, false, builtins)
}
