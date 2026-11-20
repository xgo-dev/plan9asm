package gostaticstorage

// X86SDKTarget selects an observation grammar, not a source or storage lease.
// Every object still has to carry the exact requested GOOS/GOARCH header, flags
// and original selected member identity. Darwin/386 is not a current Go target.
func X86SDKTarget(target string) bool {
	switch target {
	case "linux/386", "linux/amd64", "darwin/amd64", "windows/386", "windows/amd64":
		return true
	}
	return false
}

// Go's default Darwin PIE profile passes -shared to its compiler and assembler;
// Windows PIE does not. These are exact pinned SDK object flags, not a mask of
// acceptable flags. Direct standalone tool objects retain their separate role.
func sdkCompilerObjectFlags(target string) uint32 {
	flags := uint32(16) // ObjFlagStd.
	if target == "darwin/amd64" || target == "darwin/arm64" {
		flags |= 1 // ObjFlagShared.
	}
	return flags
}

func sdkAssemblyObjectFlags(target string) uint32 {
	return sdkCompilerObjectFlags(target) | 4 // ObjFlagFromAssembly.
}
