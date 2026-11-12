package gotoolchain

import "runtime"

// HostExecutable adds the host's executable suffix. It is independent of the
// observed assembly target: a Windows Go driver can emit Linux objects.
func HostExecutable(name string) string {
	return hostExecutable(name, runtime.GOOS)
}

func hostExecutable(name, goos string) string {
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}
