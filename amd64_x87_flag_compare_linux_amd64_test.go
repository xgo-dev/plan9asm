package plan9asm

import (
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"
	"testing"
)

// A required cross-runtime counterpart, not a host-skipped 386 object test.
func TestCrossLinuxRuntimeMatrixX87DirectFlagCompare386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x87IA32NativePreflight(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	t.Run("OriginalGo", func(t *testing.T) {
		x87IA32OriginalGoDirect(t)
	})
	x87DirectFlagCompareRuntime(t, "386", "i386-unknown-linux-gnu", func(t *testing.T, ir, main string) {
		x87IA32CompileAndRunDirect(t, llc, ir, main)
	})
	x87IA32RequireNativeHost(t)
}

func x87IA32RequireNativeHost(t *testing.T) {
	t.Helper()
	var kernel syscall.Utsname
	if err := syscall.Uname(&kernel); err != nil {
		t.Fatal(err)
	}
	var machine []byte
	for _, value := range kernel.Machine {
		if value == 0 {
			break
		}
		machine = append(machine, byte(value))
	}
	readObservation := func(name string) ([]byte, error) {
		file, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		bytes, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
		if err != nil || len(bytes) > 4<<20 {
			return nil, fmt.Errorf("unbounded native-host observation: %v", err)
		}
		return bytes, nil
	}
	cpuinfo, err := readObservation("/proc/cpuinfo")
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := readObservation("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	host, err := elf.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if err := x87IA32NativeEnvironment(runtime.GOOS, runtime.GOARCH, string(machine),
		string(cpuinfo), string(mappings), host); err != nil {
		t.Fatal(err)
	}
	t.Logf("IA32 direct host: %s/%s kernel=%s CPUsha=%x mapsha=%x",
		runtime.GOOS, runtime.GOARCH, machine, sha256.Sum256(cpuinfo), sha256.Sum256(mappings))
}
