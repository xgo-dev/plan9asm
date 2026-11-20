package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The checksum-pinned Tonistiigi bundle preserves a separate argv[0] even when
// invoked explicitly, not only through binfmt. Authenticate that transport;
// neither an executable's name nor a version banner grants this behavior.
// These are test runners, not production ISA or calling-convention permissions.
// Match the linux-amd64 deploy/v10.2.3-68 archive pinned by install-ci-qemu.sh.
func runtimeOraclePinnedQEMUSHA(name string) string {
	switch name {
	case "qemu-aarch64":
		return "52a2e9257e43c59abd033f643f05bed9ee17a2b0f345d742da11b321b9bd548d"
	case "qemu-arm":
		return "8c99a0953bdf190626889268b4f8e8cff8160bb7af82fb70c237981a00dc9c02"
	case "qemu-i386":
		return "3d5369c56c3b53ffbf3c6e9e9729e949a2bf8817701ba2c33174306184b01bb0"
	}
	return ""
}

func runtimeOracleGuestArguments(t *testing.T, prefix []string, executable string, arguments ...string) []string {
	t.Helper()
	identity := ""
	if len(prefix) != 0 && strings.HasPrefix(filepath.Base(prefix[0]), "qemu-") {
		path, err := exec.LookPath(prefix[0])
		if err != nil {
			t.Fatal("required guest runner:", err)
		}
		identity, err = runtimeOracleGuestRunnerSHA(path)
		if err != nil {
			t.Fatal("guest runner identity:", err)
		}
	}
	command, err := runtimeOracleGuestArgumentsForIdentity(prefix, executable, arguments, identity)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func runtimeOracleGuestArgumentsForIdentity(prefix []string, executable string, arguments []string, identity string) ([]string, error) {
	if executable == "" || (len(prefix) != 0 && prefix[0] == "") {
		return nil, fmt.Errorf("empty guest executable or runner")
	}
	preserveArgv0 := false
	if len(prefix) != 0 && strings.HasPrefix(filepath.Base(prefix[0]), "qemu-") {
		name := filepath.Base(prefix[0])
		pinned := runtimeOraclePinnedQEMUSHA(name)
		if pinned == "" || identity != pinned {
			return nil, fmt.Errorf("unauthenticated guest runner %q: SHA256 %q", name, identity)
		}
		preserveArgv0 = true
	} else if identity != "" {
		return nil, fmt.Errorf("unexpected QEMU identity for native execution")
	}
	command := append([]string(nil), prefix...)
	command = append(command, executable)
	if preserveArgv0 {
		command = append(command, executable)
	}
	return append(command, arguments...), nil
}

func runtimeOracleGuestRunnerSHA(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	const limit = 64 << 20
	before, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > limit {
		return "", fmt.Errorf("guest runner must be a nonempty regular file of at most %d bytes", limit)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	if size != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", fmt.Errorf("guest runner changed while authenticating")
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
