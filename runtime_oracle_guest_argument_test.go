package plan9asm

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeOracleGuestArgumentConstruction(t *testing.T) {
	arguments := []string{"numeric", "with space", "", "--option", "quote\"backslash\\", "中文"}
	for _, runner := range []string{"", "arch", "qemu-aarch64", "qemu-arm", "qemu-i386"} {
		name := runner
		if name == "" {
			name = "native"
		}
		t.Run(name, func(t *testing.T) {
			var prefix []string
			if runner == "arch" {
				prefix = []string{"arch", "-x86_64"}
			} else if runner != "" {
				prefix = []string{runner, "-L", "/guest-sysroot", "-cpu", "max"}
			}
			for _, input := range [][]string{nil, arguments} {
				beforePrefix := append([]string(nil), prefix...)
				beforeArguments := append([]string(nil), input...)
				identity := runtimeOraclePinnedQEMUSHA(runner)
				got, err := runtimeOracleGuestArgumentsForIdentity(prefix, "/guest-program", input, identity)
				if err != nil {
					t.Fatal(err)
				}
				want := append(append([]string(nil), prefix...), "/guest-program")
				if identity != "" {
					want = append(want, "/guest-program")
				}
				want = append(want, input...)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("guest arguments got %q want %q", got, want)
				}
				if !reflect.DeepEqual(prefix, beforePrefix) || !reflect.DeepEqual(input, beforeArguments) {
					t.Fatal("guest argument construction changed its inputs")
				}
				got[0] = "changed-result"
				if !reflect.DeepEqual(prefix, beforePrefix) || !reflect.DeepEqual(input, beforeArguments) {
					t.Fatal("guest command aliases its inputs")
				}
			}
		})
	}
}

func TestRuntimeOracleGuestArgumentIdentityRejection(t *testing.T) {
	for _, test := range []struct {
		name, executable, identity string
		prefix                     []string
	}{
		{"empty_executable", "", "", nil},
		{"empty_runner", "/guest", "", []string{""}},
		{"missing_identity", "/guest", "", []string{"qemu-aarch64"}},
		{"version_is_not_identity", "/guest", "qemu-aarch64 version 10.2.3", []string{"qemu-aarch64"}},
		{"unknown_identity", "/guest", strings.Repeat("0", 64), []string{"qemu-aarch64"}},
		{"different_arch_identity", "/guest", runtimeOraclePinnedQEMUSHA("qemu-arm"), []string{"qemu-aarch64"}},
		{"unknown_runner", "/guest", runtimeOraclePinnedQEMUSHA("qemu-arm"), []string{"qemu-other"}},
		{"native_with_guest_identity", "/guest", runtimeOraclePinnedQEMUSHA("qemu-arm"), nil},
		{"rosetta_with_guest_identity", "/guest", runtimeOraclePinnedQEMUSHA("qemu-arm"), []string{"arch", "-x86_64"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if command, err := runtimeOracleGuestArgumentsForIdentity(test.prefix, test.executable, nil, test.identity); err == nil || command != nil {
				t.Fatalf("invalid identity accepted: %q, %v", command, err)
			}
		})
	}
}

func TestRuntimeOracleGuestRunnerIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "qemu-aarch64")
	// A fake name/version is explicitly an invalid fixture, not native proof.
	for _, content := range []string{"qemu-aarch64 version 10.2.3\n", "changed runner bytes"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		identity, err := runtimeOracleGuestRunnerSHA(path)
		if err != nil || identity != fmt.Sprintf("%x", sha256.Sum256([]byte(content))) {
			t.Fatalf("exact runner digest: %q, %v", identity, err)
		}
		if command, err := runtimeOracleGuestArgumentsForIdentity([]string{path}, "/guest", nil, identity); err == nil || command != nil {
			t.Fatal("forged or changed runner was accepted")
		}
	}
	for _, invalid := range []string{filepath.Join(dir, "missing"), dir, filepath.Join(dir, "empty"), filepath.Join(dir, "oversize")} {
		if filepath.Base(invalid) == "empty" {
			if err := os.WriteFile(invalid, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if filepath.Base(invalid) == "oversize" {
			file, err := os.Create(invalid)
			if err != nil {
				t.Fatal(err)
			}
			truncateErr := file.Truncate((64 << 20) + 1)
			closeErr := file.Close()
			if truncateErr != nil || closeErr != nil {
				t.Fatalf("invalid fixture: %v, %v", truncateErr, closeErr)
			}
		}
		if identity, err := runtimeOracleGuestRunnerSHA(invalid); err == nil || identity != "" {
			t.Fatalf("invalid runner file accepted: %q, %v", identity, err)
		}
	}
}

func TestRuntimeOracleGuestNativeArguments(t *testing.T) {
	arguments := []string{"-test.run=^TestRuntimeOracleGuestArgumentFixture$", "--", "numeric", "with space", "", "--option", "quote\"backslash\\", "中文"}
	command := runtimeOracleGuestArguments(t, nil, os.Args[0], arguments...)
	ctx, cancel := runtimeOracleStageContext(t)
	child := exec.CommandContext(ctx, command[0], command[1:]...)
	child.Env = append(os.Environ(), "PLAN9ASM_GUEST_ARGUMENT_FIXTURE=1")
	output, err := runtimeOracleCombinedOutput(ctx, child)
	cancel()
	if err != nil {
		t.Fatalf("actual native Go argument fixture: %v\n%s", err, output)
	}
	var got []string
	if err := json.Unmarshal(output, &got); err != nil || !reflect.DeepEqual(got, command) {
		t.Fatalf("actual native argv: got %q want %q, %v", got, command, err)
	}
}

func TestRuntimeOracleGuestArgumentFixture(t *testing.T) {
	if os.Getenv("PLAN9ASM_GUEST_ARGUMENT_FIXTURE") != "1" {
		return
	}
	if err := json.NewEncoder(os.Stdout).Encode(os.Args); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
