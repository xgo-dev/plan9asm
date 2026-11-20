//go:build go1.27

package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestARM64SyscallGoCompleteConstantClassOriginalBytes(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	// Go asm7's ASVC C_VCON and C_NONE rows encode Offset & 0xffff.
	// This is an encoding observation, not entry/memory or Linux execution proof.
	cases := []struct {
		spelling string
		word     uint32
	}{
		{"SVC", 0xd4000001}, {"SVC $0", 0xd4000001}, {"SVC $1", 0xd4000021},
		{"SVC $0x80", 0xd4001001}, {"SVC $65535", 0xd41fffe1},
		{"SVC $65536", 0xd4000001}, {"SVC $65537", 0xd4000021},
		{"SVC $-1", 0xd41fffe1}, {"SVC $-65536", 0xd4000001},
		{"SVC $9223372036854775807", 0xd41fffe1}, {"SVC $-9223372036854775808", 0xd4000001},
	}
	var source strings.Builder
	for index, test := range cases {
		fmt.Fprintf(&source, "TEXT ·form_%d(SB),516,$0-0\n%s\nRET\n", index, test.spelling)
	}
	directory := t.TempDir()
	input, output := filepath.Join(directory, "forms.s"), filepath.Join(directory, "forms.o")
	if err := os.WriteFile(input, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, release := runtimeOracleStageContext(t)
	defer release()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-p", "example.com/svcforms", "-o", output, input)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm64", "GOARM64=v8.0")
	raw, err := runtimeOracleCombinedOutput(ctx, command)
	if err := goAssemblerOracleOutcome(input, output, raw, err, ctx.Err(), true, "arm64"); err != nil {
		t.Fatalf("independent original Go C_VCON/C_NONE: %v\n%s", err, raw)
	}
	object, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	builtins, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	texts, err := gostaticstorage.ObserveARM64AssemblyText(object, builtins, "linux/arm64")
	if err != nil || len(texts) != len(cases) {
		t.Fatalf("actual original object inventory: %v count=%d", err, len(texts))
	}
	for index, test := range cases {
		t.Run(test.spelling, func(t *testing.T) {
			text := texts[index]
			if text.Name != fmt.Sprintf("example.com/svcforms.form_%d", index) || text.ABI != 0 ||
				len(text.Code) < 8 || len(text.Relocations) != 0 || len(text.Positions) == 0 ||
				binary.LittleEndian.Uint32(text.Code[:4]) != test.word || binary.LittleEndian.Uint32(text.Code[4:8]) != 0xd65f03c0 {
				t.Fatalf("independent actual ASVC constant bytes differ: %+v", text)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64SyscallEffectAPI(t, api, "aarch64-unknown-linux-gnu", arm64SyscallEffectSource("CMP R2,R1\n"+test.spelling))
					if err != nil {
						t.Fatalf("Go-accepted C_VCON spelling missing: %v", err)
					}
					fragment := arm64SyscallEffectIR(t, ir, test.spelling)
					if !strings.Contains(fragment, "ptr %reg_R8") || strings.Contains(fragment, "ptr %flags_") {
						t.Fatalf("encoded immediate selected a non-Linux ABI/effect: %s", fragment)
					}
					for _, optimization := range []int{0, 2} {
						t.Run(fmt.Sprintf("O%d", optimization), func(t *testing.T) {
							arm64LinuxSyscallEffectCompileObject(t, llc, ir, optimization)
						})
					}
				})
			}
		})
	}
	for _, spelling := range []string{"SVC R0", "SVC (R0)", "SVC $0,$1", "SVC $1.5", "SVC.P $0", "SVC.W $0"} {
		t.Run("Go-reject/"+spelling, func(t *testing.T) {
			requireARM64GoAssemblerResult(t, "TEXT ·invalid(SB),516,$0-0\n"+spelling+"\nRET\n", false)
		})
	}
}
