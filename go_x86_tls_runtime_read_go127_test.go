//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoX86TLSRuntimeRead386Relocations(t *testing.T) {
	llc, readobj := findLLVM22Tool("llc"), findLLVM22Tool("llvm-readobj")
	if llc == "" || readobj == "" {
		t.Fatal("386 TLS runtime reads require LLVM 22")
	}
	for _, profile := range []struct {
		target string
		shared bool
		reloc  string
	}{
		{"linux/386", false, "R_386_TLS_LE runtime.tlsg"},
		{"linux/386", true, "R_386_TLS_GOTIE runtime.tlsg"},
		{"windows/386", false, "IMAGE_REL_I386_DIR32 _runtime.tls_g"},
		{"windows/386", true, "IMAGE_REL_I386_DIR32 _runtime.tls_g"},
	} {
		t.Run(fmt.Sprintf("%s/shared=%v", profile.target, profile.shared), func(t *testing.T) {
			pkg, file, options, original, request := x86TLSMoveSourceFixture(t, profile.target, profile.shared,
				"func Value() uint32", "MOVL (TLS),AX\nMOVL 8(TLS),DX\nXORL DX,AX\nMOVL AX,ret+0(FP)\nRET")
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoX86TLSMoveSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if _, err := source.BindTLSMoves(ctx, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("NOP-only binding borrowed a runtime slot: %v", err)
			}
			if len(source.reads) != 2 {
				t.Fatalf("missing exact original 386 TLS loads: %+v; object: %+v", source.reads, source.texts[1][0].Relocations)
			}
			first, second := source.reads[0], source.reads[1]
			modified := source.texts[1][first.Function]
			modified.Relocations = append([]gostaticstorage.TextRelocation(nil), modified.Relocations...)
			modified.Relocations[0].Add++
			ins := file.Funcs[first.Function].Instrs[first.Instruction]
			if _, ok := x86TLSObservedRuntimeRead(ins, "386", profile.target, modified, first.PC, second.PC); ok {
				t.Fatal("modified relocation admitted an original TLS read")
			}
			bound, err := source.BindRuntimeTLSReads(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86TLSMoveBoundAPI(t, pkg, file, original, bound, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					dir := t.TempDir()
					input, object := filepath.Join(dir, "tls.ll"), filepath.Join(dir, "tls.o")
					if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
						t.Fatal(err)
					}
					args := []string{level, "-mtriple=" + options.TargetTriple, "-filetype=obj", input, "-o", object}
					if profile.shared {
						args = append(args, "-relocation-model=pic")
					}
					x86FloatCompareCaptureCommand(t, exec.Command(llc, args...))
					listing := x86FloatCompareCaptureCommand(t, exec.Command(readobj, "--relocations", object))
					if !strings.Contains(string(listing), profile.reloc) {
						t.Fatalf("%s/%s lacks %s:\n%s", api, level, profile.reloc, listing)
					}
				}
			}
		})
	}
}
