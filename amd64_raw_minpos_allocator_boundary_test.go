package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These are explicit observations of an unresolved synthetic allocation, not
// successful stack semantics, source rejection, native bounds or runtime tests.
// Both original Go sources are legal, but lack a bounded initialized AUTO or
// native stack role and therefore retain public Context. A private format unit
// still observes the original >4 GiB synthetic allocator: llc O0 rejects its
// frame offsets. This is neither public success nor native stack permission.
func TestX86RawMinimumPositionHugeSPAllocatorBoundaryObservation(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	// Keep the complete mode32 address inventory in both source forms. The
	// original encoded RET remains a negative stack/continuation control;
	// the raw compile-only probe replaces only that RET with encoded UD2.
	source, _, count, _ := x86MinimumPositionAddressSources("386", "giant", "UD2")
	if count != 240 {
		t.Fatalf("complete mode32 address denominator changed: %d", count)
	}
	namedCode := x86MinimumPositionOriginalGoBytes(t, "386", source)
	namedFile, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	rawSource, _, _, _ := x86MinimumPositionAddressSources("386", "giant", "RET")
	rawCode := x86MinimumPositionOriginalGoBytes(t, "386", rawSource)
	x86UnboundVoidFormatSources(t, "TEXT giant(SB),4,$0-0\n"+x86DwordProductDirectives(rawCode),
		"386", "i386-unknown-linux-gnu")
	rawFile := x86RawStackObservingFormProbeFile(t, "386", "giant", rawCode)
	for _, fixture := range []struct {
		name   string
		file   *File
		source string
		code   []byte
	}{
		{"named", namedFile, source, namedCode},
		{"original-byte-probe", rawFile, rawSource, rawCode},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			file := fixture.file
			before := fmt.Sprintf("%#v", file.Funcs)
			for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				// The same complete 240-row typed emitter remains an explicit
				// private allocation diagnostic, with no cached input proof.
				privateIR := x86UnboundBlendMinposProbeObject(t, file, "386", triple)
				if !strings.Contains(privateIR, "%local_stack = alloca [4294967439 x i8]") {
					t.Fatal("private allocator lost the complete original SP envelope")
				}
				for _, api := range []string{"text", "module", "context"} {
					t.Run(triple+"/"+api, func(t *testing.T) {
						options := Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]FuncSig{"giant": {Name: "giant", Ret: Void}}}
						var ir string
						var err error
						switch api {
						case "text":
							ir, err = Translate(file, options)
						case "module":
							module, callErr := TranslateModule(file, options)
							err = callErr
							if !module.IsNil() {
								defer module.Dispose()
								ir = module.String()
							}
						case "context":
							ctx := llvm.NewContext()
							defer ctx.Dispose()
							module, callErr := TranslateModuleInContext(ctx, file, options)
							err = callErr
							if !module.IsNil() {
								defer module.Dispose()
								ir = module.String()
							}
						}
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || before != fmt.Sprintf("%#v", file.Funcs) {
							t.Fatalf("unbound source acquired a public AUTO/stack role: %v; complete source unchanged=%t", err, before == fmt.Sprintf("%#v", file.Funcs))
						}
						// The exact private source envelope is [-2^31, 2^31-1+16),
						// plus the original two 64-byte synthetic guards. Reusing
						// this private IR is not an API translation certificate.
						dir := t.TempDir()
						input, object := filepath.Join(dir, "giant.ll"), filepath.Join(dir, "giant.o")
						if err := os.WriteFile(input, []byte(privateIR), 0600); err != nil {
							t.Fatal(err)
						}
						ctx, cancel := runtimeOracleStageContext(t)
						defer cancel()
						command := exec.CommandContext(ctx, llc, "-O0", "-filetype=obj", "-mtriple="+triple, "-o", object, input)
						output, err := runtimeOracleCombinedOutput(ctx, command)
						if ctx.Err() != nil {
							t.Fatalf("bounded compiler observation expired: %v: %s", err, output)
						}
						exit, ordinaryExit := err.(*exec.ExitError)
						if !ordinaryExit || exit.ExitCode() != 1 {
							t.Fatalf("expected plain LLVM32 O0 offset failure, got %v: %s", err, output)
						}
						diagnostic := "error: <unknown>:0:0: 64-bit offset calculated but target is 32-bit"
						warning := regexp.MustCompile(`^warning: <unknown>:0:0: stack frame size \(([0-9]+)\) exceeds limit \(4294967295\) in function 'InstructionFormat0'$`)
						errors, warnings := 0, 0
						text := strings.ReplaceAll(string(output), "\r\n", "\n")
						if strings.Contains(text, "\r") {
							t.Fatalf("malformed diagnostic line endings: %q", output)
						}
						for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
							if line == diagnostic {
								errors++
								continue
							}
							match := warning.FindStringSubmatch(line)
							if len(match) != 2 {
								t.Fatalf("unknown diagnostic is not the observed allocator boundary: %s", output)
							}
							frameBytes, err := strconv.ParseUint(match[1], 10, 64)
							if err != nil || frameBytes <= 4294967295 {
								t.Fatalf("compiler warning did not observe an oversized frame: %s", line)
							}
							warnings++
						}
						if warnings != 1 || errors == 0 {
							t.Fatalf("missing/changed exact allocator diagnostics: errors=%d warnings=%d", errors, warnings)
						}
						t.Logf("LLVM_ALLOCATOR_BOUNDARY_OBSERVATION: source SHA=%x; original Go code SHA=%x; %s public %s=Context; private InstructionFormat0 local_stack=4294967439 bytes; compiler O0 offset errors=%d, frame warnings=%d; no object/stack correctness/runtime or source-N/A credit", sha256.Sum256([]byte(fixture.source)), sha256.Sum256(fixture.code), fixture.name, api, errors, warnings)
					})
				}
			}
		})
	}
}

func TestX86MinimumPositionInitializedBoundedAUTOPublicObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const initialized = `TEXT Bounded(SB),4,$32-4
MOVL $0x12345678,AX
MOVL AX,tmp-16(SP)
MOVL AX,tmp-12(SP)
MOVL AX,tmp-8(SP)
MOVL AX,tmp-4(SP)
VMOVUPS tmp-16(SP),X1
PHMINPOSUW X1,X2
VPHMINPOSUW tmp-16(SP),X3
MOVL X2,AX
MOVL X3,BX
XORL BX,AX
MOVL AX,ret+0(FP)
RET
`
	for _, target := range x86RawReturnTargets {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%t", target.triple, missing), func(t *testing.T) {
				source := initialized
				if missing {
					source = strings.Replace(source, "MOVL AX,tmp-12(SP)\n", "", 1)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Bounded() uint32", target.arch, target.triple, api)
						if missing {
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("bounded AUTO invented the missing original initialized word", err)
							}
							return
						}
						if err != nil || ir == "" {
							t.Fatal("complete small-frame numerical source rejected", err)
						}
						for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							x86PackedStringCompileObject(t, llc, target.triple, input, "-O0")
						}
					})
				}
			})
		}
	}
}
