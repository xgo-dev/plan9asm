package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86SHADefaultGoarchNativeTarget(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\nPXOR X1,X1\nSHA1MSG1 X1,X1\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	options := Options{TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"Value": {Name: "Value", Ret: Void}}}
	for _, api := range []string{"text", "module"} {
		t.Run(api, func(t *testing.T) {
			if api == "text" {
				if ir, err := Translate(file, options); err != nil || ir == "" {
					t.Fatal("default amd64 Go source lost its explicit native target", err)
				}
				return
			}
			context := llvm.NewContext()
			defer context.Dispose()
			module, err := TranslateModuleInContext(context, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil || module.IsNil() {
				t.Fatal("default amd64 Go source lost its explicit native target", err)
			}
		})
	}
}

func TestX86SHABackendIgnoresOrdinaryNamesAndUnusedDeclarations(t *testing.T) {
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, `target triple = "aarch64-unknown-linux-gnu"
declare <4 x i32> @llvm.x86.sha1msg1(<4 x i32>, <4 x i32>)
define void @SHA1MSG1() { ret void }
define void @ordinary() { call void @SHA1MSG1() ret void }
`)
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	if err := validateTranslatedBackend(nil, Options{}, module); err != nil {
		t.Fatal("an ordinary function name or unused declaration constrained the backend", err)
	}
}

func TestX86SHABackendRequirement(t *testing.T) {
	for _, row := range x86SHAOracleInputs {
		for _, api := range []string{"text", "module", "Go"} {
			for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
				t.Run(row.name+"/"+api+"/"+triple, func(t *testing.T) {
					body := "PXOR X0,X0\nPXOR X1,X1\nPXOR X2,X2\n" +
						x86SHAOracleRow(row.name, "X1", "X2", 3) + "\nRET"
					ir, err := targetBackendRequest(t, api, triple, targetBackendCase{arch: ArchAMD64, goarch: "amd64", body: body})
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("SHA target-specific operation escaped to an unspecified or foreign backend", err)
					}
				})
			}
		}
	}
}

func TestX86SHALoweringUsesExactLLVMOperations(t *testing.T) {
	// A format unit isolates the original semantic bug from the independent
	// initialized-source gate. It is not a successful public translation.
	for _, row := range x86SHAOracleInputs {
		t.Run(row.name, func(t *testing.T) {
			instruction := x86SHAOracleRow(row.name, "X1", "X2", 3)
			source := "TEXT sha(SB),4,$0-0\n" + instruction + "\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir := x86InstructionFormatObjectUnit(t, file, map[string]FuncSig{"sha": {Name: "sha", Ret: Void}},
				"amd64", "x86_64-unknown-linux-gnu", 0,
				func(c *amd64Ctx, ins Instr) (bool, bool, error) { return c.lowerVec(ins.Op, ins) })
			if !strings.Contains(ir, "call <4 x i32> @llvm.x86."+strings.ToLower(row.name)+"(") {
				t.Fatal("SHA must use its exact operation, not approximate lane additions")
			}
		})
	}
}

func TestX86SHAInitializedNamedRawFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range x86RawReturnTargets {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", target.triple, raw), func(t *testing.T) {
				var source, declarations strings.Builder
				count := 0
				for _, row := range x86SHAOracleInputs {
					selectors := []int{0}
					if row.name == "SHA1RNDS4" {
						selectors = []int{0, 1, 2, 3}
					}
					for _, selector := range selectors {
						name := fmt.Sprintf("Value%d", count)
						count++
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-12\nMOVL a+0(FP),AX\nMOVL b+4(FP),BX\n", name)
						// Initialize only numerically consumed dwords; untouched
						// input lanes must not be silently borrowed from alloca zero.
						for register, mask := range []uint16{row.implicit, row.source, row.old} {
							for lane := 0; lane < 4; lane++ {
								if mask&(15<<uint(lane*4)) != 0 {
									gp := []string{"AX", "BX", "AX"}[register]
									fmt.Fprintf(&source, "PINSRD $%d,%s,X%d\n", lane, gp, register)
								}
							}
						}
						instruction := x86SHAOracleRow(row.name, "X1", "X2", selector)
						if raw {
							instruction = x86RawNumericalInstruction(t, target.arch, instruction)
						}
						fmt.Fprintf(&source, "%s\nPEXTRD $0,X2,AX\nMOVL AX,ret+8(FP)\nRET\n", instruction)
						fmt.Fprintf(&declarations, "func %s(a,b uint32) uint32\n", name)
					}
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("initialized original SHA results failed", err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						}
					})
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalSHAObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	rows := fixedLocalSHACases()
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(fixedLocalVEXAssembly(row), "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *uint64,a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}
