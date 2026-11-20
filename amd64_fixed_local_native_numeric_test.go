package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalRequireNumericNativeRole(t *testing.T, fn Func, base Reg) {
	t.Helper()
	ctx := amd64Ctx{fixedLocal: fn.x86FixedLocal}
	found := false
	for _, ins := range fn.Instrs {
		for index, operand := range ins.Args {
			if operand.Kind != OpMem || operand.Mem.Base != base {
				continue
			}
			access, valid := ctx.fixedLocalMemoryAccess(ins, index)
			if !valid || !access.nativeInput || ctx.fixedLocalMemoryCertified(ins, index) {
				t.Fatal("numerical native access acquired private storage", ins.Raw, access)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing original numerical native access", base)
	}
}

// These ordinary source programs establish machine bits independently of
// pointer types. The access keeps a native address, never a private offset.
func TestGoAMD64FixedLocalNativeNumericWidths(t *testing.T) {
	var assembly strings.Builder
	count := 0
	for _, register := range []string{"BX", "BP", "R14"} {
		for _, suffix := range []string{"B", "W", "L", "Q"} {
			for _, operation := range []string{
				"MOV%s (%s),CX",
				"MOV%s $17,(%s)",
				"ADD%s $1,(%s)",
			} {
				accessSource := fmt.Sprintf(operation, suffix, register)
				body := "MOVQ AX," + register + "\n" + accessSource + "\nMOVQ $0,AX"
				fn, sig, source := fixedLocalInputFixture(t, body)
				assembly.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", count), 1))
				count++
				t.Run(register+"/"+accessSource, func(t *testing.T) {
					proved, err := proveX86FixedLocal(fn, sig)
					if err != nil {
						t.Fatal("complete numerical machine address rejected", err)
					}
					found := false
					ctx := amd64Ctx{fixedLocal: proved.x86FixedLocal}
					for _, ins := range proved.Instrs {
						if ins.Raw != accessSource {
							continue
						}
						for index, access := range ins.x86FixedLocalMemory {
							found = true
							if !access.nativeInput || access.owner != proved.x86FixedLocal || ctx.fixedLocalMemoryCertified(ins, index) {
								t.Fatal("native numerical access acquired private storage", access)
							}
						}
					}
					if !found {
						t.Fatal("original numerical access lost its exact source binding")
					}
				})
			}
		}
	}
	if count != 36 {
		t.Fatal("GP bank/width/effect inventory changed", count)
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
}

func TestGoAMD64FixedLocalNativeNumericProducers(t *testing.T) {
	for _, body := range []string{
		"MOVQ (SI),R14\nMOVQ (R14),AX",
		"MOVQ (SI),CX\nMOVQ 32(SI),DX\nADDQ DX,CX\nMOVQ CX,8(SP)\nMOVQ 8(SP),R14\nSUBQ AX,R14\nMOVQ (R14),AX",
		"MOVQ AX,R14\nMOVQ $2,CX\nLEAQ -8(R14)(CX*4),R14\nMOVQ (R14),AX",
		"MOVQ $0,R14\nMOVQ (R14),CX\nMOVQ $0,AX",
	} {
		t.Run(strings.ReplaceAll(body, "\n", "/"), func(t *testing.T) {
			fn, sig, _ := fixedLocalInputFixture(t, body)
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("native numerical address lost an initialized producer", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalNativeNumericGuards(t *testing.T) {
	for name, body := range map[string]string{
		"unknown base":             "MOVQ (R14),AX",
		"partial base":             "MOVW $0,R14\nMOVQ (R14),AX",
		"unknown index":            "MOVQ AX,R14\nMOVQ (R14)(R15*1),AX",
		"partial index":            "MOVQ AX,R14\nMOVW $0,R15\nMOVQ (R14)(R15*1),AX",
		"private address bits":     "MOVQ SP,R14\nXORQ $1,R14\nMOVQ (R14),AX",
		"private address store":    "MOVQ AX,R14\nMOVQ SP,CX\nMOVQ CX,(R14)",
		"private missing byte":     "MOVQ AX,R14\nMOVQ 8(SP),CX\nMOVQ CX,(R14)",
		"private range":            "MOVQ AX,R14\nMOVQ (R14),CX\nMOVQ CX,60(SP)",
		"opaque partial overwrite": "MOVB $0,SI\nMOVQ (SI),AX",
		"unknown incoming R14":     "ADDQ $0,R14\nMOVQ (R14),AX",
		"unknown path":             "CMPQ AX,$0\nJEQ known\nJMP join\nknown:\nMOVQ AX,R14\njoin:\nMOVQ (R14),AX",
		"segment":                  "MOVQ AX,R14\nMOVQ (R14)(FS*1),AX",
	} {
		t.Run(name, func(t *testing.T) {
			fn, sig, _ := fixedLocalInputFixture(t, body)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unknown bytes or private address acquired a native role", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalNativeNumericObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	assembly, declarations := fixedLocalNativeNumericRuntimeSources(t)
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			fixedLocalConversionPrepareToolCache(t, request)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				for _, input := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					if strings.Count(input, "load volatile i64") < 8 || strings.Count(input, "store volatile") < 4 {
						t.Fatal("native address producer or dead access lost its observable effect")
					}
					compileLLVMToObject(t, llc, target.triple, "native-numeric.ll", "native-numeric.o", input)
				}
			})
		})
	}
}

func fixedLocalNativeNumericRuntimeSources(t *testing.T) (string, string) {
	t.Helper()
	var assembly, declarations strings.Builder
	for _, store := range []bool{false, true} {
		for index, suffix := range []string{"B", "W", "L", "Q"} {
			ordinal := index
			access := "MOV" + suffix + " (R14),CX"
			if store {
				ordinal += 4
				access = "MOV" + suffix + " $17,(R14)"
			}
			body := "MOVQ (SI),R14\nMOVQ R14,8(SP)\nMOVQ 8(SP),R14\nADDQ $3,R14\nSUBQ $3,R14\n" + access + "\nMOVQ $23063,AX"
			_, _, source := fixedLocalInputFixture(t, body)
			assembly.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", ordinal), 1))
			fmt.Fprintf(&declarations, "func Value%d(p, q *uint64, a uint64) uint64\n", ordinal)
		}
	}
	return assembly.String(), declarations.String()
}
