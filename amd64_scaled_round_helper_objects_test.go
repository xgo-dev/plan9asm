package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var x86ScaledRoundSelectedMembers = []struct {
	op     string
	bits   int
	scalar bool
	reduce bool
}{
	{"VRNDSCALEPS", 32, false, false},
	{"VRNDSCALEPD", 64, false, false},
	{"VRNDSCALESS", 32, true, false},
	{"VRNDSCALESD", 64, true, false},
	{"VREDUCEPS", 32, false, true},
	{"VREDUCEPD", 64, false, true},
	{"VREDUCESS", 32, true, true},
	{"VREDUCESD", 64, true, true},
}

func x86ScaledRoundSelectedPublicSource(arch string) (string, string) {
	pointerBytes, move, extent := 8, "MOVQ", 28
	if arch == "386" {
		pointerBytes, move, extent = 4, "MOVL", 16
	}
	var source, declarations strings.Builder
	for _, member := range x86ScaledRoundSelectedMembers {
		if arch == "386" && member.scalar {
			continue // Go's named scalar row has four operands, absent in 386.
		}
		name := "Selected" + member.op
		fmt.Fprintf(&declarations, "func %s(out, source, upper *[16]byte, control uint32)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),AX\n%s source+%d(FP),BX\n%s upper+%d(FP),CX\nLDMXCSR control+%d(FP)\nVMOVUPS (CX),X1\n",
			name, extent, move, move, pointerBytes, move, 2*pointerBytes, 3*pointerBytes)
		operands := "(BX),X2"
		if member.scalar {
			operands = "(BX),X1,X2"
		}
		fmt.Fprintf(&source, "%s $49,%s\nVMOVUPS X2,(AX)\nRET\n", member.op, operands)
	}
	return source.String(), declarations.String()
}

func TestX86ScaledRoundCompleteTypedHelperRequirements(t *testing.T) {
	for _, member := range x86ScaledRoundSelectedMembers {
		t.Run(member.op, func(t *testing.T) {
			operands := "X0,X2"
			if member.scalar {
				operands = "X0,X1,X2"
			} else {
				// Packed SAE requires Z; never infer helper requirements from
				// an invalid operand/suffix combination.
				operands = "Z0,Z2"
			}
			file, err := Parse(ArchAMD64, "TEXT Requirements(SB),4,$0-0\n"+member.op+".SAE $49,"+operands+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			var helper strings.Builder
			emitAMD64FMA3RoundingHelpers(&helper, file, "amd64")
			for _, bits := range []int{32, 64} {
				want := 0
				if member.reduce && member.bits == bits {
					want = 1
				}
				for _, name := range []string{"__plan9asm_add_sub_round_f", "__plan9asm_fma3_round_f"} {
					typ := "float"
					if bits == 64 {
						typ = "double"
					}
					definition := fmt.Sprintf("define internal %s @%s%d(", typ, name, bits)
					if got := strings.Count(helper.String(), definition); got != want {
						t.Fatalf("typed %s emitted %d definitions for %s, want %d", member.op, got, definition, want)
					}
				}
			}
		})
	}
}

func TestX86ScaledRoundPublicThreeAPISelectedRoundingObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
		// Goarch and backend are independent public options. These two
		// object-only projections retain x86 MXCSR while exercising the real
		// software fallback. They do not claim a native AMD64-to-386 Go ABI,
		// or cross-ISA public MXCSR support on ARM/wasm.
		{"amd64", "i386-unknown-linux-gnu"},
		{"amd64", "i686-pc-windows-msvc"},
	} {
		t.Run(target.arch+"/"+target.triple, func(t *testing.T) {
			source, declarations := x86ScaledRoundSelectedPublicSource(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("fully initialized public selected-rounding source rejected", err)
					}
					for _, member := range x86ScaledRoundSelectedMembers {
						if target.arch == "386" && member.scalar {
							continue
						}
						body := x86StringMemoryFunction(t, ir, "Selected"+member.op)
						if x86ScalarFloatIntegerNativeTarget(target.arch, target.triple) {
							if !strings.Contains(body, "asm sideeffect") || !strings.Contains(body, strings.ToLower(member.op)) {
								t.Fatal("matching native target lost its original opcode", member.op)
							}
						} else if member.reduce {
							call := fmt.Sprintf("@__plan9asm_add_sub_round_f%d(", member.bits)
							if !strings.Contains(body, call) || strings.Contains(body, " = fsub ") {
								t.Fatal("portable public REDUCE lost selected-rounding subtraction", member.op)
							}
						}
					}
					for _, pipeline := range []struct {
						name, backend string
						optimized     bool
					}{
						{"backend_O0", "-O0", false},
						{"backend_O2", "-O2", false},
						{"IR_O2/backend_O2", "-O2", true},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							text := ir
							if pipeline.optimized {
								text = x86DwordProductIROptimize(t, ir)
							}
							x86PackedStringCompileObject(t, llc, target.triple, text, pipeline.backend)
						})
					}
				})
			}
		})
	}
}
