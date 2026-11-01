//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ScalarMoveNativeResultsAndFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, prototypes, originals, rows strings.Builder
	count := 0
	for _, row := range []struct {
		op, rexAlias string
		width        int
	}{{"MOVB", "", 1}, {"MOVW", "", 2}, {"MOVL", "", 4}, {"MOVQ", "", 8}, {"MOVD", "", 8},
		{"MOVB", "DH", 1}, {"MOVB", "BH", 1}} {
		for _, dead := range []bool{false, true} {
			name, original := fmt.Sprintf("F%d", count), fmt.Sprintf("Original%d", count)
			body := row.op + " -1(DX)(BX*1),CX"
			native := "MOVQ $0x87654321fedcba98,AX\n" + row.op + " (DI),AX\n"
			if row.rexAlias != "" {
				effective := "SI"
				if row.rexAlias == "BH" {
					effective = "DI"
				}
				body = "MOVQ DX,R8\nMOVQ $0x87654321fedcba98," + effective + "\nMOVB (R8)," + row.rexAlias + "\nMOVQ " + effective + ",CX"
				native = "MOVQ DI,R8\nMOVQ $0x87654321fedcba98," + effective + "\nMOVB (R8)," + row.rexAlias + "\nMOVQ " + effective + ",AX\n"
			}
			if dead {
				body += "\nMOVQ $0x87654321fedcba98,CX"
				native += "MOVQ $0x87654321fedcba98,AX\n"
			}
			assembly, declaration := x86ExtensionNativeFixture(name, "amd64", body, false)
			source.WriteString(assembly)
			declarations.WriteString(strings.ReplaceAll(declaration, "*[4]byte", "*[16]byte"))
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+native+"RET\n")
			var bytes []string
			for _, b := range code {
				bytes = append(bytes, fmt.Sprintf("0x%02x", b))
			}
			symbol := original
			if strings.Contains(execution.triple, "apple") {
				symbol = "_" + symbol
			}
			fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
			fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*);\nextern uint64_t %s(const uint8_t*);\n", name, original)
			discarded := 0
			if dead {
				discarded = 1
			}
			fmt.Fprintf(&rows, "{%s,%s,%d,%d,0,%d},\n", name, original, row.width, row.width, discarded)
			count++
		}
	}
	if count != 14 {
		t.Fatal("incomplete scalar native read family", count)
	}
	// Keep every original live/dead kernel. The additional ordinary register
	// entry has no result at all; its C adapter supplies the comparison value,
	// so both value and protected-page checks still require the native load.
	// This compares instruction effects, not a C-to-Go ABIInternal call bridge.
	source.WriteString("TEXT ·VoidLoad<ABIInternal>(SB),4,$0-8\nMOVQ (AX),BX\nRET\n")
	declarations.WriteString("func VoidLoad(p *uint64)\n")
	prototypes.WriteString(`extern void VoidLoad(const uint8_t*);
static uint64_t VoidAdapter(const uint8_t *p) {
    VoidLoad(p);
    return UINT64_C(0x87654321fedcba98);
}
`)
	voidCode := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\nMOVQ (DI),AX\nMOVQ $0x87654321fedcba98,AX\nRET\n")
	var voidBytes []string
	for _, value := range voidCode {
		voidBytes = append(voidBytes, fmt.Sprintf("0x%02x", value))
	}
	voidSymbol := "OriginalVoid"
	if strings.Contains(execution.triple, "apple") {
		voidSymbol = "_" + voidSymbol
	}
	fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+voidSymbol+"\n"+voidSymbol+":\n.byte "+strings.Join(voidBytes, ",")+"\n")
	prototypes.WriteString("extern uint64_t OriginalVoid(const uint8_t*);\n")
	rows.WriteString("{VoidAdapter,OriginalVoid,8,8,0,1},\n")
	count++
	if count != 15 {
		t.Fatal("Void removed a previous native scalar kernel", count)
	}
	requireAMD64RegisterResultGoObject(t, source.String())
	// Reuse the independent fork/guard-page harness, not the implementation's
	// operand/effect descriptors. Add byte preservation and room for an
	// unaligned full-qword input to its scalar value reference.
	driverTemplate := strings.NewReplacer(
		"if(k.destination==2)", "if(k.destination==1) return (seed&~UINT64_C(0xff))|(value&0xff);\n    if(k.destination==2)",
		"uint8_t bytes[8];", "uint8_t bytes[16];",
		"28 extension kernels", "15 scalar move kernels",
	).Replace(x86ExtensionNativeRuntimeC)
	driver := fmt.Sprintf(driverTemplate, prototypes.String(), originals.String(), rows.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
					text, level := ir, "-O0"
					if optimized {
						text, level = x86MulDivRoundOptimize(t, ir), "-O2"
					}
					output := execution.compileAndRunLLVM(t, "scalar-move-native", text, driver, level)
					if string(output) != "15 scalar move kernels: numerical 1920, fault 180, tripwires 2; failures 0\n" {
						t.Fatal("original Go/LLVM native reads differ", string(output))
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
}
