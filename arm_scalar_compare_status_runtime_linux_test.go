package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// These first-party witnesses distinguish Go's named VCMPE+VMRS expansion
// from both raw quiet VCMP and signaling VCMPE. FPSCR is observed even when
// source APSR results are dead; neither LLVM fcmp nor a virtual NZCV result
// establishes the native cumulative-exception or FPSCR condition effects.
func TestCrossLinuxRuntimeMatrixARMScalarCompareNativeStatus(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	var source, original, driver strings.Builder
	sigs := make(map[string]FuncSig)
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	var originalCalls, driverCalls strings.Builder
	count := 0
	for _, bits := range []int{32, 64} {
		for _, kind := range []string{"named", "quiet", "signaling"} {
			for _, signalingNaN := range []bool{false, true} {
				for _, live := range []bool{false, true} {
					name := fmt.Sprintf("compare%d", count)
					count++
					low, high := uint32(0x7fc12345), uint32(0x87654321)
					if signalingNaN {
						low = 0x7f812345
					}
					if bits == 64 {
						low, high = 0x12345678, 0x7ff81234
						if signalingNaN {
							high = 0x7ff01234
						}
					}
					status := uint32(0x30000000) // Unordered FPSCR.NZCV.
					if kind != "quiet" || signalingNaN {
						status |= 1 // IOC: VCMPE any NaN, VCMP only signaling NaN.
					}
					apsr := uint32(0x12345678)
					if live {
						apsr = 0x30000000
					}
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-4\nMOVW out+0(FP),R0\nMOVD (R0),F0\n", name)
					source.WriteString("WORD $0xeef14a10\nMOVW $0,R3\nWORD $0xeee13a10\n")
					if kind == "named" {
						op := "CMPF"
						if bits == 64 {
							op = "CMPD"
						}
						fmt.Fprintf(&source, "%s F0\n", op)
					} else {
						word := uint32(0xeeb50a40) // VCMP.F32 S0,#0.
						if bits == 64 {
							word |= 1 << 8
						}
						if kind == "signaling" {
							word |= 1 << 7
						}
						fmt.Fprintf(&source, "WORD $%#x\n", word)
						if live {
							source.WriteString("WORD $0xeef1fa10\n")
						}
					}
					if live {
						source.WriteString("MOVW CPSR,R2\nAND $0xf0000000,R2\nMOVW R2,12(R0)\n")
					}
					source.WriteString("WORD $0xeef13a10\nWORD $0xeee14a10\nMOVW R3,8(R0)\nRET\n")
					sigs[name] = FuncSig{
						Name: name, Args: []LLVMType{Ptr}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
					}
					fmt.Fprintf(&original, "func %s(out *[5]uint32)\n", name)
					fmt.Fprintf(&driver, "extern void %s(uint32_t*);\n", name)
					label := fmt.Sprintf("%s bits=%d %s sNaN=%t live=%t", name, bits, kind, signalingNaN, live)
					fmt.Fprintf(&originalCalls, "{ out := [5]uint32{%#x,%#x,0x98765432,0x12345678,0xabcdef01}\n%s(&out)\n", low, high, name)
					fmt.Fprintf(&originalCalls, "want := [5]uint32{%#x,%#x,%#x,%#x,0xabcdef01}\nif out != want { panic(fmt.Sprintf(%q,out,want)) } }\n", low, high, status, apsr, label+": got %x want %x")
					fmt.Fprintf(&driverCalls, "{ uint32_t out[5]={%#x,%#x,0x98765432,0x12345678,0xabcdef01};\n%s(out);\n", low, high, name)
					fmt.Fprintf(&driverCalls, "uint32_t want[5]={%#x,%#x,%#x,%#x,0xabcdef01};\n", low, high, status, apsr)
					fmt.Fprintf(&driverCalls, "for(unsigned i=0;i<5;i++) { if(out[i]!=want[i]) { fprintf(stderr,%q,i,out[i],want[i]); failures++; } } }\n", label+" word %u: got %08x want %08x\n")
				}
			}
		}
	}
	marker := fmt.Sprintf("ORIGINAL_ARM_SCALAR_COMPARE_STATUS %d", count)
	fmt.Fprintf(&original, "func main() {\n%s\nfmt.Println(%q)\n}\n", originalCalls.String(), marker)
	fmt.Fprintf(&driver, "int main(void) { unsigned failures=0;\n%s\nreturn failures != 0; }\n", driverCalls.String())
	if output := armConversionGoObservations(t, source.String(), original.String()); string(output) != marker+"\n" {
		t.Fatalf("original Go comparison observations:\n%s", output)
	}
	t.Log(marker)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct{ name, ir string }{{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR_%s/backend_O%d", variant.name, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
					"arm_scalar_compare_status", "armv7-unknown-linux-gnueabihf", variant.ir, driver.String(),
					[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
			})
		}
	}
}
