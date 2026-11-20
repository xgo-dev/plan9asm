package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86UnnamedAddressImmediateActualGoEncoding(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"MOVB", "MOVW", "MOVL", "MOVQ"} {
			if arch == "386" && op == "MOVQ" {
				continue // Go's Q GP instruction is a different, invalid mode.
			}
			for _, address := range []string{"16(AX)", "8(AX)(CX*1)", "-7(BP)", "32(SP)(SI*4)"} {
				t.Run(arch+"/"+op+"/"+address, func(t *testing.T) {
					end := strings.IndexByte(address, '(')
					literal := address[:end]
					fixture := func(operand string) string {
						return "TEXT addr(SB),4,$0-0\n" + op + " $" + operand + ",BX\nRET\n"
					}
					annotated := x86PackedShiftActualGoBytes(t, arch, fixture(address))
					comparison := fixture(literal)
					if op == "MOVL" || op == "MOVQ" {
						// progedit runs before oclass. These two opcodes become
						// a memory-class LEA, not a TYPE_CONST instruction.
						comparison = "TEXT addr(SB),4,$0-0\nLEA" + op[3:] + " " + address + ",BX\nRET\n"
					}
					constant := x86PackedShiftActualGoBytes(t, arch, comparison)
					if !bytes.Equal(annotated, constant) {
						t.Fatalf("actual progedit/oclass bytes differ: annotated=%x comparison=%x", annotated, constant)
					}
					t.Logf("ORIGINAL_TYPE_ADDR arch=%s op=%s operand=$%s bytes=%x", arch, op, address, annotated)
				})
			}
		}
	}
}

func TestX86UnnamedAddressImmediateGoIntegerDomains(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, family := range []string{"MOV", "ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "CMP", "TEST", "SAL", "SHL", "SHR", "SAR", "ROL", "ROR", "RCL", "RCR", "IMUL", "BT", "BTC", "BTR", "BTS"} {
			for _, suffix := range []string{"B", "W", "L", "Q"} {
				if family == "MOV" && (suffix == "L" || suffix == "Q") || suffix == "Q" && arch == "386" ||
					family == "IMUL" && suffix == "B" || strings.HasPrefix(family, "BT") && suffix == "B" {
					continue
				}
				op := family + suffix
				t.Run(arch+"/"+op, func(t *testing.T) {
					instruction := op + " $16(AX)(CX*1),BX"
					if family == "CMP" {
						instruction = op + " BX,$16(AX)(CX*1)"
					}
					fixture := "TEXT addr(SB),4,$0-0\n" + instruction + "\nRET\n"
					plain := strings.ReplaceAll(fixture, "$16(AX)(CX*1)", "$16")
					annotated := x86PackedShiftActualGoBytes(t, arch, fixture)
					constant := x86PackedShiftActualGoBytes(t, arch, plain)
					if !bytes.Equal(annotated, constant) {
						t.Fatalf("NAME_NONE register annotations changed literal encoding: annotated=%x plain=%x", annotated, constant)
					}
					t.Logf("ORIGINAL_CONSTANT_DOMAIN arch=%s instruction=%q bytes=%x", arch, instruction, annotated)
				})
			}
		}
	}
}

func TestX86UnnamedAddressImmediateGoMemoryOnlyRejections(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"FMOVB", "FMOVW", "FMOVL", "FMOVV", "FMOVD", "FMOVX"} {
			for _, instruction := range []string{op + " $16(AX),F0", op + "P F0,$16(AX)"} {
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					fixture := "TEXT addr(SB),4,$0-0\n" + instruction + "\nRET\n"
					x86ScalarLiteralExpectedGoListing(t, arch, fixture, false)
					file, err := Parse(ArchAMD64, fixture)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"addr": {Ret: Void}}}); err == nil {
						t.Fatal("Go-invalid integer TYPE_ADDR gained an x87 memory/float-literal role")
					}
				})
			}
		}
		for _, op := range []string{"MOVSS", "MOVSD", "MOVAPS", "MOVAPD", "MOVUPS", "MOVUPD", "MOVO", "MOVOU", "ADDPS", "ADDPD", "ADDSS", "ADDSD", "MULPS", "MULPD", "MULSS", "MULSD", "DIVPS", "DIVPD", "DIVSS", "DIVSD"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				fixture := "TEXT addr(SB),4,$0-0\n" + op + " $16(AX),X0\nRET\n"
				x86ScalarLiteralExpectedGoListing(t, arch, fixture, false)
				file, err := Parse(ArchAMD64, fixture)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"addr": {Ret: Void}}}); err == nil {
					t.Fatal("Go-invalid integer TYPE_ADDR gained an SSE memory/float-literal role")
				}
			})
		}
	}
}

func TestX86UnnamedAddressImmediateTranslation(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, instruction := range []string{
			"MOVB $16(AX),BX", "MOVW $8(AX)(CX*1),BX", "MOVL $-7(AX)(CX*4),BX",
			"ADDW $16(AX),BX", "SUBL $16(AX),BX", "ADCW $16(AX),BX", "SBBL $16(AX),BX",
			"ANDL $16(AX),BX", "ORW $16(AX),BX", "XORB $16(AX),BX",
			"CMPW BX,$16(AX)", "TESTL $16(AX),BX", "SHLL $16(AX),BX",
			"SHRW $16(AX),BX", "IMULW $16(AX),BX", "IMUL3L $16(AX),CX,BX",
			"BTW $16(AX),BX", "BTCL $16(AX),BX", "BTRW $16(AX),BX", "BTSL $16(AX),BX",
		} {
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				source := "TEXT addr(SB),4,$0-0\nMOVL $3,AX\nMOVL $2,CX\nMOVL $1,BX\n" + instruction + "\nRET\n"
				x86PackedShiftActualGoBytes(t, arch, source)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"addr": {Ret: Void}}}); err != nil {
					t.Fatalf("actual Go integer/address source failed translation: %v", err)
				}
			})
		}
	}
}

// Execute the same original Go instruction bytes with independently varied
// AX/CX and a full BX sentinel. This is a first-party integer observation; a
// Darwin/ARM64 Rosetta execution is diagnostic, not native AMD64 coverage.
func TestCrossLinuxRuntimeMatrixX86UnnamedAddressImmediateValues(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	for index, row := range []struct {
		op, operand string
		bits        int
		value       uint64
	}{
		{"MOVB", "$16(AX)", 8, 16}, {"MOVW", "$8(AX)(CX*1)", 16, 8},
		{"MOVL", "$-7(AX)(CX*4)", 32, 0xfffffff9}, {"MOVQ", "$32(AX)(CX*8)", 64, 32},
	} {
		t.Run(row.op, func(t *testing.T) {
			var assembly, declarations, checks strings.Builder
			name := fmt.Sprintf("addr%d", index)
			fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-24\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),CX\nMOVQ $0x5a77bb9911eecc33,BX\n%s %s,BX\nMOVQ BX,ret+16(FP)\nRET\n", name, row.op, row.operand)
			code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT addr(SB),4,$0-0\n"+row.op+" "+row.operand+",BX\nRET\n")
			decoded, err := x86asm.Decode(code, 64)
			if err != nil || decoded.Len == 0 {
				t.Fatalf("original single instruction: %x / %v", code, err)
			}
			var directive strings.Builder
			for offset, b := range code[:decoded.Len] {
				if offset != 0 {
					directive.WriteByte(',')
				}
				fmt.Fprintf(&directive, "0x%02x", b)
			}
			fmt.Fprintf(&declarations, "extern uint64_t %s(uint64_t,uint64_t);\nstatic uint64_t original%d(uint64_t a,uint64_t b) {\n uint64_t got;\n __asm__ volatile(\"movq %%1,%%%%rax; movq %%2,%%%%rcx; movabsq $0x5a77bb9911eecc33,%%%%rbx; .byte %s; movq %%%%rbx,%%0\" : \"=r\"(got) : \"r\"(a),\"r\"(b) : \"rax\",\"rcx\",\"rbx\",\"cc\");\n return got;\n}\n", name, index, directive.String())
			mask := ^uint64(0)
			if row.bits < 64 {
				mask = uint64(1)<<uint(row.bits) - 1
			}
			want := fmt.Sprintf("UINT64_C(%d)", row.value&mask|uint64(0x5a77bb9911eecc33)&^mask)
			if row.bits == 32 {
				want = "(uint64_t)(uint32_t)(a+4*b-7)"
			} else if row.bits == 64 {
				want = "(a+8*b+32)"
			}
			fmt.Fprintf(&checks, "  { uint64_t want=%s;\n    if (original%d(a,b)!=want || %s(a,b)!=want) { fprintf(stderr,\"bad TYPE_ADDR case %d seed %%u\\n\",seed); return %d; }\n  }\n", want, index, name, index, index+11)
			file, err := Parse(ArchAMD64, assembly.String())
			if err != nil {
				t.Fatal(err)
			}
			sigs := make(map[string]FuncSig)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{I64, I64}, Ret: I64, Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}},
				Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
			}}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			main := "#include <stdint.h>\n#include <stdio.h>\n" + declarations.String() + "int main(void) {\n for(unsigned seed=0;seed<256;seed++) {\n  uint64_t a=UINT64_C(0x1313939382827272)*seed,b=~a;\n" + checks.String() + " }\n puts(\"TYPE_ADDR_NATIVE_MATH_256_OK\");\n return 0;\n}\n"
			for _, level := range []string{"-O0", "-O2"} {
				execution.compileAndRunLLVM(t, "unnamed-address", ir, main, level)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86UnnamedAddressImm32MathAndCanaries(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	for _, row := range []struct {
		operation, expected string
	}{
		{"ADDQ", "a-1"}, {"SUBQ", "a+1"}, {"ADCQ", "a-1"}, {"SBBQ", "a+1"},
		{"ANDQ", "a"}, {"ORQ", "UINT64_MAX"}, {"XORQ", "~a"}, {"IMULQ", "0-a"},
		{"CMPQ", "(uint64_t)(a<UINT64_MAX)"}, {"TESTQ", "(uint64_t)(a==0)"},
	} {
		t.Run(row.operation, func(t *testing.T) {
			instruction := row.operation + " $0xffffffff(AX),BX"
			if row.operation == "CMPQ" {
				instruction = row.operation + " BX,$0xffffffff(AX)"
			}
			observation, originalObservation := "", ""
			if row.operation == "CMPQ" || row.operation == "TESTQ" {
				flag := "SETCS"
				cFlag := "setc"
				if row.operation == "TESTQ" {
					flag, cFlag = "SETEQ", "sete"
				}
				observation = flag + " DL\nMOVBQZX DX,BX\n"
				originalObservation = cFlag + " %%dl; movzbq %%dl,%%rbx; "
			}
			code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT addr(SB),4,$0-0\n"+instruction+"\nRET\n")
			decoded, err := x86asm.Decode(code, 64)
			if err != nil || decoded.Len == 0 {
				t.Fatalf("actual Go single instruction: %x / %v", code, err)
			}
			var directive strings.Builder
			for index, value := range code[:decoded.Len] {
				if index != 0 {
					directive.WriteByte(',')
				}
				fmt.Fprintf(&directive, "0x%02x", value)
			}
			source := "TEXT addr(SB),4,$0-24\nMOVQ a+0(FP),BX\nMOVQ b+8(FP),AX\nCLC\n" + instruction + "\n" + observation + "MOVQ BX,ret+16(FP)\nRET\n"
			x86LEAActualTargetGoObject(t, "amd64", execution.triple, source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			signature := FuncSig{Name: "addr", Args: []LLVMType{I64, I64}, Ret: I64, Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}},
				Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
			}}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: map[string]FuncSig{"addr": signature}})
			if err != nil {
				t.Fatal(err)
			}
			main := fmt.Sprintf(`
#include <stdint.h>
#include <stdio.h>
extern uint64_t addr(uint64_t, uint64_t);

static uint64_t original(uint64_t a, uint64_t b) {
    uint64_t got;
    __asm__ volatile("movq %%1,%%%%rbx; movq %%2,%%%%rax; clc; .byte %s; %smovq %%%%rbx,%%0"
        : "=&r"(got) : "r"(a), "r"(b) : "rax", "rbx", "rdx", "cc");
    return got;
}

int main(void) {
    for (unsigned seed = 0; seed < 256; seed++) {
        volatile struct { uint64_t before, a, b, after; } input = {
            UINT64_C(0x8977665544332211), UINT64_C(0x2398111297893221) * seed,
            UINT64_C(0xabbacafe137a3366) * seed, UINT64_C(0x998812345679abcd)
        };
        uint64_t a = input.a, b = input.b;
        uint64_t want = %s;
        if (original(a,b) != want || addr(a,b) != want) {
            fprintf(stderr, "imm32 result %s seed %%u\n", seed);
            return 31;
        }
        if (input.before != UINT64_C(0x8977665544332211) || input.a != a || input.b != b ||
            input.after != UINT64_C(0x998812345679abcd)) {
            fputs("input/canary changed\n", stderr);
            return 32;
        }
    }
    puts("IMM32_MATH_FLAGS_CANARIES_256_OK");
    return 0;
}
`, directive.String(), originalObservation, row.expected, row.operation)
			for _, optimization := range []string{"-O0", "-O2"} {
				execution.compileAndRunLLVM(t, "source-imm32", ir, main, optimization)
			}
		})
	}
}
