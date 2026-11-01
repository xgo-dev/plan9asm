package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalInputFixture(t *testing.T, body string) (Func, FuncSig, string) {
	t.Helper()
	_, _, sig, source := x86ResultInitializationFixture(t, "amd64",
		"func Value(p, q *uint64, a uint64) uint64",
		"MOVQ p+0(FP),SI\nMOVQ q+8(FP),DI\nMOVQ a+16(FP),AX\nMOVQ AX,0(SP)\n"+
			body+"\nMOVQ AX,ret+24(FP)\nRET")
	source = strings.Replace(source, "$0-32", "$64-32", 1)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0], sig, source
}

func TestGoAMD64FixedLocalInputMemoryWidths(t *testing.T) {
	var original strings.Builder
	count := 0
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, operation := range []string{
			"MOV%s 3(SI),CX\nMOVQ CX,8(SP)\nMOVQ 8(SP),AX",
			"MOV%s AX,5(DI)",
			"ADD%s 3(SI),AX",
			"ADD%s $1,5(DI)",
			"NEG%s 5(DI)",
			"CMP%s 3(SI),$1\nSETCS CL",
		} {
			body := "MOVQ AX,CX\n" + fmt.Sprintf(operation, width)
			fn, sig, source := fixedLocalInputFixture(t, body)
			original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", count), 1))
			count++
			t.Run(fmt.Sprintf("%s/%d", width, count), func(t *testing.T) {
				if _, err := proveX86FixedLocal(fn, sig); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	if count != 24 {
		t.Fatal("changed independent scalar memory width inventory", count)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalInputMemoryProvenance(t *testing.T) {
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"copy", "MOVQ SI,CX\nMOVQ 3(CX),AX", true},
		{"private pointer spill", "MOVQ SI,8(SP)\nMOVQ 8(SP),CX\nMOVQ 3(CX),AX", true},
		{"private numerical spill", "MOVQ (SI),CX\nMOVQ CX,8(SP)\nMOVQ 8(SP),AX", true},
		{"unaligned vector", "MOVOU (SI),X0\nMOVOU X0,16(SP)\nMOVQ 16(SP),AX", true},
		{"aligned native vector", "MOVO (SI),X0\nMOVOU X0,16(SP)\nMOVQ 16(SP),AX", true},
		{"native vector output", "MOVOU (SI),X0\nMOVOU X0,(DI)", true},
		{"mask zeroing native input", "KMOVQ AX,K1\nVMOVDQU8.Z (SI),K1,Z0\nVMOVDQU8 Z0,0(SP)\nMOVQ 0(SP),AX", true},
		{"mask native output", "KMOVQ AX,K1\nVMOVDQU8 (SI),Z0\nVMOVDQU8 Z0,K1,(DI)", true},
		{"numerical loop", "MOVQ $3,CX\nagain:\nADDQ (SI),AX\nSUBQ $1,CX\nJNE again", true},
		{"same input join", "CMPQ AX,$1\nJEQ left\nMOVQ SI,CX\nJMP join\nleft:\nMOVQ SI,CX\njoin:\nMOVQ (CX),AX", true},
		{"numerical address", "MOVQ (AX),CX", false},
		{"loaded integer is not pointer", "MOVQ (SI),CX\nMOVQ (CX),AX", false},
		{"private pointer escape", "MOVQ SP,CX\nMOVQ CX,(DI)", false},
		{"opaque pointer store", "MOVQ SI,(DI)", false},
		{"private pointer arithmetic", "ADDQ SI,AX", false},
		{"input pointer arithmetic", "ADDQ $8,SI\nMOVQ (SI),AX", true},
		{"input pointer LEA", "LEAQ 8(SI),CX\nMOVQ (CX),AX", true},
		{"input pointer partial write", "MOVB $0,SI\nMOVQ (SI),AX", false},
		{"input pointer partial spill", "MOVQ SI,8(SP)\nMOVB $0,8(SP)\nMOVQ 8(SP),CX\nMOVQ (CX),AX", false},
		{"numerical index", "MOVQ (SI)(AX*2),CX", true},
		{"private index", "MOVQ (SI)(SP*1),CX", false},
		{"segment", "MOVQ (SI)(FS*1),CX", false},
		{"different input join", "CMPQ AX,$1\nJEQ left\nMOVQ SI,CX\nJMP join\nleft:\nMOVQ DI,CX\njoin:\nMOVQ (CX),AX", true},
		{"pointer and number join", "CMPQ AX,$1\nJEQ left\nMOVQ SI,CX\nJMP join\nleft:\nMOVQ AX,CX\njoin:\nMOVQ (CX),AX", false},
		{"private missing byte", "MOVQ (SI),AX\nADDQ $1,8(SP)", false},
		{"private crossing frame", "MOVQ (SI),AX\nMOVQ AX,60(SP)", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalInputFixture(t, row.body)
			_, err := proveX86FixedLocal(fn, sig)
			if (err == nil) != row.valid {
				t.Fatalf("valid=%v: %v", row.valid, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalInputMemoryActualObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var assembly, declarations strings.Builder
	for index, body := range []string{
		"MOVQ (SI),CX\nMOVQ CX,8(SP)\nMOVQ 8(SP),AX\nMOVQ AX,(DI)",
		"ADDQ (SI),AX\nSUBW $1,(DI)\nNEGB 1(DI)",
		"CMPQ (SI),$1\nCMOVQCS 8(SI),AX\nSETCS 8(DI)",
		"MOVO (SI),X0\nMOVOU X0,16(SP)\nMOVOU X0,(DI)\nMOVQ 16(SP),AX",
		"KMOVQ AX,K1\nVMOVDQU8.Z (SI),K1,Z0\nVMOVDQU8 Z0,0(SP)\nVMOVDQU8 Z0,K1,(DI)\nMOVQ 0(SP),AX",
		"MOVQ SI,8(SP)\nMOVQ 8(SP),CX\nMOVQ (CX),AX\nMOVQ $0,AX",
		"ADDQ AX,SI\nMOVQ (SI),AX",
		"ADDQ SI,AX\nMOVQ (AX),AX",
		"SUBQ AX,SI\nMOVQ (SI),AX",
		"LEAQ -64(SI)(AX*8),CX\nMOVQ (CX),AX",
		"INCQ SI\nDECQ SI\nMOVQ (SI),AX",
		"MOVQ SI,8(SP)\nCMPQ DI,8(SP)\nSETCS AL",
		"MOVQ SI,8(SP)\nCMPQ 8(SP),DI\nSETCS AL",
		"CMPQ AX,$0\nJEQ join\nMOVQ SI,8(SP)\njoin:",
	} {
		_, _, source := fixedLocalInputFixture(t, body)
		assembly.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		fmt.Fprintf(&declarations, "func Value%d(p, q *uint64, a uint64) uint64\n", index)
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(), target.name, target.triple)
			fixedLocalConversionPrepareToolCache(t, request)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					for _, required := range []string{"load volatile i64", "store volatile i64", "movdqa"} {
						if !strings.Contains(ir, required) {
							t.Fatal("native memory instruction lost observable access", required)
						}
					}
					masked := x86StringMemoryFunction(t, ir, pkg.Path+".Value4")
					if strings.Count(masked, "load volatile i8,") != 64 ||
						strings.Count(masked, "store volatile i8 ") != 64 || strings.Count(masked, "br i1 ") != 128 {
						t.Fatal("masked input/output lost its active-lane volatile accesses")
					}
					optimized := x86MulDivRoundOptimize(t, ir)
					for _, version := range []string{ir, optimized} {
						dead := x86StringMemoryFunction(t, version, pkg.Path+".Value5")
						if !strings.Contains(dead, "load volatile i64") {
							t.Fatal("dead native input read disappeared from its own function")
						}
					}
					compileLLVMToObject(t, llc, target.triple, "input-memory.ll", "input-memory.o", ir)
					compileLLVMToObject(t, llc, target.triple, "input-memory-opt.ll", "input-memory-opt.o", optimized)
				})
		})
	}
}

func TestGoAMD64FixedLocalInputMemoryRoleCertificate(t *testing.T) {
	fn, sig, _ := fixedLocalInputFixture(t, "MOVQ (SI),CX\nMOVQ CX,8(SP)\nMOVQ 8(SP),AX\nMOVQ AX,(DI)")
	proved, err := proveX86FixedLocal(fn, sig)
	if err != nil {
		t.Fatal(err)
	}
	ctx := amd64Ctx{fixedLocal: proved.x86FixedLocal}
	native, private := 0, 0
	for _, instruction := range proved.Instrs {
		for index, access := range instruction.x86FixedLocalMemory {
			if _, valid := ctx.fixedLocalMemoryAccess(instruction, index); !valid {
				t.Fatal("original access lost its whole-function binding")
			}
			if ctx.fixedLocalMemoryCertified(instruction, index) == access.nativeInput {
				t.Fatal("native input acquired a private extent/alignment certificate")
			}
			if access.nativeInput {
				native++
			} else {
				private++
			}
			changed := instruction
			changed.x86FixedLocalMemory = map[int]x86FixedLocalAccess{index: access}
			access.nativeInput = !access.nativeInput
			changed.x86FixedLocalMemory[index] = access
			if _, valid := ctx.fixedLocalMemoryAccess(changed, index); valid {
				t.Fatal("mutated address role retained authority")
			}
		}
	}
	if native != 2 || private != 3 {
		t.Fatal("incomplete independent memory role inventory", native, private)
	}
}
