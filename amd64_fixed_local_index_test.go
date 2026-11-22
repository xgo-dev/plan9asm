package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixedLocalNamedIndexedSource = `TEXT ·Value(SB),4,$64-16
MOVQ a+0(FP),AX
MOVQ $3,R11
MOVQ AX,slot-72(SP)(R11*8)
MOVW $0x6655,slot-58(SP)(R11*4)
MOVB $0x77,slot-53(SP)(R11*2)
MOVL $0x12345678,slot-47(SP)(R11*1)
MOVB slot-53(SP)(R11*2),DX
MOVW slot-58(SP)(R11*4),BX
MOVL slot-47(SP)(R11*1),CX
MOVQ slot-72(SP)(R11*8),AX
MOVQ AX,ret+8(FP)
RET
`

func TestGoAMD64FixedLocalNamedIndexedScalarMoveOriginalObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	pkg, request := goAMD64FrameSourceFixture(t)
	if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(fixedLocalNamedIndexedSource), 0600); err != nil {
		t.Fatal(err)
	}
	name := pkg.Path + ".Value"
	sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) },
		Sigs:       map[string]FuncSig{name: sig},
	}
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
		if err != nil {
			t.Fatal(err)
		}
		for _, typ := range []string{"i8", "i16", "i32", "i64"} {
			if !strings.Contains(ir, "load volatile "+typ+",") || !strings.Contains(ir, "store volatile "+typ+" ") {
				t.Fatalf("missing exact indexed read or write for %s", typ)
			}
		}
		compileLLVMToObject(t, llc, options.TargetTriple, "indexed-auto.ll", "indexed-auto.o", ir)
	})
}

func TestGoAMD64FixedLocalNamedIndexedScalarMoves(t *testing.T) {
	for _, tc := range []struct {
		op    string
		width int64
	}{
		{"MOVB", 1}, {"MOVW", 2}, {"MOVL", 4}, {"MOVQ", 8},
	} {
		for _, scale := range []int{1, 2, 4, 8} {
			t.Run(fmt.Sprintf("%s/scale=%d", tc.op, scale), func(t *testing.T) {
				address := fmt.Sprintf("slot-%d(SP)(R11*%d)", 8+3*scale, scale)
				body := fmt.Sprintf("MOVQ $3,R11\n%s $77,%s\n%s %s,DX\nMOVQ 0(SP),AX", tc.op, address, tc.op, address)
				fn, sig, source := fixedLocalGPFixture(t, body)
				requireX86GoAssemblerResult(t, "amd64", source, true)
				file, err := Parse(ArchAMD64, "TEXT route(SB),4,$64-0\n"+tc.op+" "+address+",DX\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
					t.Fatal("named indexed MOV did not route to the native frame proof")
				}
				proved, err := proveX86FixedLocal(fn, sig)
				if err != nil {
					t.Fatal(err)
				}
				reads, writes := 0, 0
				for _, ins := range proved.Instrs {
					for index, arg := range ins.Args {
						if arg.Kind != OpMem || arg.Mem.Index == "" {
							continue
						}
						fact, found := ins.x86FixedLocalMemory[index]
						if !found || fact.width != tc.width || fact.nativeInput ||
							fact.offset != [8]int64{56, 56, 56, 56, 56, 56, 56, 56} {
							t.Fatalf("wrong exact width or stack offset: %+v", fact)
						}
						if fact.write {
							writes++
						} else {
							reads++
						}
					}
				}
				if reads != 1 || writes != 1 {
					t.Fatalf("reads=%d writes=%d", reads, writes)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalNamedIndexedScalarMoveRejectsUnsafeAccess(t *testing.T) {
	for _, body := range []string{
		"MOVQ $3,R11\nMOVQ slot-32(SP)(R11*8),DX",       // The final qword is uninitialized.
		"MOVQ $4,R11\nMOVQ $77,slot-32(SP)(R11*8)",      // Offset 64, above the frame.
		"MOVQ $-5,R11\nMOVQ $77,slot-32(SP)(R11*8)",     // Offset -8.
		"MOVQ a+0(FP),R11\nMOVQ $77,slot-32(SP)(R11*8)", // Unknown index.
	} {
		fn, sig, _ := fixedLocalGPFixture(t, body+"\nMOVQ 0(SP),AX")
		if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s acquired private backing: %v", body, err)
		}
	}
	for _, body := range []string{
		"MOVQ slot-32(SP)(R11*8),DX",
		"MOVQ $77,slot-32(SP)(R11*8)",
	} {
		ins := x86PureGPUnknownInstruction(t, body)
		state := x86FixedLocalState{constants: map[Reg]int64{"R11": 3}}
		if err := fixedLocalStep(&ins, &state, FuncSig{}, nil, 0); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("indexed move without a frame proof: %s: %v", body, err)
		}
	}
}

type fixedLocalConstantIndexCase struct {
	name, body string
	literal    bool
}

func fixedLocalConstantIndexCases() []fixedLocalConstantIndexCase {
	var cases []fixedLocalConstantIndexCase
	// Independent physical GP inventory: SP is a base, never an index.
	for _, register := range strings.Fields("AX BX CX DX DI SI BP R8 R9 R10 R11 R12 R13 R14 R15") {
		for _, literal := range []bool{false, true} {
			var body strings.Builder
			body.WriteString("MOVQ $0,8(SP)\n")
			base, name := "SP", "private/"+register
			if literal {
				base, name = "SI", "literal/"+register
				if register == base {
					base = "DI"
				}
				fmt.Fprintf(&body, "LEAQ literal<>(SB),%s\n", base)
			} else {
				body.WriteString("MOVQ $77,48(SP)\n")
			}
			for ordinal, scale := range []int{1, 2, 4, 8} {
				offset := 56 // The final qword of this private 64-byte frame.
				if literal {
					offset = ordinal * 8
				}
				address := fmt.Sprintf("%d(%s)(%s*%d)", offset-3*scale, base, register, scale)
				if !literal {
					body.WriteString("MOVQ $0,56(SP)\n")
				}
				fmt.Fprintf(&body, "MOVQ $3,%s\n", register)
				if !literal {
					fmt.Fprintf(&body, "MOVQ $%d,%s\nADDQ $1,%s\n", 17+scale, address, address)
				}
				fmt.Fprintf(&body, "MOVQ %s,AX\nADDQ AX,8(SP)\n", address)
				if !literal {
					body.WriteString("MOVQ 56(SP),AX\nADDQ AX,8(SP)\n")
				}
			}
			if !literal {
				body.WriteString("MOVQ 48(SP),AX\nADDQ AX,8(SP)\n")
			}
			body.WriteString("MOVQ 8(SP),AX")
			cases = append(cases, fixedLocalConstantIndexCase{name, body.String(), literal})
		}
	}
	return cases
}

func TestGoAMD64FixedLocalConstantIndexPrivate(t *testing.T) {
	var original strings.Builder
	count := 0
	for _, row := range fixedLocalConstantIndexCases() {
		if row.literal {
			continue
		}
		fn, sig, source := fixedLocalGPFixture(t, row.body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", count), 1))
		count++
		t.Run(row.name, func(t *testing.T) {
			proved, err := proveX86FixedLocal(fn, sig)
			if err != nil {
				t.Fatal("constant index must retain exact private bytes", err)
			}
			accesses := 0
			for _, instruction := range proved.Instrs {
				for index, operand := range instruction.Args {
					if operand.Kind != OpMem || operand.Mem.Index == "" {
						continue
					}
					accesses++
					access, found := instruction.x86FixedLocalMemory[index]
					write := instruction.Op == "ADDQ" || index == 1
					if !found || access.owner != proved.x86FixedLocal || access.width != 8 ||
						access.nativeInput || access.write != write || access.offset != [8]int64{56, 56, 56, 56, 56, 56, 56, 56} {
						t.Fatalf("indexed access lost its exact byte/role certificate: %+v", access)
					}
				}
			}
			if accesses != 12 {
				t.Fatal("expected one store/RMW/load for each scale", accesses)
			}
		})
	}
	if count != 15 {
		t.Fatal("independent non-SP GP inventory changed", count)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}
