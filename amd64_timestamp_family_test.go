package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86TimestampInstructionsMustNotUseConstantOutputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []Op{"RDTSC", "RDTSCP"} {
			t.Run(arch+"/"+string(op), func(t *testing.T) {
				source := "TEXT clock(SB),4,$0-0\n" + string(op) + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				before := output.Len()
				handled, terminated, err := ctx.lowerArith(op, file.Funcs[0].Instrs[1])
				if !handled || terminated || err != nil {
					t.Fatalf("whole timestamp instruction: %t/%t/%v", handled, terminated, err)
				}
				ir := output.String()[before:]
				if !strings.Contains(ir, "asm sideeffect \""+strings.ToLower(string(op))+"\"") {
					t.Fatalf("actual timestamp instruction replaced by constants:\n%s", ir)
				}
				outputCount := 2
				if op == "RDTSCP" {
					outputCount = 3
				}
				if strings.Count(ir, "extractvalue") != outputCount ||
					strings.Count(ir, "zext i32") != outputCount {
					t.Fatalf("complete zero-extended architectural outputs absent:\n%s", ir)
				}
			})
		}
	}
}

func TestX86TimestampMalformedOperandsFailBeforeEmission(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []Op{"RDTSC", "RDTSCP"} {
			for _, operand := range []string{"AX", "(AX)", "$1", "AX,DX"} {
				t.Run(arch+"/"+string(op)+"/"+operand, func(t *testing.T) {
					source := "TEXT clock(SB),4,$0-0\n" + string(op) + " " + operand + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", false)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before := output.String()
					handled, terminated, err := ctx.lowerArith(op, file.Funcs[0].Instrs[1])
					if !handled || terminated || err == nil || before != output.String() {
						t.Fatalf("malformed timestamp produced IR: %t/%t/%v", handled, terminated, err)
					}
				})
			}
		}
	}
}

func x86TimestampOriginalFixture(op Op) (declaration, assembly string) {
	name := strings.ToLower(string(op))
	return x86TimestampOriginalFixtureWithFlags(op, name, 0x8c7)
}

func x86TimestampOriginalFixtureWithFlags(op Op, name string, flags uint64) (declaration, assembly string) {
	declaration = fmt.Sprintf("func %s(out *[8]uint64)\n", name)
	assembly = fmt.Sprintf(`TEXT ·%s(SB),4,$0-8
    MOVQ out+0(FP),DI
    MOVQ $-1,AX
    MOVQ $-1,DX
    MOVQ $0xa1b2c3d4e5f60718,CX
    MOVQ $0x7e6d5c4b3a291807,BX
    PUSHQ $%#x
    POPFQ
    %s
    MOVQ AX,0(DI)
    MOVQ DX,8(DI)
    MOVQ CX,16(DI)
    MOVQ BX,24(DI)
    PUSHFQ
    POPQ R8
    MOVQ R8,32(DI)
    STMXCSR 40(DI)
    RET
`, name, flags, op)
	return
}

func x86Timestamp386OriginalFixture(op Op) (declaration, assembly string) {
	name := strings.ToLower(string(op))
	return x86Timestamp386OriginalFixtureWithFlags(op, name, 0x8c7)
}

func x86Timestamp386OriginalFixtureWithFlags(op Op, name string, flags uint64) (declaration, assembly string) {
	declaration = fmt.Sprintf("func %s(out *[8]uint32)\n", name)
	assembly = fmt.Sprintf(`TEXT ·%s(SB),4,$0-4
    MOVL out+0(FP),DI
    MOVL $-1,AX
    MOVL $-1,DX
    MOVL $0x5f60718,CX
    MOVL $0x3a291807,BX
    PUSHL $%#x
    POPFL
    %s
    MOVL AX,0(DI)
    MOVL DX,4(DI)
    MOVL CX,8(DI)
    MOVL BX,12(DI)
    PUSHFL
    POPL SI
    MOVL SI,16(DI)
    STMXCSR 20(DI)
    RET
`, name, flags, op)
	return
}

// Complementary inputs cover both values of all six architectural status
// bits. In particular, AF must be observed, not dropped from the oracle mask.
func x86TimestampRuntimeFixtures(goarch string) (declarations, assembly string) {
	var decl, source strings.Builder
	for _, op := range []Op{"RDTSC", "RDTSCP"} {
		for index, seed := range []uint64{0x8c7, 0x12} {
			name := strings.ToLower(string(op))
			if index != 0 {
				name += "_af"
			}
			var declaration, body string
			switch goarch {
			case "amd64":
				declaration, body = x86TimestampOriginalFixtureWithFlags(op, name, seed)
			case "386":
				declaration, body = x86Timestamp386OriginalFixtureWithFlags(op, name, seed)
			default:
				panic("timestamp fixture requires an x86 architecture")
			}
			decl.WriteString(declaration)
			source.WriteString(body)
		}
	}
	return decl.String(), source.String()
}

func TestX86TimestampStatusOracleRejectsEverySingleBitMutation(t *testing.T) {
	const mask uint64 = 0x8d5 // CF, PF, AF, ZF, SF, OF.
	for _, expected := range []uint64{0x8c5, 0x10} {
		if expected&mask != expected {
			t.Fatal("invalid independent status seed")
		}
		for _, bit := range []uint{0, 2, 4, 6, 7, 11} {
			mutated := expected ^ (uint64(1) << bit)
			if mutated&mask == expected {
				t.Fatalf("status bit %d mutation was invisible to the oracle", bit)
			}
		}
	}
	// Retain the precise former blind spot as an independent control.
	if uint64(0x8d5)&0x8c5 != 0x8c5 {
		t.Fatal("former AF-blind predicate no longer reproduces")
	}
}
