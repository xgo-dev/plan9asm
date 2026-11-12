package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// This independent inventory includes PADDD's source alias separately from
// the 27 canonical legacy XMM instructions. No production spec defines it.
func fixedLocalBinaryEffectNames() []string {
	names := append([]string(nil), x86LegacyIntegerArithmeticTestNames...)
	return append(names, "PMULLD", "PMULLW", "PMULHW", "PMULHUW", "PMULHRSW",
		"PMULDQ", "PMULULQ", "PAVGB", "PAVGW", "PMADDWL", "PMADDUBSW")
}

func TestGoAMD64FixedLocalTypedBinaryEffects(t *testing.T) {
	names := fixedLocalBinaryEffectNames()
	if len(names) != 28 {
		t.Fatalf("independent legacy family inventory: %d, want 27 + one alias", len(names))
	}
	var original strings.Builder
	ordinal := 0
	for _, name := range names {
		for _, input := range []string{"16(SP)", "X1", "X0"} {
			t.Run(name+"/"+input, func(t *testing.T) {
				operation := name + " " + input + ",X0"
				source, sig, _ := x86PrivateAlignedFrameAuditFixture(t, "MOVOU 16(SP),X1\n"+operation)
				original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", ordinal), 1))
				ordinal++
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				proved, err := proveX86FixedLocal(file.Funcs[0], sig)
				if err != nil {
					t.Fatal("initialized complete legacy family source rejected", err)
				}
				observed := 0
				for _, ins := range proved.Instrs {
					if string(ins.Op) != name {
						continue
					}
					observed++
					access, found := ins.x86FixedLocalMemory[0]
					if found != (input == "16(SP)") || found &&
						(access.width != 16 || access.write || access.nativeInput || access.owner != proved.x86FixedLocal) {
						t.Fatalf("wrong exact private memory role: %+v", access)
					}
				}
				if observed != 1 {
					t.Fatalf("proved source retained %d target instructions, want one", observed)
				}
				candidate, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$160-40\n"+operation+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				if GoAMD64FixedLocalFrameBindingNeeded(candidate, "amd64") != (input == "16(SP)") ||
					GoAMD64FixedLocalFrameBindingNeeded(candidate, "386") {
					t.Fatal("candidate query differs from the typed memory role")
				}
			})
		}
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalTypedBinaryAliasBytes(t *testing.T) {
	for _, name := range fixedLocalBinaryEffectNames() {
		for _, old := range []uint64{0xffff, 0x804020100000ffff, ^uint64(0)} {
			t.Run(fmt.Sprintf("%s/%x", name, old), func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+name+" X1,X0\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				state := x86FixedLocalState{
					vectors: map[Reg]uint64{x86CallerVectorRoot("X0"): old, x86CallerVectorRoot("X1"): 0xffff},
					flags:   x86ByteFlagCF,
				}
				if err := fixedLocalVectorStep(&file.Funcs[0].Instrs[1], &state, nil, 0); err != nil {
					t.Fatal(err)
				}
				if state.vectors[x86CallerVectorRoot("X0")] != old || state.flags != x86ByteFlagCF {
					t.Fatal("legacy arithmetic changed upper vector definedness or FLAGS", state)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalTypedBinaryMetadata(t *testing.T) {
	for _, name := range fixedLocalBinaryEffectNames() {
		file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+name+" X1,X0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
		if !known || err != nil || effect.vector.upperWrite != x86TypedVectorUpperPreserve ||
			effect.vector.memoryAlignment != 16 || len(effect.operands) != 2 {
			t.Fatal("shared descriptor lost the complete validated alias/storage role", name, effect, err)
		}
		lowercase := ins
		lowercase.Op = Op(strings.ToLower(name))
		lowerEffect, lowerKnown, lowerErr := x86TypedInstructionByteEffect(lowercase.Op, lowercase, "amd64")
		if !lowerKnown || lowerErr != nil || !reflect.DeepEqual(lowerEffect, effect) {
			t.Fatal("negative prefix filter changed the case-insensitive family contract", name, lowerErr)
		}
		effect.vector = x86TypedVectorEffect{}
		state := x86FixedLocalState{vectors: map[Reg]uint64{
			x86CallerVectorRoot("X0"): ^uint64(0), x86CallerVectorRoot("X1"): ^uint64(0),
		}}
		if err := fixedLocalTypedByteStep(&ins, &state, FuncSig{}, nil, 0, effect); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unregistered default metadata authorized a vector effect", name, err)
		}
	}
	for _, name := range []string{"PADDW", "PMULLW", "PMULULQ", "PAVGB", "PMADDWL"} {
		file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+name+" AX,M1\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
		if !known || err != nil || len(effect.operands) != 2 || effect.operands[0].operand.Reg != "M0" ||
			effect.operands[0].width != 8 || effect.vector != (x86TypedVectorEffect{}) {
			t.Fatal("GP spelling changed the physical MMX bank or granted XMM metadata", name, effect, err)
		}
	}
}

func TestGoAMD64FixedLocalTypedBinaryBoundaries(t *testing.T) {
	for _, name := range []string{"PSUBSW", "PMULLD", "PMULHW", "PMULDQ", "PAVGB", "PMADDUBSW"} {
		source, sig, _ := x86PrivateAlignedFrameAuditFixture(t, name+" 16(SP),X0")
		for _, row := range []struct{ name, from, to string }{
			{"missing memory byte", "MOVQ CX,24(SP)", "MOVB CX,24(SP)"},
			{"unknown destination", "MOVOU 48(SP),X0", "MOVOU 48(SP),X1"},
			{"unaligned memory", name + " 16(SP)", name + " 17(SP)"},
			{"outside frame", name + " 16(SP)", name + " 160(SP)"},
			{"unknown source", name + " 16(SP)", name + " X2"},
			{"MMX source bank", name + " 16(SP),X0", name + " 16(SP),M0"},
			{"unbound FP", name + " 16(SP)", name + " a+0(FP)"},
			{"raw source", name + " 16(SP),X0", "BYTE $0x90"},
			{"private pointer spill", "MOVQ AX,16(SP)", "MOVQ SP,16(SP)"},
		} {
			t.Run(name+"/"+row.name, func(t *testing.T) {
				changed := strings.Replace(source, row.from, row.to, 1)
				if changed == source {
					t.Fatal("negative fixture did not change the complete source")
				}
				file, err := Parse(ArchAMD64, changed)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unproved native bytes gained fixed-local authority", err)
				}
			})
		}
		t.Run(name+"/opaque pointer spill", func(t *testing.T) {
			source, sig, _ := x86PrivateAlignedFrameAuditTypedFixture(t, name+" 16(SP),X0",
				"package frameaudit\nfunc Value(a *uint64, b, c, d uint64) uint64\n")
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
				t.Fatal("complete native spill bits were rejected as vector input", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTypedBinaryObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	assembly, declarations, _, _ := fixedLocalBinaryRuntimeProgram(t, "x86_64-unknown-linux-gnu")
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			var names []string
			for index := range fixedLocalBinaryEffectNames() {
				names = append(names, fmt.Sprintf("%s.Value%d", pkg.Path, index))
			}
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					compileLLVMToObject(t, llc, target.triple, "legacy-binary.ll", "legacy-binary.o", ir)
					compileLLVMToObject(t, llc, target.triple, "legacy-binary-opt.ll", "legacy-binary-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
}

// One complete original source serves both the object matrix and native
// differential test. Observe both result halves and a separate input canary.
func fixedLocalBinaryRuntimeProgram(t *testing.T, triple string) (string, string, string, string) {
	t.Helper()
	return fixedLocalBinaryRuntimeProgramForNames(t, triple, fixedLocalBinaryEffectNames())
}

func fixedLocalBinaryRuntimeProgramForNames(t *testing.T, triple string, names []string) (string, string, string, string) {
	t.Helper()
	var assembly, declarations, goRows, cRows, cDeclarations strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for index, name := range names {
		source, _, _ := x86PrivateAlignedFrameAuditFixture(t, name+" 16(SP),X0")
		source = strings.Replace(source, "$160-40", "$160-48", 1)
		source = strings.Replace(source, "MOVQ SP,R11", "MOVQ mode+32(FP),R8\nMOVQ SP,R11", 1)
		source = strings.Replace(source, "MOVQ X0,AX", `MOVOU X0,48(SP)
CMPQ R8,$1
JEQ high
CMPQ R8,$2
JEQ canary
MOVQ 48(SP),AX
JMP done
high:
MOVQ 56(SP),AX
JMP done
canary:
MOVQ 16(SP),AX
done:`, 1)
		source = strings.Replace(source, "ret+32(FP)", "ret+40(FP)", 1)
		function := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+function, 1))
		fmt.Fprintf(&declarations, "func %s(a,b,c,d,mode uint64) uint64\n", function)
		fmt.Fprintf(&goRows, "%s,\n", function)
		fmt.Fprintf(&cRows, "value%d,\n", index)
		label := runtimeCAsmLabel(prefix + "example.invalid/framefixture." + function)
		fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t) __asm__(%s);\n", index, label)
	}
	const values = `0,1,0x7f7f7f7f7f7f7f7f,0x8080808080808080,
0x7fff7fff7fff7fff,0x8000800080008000,0x7fffffff7fffffff,
0x8000000080000000,0xffffffffffffffff,0x0123456789abcdef`
	original := `package main
import "fmt"
` + declarations.String() + `
func main() {
    rows := []func(uint64,uint64,uint64,uint64,uint64) uint64{
` + goRows.String() + `
    }
    values := []uint64{` + values + `}
    for n, call := range rows {
        for v, value := range values {
            for mode := uint64(0); mode < 3; mode++ {
                got := call(value,values[(v+1)%len(values)],^value,values[(v+len(values)-1)%len(values)],mode)
                fmt.Printf("%d %d %d %016x\n",n,v,mode,got)
            }
        }
    }
}
`
	driver := `#include <stdint.h>
#include <stdio.h>
` + runtimeCAsmLabelPreamble + cDeclarations.String() + `
int main(void) {
    uint64_t (*rows[])(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t) = {
` + cRows.String() + `
    };
    const uint64_t values[] = {` + values + `};
    const size_t count = sizeof(values)/sizeof(values[0]);
    for (size_t n = 0; n < sizeof(rows)/sizeof(rows[0]); n++) {
        for (size_t v = 0; v < count; v++) {
            for (unsigned mode = 0; mode < 3; mode++) {
                uint64_t got = rows[n](values[v],values[(v+1)%count],~values[v],values[(v+count-1)%count],mode);
                printf("%zu %zu %u %016llx\n",n,v,mode,(unsigned long long)got);
            }
        }
    }
    return 0;
}
`
	return assembly.String(), declarations.String(), original, driver
}

func BenchmarkFixedLocalLegacyVectorStep(b *testing.B) {
	for _, operation := range []string{"PADDQ X1,X0", "PMADDWL X1,X0", "CMPPS X1,X0,$0"} {
		b.Run(strings.Fields(operation)[0], func(b *testing.B) {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+operation+"\nRET\n")
			if err != nil {
				b.Fatal(err)
			}
			state := x86FixedLocalState{vectors: map[Reg]uint64{
				x86CallerVectorRoot("X0"): ^uint64(0), x86CallerVectorRoot("X1"): ^uint64(0),
			}}
			instruction := &file.Funcs[0].Instrs[1]
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := fixedLocalVectorStep(instruction, &state, nil, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkFixedLocalLegacyVectorProof(b *testing.B) {
	for _, operation := range []string{"PADDQ X1,X0", "PMADDWL X1,X0", "CMPPS X1,X0,$0"} {
		b.Run(strings.Fields(operation)[0], func(b *testing.B) {
			source := "TEXT ·Value(SB),4,$64-16\nMOVQ a+0(FP),AX\n" +
				"MOVQ AX,0(SP)\nMOVQ AX,8(SP)\nMOVOU 0(SP),X0\nMOVOU X0,X1\n" +
				strings.Repeat(operation+"\n", 8) + "MOVQ X0,AX\nMOVQ AX,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				b.Fatal(err)
			}
			sig := FuncSig{Name: "Value", Args: []LLVMType{I64}, Ret: I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
