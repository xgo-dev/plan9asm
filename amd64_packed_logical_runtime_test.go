package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// The numerical oracle derives semantics from the source mnemonic, not the
// emitter's mode field; a wrong opcode-to-mode registration must still fail.
func x86LogicalIndependentCOperator(t *testing.T, opcode Op) string {
	t.Helper()
	name := string(opcode)
	switch {
	case strings.Contains(name, "ANDN"):
		return "aByte & (uint8_t)~b[i]"
	case strings.Contains(name, "AND"):
		return "aByte & b[i]"
	case strings.Contains(name, "XOR"):
		return "aByte ^ b[i]"
	case strings.Contains(name, "OR"):
		return "aByte | b[i]"
	default:
		t.Fatalf("unknown numerical oracle opcode %s", opcode)
		return ""
	}
}

func TestCrossLinuxRuntimeMatrixX86PackedLogicalCompleteSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires Linux/amd64 runtime counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang missing")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	var prefix []string
	if crossRosetta {
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	fixtures := x86LogicalRuntimeFixtures(t)
	for index, batch := range x86LogicalRuntimeBatches(fixtures) {
		t.Run(fmt.Sprintf("batch-%02d", index), func(t *testing.T) {
			var assembly strings.Builder
			sigs := make(map[string]FuncSig, len(batch))
			for _, fixture := range batch {
				assembly.WriteString(fixture.assembly)
				sigs[fixture.name] = fixture.signature
			}
			requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
			file, err := Parse(ArchAMD64, assembly.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "logical_complete_semantics",
				triple, ir, x86LogicalRuntimeC(batch), prefix)
		})
	}
	t.Logf("%d exact opcode/width/memory/mask programs; 16 independently expected numerical/canary inputs each", len(fixtures))
}

type x86LogicalRuntimeFixture struct {
	name, assembly, declaration, checks string
	signature                           FuncSig
}

func x86LogicalRuntimeBatches(fixtures []x86LogicalRuntimeFixture) [][]x86LogicalRuntimeFixture {
	const batchSize = 64
	var batches [][]x86LogicalRuntimeFixture
	for start := 0; start < len(fixtures); start += batchSize {
		end := start + batchSize
		if end > len(fixtures) {
			end = len(fixtures)
		}
		batches = append(batches, fixtures[start:end])
	}
	return batches
}

func x86LogicalRuntimeC(fixtures []x86LogicalRuntimeFixture) string {
	var declarations, checks, calls strings.Builder
	for _, fixture := range fixtures {
		declarations.WriteString(fixture.declaration)
		// Keep independent reference loops out of one giant optimizer graph.
		// noinline also prevents -O2 from reconstructing that graph in main.
		fmt.Fprintf(&checks, "static __attribute__((noinline)) int check_%s(void) {\n", fixture.name)
		checks.WriteString("const uint64_t masks[]={0,1,0x55aa55aa55aa55aaULL,~0ULL};\n")
		checks.WriteString(fixture.checks)
		checks.WriteString("return 0;\n}\n")
		// Case IDs belong in diagnostics, not process exit codes: Unix keeps
		// only eight bits and would report return 256 as successful execution.
		fmt.Fprintf(&calls, "if (check_%s()) { fprintf(stderr, \"%s numerical/canary failure\\n\"); return 1; }\n",
			fixture.name, fixture.name)
	}
	return "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" +
		declarations.String() + checks.String() +
		"int main(void) {\n" + calls.String() + "return 0;\n}\n"
}

func x86LogicalRuntimeFixtures(t *testing.T) []x86LogicalRuntimeFixture {
	t.Helper()
	var fixtures []x86LogicalRuntimeFixture
	count := 0
	for _, opcode := range x86LogicalOpcodeNames() {
		spec := x86PackedLogicalSpecs[opcode]
		widths := []int{16, 32, 64}
		if spec.encoding <= x86PackedLogicalLegacyInteger {
			widths = widths[:1]
		}
		if spec.encoding == x86PackedLogicalVEX {
			widths = widths[:2]
		}
		for _, width := range widths {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, memory := range []string{"register", "memory", "broadcast"} {
				if memory == "broadcast" && spec.broadcastBytes == 0 {
					continue
				}
				for _, mode := range []string{"unmasked", "merge", "zero"} {
					if mode != "unmasked" && spec.broadcastBytes == 0 {
						continue
					}
					var assembly, declarations, checks strings.Builder
					name := fmt.Sprintf("logical%d", count)
					count++
					legacy := spec.encoding <= x86PackedLogicalLegacyInteger
					first := bank + "1"
					if memory != "register" {
						first = "(BX)"
					}
					operation := string(opcode)
					if memory == "broadcast" {
						operation += ".BCST"
					}
					if mode == "zero" {
						operation += ".Z"
					}
					row := operation + " " + first + "," + bank + "0"
					destination := 2
					if legacy {
						destination = 0
					} else {
						if mode != "unmasked" {
							row += ",K1"
						}
						row += "," + bank + "2"
					}
					fmt.Fprintf(&assembly, "TEXT %s(SB),$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\nVMOVUPS (CX),Z0\nVMOVUPS (CX),Z2\n", name)
					if memory == "register" {
						assembly.WriteString("VMOVUPS (BX),Z1\n")
					}
					assembly.WriteString("KMOVQ DX,K1\nSTC\n" + row + "\n")
					fmt.Fprintf(&assembly, "VMOVUPS Z%d,(AX)\nSETCS 64(AX)\nRET\n", destination)
					signature := FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
					}}}
					fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
					operator := x86LogicalIndependentCOperator(t, opcode)
					maskExpression := "1"
					if mode != "unmasked" {
						maskExpression = fmt.Sprintf("((mask>>(i/%d))&1)", spec.laneBits/8)
					}
					inactive := "b[i]"
					if mode == "zero" {
						inactive = "0"
					}
					upper := "0"
					if legacy {
						upper = "b[i]"
					}
					index := "i"
					if memory == "broadcast" {
						index = fmt.Sprintf("i%%%d", spec.broadcastBytes)
					}
					aOffset := 1
					if legacy && memory == "memory" {
						// The original legacy m128 instruction requires 16-byte
						// alignment. Keep other source forms deliberately unaligned;
						// the independent native fault root checks legacy misalignment.
						aOffset = 16
					}
					fmt.Fprintf(&checks, `
 for(int round=0;round<4;++round) for(int m=0;m<4;++m) {
  uint64_t mask=masks[m]; _Alignas(16) uint8_t aStorage[96]; uint8_t bStorage[68],output[67]; uint8_t *a=aStorage+%[9]d,*b=bStorage+3;
  memset(aStorage,0xa7,96); memset(bStorage,0xb9,68); memset(output,0xc3,67);
  for(int i=0;i<64;++i) { a[i]=(uint8_t)(i*19+round*83+7); b[i]=(uint8_t)(i*31+round*59+13); }
  %[1]s(output+1,a,b,mask);
  if(output[0]!=0xc3 || output[66]!=0xc3 || output[65]!=1) return %[2]d;
  for(int i=0;i<64;++i) {
   uint8_t aByte=a[%[3]s]; uint8_t want=i<%[4]d ? ((%[5]s) ? (%[6]s) : (%[7]s)) : (%[8]s);
   if(output[i+1]!=want || a[i]!=(uint8_t)(i*19+round*83+7) || b[i]!=(uint8_t)(i*31+round*59+13)) return %[2]d;
  }
  for(int i=0;i<96;++i) if((i<%[9]d || i>=%[9]d+64) && aStorage[i]!=0xa7) return %[2]d;
  if(bStorage[2]!=0xb9 || bStorage[67]!=0xb9) return %[2]d;
 }
`, name, count+10, index, width, maskExpression, operator, inactive, upper, aOffset)
					if mode != "unmasked" && memory != "register" {
						// A zero relevant mask suppresses every memory read,
						// including broadcast. NULL is never dereferenced.
						fmt.Fprintf(&checks, `{ uint8_t b[64],out[65]; memset(b,0x5a,64); %[1]s(out,0,b,0);
 for(int i=0;i<64;++i) { uint8_t want=i<%[2]d ? (%[3]s) : 0; if(out[i]!=want) return %[4]d; } }
`, name, width, map[string]string{"merge": "0x5a", "zero": "0"}[mode], count+10)
					}
					fixtures = append(fixtures, x86LogicalRuntimeFixture{
						name: name, assembly: assembly.String(), declaration: declarations.String(),
						checks: checks.String(), signature: signature,
					})
				}
			}
		}
	}
	return fixtures
}

func TestX86PackedLogicalXWritesClearWiderAliases(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires amd64 or Rosetta; Linux counterpart executes the same oracle")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if crossRosetta {
		triple, prefix = "x86_64-apple-darwin", []string{"/usr/bin/arch", "-x86_64"}
	}
	for _, opcode := range []string{"VXORPS", "VPXOR", "VPXORD"} {
		t.Run(opcode, func(t *testing.T) {
			source := "TEXT logicalalias(SB),$0-16\nMOVQ out+0(FP),AX\nMOVQ in+8(FP),BX\nVMOVUPS (BX),Z0\n" + opcode + " X0,X0,X0\nVMOVUPS Z0,(AX)\nRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{
				"logicalalias": {Name: "logicalalias", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			const mainC = `
#include <stdint.h>
#include <string.h>
extern void logicalalias(uint8_t *, const uint8_t *);
int main(void) {
  uint8_t in[66], out[66];
  for (int k=0; k<66; ++k) { in[k]=(uint8_t)(k*19+7); out[k]=0xa5; }
  logicalalias(out+1,in+1);
  if(out[0]!=0xa5 || out[65]!=0xa5) return 2;
  for(int k=1; k<65; ++k) if(out[k]!=0) return k+10;
  for(int k=0; k<66; ++k) if(in[k]!=(uint8_t)(k*19+7)) return 3;
  return 0;
}
`
			compileAndRunRuntimeTestForTarget(t, llc, clang, strings.ToLower(opcode)+"_alias", triple, ir, mainC, prefix)
		})
	}
}
