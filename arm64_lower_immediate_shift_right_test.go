package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func encodeARM64ImmediateShiftRight(base uint32, elementBits, shift int, fullVector bool, source, destination int) uint32 {
	encodedImmediate := uint32(2*elementBits - shift)
	word := base | encodedImmediate<<16 | uint32(source)<<5 | uint32(destination)
	if fullVector {
		word |= 1 << 30
	}
	return word
}

func TestTranslateARM64RawImmediateShiftRightCompleteArchitectureFamily(t *testing.T) {
	families := []struct {
		name string
		base uint32
	}{
		{name: "VSSHR", base: 0x0f000400},
		{name: "VSSRA", base: 0x0f001400},
		{name: "VSRSHR", base: 0x0f002400},
		{name: "VSRSRA", base: 0x0f003400},
		{name: "VUSHR", base: 0x2f000400},
		{name: "VUSRA", base: 0x2f001400},
		{name: "VURSHR", base: 0x2f002400},
		{name: "VURSRA", base: 0x2f003400},
	}
	type form struct {
		elementBits int
		fullVector  bool
	}
	forms := []form{
		{elementBits: 8}, {elementBits: 8, fullVector: true},
		{elementBits: 16}, {elementBits: 16, fullVector: true},
		{elementBits: 32}, {elementBits: 32, fullVector: true},
		{elementBits: 64, fullVector: true},
	}
	arrangementName := func(form form) string {
		lanes := 64 / form.elementBits
		if form.fullVector {
			lanes *= 2
		}
		letter := map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}[form.elementBits]
		return fmt.Sprintf("%s%d", letter, lanes)
	}

	var source strings.Builder
	source.WriteString("TEXT ·immediateShiftRightArchitectureForms(SB), $0-0\n")
	for _, family := range families {
		for _, form := range forms {
			for _, shift := range []int{1, form.elementBits} {
				word := encodeARM64ImmediateShiftRight(family.base, form.elementBits, shift, form.fullVector, 29, 28)
				decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
				if err != nil {
					t.Fatalf("decode %s %d-bit Q=%v shift=%d: %v", family.name, form.elementBits, form.fullVector, shift, err)
				}
				wantSource := Reg("V29." + arrangementName(form))
				wantDestination := Reg("V28." + arrangementName(form))
				if decoded.Op != Op(family.name) || len(decoded.Args) != 3 || decoded.Args[0].Kind != OpImm || decoded.Args[0].Imm != int64(shift) ||
					decoded.Args[1].Reg != wantSource || decoded.Args[2].Reg != wantDestination {
					t.Fatalf("decoded %s %d-bit Q=%v shift=%d %#08x as %#v", family.name, form.elementBits, form.fullVector, shift, word, decoded)
				}
				fmt.Fprintf(&source, "\tWORD $%#08x // %s %d-bit Q=%v shift=%d\n", word, family.name, form.elementBits, form.fullVector, shift)
			}
		}
		for _, shift := range []int{1, 64} {
			scalarBase := family.base | 0x50000000
			word := encodeARM64ImmediateShiftRight(scalarBase, 64, shift, false, 29, 28)
			decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			if err != nil {
				t.Fatalf("decode scalar %s shift=%d: %v", family.name, shift, err)
			}
			if decoded.Op != Op(family.name) || len(decoded.Args) != 3 || decoded.Args[0].Kind != OpImm || decoded.Args[0].Imm != int64(shift) || decoded.Args[1].Reg != "V29" || decoded.Args[2].Reg != "V28" {
				t.Fatalf("decoded scalar %s shift=%d %#08x as %#v", family.name, shift, word, decoded)
			}
			fmt.Fprintf(&source, "\tWORD $%#08x // scalar %s D shift=%d\n", word, family.name, shift)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"immediateShiftRightArchitectureForms": {Name: "immediateShiftRightArchitectureForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(ll, "\n") {
				if !strings.Contains(line, " = ashr ") && !strings.Contains(line, " = lshr ") {
					continue
				}
				if strings.Contains(line, "ashr i64") || strings.Contains(line, "lshr i64") {
					if strings.HasSuffix(line, ", 64") {
						t.Fatalf("%s emitted undefined scalar width-sized shift: %s", triple, line)
					}
				}
				for _, bits := range []int{8, 16, 32, 64} {
					if strings.Contains(line, fmt.Sprintf("x i%d>", bits)) && strings.Contains(line, fmt.Sprintf("i%d %d", bits, bits)) {
						t.Fatalf("%s emitted undefined vector width-sized shift: %s", triple, line)
					}
				}
			}
			for _, operation := range []string{"ashr", "lshr", "add"} {
				if !strings.Contains(ll, " = "+operation+" ") {
					t.Fatalf("%s omitted %s semantics:\n%s", triple, operation, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-immediate-shift-right.ll", "arm64-immediate-shift-right.o", ll)
		})
	}
}

func TestTranslateARM64ImmediateShiftRightRejectsInvalidArchitectureForms(t *testing.T) {
	for _, instruction := range []string{
		"VURSHR V0.S4, V1.S4",
		"VURSRA $0, V0.S4, V1.S4",
		"VSSRA $33, V0.S4, V1.S4",
		"VSRSRA $1, V0.S2, V1.S4",
		"VURSHR $1, V0.D1, V1.D1",
		"VURSRA.P $1, V0.S4, V1.S4",
	} {
		file, err := Parse(ArchARM64, "TEXT ·badImmediateShift(SB), $0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs:         map[string]FuncSig{"badImmediateShift": {Name: "badImmediateShift", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted invalid ARM64 immediate shift-right form %q", instruction)
		}
	}
}

func TestARM64ImmediateShiftRightRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	families := []uint32{
		0x0f000400, // SSHR
		0x0f001400, // SSRA
		0x0f002400, // SRSHR
		0x0f003400, // SRSRA
		0x2f000400, // USHR
		0x2f001400, // USRA
		0x2f002400, // URSHR
		0x2f003400, // URSRA
	}
	var source strings.Builder
	source.WriteString("TEXT immediateShiftRightSemantics(SB),$0-24\n")
	source.WriteString("\tMOVD in+0(FP), R0\n\tMOVD initial+8(FP), R1\n\tMOVD out+16(FP), R2\n")
	source.WriteString("\tVLD1 (R0), [V0.B16]\n")
	source.WriteString("\tVLD1.P 64(R1), [V8.B16, V9.B16, V10.B16, V11.B16]\n")
	source.WriteString("\tVLD1 (R1), [V12.B16, V13.B16, V14.B16, V15.B16]\n")
	for i, base := range families {
		word := encodeARM64ImmediateShiftRight(base, 8, 4, true, 0, 8+i)
		fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
	}
	source.WriteString("\tVST1.P [V8.B16, V9.B16, V10.B16, V11.B16], 64(R2)\n")
	source.WriteString("\tVST1 [V12.B16, V13.B16, V14.B16, V15.B16], (R2)\n\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"immediateShiftRightSemantics": {
			Name: "immediateShiftRightSemantics", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void immediateShiftRightSemantics(const uint8_t *, const uint8_t *, uint8_t *);
int main(void) {
  uint8_t in[16], initial[128], got[128] = {0};
  for (int i = 0; i < 16; i++) in[i] = (uint8_t)(i * 29u + 3u);
  for (int i = 0; i < 128; i++) initial[i] = (uint8_t)(i * 7u + 5u);
  immediateShiftRightSemantics(in, initial, got);
  for (int i = 0; i < 16; i++) {
    const int16_t sx = (int8_t)in[i];
    const uint16_t ux = in[i];
    const int16_t signed_shift = sx >> 4;
    const int16_t signed_round = signed_shift + ((sx >> 3) & 1);
    const uint16_t unsigned_shift = ux >> 4;
    const uint16_t unsigned_round = unsigned_shift + ((ux >> 3) & 1);
    const uint8_t want[8] = {
      (uint8_t)signed_shift,
      (uint8_t)(initial[1*16+i] + signed_shift),
      (uint8_t)signed_round,
      (uint8_t)(initial[3*16+i] + signed_round),
      (uint8_t)unsigned_shift,
      (uint8_t)(initial[5*16+i] + unsigned_shift),
      (uint8_t)unsigned_round,
      (uint8_t)(initial[7*16+i] + unsigned_round),
    };
    for (int op = 0; op < 8; op++) if (got[op*16+i] != want[op]) return op*16+i+1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_immediate_shift_right", triple, ll, mainC, nil)
}
