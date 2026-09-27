package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type rawDuplicateMoveSpec struct {
	legacyPrefix byte
	opcode       byte
	legacy       Op
	vector       Op
	double       bool
}

var rawDuplicateMoveSpecs = []rawDuplicateMoveSpec{
	{legacyPrefix: 0xf2, opcode: 0x12, legacy: "MOVDDUP", vector: "VMOVDDUP", double: true},
	{legacyPrefix: 0xf3, opcode: 0x16, legacy: "MOVSHDUP", vector: "VMOVSHDUP"},
	{legacyPrefix: 0xf3, opcode: 0x12, legacy: "MOVSLDUP", vector: "VMOVSLDUP"},
}

func encodeX86RawLegacyDuplicateMove(spec rawDuplicateMoveSpec, source, destination int) []byte {
	rex := byte(0x40 | source>>3&1 | destination>>3&1<<2)
	code := []byte{spec.legacyPrefix}
	if rex != 0x40 {
		code = append(code, rex)
	}
	return append(code, 0x0f, spec.opcode, byte(0xc0|destination&7<<3|source&7))
}

func encodeX86RawVEXDuplicateMove(spec rawDuplicateMoveSpec, vectorBits byte, source, destination int) []byte {
	p0 := byte((^destination>>3)&1)<<7 | 0x40 | byte((^source>>3)&1)<<5 | 1
	pp := byte(2)
	if spec.double {
		pp = 3
	}
	p1 := byte(0x78 | vectorBits<<2 | pp)
	return []byte{0xc4, p0, p1, spec.opcode, byte(0xc0 | destination&7<<3 | source&7)}
}

func encodeX86RawEVEXDuplicateMove(spec rawDuplicateMoveSpec, vectorBits byte, mask int, zeroing bool, source, destination int) []byte {
	p0 := byte((^destination>>3)&1)<<7 |
		byte((^source>>4)&1)<<6 |
		byte((^source>>3)&1)<<5 |
		byte((^destination>>4)&1)<<4 | 1
	pp := byte(2)
	if spec.double {
		pp = 3
	}
	p1 := byte(0x7c | pp)
	if spec.double {
		p1 |= 0x80
	}
	p2 := vectorBits<<5 | 0x08 | byte(mask)
	if zeroing {
		p2 |= 0x80
	}
	return []byte{0x62, p0, p1, p2, spec.opcode, byte(0xc0 | destination&7<<3 | source&7)}
}

func TestDecodeX86RawDirectiveGroupReportedSegDSPVMOVSHDUP(t *testing.T) {
	// vmovshdup %xmm0, %xmm1;
	// vpermilps $208, %xmm7, %xmm0
	code := []byte{0xc5, 0xfa, 0x16, 0xc8, 0xc4, 0xe3, 0x79, 0x04, 0xc7, 0xd0}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "segdsp VMOVSHDUP sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || !strings.HasPrefix(decoded[0].Raw, "VMOVSHDUP X0, X1 ") {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodedX86RawDuplicateMoveCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawDuplicateMoveSpecs {
		for source := 0; source < 16; source++ {
			for destination := 0; destination < 16; destination++ {
				code := encodeX86RawLegacyDuplicateMove(spec, source, destination)
				got, length, ok, err := decodedX86DuplicateMoveInstruction(code, 64)
				want := fmt.Sprintf("%s X%d, X%d", spec.legacy, source, destination)
				if err != nil || !ok || length != len(code) || got.Raw != want {
					t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
				}
				count++
			}
		}
		for vectorBits := byte(0); vectorBits < 2; vectorBits++ {
			vectorName := [...]string{"X", "Y"}[vectorBits]
			for source := 0; source < 16; source++ {
				for destination := 0; destination < 16; destination++ {
					code := encodeX86RawVEXDuplicateMove(spec, vectorBits, source, destination)
					got, length, ok, err := decodedX86DuplicateMoveInstruction(code, 64)
					want := fmt.Sprintf("%s %s%d, %s%d", spec.vector, vectorName, source, vectorName, destination)
					if err != nil || !ok || length != len(code) || got.Raw != want {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
					}
					count++
				}
			}
		}
		for vectorBits := byte(0); vectorBits < 3; vectorBits++ {
			vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
			for _, masking := range []struct {
				mask    int
				zeroing bool
				suffix  string
			}{{}, {mask: 3}, {mask: 7, zeroing: true, suffix: ".Z"}} {
				for source := 0; source < 32; source++ {
					for destination := 0; destination < 32; destination++ {
						code := encodeX86RawEVEXDuplicateMove(spec, vectorBits, masking.mask, masking.zeroing, source, destination)
						got, length, ok, err := decodedX86DuplicateMoveInstruction(code, 64)
						args := []string{fmt.Sprintf("%s%d", vectorName, source)}
						if masking.mask != 0 {
							args = append(args, fmt.Sprintf("K%d", masking.mask))
						}
						args = append(args, fmt.Sprintf("%s%d", vectorName, destination))
						want := string(spec.vector) + masking.suffix + " " + strings.Join(args, ", ")
						if err != nil || !ok || length != len(code) || got.Raw != want {
							t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
						}
						count++
					}
				}
			}
		}
	}
	if count != 29952 {
		t.Fatalf("covered %d duplicate-move register encodings, want 29952", count)
	}
}

func TestDecodedX86RawDuplicateMoveMemoryAndInvalidForms(t *testing.T) {
	legacyMemory := []byte{0xf3, 0x47, 0x0f, 0x16, 0x7c, 0x8b, 0x01}
	got, length, ok, err := decodedX86DuplicateMoveInstruction(legacyMemory, 64)
	wantMemory := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: 1}
	if err != nil || !ok || length != len(legacyMemory) || got.Op != "MOVSHDUP" || got.Args[1].String() != "X15" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", legacyMemory, got, length, ok, err)
	}
	vexMemory := []byte{0xc4, 0x01, 0x7e, 0x16, 0x7c, 0x8b, 0x02}
	got, length, ok, err = decodedX86DuplicateMoveInstruction(vexMemory, 64)
	wantMemory.Off = 2
	if err != nil || !ok || length != len(vexMemory) || got.Op != "VMOVSHDUP" || got.Args[1].String() != "Y15" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", vexMemory, got, length, ok, err)
	}
	evexMemory := []byte{0x62, 0xf1, 0xff, 0x8b, 0x12, 0x50, 0x02}
	got, length, ok, err = decodedX86DuplicateMoveInstruction(evexMemory, 64)
	wantMemory = MemRef{Base: "AX", Off: 16}
	if err != nil || !ok || length != len(evexMemory) || got.Op != "VMOVDDUP.Z" || got.Args[1].String() != "K3" || got.Args[2].String() != "X2" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", evexMemory, got, length, ok, err)
	}

	validVEX := encodeX86RawVEXDuplicateMove(rawDuplicateMoveSpecs[1], 0, 7, 7)
	validEVEX := encodeX86RawEVEXDuplicateMove(rawDuplicateMoveSpecs[1], 2, 0, false, 7, 5)
	for name, invalid := range map[string][]byte{
		"vex W":                {validVEX[0], validVEX[1], validVEX[2] | 0x80, validVEX[3], validVEX[4]},
		"vex vvvv":             {validVEX[0], validVEX[1], validVEX[2] &^ 0x08, validVEX[3], validVEX[4]},
		"evex fixed bit":       {validEVEX[0], validEVEX[1], validEVEX[2] &^ 0x04, validEVEX[3], validEVEX[4], validEVEX[5]},
		"evex wrong W":         {validEVEX[0], validEVEX[1], validEVEX[2] | 0x80, validEVEX[3], validEVEX[4], validEVEX[5]},
		"evex vvvvv":           {validEVEX[0], validEVEX[1], validEVEX[2] &^ 0x08, validEVEX[3] &^ 0x08, validEVEX[4], validEVEX[5]},
		"evex broadcast":       {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 0x10, validEVEX[4], validEVEX[5]},
		"evex reserved length": {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 0x60, validEVEX[4], validEVEX[5]},
		"zero without mask":    {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 0x80, validEVEX[4], validEVEX[5]},
		"address override":     append([]byte{0x67}, validVEX...),
	} {
		if instruction, _, matched, decodeErr := decodedX86DuplicateMoveInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	highZ386 := encodeX86RawEVEXDuplicateMove(rawDuplicateMoveSpecs[1], 2, 0, false, 8, 2)
	if instruction, _, matched, decodeErr := decodedX86DuplicateMoveInstruction(highZ386, 32); !matched || decodeErr == nil {
		t.Fatalf("386 high-Z encoding %x decoded as %+v, ok=%v, err=%v", highZ386, instruction, matched, decodeErr)
	}
}

func TestX86DuplicateMoveRawGo127ArchitectureOracle(t *testing.T) {
	const accepted386 = `TEXT ok(SB),$0-0
	MOVDDUP X6, X7
	MOVSHDUP X6, X7
	MOVSLDUP X6, X7
	VMOVDDUP Y6, Y7
	VMOVSHDUP X20, K1, X21
	VMOVSLDUP.Z Y20, K2, Y21
	VMOVDDUP Z6, K3, Z7
	RET
`
	requireX86GoAssemblerResult(t, "386", accepted386, true)
	for _, instruction := range []string{
		"MOVSHDUP X8, X0",
		"VMOVDDUP Z8, Z0",
	} {
		requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
	}
}

func TestTranslateX86RawDuplicateMoveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT raw_duplicate_move(SB),NOSPLIT,$0-0\n")
			for _, spec := range rawDuplicateMoveSpecs {
				var encodings [][]byte
				if target.goarch == "amd64" {
					encodings = append(encodings,
						encodeX86RawLegacyDuplicateMove(spec, 15, 14),
						encodeX86RawVEXDuplicateMove(spec, 1, 15, 14),
						encodeX86RawEVEXDuplicateMove(spec, 2, 7, true, 31, 30),
					)
				} else {
					encodings = append(encodings,
						encodeX86RawLegacyDuplicateMove(spec, 7, 6),
						encodeX86RawVEXDuplicateMove(spec, 1, 7, 6),
						encodeX86RawEVEXDuplicateMove(spec, 0, 1, false, 20, 21),
						encodeX86RawEVEXDuplicateMove(spec, 2, 2, true, 6, 7),
					)
				}
				for _, encoding := range encodings {
					for _, value := range encoding {
						fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
					}
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"raw_duplicate_move": {Name: "raw_duplicate_move", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-duplicate-move-"+target.name+".ll", "raw-duplicate-move-"+target.name+".o", ll)
		})
	}
}

func TestAMD64DuplicateMoveRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT duplicateMoveSemantics(SB),NOSPLIT,$0-32
	MOVQ out+0(FP), AX
	MOVQ source+8(FP), BX
	MOVQ old+16(FP), CX
	KMOVQ mask+24(FP), K1
	VMOVUPS (BX), Y0
	VMOVSHDUP Y0, Y1
	VMOVUPS Y1, 0(AX)
	VMOVSLDUP Y0, Y2
	VMOVUPS Y2, 32(AX)
	VMOVDDUP (BX), X3
	VMOVUPS X3, 64(AX)
	VMOVUPS (CX), Y4
	VMOVSHDUP Y0, K1, Y4
	VMOVUPS Y4, 80(AX)
	VMOVUPS (CX), Y4
	VMOVSLDUP.Z Y0, K1, Y4
	VMOVUPS Y4, 112(AX)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		{Offset: 24, Type: I64, Index: 3, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"duplicateMoveSemantics": {Name: "duplicateMoveSemantics", Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void duplicateMoveSemantics(uint32_t *, const uint32_t *, const uint32_t *, uint64_t);
int main(void) {
  uint32_t source[8] = {10, 11, 20, 21, 30, 31, 40, 41};
  uint32_t old[8] = {100, 101, 102, 103, 104, 105, 106, 107};
  uint32_t out[36] = {0};
  uint64_t mask = 0x55;
  duplicateMoveSemantics(out, source, old, mask);
  uint32_t sh[8] = {11, 11, 21, 21, 31, 31, 41, 41};
  uint32_t sl[8] = {10, 10, 20, 20, 30, 30, 40, 40};
  uint32_t dd[4] = {10, 11, 10, 11};
  for (int i = 0; i < 8; i++) if (out[i] != sh[i]) return 1 + i;
  for (int i = 0; i < 8; i++) if (out[8+i] != sl[i]) return 20 + i;
  for (int i = 0; i < 4; i++) if (out[16+i] != dd[i]) return 40 + i;
  for (int i = 0; i < 8; i++) {
    uint32_t want = (mask >> i) & 1 ? sh[i] : old[i];
    if (out[20+i] != want) return 50 + i;
  }
  for (int i = 0; i < 8; i++) {
    uint32_t want = (mask >> i) & 1 ? sl[i] : 0;
    if (out[28+i] != want) return 70 + i;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "duplicate_move", triple, ll, mainC, runPrefix)
}
