package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func fixedLocalCompactAssembly(name, body string) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$256-16\nMOVQ a+0(FP),AX\n", name)
	for offset := 0; offset < 128; offset += 8 {
		fmt.Fprintf(&source, "MOVQ AX,%d(SP)\n", offset)
	}
	source.WriteString("VMOVUPS (SP),Z0\n")
	for _, reg := range []int{2, 11, 16, 18, 20} {
		fmt.Fprintf(&source, "VMOVUPS Z0,Z%d\n", reg)
	}
	source.WriteString("KMOVQ AX,K1\nKMOVQ AX,K7\nMOVQ $1,BP\n")
	source.WriteString(body)
	source.WriteString("\nMOVQ AX,ret+8(FP)\nRET\n")
	return source.String()
}

func TestGoAMD64FixedLocalCompactExpandOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	bodies := []string{
		"VEXPANDPS 17(SP)(BP*2), K7, Y11\nVMOVUPS Y11,128(SP)\nMOVQ 128(SP),AX",
		"VEXPANDPS 17(SP), K7, X20\nVMOVUPS X20,128(SP)\nMOVQ 128(SP),AX",
		"VCOMPRESSPS X16, K7, 17(SP)(BP*8)\nMOVQ 25(SP),AX",
	}
	for index, body := range bodies {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalCompactAssembly(name, body))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(bodies))
}

func TestGoAMD64FixedLocalCompactExpandOfficialRows(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86CompactExpandRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	var assembly strings.Builder
	var operations []string
	var traps []bool
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
			trap := witness.Destination == "(AX)" && witness.Zeroing
			assembly.WriteString(fixedLocalCompactAssembly(fmt.Sprintf("Value%d", len(operations)), operation))
			operations = append(operations, operation)
			traps = append(traps, trap)
		}
	}
	if len(rows) != 72 || len(operations) != 216 {
		t.Fatal("the original compact/expand encoding inventory changed", len(rows), len(operations))
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("original Go compact/expand instruction count changed", len(pcs))
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	terminal := 0
	for index, operation := range operations {
		encoding := code[pcs[index]:pcs[index+1]]
		size, err := x86NumericalVectorBoundary(encoding, 64)
		if encoding[0] != 0x62 || err != nil || size != len(encoding) {
			t.Errorf("%s: cannot bind the exact Go EVEX bytes %x: length=%d err=%v", operation, encoding, size, err)
		}
		_, err = proveX86FixedLocal(file.Funcs[index], sig)
		if traps[index] {
			terminal++
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s: terminal memory zeroing acquired an ordinary proof: %v", operation, err)
			}
		} else if err != nil {
			t.Errorf("%s: initialized frame did not bind: %v", operation, err)
		}
	}
	if terminal != 18 {
		t.Fatal("the original terminal memory zeroing inventory changed", terminal)
	}
}

func TestGoAMD64FixedLocalCompactExpandProofBoundaries(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"masked write is permitted", "VPCOMPRESSQ Z16,K7,128(SP)", true},
		{"masked write does not initialize unknown bytes", "VPCOMPRESSQ Z16,K7,128(SP)\nMOVQ 128(SP),AX", false},
		{"masked write retains initialized bytes", "VPCOMPRESSQ Z16,K7,64(SP)\nMOVQ 64(SP),AX", true},
		{"unmasked write defines the entire output", "VPCOMPRESSQ Z16,128(SP)\nMOVQ 184(SP),AX", true},
		{"masked write can invalidate a spilled address", "LEAQ 32(SP),R10\nMOVQ R10,128(SP)\nVPCOMPRESSQ Z16,K7,128(SP)\nMOVQ 128(SP),DX\nMOVQ (DX),AX", false},
		{"masked write must fit its possible span", "VPCOMPRESSQ Z16,K7,208(SP)", false},
		{"masked read needs every possible input byte", "VPEXPANDQ Z16,K7,Z20\nVPEXPANDQ 80(SP),K7,Z20", false},
		{"merge needs the retained vector", "VPEXPANDQ (SP),K7,Z19", false},
		{"zeroing defines the retained vector", "VPEXPANDQ.Z (SP),K7,Z19\nVMOVUPS Z19,128(SP)", true},
		{"zeroing still needs its mask", "VPEXPANDQ.Z (SP),K6,Z19", false},
		{"zeroing store is terminal", "VPCOMPRESSQ.Z Z16,K7,128(SP)", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, fixedLocalCompactAssembly("Value", row.body))
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("valid=%t: %v", row.valid, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalCompactExpandRIPBoundaryOnly(t *testing.T) {
	const source = "VEXPANDPS table<>(SB),K1,X18\nVCOMPRESSPD Y16,K1,table<>(SB)\nRET"
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source)
	if len(pcs) != 3 {
		t.Fatal("missing original compact RIP boundaries", pcs)
	}
	for index := 0; index < 2; index++ {
		encoding := code[pcs[index]:pcs[index+1]]
		size, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || size != len(encoding) {
			t.Fatalf("original compact RIP bytes %x did not bind a boundary: %d, %v", encoding, size, err)
		}
		if _, _, known, err := decodedX86PackedCompactInstruction(encoding, 64, x86RawMemoryDecoder{}); !known || err == nil {
			t.Fatalf("compact RIP bytes %x acquired a raw source address", encoding)
		}
	}
}
