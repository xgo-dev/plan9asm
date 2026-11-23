package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawLiteralPrefetchEncoding(t *testing.T) {
	var lines []string
	offsets := []int64{-1048576, -4, 0, 4, 1048572}
	for hint := 0; hint < 32; hint++ {
		for _, offset := range offsets {
			lines = append(lines, fmt.Sprintf("prfm #%d, #%d", hint, offset))
		}
	}
	for index, word := range assembleARM64LLVMWords(t, lines, "") {
		hint, offset, ok := decodeARM64RawLiteralPrefetch(word)
		if !ok || int(hint) != index/len(offsets) || offset != offsets[index%len(offsets)] {
			t.Errorf("%s (%#08x): hint %d offset %d recognized %t", lines[index], word, hint, offset, ok)
		}
		if effects, ok := arm64RawContinuationEffectsForWord(word); !ok || effects != (arm64RawContinuationEffects{}) {
			t.Errorf("%s: effects %+v, recognized %t", lines[index], effects, ok)
		}
	}
}

const arm64LiteralCodePrefetch = `TEXT literalCode(SB),516,$0-0
WORD $0xd800004a
WORD $0xd28004a0
target:
WORD $0xd503201f
RET
`

const arm64LiteralDataPrefetch = `TEXT literalData(SB),516,$0-0
WORD $0xd8000078
WORD $0x14000003
pool:
WORD $0x44332211
WORD $0x88776655
end:
WORD $0xd2800580
RET
`

func TestARM64RawLiteralPrefetchUsesProvenSourceLayout(t *testing.T) {
	const pool = `WORD $0x14000003
pool:
WORD $0x44332211
WORD $0x88776655
end:
RET
`
	for _, test := range []struct {
		name, body, hint, address string
	}{
		{
			"forward-code-label",
			"WORD $0xd800004a\nWORD $0xd503201f\ntarget:\nWORD $0xd503201f\nRET\n",
			"10", "blockaddress(@literalPrefetch, %bb_target)",
		},
		{
			"backward-code-label",
			"target:\nWORD $0xd503201f\nWORD $0xd8ffffe0\nRET\n",
			"0", "blockaddress(@literalPrefetch, %bb_target)",
		},
		{"pool-start", "WORD $0xd8000040\n" + pool, "0", "ptrtoint ptr @literalPrefetch.pool.raw_data"},
		{
			"pool-interior", "WORD $0xd8000078\n" + pool,
			"24", "getelementptr (i8, ptr @literalPrefetch.pool.raw_data, i64 4)",
		},
		{
			"pool-unlabelled",
			"WORD $0xd800007f\nWORD $0x14000003\nWORD $0x44332211\nWORD $0x88776655\nRET\n",
			"31", ", i64 4) to i64",
		},
		{"after-return-data", "WORD $0xd8000040\nRET\nWORD $0x44332211\n", "0", "__unreferenced_data_"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT literalPrefetch(SB),516,$0-0\n" + test.body
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc is required")
			}
			for _, triple := range []string{arm64LinuxGNUTriple, "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
				ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
					Sigs: map[string]FuncSig{"literalPrefetch": {Name: "literalPrefetch", Ret: Void}}})
				if err != nil {
					t.Errorf("%s: %v", triple, err)
					continue
				}
				for _, want := range []string{test.address, "prfum #" + test.hint + ", [$0, #0]"} {
					if !strings.Contains(ir, want) {
						t.Fatalf("%s: expected address or hint %q in:\n%s", triple, want, ir)
					}
				}
				compileLLVMToObject(t, llc, triple, "literal-prefetch.ll", "literal-prefetch.o", ir)
			}
		})
	}
}

func TestARM64RawLiteralPrefetchRejectsUnprovenSourceLayout(t *testing.T) {
	for _, body := range []string{
		"WORD $0xd87fffe0\nRET\n",
		"WORD $0xd8000040\nRET\n", // One past the function.
		"WORD $0xd8000040\nMOVD $0x123456789abcdef0,R0\nRET\n",
	} {
		source := "TEXT missingTarget(SB),516,$0-0\n" + body
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
			Sigs: map[string]FuncSig{"missingTarget": {Name: "missingTarget", Ret: Void}}})
		if err == nil || !strings.Contains(err.Error(), "does not land on a proven source boundary") {
			t.Errorf("%q: expected an unproven target error, got %v", body, err)
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64LiteralPrefetch(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source := arm64LiteralCodePrefetch + arm64LiteralDataPrefetch
	requireARM64GoAssemblerResult(t, source, true)
	original := strings.NewReplacer(
		"literalCode(SB),516,$0-0", "·literalCode<ABIInternal>(SB),516,$0-8",
		"literalData(SB),516,$0-0", "·literalData<ABIInternal>(SB),516,$0-8",
	).Replace(source)
	runARM64GoInternalOracle(t, original, `package main
func literalCode() uint64
func literalData() uint64
func main() {
    if literalCode() != 37 || literalData() != 44 {
        panic("literal prefetch did not preserve the original results")
    }
}
`, len(runner) != 0)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{
		"literalCode": {Name: "literalCode", Ret: I64},
		"literalData": {Name: "literalData", Ret: I64},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const main = `#include <stdint.h>
extern uint64_t literalCode(void), literalData(void);
int main(void) { return literalCode() != 37 || literalData() != 44; }
`
	for _, optimization := range []int{0, 2} {
		name := fmt.Sprintf("literal_prefetch_O%d", optimization)
		t.Run(name, func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, name, triple, ir, main, runner, optimization)
		})
	}
}
