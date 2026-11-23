package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64LiteralLoadTestForm struct {
	instruction string
	bits        int
	register    int
	vector      bool
	signed      bool
	first       [2]uint64
	second      [2]uint64
}

var arm64LiteralLoadTestForms = []arm64LiteralLoadTestForm{
	{"ldr w9", 32, 9, false, false, [2]uint64{0x88776655}, [2]uint64{0x44332211}},
	{"ldr x9", 64, 9, false, false, [2]uint64{0x4433221188776655}, [2]uint64{0xfedcba9844332211}},
	{"ldrsw x9", 32, 9, false, true, [2]uint64{0xffffffff88776655}, [2]uint64{0x44332211}},
	{"ldr s7", 32, 7, true, false, [2]uint64{0x88776655}, [2]uint64{0x44332211}},
	{"ldr d7", 64, 7, true, false, [2]uint64{0x4433221188776655}, [2]uint64{0xfedcba9844332211}},
	{"ldr q7", 128, 7, true, false,
		[2]uint64{0x4433221188776655, 0x76543210fedcba98}, [2]uint64{0xfedcba9844332211, 0x8000000176543210}},
	{"ldr wzr", 32, 31, false, false, [2]uint64{1, 2}, [2]uint64{1, 2}},
	{"ldr xzr", 64, 31, false, false, [2]uint64{1, 2}, [2]uint64{1, 2}},
	{"ldrsw xzr", 32, 31, false, true, [2]uint64{1, 2}, [2]uint64{1, 2}},
}

func TestARM64RawLiteralLoadEncoding(t *testing.T) {
	offsets := []int64{-1048576, -4, 0, 4, 1048572}
	var lines []string
	for _, form := range arm64LiteralLoadTestForms {
		for _, offset := range offsets {
			lines = append(lines, fmt.Sprintf("%s, #%d", form.instruction, offset))
		}
	}
	for index, word := range assembleARM64LLVMWords(t, lines, "") {
		want := arm64LiteralLoadTestForms[index/len(offsets)]
		form, ok := decodeARM64RawLiteralLoad(word)
		if !ok || form != (arm64LiteralLoadForm{
			bits: want.bits, register: want.register, displacement: offsets[index%len(offsets)],
			vector: want.vector, signed: want.signed,
		}) {
			t.Errorf("%s: decoded %+v, recognized %t", lines[index], form, ok)
		}
		effects := arm64RawContinuationEffects{}
		if !want.vector && want.register != 31 {
			effects.gpWrites = 1 << want.register
		}
		if actual, ok := arm64RawContinuationEffectsForWord(word); !ok || actual != effects {
			t.Errorf("%s: effects %+v, recognized %t, want %+v", lines[index], actual, ok, effects)
		}
	}
	for _, word := range []uint32{0xdc000007, 0xd8000000, 0xf9400029} {
		if form, ok := decodeARM64RawLiteralLoad(word); ok {
			t.Errorf("non-load or reserved encoding %#08x accepted as %+v", word, form)
		}
	}
}

type arm64LiteralLoadRuntimeCase struct {
	name string
	want [2]uint64
}

func arm64LiteralLoadFixture(t *testing.T, original bool) (string, []arm64LiteralLoadRuntimeCase, map[string]FuncSig) {
	t.Helper()
	const pool = `WORD $0x14000006
pool:
WORD $0x88776655
tail:
WORD $0x44332211
WORD $0xfedcba98
WORD $0x76543210
WORD $0x80000001
end:
`
	var lines []string
	for _, form := range arm64LiteralLoadTestForms {
		lines = append(lines, form.instruction+", #8", form.instruction+", #-16")
	}
	words := assembleARM64LLVMWords(t, lines, "")
	var source strings.Builder
	var cases []arm64LiteralLoadRuntimeCase
	signatures := make(map[string]FuncSig)
	for i, word := range words {
		form := arm64LiteralLoadTestForms[i/2]
		name := fmt.Sprintf("literalLoad%d", i)
		symbol := name
		if original {
			symbol = "·" + name + "<ABIInternal>"
		}
		fmt.Fprintf(&source, "TEXT %s(SB),516,$0-8\n", symbol)
		if form.vector {
			source.WriteString("VLD1 (R0), [V7.D2]\n")
		} else if form.register != 31 {
			source.WriteString("MOVD (R0), R9\n")
		}
		want := form.first
		if i%2 == 0 {
			fmt.Fprintf(&source, "WORD $%#08x\n%s", word, pool)
		} else {
			source.WriteString(pool)
			fmt.Fprintf(&source, "WORD $%#08x\n", word)
			want = form.second
		}
		if form.vector {
			source.WriteString("VST1 [V7.D2], (R0)\n")
		} else if form.register != 31 {
			source.WriteString("MOVD R9, (R0)\nMOVD ZR, 8(R0)\n")
		}
		source.WriteString("RET\n")
		cases = append(cases, arm64LiteralLoadRuntimeCase{name, want})
		signatures[name] = FuncSig{Name: name, Args: []LLVMType{Ptr}, Ret: Void, ArgRegs: []Reg{"R0"}}
	}
	return source.String(), cases, signatures
}

func TestARM64RawLiteralLoadsUseProvenDataPool(t *testing.T) {
	source, _, signatures := arm64LiteralLoadFixture(t, false)
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
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: signatures})
			if err != nil {
				t.Fatal(err)
			}
			for text, count := range map[string]int{
				"load volatile i32,":       10,
				"load volatile i64,":       6,
				"load volatile <16 x i8>,": 2,
				"sext i32 ":                2,
			} {
				if got := strings.Count(ir, text); got != count {
					t.Errorf("%q count %d, want %d", text, got, count)
				}
			}
			compileLLVMToObject(t, llc, triple, "literal-load.ll", "literal-load.o", ir)
		})
	}
}

func TestARM64RawLiteralLoadsRejectUnprovenBytes(t *testing.T) {
	for _, test := range []struct {
		name, source string
	}{
		{"code", "WORD $0x58000020\nWORD $0xd503201f\nRET\n"},
		{"truncated-vector", "WORD $0x9c000040\nWORD $0x14000002\npool:\nWORD $0x11223344\nend:\nRET\n"},
		{"raw-branch-into-pool", "WORD $0x18000040\nWORD $0x14000002\npool:\nWORD $0x11223344\nWORD $0xd503201f\nend:\nRET\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT literal(SB),516,$0-0\n" + test.source
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
				Sigs: map[string]FuncSig{"literal": {Name: "literal", Ret: Void}}})
			if err == nil || !strings.Contains(err.Error(), "span in a proven constant pool") {
				t.Errorf("expected a literal data proof failure, got %v", err)
			}
		})
	}
}

func TestARM64RawLiteralLoadCanReadBranchShapedData(t *testing.T) {
	const source = `TEXT literal(SB),516,$0-0
WORD $0x18000040
WORD $0x14000002
pool:
WORD $0x14000000
end:
RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"literal": {Name: "literal", Ret: I64}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "load volatile i32, ptr @literal.pool.raw_data") {
		t.Fatalf("literal read did not use the branch-shaped pool word:\n%s", ir)
	}
}

func TestCrossLinuxRuntimeMatrixARM64LiteralLoads(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	original, cases, _ := arm64LiteralLoadFixture(t, true)
	var goMain strings.Builder
	goMain.WriteString("package main\n")
	for _, test := range cases {
		fmt.Fprintf(&goMain, "func %s(*[2]uint64)\n", test.name)
	}
	goMain.WriteString("func main() {\nvar out [2]uint64\n")
	for _, test := range cases {
		fmt.Fprintf(&goMain, "out = [2]uint64{1,2}; %s(&out); if out != [2]uint64{%#x,%#x} { panic(%q) }\n",
			test.name, test.want[0], test.want[1], test.name)
	}
	goMain.WriteString("}\n")
	runARM64GoInternalOracle(t, original, goMain.String(), len(runner) != 0)

	source, _, signatures := arm64LiteralLoadFixture(t, false)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: signatures})
	if err != nil {
		t.Fatal(err)
	}
	var cMain strings.Builder
	cMain.WriteString("#include <stdint.h>\n")
	for _, test := range cases {
		fmt.Fprintf(&cMain, "extern void %s(uint64_t *);\n", test.name)
	}
	cMain.WriteString("int main(void) { uint64_t out[2];\n")
	for i, test := range cases {
		fmt.Fprintf(&cMain, "out[0]=1; out[1]=2; %s(out); if (out[0]!=UINT64_C(%#x) || out[1]!=UINT64_C(%#x)) return %d;\n",
			test.name, test.want[0], test.want[1], i+1)
	}
	cMain.WriteString("return 0; }\n")
	for _, optimization := range []int{0, 2} {
		name := fmt.Sprintf("literal_loads_O%d", optimization)
		t.Run(name, func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, name, triple, ir, cMain.String(), runner, optimization)
		})
	}
}
