package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86UnaryYmbGrammarMatchesGoEncoder(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{A((?:NEG|NOT)[BWLQ]),\s*yscond,`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != len(x86UnaryYmbSpecs) || len(rows) != 8 {
		t.Fatalf("Go encoder has %d NEG/NOT Ymb rows; grammar has %d", len(rows), len(x86UnaryYmbSpecs))
	}
	for _, row := range rows {
		name := row[1]
		spec, ok := x86UnaryYmbSpecs[Op(name)]
		width := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[name[len(name)-1]]
		if !ok || spec.bits != width || spec.negate != strings.HasPrefix(name, "NEG") {
			t.Errorf("Go %s encoder row disagrees with grammar: %+v, present=%v", name, spec, ok)
		}
	}
}

func x86NEGCompleteFormsSource(goarch string) string {
	var source strings.Builder
	symbol := "negdata"
	size := 8
	if goarch == "386" {
		symbol = "negdata386"
		size = 4
	}
	fmt.Fprintf(&source, "DATA %s+0(SB)/%d, $1\n", symbol, size)
	fmt.Fprintf(&source, "GLOBL %s(SB), $%d\n", symbol, size)
	source.WriteString("TEXT negforms(SB),$0-0\n")
	if goarch == "amd64" {
		source.WriteString("\tNEGB AH\n\tNEGB R11\n")
	} else {
		source.WriteString("\tNEGB AH\n\tNEGB BP\n")
	}
	source.WriteString("\tNEGB 8(BX)\n\tNEGB " + symbol + "(SB)\n")
	widths := []string{"W", "L"}
	if goarch == "amd64" {
		widths = append(widths, "Q")
	}
	for _, width := range widths {
		// yscond uses Ymb even for wide opcodes. Byte spellings therefore
		// select the full register with the same raw ModRM number.
		for _, reg := range []string{"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"} {
			fmt.Fprintf(&source, "\tNEG%s %s\n", width, reg)
		}
		fmt.Fprintf(&source, "\tNEG%s DX\n", width)
		if goarch == "amd64" {
			for _, reg := range []string{"SP", "BPB", "SIB", "DIB", "R8", "R15", "R8B", "R15B"} {
				fmt.Fprintf(&source, "\tNEG%s %s\n", width, reg)
			}
		} else {
			fmt.Fprintf(&source, "\tNEG%s SI\n", width)
		}
		fmt.Fprintf(&source, "\tNEG%s 8(BX)\n\tNEG%s %s(SB)\n", width, width, symbol)
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86NEGCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86NEGCompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"negforms": {Name: "negforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"sub i8 0", "sub i16 0", "sub i32 0", "store i1"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("NEG lowering omitted %q:\n%s", want, ll)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ll, "sub i64 0") {
				t.Fatalf("NEGQ lowering omitted sub i64:\n%s", ll)
			}
			compileLLVMToObject(t, llc, target.triple, "neg-"+target.name+".ll", "neg-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86NEGRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "NEGB X0"},
		{goarch: "amd64", instruction: "NEGW $1"},
		{goarch: "amd64", instruction: "NEGL AX, BX"},
		{goarch: "amd64", instruction: "NEGQ"},
		{goarch: "amd64", instruction: "NEGQ.Z AX"},
		{goarch: "386", instruction: "NEGB SP"},
		{goarch: "386", instruction: "NEGW SP"},
		{goarch: "386", instruction: "NEGL SP"},
		{goarch: "386", instruction: "NEGL R8"},
		{goarch: "386", instruction: "NEGQ AX"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				Goarch:       test.goarch,
				TargetTriple: triple,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's NEG yscond table", test.instruction)
			}
		})
	}
}

func TestAMD64NEGRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT negsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVQ $0x1122, AX
	NEGB AH
	MOVQ AX, 0(DI)
	MOVQ $0x1122334455660001, AX
	NEGW AX
	MOVQ AX, 8(DI)
	MOVQ $0x1122334480000000, AX
	NEGL AX
	MOVQ AX, 16(DI)
	SETCS 32(DI)
	SETOS 33(DI)
	SETEQ 34(DI)
	SETMI 35(DI)
	SETPS 36(DI)
	MOVQ $5, 24(DI)
	NEGQ 24(DI)
	MOVB $0, 40(DI)
	NEGB 40(DI)
	SETCS 41(DI)
	SETOS 42(DI)
	SETEQ 43(DI)
	SETMI 44(DI)
	SETPS 45(DI)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ll, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"negsemantics": {
				Name:  "negsemantics",
				Args:  []LLVMType{Ptr},
				Ret:   Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void negsemantics(uint8_t *);
int main(void) {
  uint8_t out[48] = {0};
  negsemantics(out);
  if (*(uint64_t *)(out+0) != UINT64_C(0xef22)) return 10;
  if (*(uint64_t *)(out+8) != UINT64_C(0x112233445566ffff)) return 11;
  if (*(uint64_t *)(out+16) != UINT64_C(0x80000000)) return 12;
  if (*(uint64_t *)(out+24) != UINT64_C(0xfffffffffffffffb)) return 13;
  if (out[32] != 1 || out[33] != 1 || out[34] != 0 || out[35] != 1 || out[36] != 1) return 14;
  if (out[40] != 0 || out[41] != 0 || out[42] != 0 || out[43] != 1 || out[44] != 0 || out[45] != 1) return 15;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "neg_semantics", triple, ll, mainC, runPrefix)
}

func TestAMD64UnaryYmbAliasesRuntime(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source, checks strings.Builder
	source.WriteString("TEXT unaryaliases(SB),$0-8\n\tMOVQ out+0(FP), R14\n")
	index := 0
	for _, family := range []string{"NEG", "NOT"} {
		for _, width := range []struct {
			suffix string
			bits   uint
		}{{"W", 16}, {"L", 32}, {"Q", 64}} {
			for _, reg := range []struct{ spelling, effective string }{
				{"AL", "AX"}, {"CL", "CX"}, {"DL", "DX"}, {"BL", "BX"},
				{"AH", "SP"}, {"CH", "BP"}, {"DH", "SI"}, {"BH", "DI"},
				{"BPB", "BP"}, {"SIB", "SI"}, {"DIB", "DI"}, {"R8B", "R8"}, {"R15B", "R15"},
			} {
				const input uint64 = 0x1122334455667701
				want := ^input
				if family == "NEG" {
					want++
				}
				if width.bits == 16 {
					want = (input &^ 0xffff) | (want & 0xffff)
				}
				if width.bits == 32 {
					want &= 0xffffffff
				}
				fmt.Fprintf(&source, "\tMOVQ $%#x, %s\n\t%s%s %s\n\tMOVQ %s, %d(R14)\n", input, reg.effective, family, width.suffix, reg.spelling, reg.effective, index*8)
				fmt.Fprintf(&checks, "  if (out[%d] != UINT64_C(%#x)) return %d;\n", index, want, index+1)
				index++
			}
		}
	}
	source.WriteString("\tRET\n")
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple, runPrefix = "x86_64-apple-macosx", []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{
		"unaryaliases": {Name: "unaryaliases", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mainC := fmt.Sprintf("#include <stdint.h>\nextern void unaryaliases(uint64_t *);\nint main(void) {\n  uint64_t out[%d] = {0};\n  unaryaliases(out);\n%s  return 0;\n}\n", index, checks.String())
	compileAndRunRuntimeTestForTarget(t, llc, clang, "unary_aliases", triple, ir, mainC, runPrefix)
}
