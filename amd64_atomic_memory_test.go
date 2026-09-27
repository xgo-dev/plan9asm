package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// An object-only success is insufficient: LLVM can legalize an under-aligned
// atomicrmw into an unresolved libatomic call, absent from the Windows CRT.
func TestX86AtomicExchangeMemoryNeedsNoRuntimeHelpers(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ arch, triple string }{
		{"386", "i686-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-w64-windows-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"amd64", "x86_64-w64-windows-gnu"},
		{"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-apple-darwin"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT exchange(SB),$0-0\n")
			for _, family := range []string{"XADD", "XCHG"} {
				widths := "BWL"
				if target.arch == "amd64" {
					widths += "Q"
				}
				for _, width := range widths {
					reg := "DX"
					if width == 'B' {
						reg = "DL"
					}
					fmt.Fprintf(&source, "%s%c %s, 1(BX)\n", family, width, reg)
					fmt.Fprintf(&source, "%s%c %s, 1(FS)\n", family, width, reg)
					fmt.Fprintf(&source, "%s%c %s, 1(GS)\n", family, width, reg)
				}
			}
			source.WriteString("RET\n")
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"exchange": {Name: "exchange", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			input := filepath.Join(dir, "exchange.ll")
			if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
				t.Fatal(err)
			}
			asm, err := exec.Command(llc, "-mtriple="+target.triple, "-filetype=asm", input, "-o", "-").CombinedOutput()
			if err != nil {
				t.Fatalf("LLVM 22: %v\n%s", err, asm)
			}
			if strings.Contains(string(asm), "__atomic") || strings.Contains(string(asm), "__sync") {
				t.Fatalf("native x86 exchange acquired an external atomic helper:\n%s", asm)
			}
			for _, segment := range []string{"%fs:", "%gs:"} {
				want := 6
				if target.arch == "amd64" {
					want = 8
				}
				if got := strings.Count(string(asm), segment); got != want {
					t.Fatalf("atomic memory operand retained %d/%d %s overrides:\n%s", got, want, segment, asm)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "exchange.ll", "exchange.o", ir)
		})
	}
}

func TestX86ExchangeGrammarMatchesGoEncoder(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{A((?:XADD|XCHG)[BWLQ]),\s*(\w+),`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 8 || len(rows) != len(amd64ExchangeSpecs) {
		t.Fatalf("Go encoder has %d exchange opcodes; grammar has %d", len(rows), len(amd64ExchangeSpecs))
	}
	for _, row := range rows {
		spec, ok := amd64ExchangeSpecs[Op(row[1])]
		bits := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[row[1][len(row[1])-1]]
		kind, table := amd64ExchangeSwap, "yxchg"
		if strings.HasPrefix(row[1], "XADD") {
			kind, table = amd64ExchangeAdd, "yrl_ml"
			if bits == 8 {
				table = "yrb_mb"
			}
		} else if bits == 8 {
			table = "yml_mb"
		}
		if !ok || spec.bits != bits || spec.kind != kind || row[2] != table {
			t.Errorf("Go %s/%s disagrees with typed grammar: %+v", row[1], row[2], spec)
		}
	}
}

func TestAMD64ExchangeUnalignedRuntimeSemantics(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution requires amd64 or Rosetta; the all-host object matrix remains required")
	}
	var source, declarations, cases strings.Builder
	sigs := make(map[string]FuncSig)
	for _, family := range []string{"XADD", "XCHG", "REVERSE"} {
		for i, width := range "BWLQ" {
			bits := []int{8, 16, 32, 64}[i]
			name := fmt.Sprintf("exchange_%s_%d", family, bits)
			reg := "AX"
			if bits == 8 {
				reg = "AL"
			}
			instruction := fmt.Sprintf("%s%c %s, 1(BX)", family, width, reg)
			if family == "REVERSE" {
				instruction = fmt.Sprintf("XCHG%c 1(BX), %s", width, reg)
			}
			fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVQ p+0(FP), BX\nMOVQ v+8(FP), AX\n%s\nMOVQ AX, ret+16(FP)\nRET\n", name, instruction)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, I64}, Ret: I64, Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}},
				Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0}},
			}}
			fmt.Fprintf(&declarations, "extern uint64_t %s(uint8_t *, uint64_t);\n", name)
			add := 0
			if family == "XADD" {
				add = 1
			}
			fmt.Fprintf(&cases, "{%s, %d, %d},\n", name, bits, add)
		}
	}
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
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <string.h>
` + declarations.String() + `
int main(void) {
  struct { uint64_t (*fn)(uint8_t *, uint64_t); int bits, add; } cases[] = {
` + cases.String() + `
  };
  const uint64_t values[] = {0, 1, UINT64_MAX, UINT64_C(0x8877665544332211), UINT64_C(0x8000000080008080)};
  for (unsigned c = 0; c < sizeof(cases)/sizeof(cases[0]); c++) {
    int bits = cases[c].bits, bytes = bits/8;
    uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
    for (unsigned offset = 0; offset < 8; offset++) {
      for (unsigned a = 0; a < 5; a++) for (unsigned b = 0; b < 5; b++) {
        _Alignas(64) uint8_t storage[64];
        memset(storage, 0x5a, sizeof(storage));
        uint64_t initial = values[a], value = values[b];
        memcpy(storage + offset + 1, &initial, bytes);
        uint64_t got = cases[c].fn(storage + offset, value), memory = 0;
        memcpy(&memory, storage + offset + 1, bytes);
        uint64_t want = initial & mask;
        if (bits < 32) want |= value & ~mask;
        if (got != want || memory != ((cases[c].add ? initial + value : value) & mask)) return 1;
        for (unsigned i = 0; i < sizeof(storage); i++) {
          if ((i < offset + 1 || i >= offset + 1 + bytes) && storage[i] != 0x5a) return 2;
        }
      }
    }
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "exchange_unaligned", triple, ir, mainC, runPrefix)
}
