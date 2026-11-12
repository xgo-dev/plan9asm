package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RegisterAddressClobberedLinkNeedsContext(t *testing.T) {
	const source = "TEXT addressLink(SB),516,$0-0\nMOVD R30,R27\nMOVD $-4097(R2),R3\nRET R27\n"
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
		"addressLink": {Name: "addressLink", Ret: Void},
	}})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("R27 literal materialization cannot retain a saved caller-link proof: %v", err)
	}
}

func TestARM64RegisterAddressGrammarMatchesGoEncoder(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Older Go tables have no trailing To3 operand class. In both layouts
	// the same three address classes select encoder types 4 and 34.
	rows := regexp.MustCompile(`\{AMOVD, C_(AACON2?|LACON), C_NONE, C_NONE, C_RSP, (?:C_NONE, )?(\d+),`).FindAllStringSubmatch(string(source), -1)
	want := map[string]string{"AACON": "4", "AACON2": "4", "LACON": "34"}
	if len(rows) != len(want) {
		t.Fatalf("Go register-address family has %d rows, want %d", len(rows), len(want))
	}
	for _, row := range rows {
		if want[row[1]] != row[2] {
			t.Fatalf("unexpected Go register-address row: %s", row[0])
		}
		delete(want, row[1])
	}
	if len(want) != 0 {
		t.Fatalf("missing Go register-address classes: %v", want)
	}
}

func TestARM64RegisterAddressClassBoundaries(t *testing.T) {
	for _, item := range []struct {
		offset  int64
		scratch bool
	}{
		{0, false}, {4095, false}, {-4095, false}, {4096, false}, {-4096, false},
		{4097, false}, {-4097, true}, {0xfff000, false}, {-0xfff000, false},
		{0xffffff, false}, {-0xffffff, true}, {1 << 24, true}, {-1 << 24, true},
		{1<<63 - 1, true}, {-1 << 63, true},
	} {
		if got := arm64AddressUsesScratch(item.offset); got != item.scratch {
			t.Errorf("offset %d scratch=%v, want %v", item.offset, got, item.scratch)
		}
	}
}

// asm7's C_AACON, C_AACON2 and C_LACON MOVD rows share address arithmetic,
// not symbol loads. Row 34 additionally materializes its offset into R27.
func TestARM64RegisterAddressCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT addressForms(SB),516,$0-0\nMOVD RSP,R20\n")
	for _, offset := range []int64{-65537, -65536, -4097, -4096, -1, 0, 1, 4095, 4096, 4097, 5900, 65536, 65537} {
		for _, base := range []string{"R0", "R2", "R27", "RSP", "LR", "g", "R18_PLATFORM"} {
			for _, destination := range []string{"R2", "R27", "RSP"} {
				fmt.Fprintf(&source, "MOVD $%d(%s),%s\nMOVD R20,RSP\n", offset, base, destination)
			}
		}
	}
	source.WriteString("B (ZR)\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
			Sigs: map[string]FuncSig{"addressForms": {Name: "addressForms", Ret: Void}},
		})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "register-address.ll", "register-address.o", ir)
	}
}

func TestARM64RegisterAddressZeroBaseConstantGoForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT zeroAddress(SB),516,$0-0\n")
	for _, offset := range []int64{-1 << 63, -65537, -4097, -1, 0, 1, 4097, 65537, 1 << 24, 1<<63 - 1} {
		for _, destination := range []string{"R2", "R27", "ZR"} {
			fmt.Fprintf(&source, "MOVD $%d(ZR),%s\n", offset, destination)
		}
	}
	source.WriteString("B (ZR)\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm64", Sigs: map[string]FuncSig{
		"zeroAddress": {Name: "zeroAddress", Ret: Void},
	}}
	if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "native inline assembly") {
		t.Fatal("native zero-base branch escaped its explicit target requirement", ir != "", err)
	}
	options.TargetTriple = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "zero-address.ll", "zero-address.o", ir)
}

func TestARM64RegisterAddressPreservesLargeScratch(t *testing.T) {
	for _, offset := range []int64{-65537, -4097, 1 << 24} {
		source := fmt.Sprintf("TEXT addressScratch(SB),516,$0-8\nMOVD $73,R27\nMOVD $%d(R27),R2\nMOVD R27,result+0(FP)\nRET\n", offset)
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
			"addressScratch": {Name: "addressScratch", Ret: I64,
				Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ir, fmt.Sprintf("store i64 %d, ptr %%reg_R27", offset)) {
			t.Fatal("large address must preserve Go's R27 literal materialization before reading an R27 base")
		}
	}
}

func TestARM64RegisterAddressRejectsGoInvalidForms(t *testing.T) {
	for _, instruction := range []string{
		"MOVD $8(R2),ZR", "MOVD $8(R2),F0", "MOVD $8(R2),(R3)",
		"MOVW $8(R2),R3", "MOVWU $8(R2),R3", "MOVB $8(R2),R3",
		"MOVD.P $8(R2),R3", "MOVD.W $8(R2),R3", "MOVD $8(R31),R3",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT badAddress(SB),516,$0-0\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"badAddress": {Name: "badAddress", Ret: Void},
			}}); err == nil {
				t.Fatal("Go-rejected address form was accepted")
			}
		})
	}
}
