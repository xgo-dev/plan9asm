package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestARM64RawWordsUseOfficialDecoderAndSemanticLowering(t *testing.T) {
	const source = `TEXT rawDecoded(SB), $0-0
	MOVD $9, R0
	MOVD $3, R16
	WORD $0x9ad00800 // UDIV R16, R0, R0
	WORD $0x2e211402 // VURHADD V1.B8, V0.B8, V2.B8
	WORD $0x4ee0f8e7 // VFABS V7.D2, V7.D2
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch:       "arm64",
				TargetTriple: triple,
				Sigs: map[string]FuncSig{
					"rawDecoded": {Name: "rawDecoded", Ret: Void},
				},
			})
			if err != nil {
				t.Fatalf("Translate() error = %v", err)
			}
			for _, want := range []string{"udiv i64", "lshr <8 x i16>", "@llvm.fabs.v2f64"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("decoded semantics omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-decoded.ll", "arm64-raw-decoded.o", ir)
		})
	}
}

func TestARM64RawPCRelativeInstructionFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		word uint32
	}{
		{name: "ADR without proven boundary", word: 0x100000a0},
		{name: "ADRP nonzero page delta", word: 0xb0000000},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT rawADR(SB), $0-0\n\tWORD $" + fmt.Sprintf("%#08x", test.word) + "\n\tRET\n"
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			_, err = Translate(file, Options{
				Goarch:       "arm64",
				TargetTriple: "aarch64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{
					"rawADR": {Name: "rawADR", Ret: Void},
				},
			})
			if err == nil || !strings.Contains(err.Error(), "PC-relative") {
				t.Fatalf("Translate() error = %v, want explicit PC-relative raw-instruction rejection", err)
			}
		})
	}
}

func TestARM64RawZeroPageADRPResolvesAtExactInstructionBoundary(t *testing.T) {
	const source = `TEXT rawADRPPage(SB), $0-8
	WORD $0x90000000 // ADRP current page, R0
	MOVD R0, ret+0(FP)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       "arm64",
				TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawADRPPage": {
					Name: "rawADRPPage", Ret: I64,
					Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "blockaddress(@rawADRPPage") || !strings.Contains(ir, "and i64") || !strings.Contains(ir, ", -4096") {
				t.Fatalf("zero-page ADRP semantics missing:\n%s", ir)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-zero-adrp.ll", "arm64-raw-zero-adrp.o", ir)
			if triple != "aarch64-apple-darwin" || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
				return
			}
			clang := findLLVM22Tool("clang")
			if clang == "" {
				t.Fatal("LLVM 22 clang not found")
			}
			const mainC = `
#include <stdint.h>
extern uintptr_t rawADRPPage(void);
int main(void) {
  uintptr_t got = rawADRPPage();
  uintptr_t want = ((uintptr_t)&rawADRPPage) & ~(uintptr_t)4095;
  return got == want ? 0 : 1;
}
`
			compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_zero_adrp", triple, ir, mainC, nil)
		})
	}
}

func TestARM64RawPCRelativeWordsResolveExactInstructionBoundaries(t *testing.T) {
	const source = `TEXT rawPCRelative(SB), $16-0
	WORD $0x100000a0 // ADR +20, R0; crosses the framed RET expansion
	MOVD R0, R1
	RET
target:
	WORD $0x14000002 // B +8
	WORD $0x91000400 // ADD $1, R0, R0
done:
	WORD $0xd65f03c0 // RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"rawPCRelative": {Name: "rawPCRelative", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	for _, want := range []string{
		"blockaddress(@rawPCRelative, %target)",
		"br label %done",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw PC-relative lowering omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-raw-pcrel.ll", "arm64-raw-pcrel.o", ir)
}

func TestARM64RawPCRelativeLayoutMatchesFramedEntryWrapper(t *testing.T) {
	const source = `TEXT rawEntry(SB), $16
	NO_LOCAL_POINTERS
	WORD $0x100000a0
	MOVD R0, ret(FP)
	RET
rawBody:
	WORD $0xd65f03c0
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(file.Funcs) != 1 {
		t.Fatalf("Parse() funcs = %d, want 1", len(file.Funcs))
	}
	if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err != nil {
		for i, ins := range file.Funcs[0].Instrs {
			t.Logf("instruction %d: op=%s args=%#v raw=%q", i, ins.Op, ins.Args, ins.Raw)
		}
		t.Fatalf("normalizeARM64RawPCRelative() error = %v", err)
	}
}

func TestARM64RawPCRelativeSeparatesEmbeddedCodeAndConstantPools(t *testing.T) {
	const source = `TEXT rawEmbedded(SB), $16-0
	WORD $0x100000a0 // ADR +20, R0: entry wrapper returns embedded code
	MOVD R0, R1
	RET
code:
	WORD $0x10000042 // ADR +8, R2: embedded code addresses its constant pool
	WORD $0xd65f03c0 // RET
data:
	WORD $0x04030201
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"rawEmbedded": {Name: "rawEmbedded", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	for _, want := range []string{
		`@rawEmbedded.data.raw_data = private constant [4 x i8] c"\01\02\03\04"`,
		"blockaddress(@rawEmbedded, %code)",
		"ptrtoint ptr @rawEmbedded.data.raw_data to i64",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("embedded raw-data lowering omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-raw-data.ll", "arm64-raw-data.o", ir)
}

func TestARM64RawPCRelativeCrossesCompleteFixedWidthJumpFamily(t *testing.T) {
	for _, jump := range []string{
		"B branchTarget",
		"JMP branchTarget",
		"JMP 1(PC)",
		"JMP (R11)",
		"BL branchTarget",
		"BL 1(PC)",
		"BL R3",
		"BL (R4)",
		"BL global(SB)",
		"CALL R5",
		"CALL (R6)",
		"CALL global(SB)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(jump), func(t *testing.T) {
			source := "TEXT rawJumpFamily(SB), $0-0\n\tWORD $0x1000005e // ADR +8, R30\n\t" + jump + "\n\tMOVD R0, R0\nbranchTarget:\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err != nil {
				t.Fatalf("fixed-width %q broke raw PC-relative layout: %v", jump, err)
			}
		})
	}
}

func TestARM64RawPCRelativeCrossesConditionalBranchFamily(t *testing.T) {
	for _, branch := range []string{
		"BCC", "BCS", "BEQ", "BGE", "BGT", "BHI", "BHS", "BLE",
		"BLO", "BLS", "BLT", "BMI", "BNE", "BPL", "BVC", "BVS",
	} {
		t.Run(branch, func(t *testing.T) {
			source := "TEXT rawConditionalBranch(SB), $0-0\n\tWORD $0x1000005e // ADR +8, R30\n\t" +
				branch + " branchTarget\n\tMOVD R0, R0\nbranchTarget:\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err != nil {
				t.Fatalf("fixed-width %s broke raw PC-relative layout: %v", branch, err)
			}
		})
	}
}

func requireARM64GoSingleWordLogicalSpan(t *testing.T, source string) {
	t.Helper()
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return
	}
	dir := t.TempDir()
	asm := filepath.Join(dir, "logical.s")
	obj := filepath.Join(dir, "logical.o")
	if err := os.WriteFile(asm, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	assemble := exec.Command("go", "tool", "asm", "-p", "example.com/forms", "-o", obj, asm)
	assemble.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	if out, err := assemble.CombinedOutput(); err != nil {
		t.Fatalf("Go 1.27 assembler rejected logical form: %v\n%s", err, out)
	}
	objdump := exec.Command("go", "tool", "objdump", "-s", "rawLogical", obj)
	objdump.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	out, err := objdump.CombinedOutput()
	if err != nil {
		t.Fatalf("Go object disassembly failed: %v\n%s", err, out)
	}
	pcByLine := make(map[int][]uint64)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "logical.s:") {
			continue
		}
		lineNumber, lineErr := strconv.Atoi(strings.TrimPrefix(fields[0], "logical.s:"))
		pc, pcErr := strconv.ParseUint(fields[1], 0, 64)
		if lineErr != nil || pcErr != nil {
			t.Fatalf("invalid Go object location %q", line)
		}
		pcByLine[lineNumber] = append(pcByLine[lineNumber], pc)
	}
	for _, line := range []int{2, 3, 4, 6} {
		if len(pcByLine[line]) != 1 {
			t.Fatalf("source line %d emitted %d instructions, want one:\n%s", line, len(pcByLine[line]), out)
		}
	}
	for _, pair := range [][2]int{{2, 3}, {3, 4}, {4, 6}} {
		if got := pcByLine[pair[1]][0] - pcByLine[pair[0]][0]; got != 4 {
			t.Fatalf("source lines %d-%d span %d bytes, want 4:\n%s", pair[0], pair[1], got, out)
		}
	}
}

func TestARM64RawPCRelativeCrossesLogicalImmediateFamily(t *testing.T) {
	for _, logical := range []string{
		"AND $0xffff000000000000, R1, R1",
		"ORR $0xffff000000000000, R1, R1",
		"EOR $0xffff000000000000, R1, R1",
		"ANDS $0xffff000000000000, R1, R1",
		"BIC $0xffff000000000000, R1, R1",
		"ORN $0xffff000000000000, R1, R1",
		"EON $0xffff000000000000, R1, R1",
		"BICS $0xffff000000000000, R1, R1",
		"TST $0xffff000000000000, R1",
		"ANDW $0xff000000, R1, R1",
		"ORRW $0xff000000, R1, R1",
		"EORW $0xff000000, R1, R1",
		"ANDSW $0xff000000, R1, R1",
		"BICW $0xff000000, R1, R1",
		"ORNW $0xff000000, R1, R1",
		"EONW $0xff000000, R1, R1",
		"BICSW $0xff000000, R1, R1",
		"TSTW $0xff000000, R1",
		"ORR $0xffff000000000000, R1",
		"AND $0xffff000000000000, R1, RSP",
	} {
		t.Run(strings.Fields(logical)[0], func(t *testing.T) {
			source := "TEXT rawLogical(SB), $0-0\n\tWORD $0x10000061 // ADR +12, R1\n\t" +
				logical + "\n\tJMP (R1)\ntarget:\n\tRET\n"
			requireARM64GoSingleWordLogicalSpan(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err != nil {
				t.Fatalf("logical immediate %q broke raw PC-relative layout: %v", logical, err)
			}
		})
	}
}

func TestARM64RawPCRelativeCrossesLogicalRegisterForms(t *testing.T) {
	for _, logical := range []string{
		"AND R2, R1, R1",
		"ORR R2<<3, R1, R1",
		"TST R2, R1",
		"EORW R2<<3, R1, R1",
		"AND R2, R1",
		"ORR R2<<3, R1",
	} {
		t.Run(strings.Fields(logical)[0], func(t *testing.T) {
			source := "TEXT rawLogical(SB), $0-0\n\tWORD $0x10000061 // ADR +12, R1\n\t" +
				logical + "\n\tJMP (R1)\ntarget:\n\tRET\n"
			requireARM64GoSingleWordLogicalSpan(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err != nil {
				t.Fatalf("logical register %q broke raw PC-relative layout: %v", logical, err)
			}
		})
	}
}

func TestARM64RawPCRelativeRejectsExpandingLogicalImmediate(t *testing.T) {
	const source = `TEXT rawLogicalExpanded(SB), $0-0
	WORD $0x10000061 // ADR +12, R1 does not reach the label after expansion.
	ORR $0x123456789abcdef, R1, R1
	JMP (R1)
target:
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err == nil ||
		!strings.Contains(err.Error(), "proven instruction boundary") {
		t.Fatalf("expanding logical immediate was accepted as a fixed-width span: %v", err)
	}
}

func TestARM64RawTrailingUnreferencedWordsBecomeDataAfterTerminator(t *testing.T) {
	const source = `TEXT rawTrailingData(SB), $0-0
	WORD $0xd65f03c0 // RET
mask:
	WORD $0x00000002
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"rawTrailingData": {Name: "rawTrailingData", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, `@rawTrailingData.mask.raw_data = private constant [4 x i8] c"\02\00\00\00"`) {
		t.Fatalf("trailing raw data was not separated from code:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-raw-trailing-data.ll", "arm64-raw-trailing-data.o", ir)
}

func TestARM64RawReachableInvalidWordDoesNotBecomeData(t *testing.T) {
	const source = `TEXT rawReachableInvalid(SB), $0-0
	WORD $0xd503201f // NOP falls through
reachable:
	WORD $0x00000002
	RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"rawReachableInvalid": {Name: "rawReachableInvalid", Ret: Void},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported ARM64 WORD encoding") {
		t.Fatalf("reachable invalid WORD error = %v, want fail-closed rejection", err)
	}
}
