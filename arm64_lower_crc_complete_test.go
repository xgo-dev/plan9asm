package plan9asm

import (
	"strings"
	"testing"
)

func arm64CRCCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT crcComplete(SB),$0-0\n")
	for _, op := range []string{"CRC32B", "CRC32H", "CRC32W", "CRC32X", "CRC32CB", "CRC32CH", "CRC32CW", "CRC32CX"} {
		source.WriteString("\t" + op + " R1, R2\n")
		source.WriteString("\t" + op + " R3, R4, R5\n")
		source.WriteString("\t" + op + " ZR, R6, R7\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64CRCCompleteFormats(t *testing.T) {
	source := arm64CRCCompleteForms()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"crcComplete": {Name: "crcComplete", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, intrinsic := range []string{
		"llvm.aarch64.crc32b", "llvm.aarch64.crc32h", "llvm.aarch64.crc32w", "llvm.aarch64.crc32x",
		"llvm.aarch64.crc32cb", "llvm.aarch64.crc32ch", "llvm.aarch64.crc32cw", "llvm.aarch64.crc32cx",
	} {
		if !strings.Contains(ll, intrinsic) {
			t.Fatalf("ARM64 CRC lowering omitted %q:\n%s", intrinsic, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-crc-complete.ll", "arm64-crc-complete.o", ll)
}

func TestTranslateARM64CRCRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"CRC32B R0",
		"CRC32H R0, R1, R2, R3",
		"CRC32W (R0), R1",
		"CRC32X R0, RSP, R2",
		"CRC32CB R0<<1, R1, R2",
		"CRC32CH R0, R1, RSP",
		"CRC32CW.P R0, R1",
		"CRC32CX $0, R1, R2",
	} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: arm64LinuxGNUTriple,
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 CRC optab", instruction)
		}
	}
}
