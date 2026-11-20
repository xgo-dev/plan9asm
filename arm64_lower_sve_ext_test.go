package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEEXTCompleteGo127Family(t *testing.T) {
	source := "TEXT sveextforms(SB),$0-0\n" +
		"\tZEXT $0, Z2.B, Z1.B, Z1.B\n" +
		"\tZEXT $255, Z4.B, Z3.B, Z3.B\n" +
		"\tZEXT $6, [Z5.B, Z6.B], Z7.B\n" +
		"\tZEXT $255, [Z30.B, Z31.B], Z8.B\n" +
		"\tRET\n"
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveextforms": {Name: "sveextforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.ext.nxv16i8",
				"i32 0)",
				"i32 255)",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE EXT lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-ext.ll", "arm64-sve-ext.o", ll)
		})
	}
}

func TestTranslateARM64SVEEXTRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZEXT $-1, Z1.B, Z0.B, Z0.B",
		"ZEXT $256, Z1.B, Z0.B, Z0.B",
		"ZEXT $1, Z1.B, Z0.B, Z2.B",
		"ZEXT $1, Z1.H, Z0.H, Z0.H",
		"ZEXT $1, [Z1.B], Z0.B",
		"ZEXT $1, [Z1.B, Z3.B], Z0.B",
		"ZEXT $1, [Z31.B, Z0.B], Z0.B",
		"ZEXT.Z $1, Z1.B, Z0.B, Z0.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveext(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveext": {Name: "badsveext", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE EXT forms", instruction)
			}
		})
	}
}

func TestTranslateARM64SVEEXTQCompleteGo127Family(t *testing.T) {
	source := "TEXT sveextqforms(SB),$0-0\n" +
		"\tZEXTQ $0, Z2.B, Z1.B, Z1.B\n" +
		"\tZEXTQ $15, Z4.B, Z3.B, Z3.B\n" +
		"\tRET\n"
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveextqforms": {Name: "sveextqforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve,+sve2p1\"",
				"@llvm.aarch64.sve.extq.nxv16i8",
				"i32 0)",
				"i32 15)",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE EXTQ lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-extq.ll", "arm64-sve-extq.o", ll)
		})
	}
}

func TestTranslateARM64SVEEXTQRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZEXTQ $-1, Z1.B, Z0.B, Z0.B",
		"ZEXTQ $16, Z1.B, Z0.B, Z0.B",
		"ZEXTQ $1, Z1.B, Z0.B, Z2.B",
		"ZEXTQ $1, Z1.H, Z0.H, Z0.H",
		"ZEXTQ $1, [Z1.B, Z2.B], Z0.B",
		"ZEXTQ.Z $1, Z1.B, Z0.B, Z0.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveextq(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveextq": {Name: "badsveextq", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE EXTQ forms", instruction)
			}
		})
	}
}
