package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
)

func TestNativeAMD64BoundMachineSymbolsAndCallTable(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, width := range []string{"W", "L", "Q"} {
			t.Run(goos+"/address_"+width, func(t *testing.T) {
				source := fmt.Sprintf("#include \"textflag.h\"\nTEXT address<>(SB),NOSPLIT|NOFRAME,$0-0\nMOV%s $·word(SB),AX\nRET\nGLOBL ·word(SB),NOPTR,$8\nDATA ·word(SB)/8,$7\n", width)
				listing := nativeAMD64OriginalObject(t, goos, source)
				ir := nativeAMD64PhysicalObjects(t, source, NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe"})
				nativeAMD64CompareFrameMachineCode(t, goos, listing, ir)
			})
		}
		t.Run(goos+"/external_data", func(t *testing.T) {
			const source = "#include \"textflag.h\"\nTEXT load<>(SB),NOSPLIT|NOFRAME,$0-0\nMOVQ ·descriptor(SB),DI\nMOVQ (DI),DI\nRET\n"
			nativeAMD64OriginalObject(t, goos, source)
			opts := NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe",
				Imports: map[string]string{"·descriptor": "example.com/owner.descriptor"}}
			ir := nativeAMD64PhysicalObjects(t, source, opts)
			if !strings.Contains(ir, `@"example.com/owner.descriptor" = external global i8`) {
				t.Fatal("external data identity was not an address reference", ir)
			}
		})
		t.Run(goos+"/call_table", func(t *testing.T) {
			const source = "#include \"textflag.h\"\nTEXT table<>(SB),NOSPLIT|NOFRAME,$0-0\nCALL target(SB)\nCALL target(SB)\nCALL target(SB)\n"
			listing := nativeAMD64OriginalObject(t, goos, source)
			if strings.Count(listing, "\tCALL\t") != 3 {
				t.Fatal("original Go call table changed", listing)
			}
			ir := nativeAMD64PhysicalObjects(t, source, NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe",
				Imports: map[string]string{"target": "machine_target"}})
			for _, level := range []string{"-O0", "-O2"} {
				code := nativeAMD64ObjectCode(t, goos, ir, level)
				if len(code) < 17 || code[0] != 0xe8 || code[5] != 0xe8 || code[10] != 0xe8 || code[15] != 0x0f || code[16] != 0x0b {
					t.Fatalf("CALL slots or explicit fallthrough boundary changed: %x", code)
				}
			}
		})
	}
	for _, row := range []struct {
		body, symbol, object string
	}{
		{"CALL ·descriptor(SB)", "·descriptor", "owner.descriptor"},
		{"JMP ·descriptor(SB)", "·descriptor", "owner.descriptor"},
		{"MOVQ ·missing(SB),AX", "·descriptor", "owner.descriptor"},
		{"MOVQ ·descriptor(SB),AX", "·descriptor+8", "owner.descriptor"},
		{"MOVQ ·descriptor(SB),AX", "·descriptor", "unsafe\n.globl injected"},
	} {
		t.Run(row.body+"/"+row.symbol+"/"+row.object, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			mod, err := TranslateNativeModule(ctx, []byte("#include \"textflag.h\"\nTEXT load<>(SB),NOSPLIT|NOFRAME,$0-0\n"+row.body+"\nRET\n"),
				NativeOptions{GOOS: "linux", GOARCH: "amd64", PackagePath: "probe", Imports: map[string]string{row.symbol: row.object}})
			if err == nil {
				mod.Dispose()
				t.Fatal("external data acquired a callable or mismatched symbol role")
			}
		})
	}
}
