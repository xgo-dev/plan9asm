package plan9asm

import (
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86PackedShiftActualGoBytes(t *testing.T, arch, source string) []byte {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "original.s")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-o", filepath.Join(dir, "original.o"), input)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("actual Go %s original source: %v\n%s", arch, err, output)
	}
	var code []byte
	for _, line := range regexp.MustCompile(`(?m)^\s*0x[[:xdigit:]]+\s+((?:[[:xdigit:]]{2} )+)`).FindAllSubmatch(output, -1) {
		part, err := hex.DecodeString(strings.ReplaceAll(string(line[1]), " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		code = append(code, part...)
	}
	return code
}

func TestX86PackedShiftMode32NamedPhysicalBanks(t *testing.T) {
	for _, row := range []string{
		"VPSRLW $1,X20,X21", "VPSRLD X0,Y20,Y21", "VPSRLQ (AX),X20,X21",
		"VPSRLVW X1,X20,X21", "VPSRLVD.BCST (AX),Y20,Y21", "VPSRLVQ X0,X20,X21",
		"VPSLLDQ $1,X16,X31", "VPSRLDQ $1,Y20,Y21",
	} {
		source := "TEXT shifts(SB),4,$0-0\n" + row + "\nRET\n"
		code := x86PackedShiftActualGoBytes(t, "386", source)
		_, _, recognized, err := decodedX86PackedUniformShiftInstruction(code, 32)
		if !recognized {
			_, _, recognized, err = decodedX86PerLaneVariableShiftInstruction(code, 32)
		}
		if !recognized {
			_, _, recognized, err = decodedX86RawVectorByteShiftInstruction(code, 32)
		}
		if !recognized || err == nil {
			t.Fatalf("mode32 raw bytes %x for %s did not reject unavailable physical bank: %v", code, row, err)
		}
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
			options := Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]FuncSig{"shifts": {Ret: Void}}}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s named unavailable SIMD bank %s: %v", triple, row, err)
			}
			context := llvm.NewContext()
			func() {
				defer context.Dispose()
				module, err := TranslateModuleInContext(context, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s module unavailable SIMD bank %s: %v", triple, row, err)
				}
				result, err := translateGoModuleInContext(context, x86PackedShiftGoPackage(t, "386"),
					[]byte(strings.Replace(source, "shifts(SB)", "·shifts(SB)", 1)), GoModuleOptions{GOARCH: "386", TargetTriple: triple})
				if result != nil && !result.Module.IsNil() {
					defer result.Module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s Go module unavailable SIMD bank %s: %v", triple, row, err)
				}
			}()
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			ctx.goarch = "386"
			before := output.Len()
			ins := file.Funcs[0].Instrs[1]
			if _, _, err := ctx.lowerX86PackedShift(ins.Op, ins); !errors.Is(err, ErrProbeNeedsContext) || output.Len() != before {
				t.Fatalf("unavailable mode32 SIMD bank emitted IR: %s %v", row, err)
			}
		}
	}
}
