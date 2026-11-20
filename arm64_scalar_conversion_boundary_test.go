package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64ScalarConversionAPI(t *testing.T, api, source, triple string) (string, error) {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"conversion": {Name: "conversion", Ret: Void}},
	}
	if api == "text" {
		return Translate(file, options)
	}
	if api == "module" {
		context := llvm.NewContext()
		defer context.Dispose()
		module, err := TranslateModuleInContext(context, file, options)
		if err != nil {
			return "", err
		}
		defer module.Dispose()
		return module.String(), nil
	}
	pkg := mustGoPackage(t, "example.com/conversion", "package conversion\nfunc conversion()\n")
	result, err := TranslateGoModule(pkg, []byte(strings.ReplaceAll(source, "TEXT conversion", "TEXT ·conversion")), GoModuleOptions{
		GOOS: "linux", GOARCH: "arm64", TargetTriple: triple,
	})
	if result != nil {
		defer result.Module.Dispose()
		return result.Module.String(), err
	}
	return "", err
}

func arm64ScalarConversionInstruction(fixture arm64ScalarConversionFixture) string {
	if fixture.word != 0 {
		word := fixture.word
		if fixture.zero && !fixture.simd {
			if fixture.toFloat {
				word = word&^uint32(31<<5) | 31<<5
			} else {
				word |= 31
			}
		}
		return fmt.Sprintf("WORD $%#08x", word)
	}
	gp := "R2"
	if fixture.toFloat {
		if fixture.zero {
			gp = "ZR"
		}
		return fixture.name + " " + gp + ",F23"
	}
	if fixture.zero {
		return fixture.name + " F6,ZR"
	}
	return fixture.name + " F6,R3"
}

func TestARM64ScalarConversionThreeAPIObjectsAndTargetBoundary(t *testing.T) {
	var body strings.Builder
	for _, fixture := range arm64ScalarConversionFixtures() {
		body.WriteString(arm64ScalarConversionInstruction(fixture) + "\n")
	}
	source := "TEXT conversion(SB),4,$0-0\n" + body.String() + "RET\n"
	requireARM64GoAssemblerResult(t, source, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, api := range []string{"text", "module", "Go"} {
		for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
			t.Run(api+"/"+triple, func(t *testing.T) {
				ir, err := arm64ScalarConversionAPI(t, api, source, triple)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "scalar-conversion.ll", "scalar-conversion.o", ir)
			})
		}
		for _, triple := range []string{"", "armv7-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "aarch64_be-unknown-linux-gnu", "arm64_32-apple-watchos", "arm64e-apple-darwin", "wasm32-unknown-unknown"} {
			if _, err := arm64ScalarConversionAPI(t, api, source, triple); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s %q lost native target boundary: %v", api, triple, err)
			}
			for _, body := range []string{
				"FCVTZSS F0,R0\nWORD $0xffffffff", "WORD $0xffffffff\nFCVTZSS F0,R0",
				"RET\nFCVTZSS F0,R0\nWORD $0xffffffff", "RET\nWORD $0xffffffff\nFCVTZSS F0,R0",
				"SCVTFD R0,F0\nSCVTFWS.P R0,F1", "RET\nSCVTFS RSP,F0",
			} {
				bad := "TEXT conversion(SB),4,$0-0\n" + body + "\nRET\n"
				if _, err := arm64ScalarConversionAPI(t, api, bad, triple); err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s %q invalid/dead form hidden by native target: %v", api, body, err)
				}
			}
		}
	}
}

func TestARM64ScalarConversionDoesNotDefineUnknownMergedLanes(t *testing.T) {
	for _, instruction := range []string{"SCVTFD R0,F21", "SCVTFWS R0,F21", "WORD $0x5ee1b815"} {
		for _, initialize := range []bool{false, true} {
			body := "FMOVD R0,F0\n"
			if initialize {
				body += "VMOV R0,V21.D[1]\n"
			}
			body += instruction + "\nVMOV V21.D[1],R0\nRET\n"
			arm64ImmediateOriginalGoBytes(t, "TEXT original(SB),4,$0-0\n"+body, "linux")
			pkg := mustGoPackage(t, "example.com/merge", "package merge\nfunc Pass(uint64) uint64\n")
			result, err := TranslateGoModule(pkg, []byte("TEXT ·Pass<ABIInternal>(SB),4,$0-16\n"+body), GoModuleOptions{
				GOOS: "linux", GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
			})
			if result != nil {
				result.Module.Dispose()
			}
			if initialize && err != nil || !initialize && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s initialized=%v: %v", instruction, initialize, err)
			}
			if !initialize && !strings.Contains(err.Error(), "read") {
				t.Fatalf("missing high-lane proof failed for unrelated reason: %v", err)
			}
		}
	}
}

func TestARM64ScalarConversionDecoderSpellingsAreNotGoSource(t *testing.T) {
	for _, name := range []string{"SCVTFDD", "SCVTFSS", "UCVTFDD", "UCVTFSS"} {
		source := "TEXT conversion(SB),4,$0-0\n" + name + " F0,F1\nRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		for _, api := range []string{"text", "module", "Go"} {
			if _, err := arm64ScalarConversionAPI(t, api, source, "aarch64-unknown-linux-gnu"); err == nil {
				t.Errorf("%s accepted decoder-only %s as public Go source", api, name)
			}
		}
	}
}

func TestARM64ScalarConversionTargetPreflightPreservesRegisteredRawFamilies(t *testing.T) {
	lines := []string{
		"mul z0.b, z1.b, z2.b", "tbl z0.b, {z1.b}, z2.b",
		"umullb z0.h, z1.b, z2.b", "umlalb z0.h, z1.b, z2.b",
		"fmaxnmv h0, p0, z1.h",
	}
	for index, word := range assembleARM64LLVMWords(t, lines, "+sve2,+fullfp16") {
		if _, registered := arm64RawSVEEffects(word); !registered {
			t.Fatalf("fixture %s has no existing registered grammar", lines[index])
		}
		source := fmt.Sprintf("TEXT conversion(SB),4,$0-0\nSCVTFD R0,F0\nWORD $%#08x\nRET\n", word)
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateARM64ScalarConversionNativeTarget(file, Options{TargetTriple: "aarch64-unknown-linux-gnu"}); err != nil {
			t.Errorf("native scalar preflight rejected existing %s: %v", lines[index], err)
		}
		if err := validateARM64ScalarConversionNativeTarget(file, Options{}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("existing %s obscured missing native target: %v", lines[index], err)
		}
	}
}
