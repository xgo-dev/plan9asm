package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func armWordFloatBoundaryAPI(t *testing.T, api, source, triple string) error {
	t.Helper()
	file, err := Parse(ArchARM, source)
	if err != nil {
		return err
	}
	options := Options{Goarch: "arm", TargetTriple: triple,
		Sigs: map[string]FuncSig{"conversion": {Name: "conversion", Ret: Void}},
	}
	switch api {
	case "text":
		_, err = Translate(file, options)
	case "module":
		context := llvm.NewContext()
		defer context.Dispose()
		module, moduleErr := TranslateModuleInContext(context, file, options)
		if !module.IsNil() {
			module.Dispose()
		}
		err = moduleErr
	case "Go":
		pkg := mustGoPackage(t, "example.com/conversion", "package conversion\nfunc conversion()\n")
		module, moduleErr := TranslateGoModule(pkg, []byte(strings.ReplaceAll(source, "TEXT conversion", "TEXT ·conversion")), GoModuleOptions{
			GOOS: "linux", GOARCH: "arm", TargetTriple: triple,
		})
		if module != nil {
			module.Module.Dispose()
		}
		err = moduleErr
	default:
		t.Fatal("unknown translation API")
	}
	return err
}

func TestARMWordFloatNativeTargetBoundary(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, body := range []string{"MOVFW F0,F1", "WORD $0xeefd0bc0"} {
			for _, triple := range []string{
				"", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "arm64-apple-darwin",
				"armeb-unknown-linux-gnueabi", "armv7eb-unknown-linux-gnueabi", "thumbeb-unknown-linux-gnueabi",
				"armanything-unknown-linux-gnu", "wasm32-unknown-unknown",
				"armv5te-unknown-linux-gnueabi", "armv6-unknown-linux-gnueabihf",
				"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc",
			} {
				t.Run(api+"/"+body+"/"+triple, func(t *testing.T) {
					source := "TEXT conversion(SB),4,$0-0\nMOVD $1.5,F0\n" + body + "\nRET\n"
					err := armWordFloatBoundaryAPI(t, api, source, triple)
					valid := triple == "armv5te-unknown-linux-gnueabi" || triple == "armv6-unknown-linux-gnueabihf" ||
						triple == "armv7-unknown-linux-gnueabihf" || triple == "thumbv7-pc-windows-msvc"
					if valid && err != nil || !valid && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("native=%v: %v", valid, err)
					}
				})
			}
		}
	}
}

func TestARMWordFloatNativeTargetDoesNotReclassifyInvalidSource(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, body := range []string{"MOVWF R0,R1", "MOVDW S0,F1", "MOVFW.P F0,F1", "WORD $0xffffffff"} {
			source := "TEXT conversion(SB),4,$0-0\n" + body + "\nRET\n"
			if err := armWordFloatBoundaryAPI(t, api, source, ""); err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s %s invalid source became native-target context: %v", api, body, err)
			}
		}
		if err := armWordFloatBoundaryAPI(t, api, "TEXT conversion(SB),4,$0-0\nRET\n", ""); err != nil {
			t.Fatalf("%s ordinary non-conversion behavior changed: %v", api, err)
		}
	}
}

func TestARMWordFloatRawDoubleWordCarriers(t *testing.T) {
	translateARMCompleteForms(t, `TEXT conversion(SB),4,$0-0
WORD $0xeefd0bc0 // VCVT.S32.F64 S1,D0
WORD $0xeeb80be0 // VCVT.F64.S32 D0,S1
WORD $0xeebc0bc0 // VCVT.U32.F64 S0,D0
WORD $0xeeb80b60 // VCVT.F64.U32 D0,S1
RET
`, map[string]FuncSig{"conversion": {Name: "conversion", Ret: Void}})
}

func TestARMWordFloatNativeTargetKeepsMixedRawErrors(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf"} {
			for _, body := range []string{
				"MOVFW F0,F1\nWORD $0xffffffff",
				"WORD $0xffffffff\nMOVFW F0,F1",
				"MOVFW F0,F1\nRET\nWORD $0xffffffff",
				"RET\nWORD $0xffffffff\nMOVFW F0,F1",
			} {
				t.Run(api+"/"+triple+"/"+body, func(t *testing.T) {
					source := "TEXT conversion(SB),4,$0-0\nMOVD $1.5,F0\n" + body + "\nRET\n"
					err := armWordFloatBoundaryAPI(t, api, source, triple)
					if err == nil || errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "WORD") {
						t.Fatalf("invalid original raw source was hidden by target/deadness: %v", err)
					}
				})
			}
		}
	}
}

func TestARMWordFloatNativeTargetPreservesSpecializedRawRegistry(t *testing.T) {
	variants := armRawStatusFamilies()
	variants = append(variants,
		armRawStatusCase{family: "VFPStatus", instruction: "vmrs r0,fpscr"},
		armRawStatusCase{family: "VFPCompare", instruction: "vcmp.f32 s0,s1"},
		armRawStatusCase{family: "Yield", instruction: "yield"},
		armRawStatusCase{family: "TSTCarry", instruction: "tst r0,#0x80000000"},
	)
	words := assembleARMRawStatusWords(t, variants)
	for index, word := range words {
		source := fmt.Sprintf("TEXT conversion(SB),4,$0-0\nWORD $%#x\nMOVFW F0,F1\nRET\n", word)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateARMWordFloatNativeTarget(file, Options{}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("registered raw %s became invalid source: %v", variants[index].family, err)
		}
		if err := validateARMWordFloatNativeTarget(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf"}); err != nil {
			t.Fatalf("registered raw %s rejected by native conversion preflight: %v", variants[index].family, err)
		}
	}
}
