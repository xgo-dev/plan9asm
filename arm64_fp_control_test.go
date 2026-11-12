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

func arm64FPControlTargetAPI(t *testing.T, api, source, triple string) (bool, error) {
	t.Helper()
	if api != "public-module" {
		return arm64CompareTargetAPI(t, api, source, triple)
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return false, err
	}
	module, err := TranslateModule(file, Options{
		Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"comparison": {Name: "comparison", Ret: Void}},
	})
	present := !module.IsNil()
	if present {
		module.Dispose()
	}
	return present, err
}

func TestARM64FPControlCompleteGoForms(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		// The older optab lacks the extra no-operand column. Every actual
		// operand/encoding/size/attribute remains pinned in either layout.
		`\{AMRS,\s*C_SPR,\s*C_NONE,\s*C_NONE,\s*C_ZREG,\s*(?:C_NONE,\s*)?35,\s*4,\s*0,\s*0,\s*0\}`,
		`\{AMSR,\s*C_ZREG,\s*C_NONE,\s*C_NONE,\s*C_SPR,\s*(?:C_NONE,\s*)?36,\s*4,\s*0,\s*0,\s*0\}`,
	} {
		if !regexp.MustCompile(row).Match(contents) {
			t.Fatalf("actual Go MRS/MSR register encoder row changed: %s", row)
		}
	}
	var original strings.Builder
	original.WriteString("TEXT controlFormats(SB),4,$0-0\n")
	count := 0
	for _, register := range []struct {
		name     string
		encoding uint16
	}{{"FPCR", 0x5a20}, {"FPSR", 0x5a21}} {
		spec, ok := arm64GoSystemRegisters[register.name]
		if !ok || spec.encoding != register.encoding || !spec.readable || !spec.writable {
			t.Fatalf("Go system-register role changed for %s", register.name)
		}
		for bank := 0; bank < 32; bank++ {
			name := fmt.Sprintf("R%d", bank)
			if bank == 18 {
				name = "R18_PLATFORM"
			} else if bank == 28 {
				name = "g"
			} else if bank == 31 {
				name = "ZR"
			}
			for _, read := range []bool{true, false} {
				instruction := fmt.Sprintf("MSR %s,%s", name, register.name)
				word := uint32(0xd5100000) | uint32(register.encoding)<<5 | uint32(bank)
				if read {
					instruction = fmt.Sprintf("MRS %s,%s", register.name, name)
					word |= 1 << 21
				}
				file, err := Parse(ArchARM64, "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				form, matched, err := parseARM64FPControl(arm64ControlOp(ins), ins)
				if !matched || err != nil {
					t.Fatalf("named grammar %s: %t %v", instruction, matched, err)
				}
				raw, matched := decodeARM64RawSystemRegister(word)
				decoded, control := arm64RawFPControl(raw)
				if !matched || !control || form != decoded {
					t.Fatalf("named/raw role disagreement for %s / %#08x", instruction, word)
				}
				fmt.Fprintf(&original, "%s\nWORD $%#08x\n", instruction, word)
				count++
			}
		}
		fmt.Fprintf(&original, "MSR $0,%s\n", register.name)
	}
	original.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, original.String(), true)
	if count != 128 {
		t.Fatal("incomplete two-register/two-direction/full-GP grammar", count)
	}
}

func TestARM64FPControlNativeObjectsAllAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, declarations, _, _ := arm64FPControlFlagFixture()
	for _, triple := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc",
	} {
		for api, ir := range arm64FPControlIRs(t, source, declarations, triple) {
			t.Run(fmt.Sprintf("%s/api%d", triple, api), func(t *testing.T) {
				compileLLVMToObject(t, llc, triple, "control.ll", "control.o", ir)
			})
		}
	}
}

func TestARM64FPControlNativeTargetAndSourceErrors(t *testing.T) {
	valid := []string{
		"MRS FPCR,R0", "MRS FPSR,ZR", "MSR R0,FPCR", "MSR ZR,FPSR", "MSR $0,FPCR",
		"WORD $0xd53b4400", "WORD $0xd53b443f", "WORD $0xd51b4400", "WORD $0xd51b443f",
	}
	invalid := []string{
		"MRS FPCR", "MRS FPCR,R0,R1", "MRS FPCR,F0", "MRS FPCR,RSP", "MRS FPCR,$0",
		"MRS.P FPSR,R0", "MSR.P R0,FPCR", "MSR FPCR,R0", "MSR F0,FPSR",
		"MSR RSP,FPCR", "MSR $1,FPCR", "MSR $-1,FPSR", "MSR $(0.0),FPCR",
		"MRS fpcr,R0", "MSR R0,fpsr", "MRS S3_3_C4_C4_0,R0", "MSR R0,S3_3_C4_C4_1",
	}
	for _, instruction := range invalid {
		requireARM64GoAssemblerResult(t, "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n", false)
	}
	for _, api := range []string{"text", "module", "Go", "public-module"} {
		for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown", "aarch64_be-unknown-linux-gnu"} {
			for _, instruction := range valid {
				for _, prefix := range []string{"", "RET\n"} {
					source := "TEXT comparison(SB),4,$0-0\n" + prefix + instruction + "\nRET\n"
					present, err := arm64FPControlTargetAPI(t, api, source, triple)
					if present || !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s %q unbound native %s accepted: %t %v", api, triple, instruction, present, err)
					}
				}
			}
			for _, instruction := range invalid {
				source := "TEXT comparison(SB),4,$0-0\nMRS FPCR,R0\nRET\n" + instruction + "\nRET\n"
				present, err := arm64FPControlTargetAPI(t, api, source, triple)
				if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s malformed %s erased by native context: %t %v", api, instruction, present, err)
				}
			}
		}
	}
}

func TestARM64FPControlRetainsTypedEntryBoundaries(t *testing.T) {
	for _, body := range []string{
		"MSR R9,FPCR", // No source-defined numerical input.
		"MSR R9,FPSR",
		"MRS FPCR,R18_PLATFORM", "MRS FPSR,g", "MRS FPCR,R30",
		"MRS FPSR,R0\nCSET EQ,R0", // A status read does not define NZCV.
		"CMP R0,R0\nMRS TPIDR_EL0,R1\nCSET EQ,R0",
		"CMP R0,R0\nMSR R0,TPIDR_EL0\nCSET EQ,R0",
	} {
		file, err := Parse(ArchARM64, arm64TypedNativeSource(body))
		if err != nil {
			t.Fatal(err)
		}
		if ir, err := Translate(file, arm64TypedNativeOptions(t, "aarch64-unknown-linux-gnu")); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("unproved source gained a machine role: %s: %v", body, err)
		}
	}
	for _, body := range []string{
		"CMP R0,R0\nMRS FPCR,R1\nCSET EQ,R0",
		"CMP R0,R0\nMRS FPSR,R1\nCSET EQ,R0",
		"CMP R0,R0\nMSR R0,FPCR\nCSET EQ,R0",
		"CMP R0,R0\nMSR $0,FPSR\nCSET EQ,R0",
	} {
		file, err := Parse(ArchARM64, arm64TypedNativeSource(body))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, arm64TypedNativeOptions(t, "aarch64-unknown-linux-gnu")); err != nil {
			t.Errorf("exact source-defined FP control lost its flags: %s: %v", body, err)
		}
	}
}

func TestARM64FPControlMalformedWordBeforeTargetContext(t *testing.T) {
	for _, bad := range []string{"WORD $0xffffffff", "WORD $(0.0)", "WORD R0", "WORD $0,$1"} {
		for _, body := range []string{
			bad + "\nMRS FPCR,R0", "MRS FPCR,R0\n" + bad,
			"MRS FPSR,R0\nRET\n" + bad,
		} {
			for _, api := range []string{"text", "module", "Go", "public-module"} {
				for _, target := range []string{"", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
					source := "TEXT comparison(SB),4,$0-0\n" + body + "\nRET\n"
					present, err := arm64FPControlTargetAPI(t, api, source, target)
					if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s %s malformed WORD hidden by native context: %s: %t %v", api, target, body, present, err)
					}
				}
			}
		}
	}
}
