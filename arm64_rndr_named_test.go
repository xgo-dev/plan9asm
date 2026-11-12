package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestARM64RNDRNamedAndRawStatusAgreement(t *testing.T) {
	for _, operation := range []struct {
		name string
		word uint32
	}{{"RNDR", 0xd53b2400}, {"RNDRRS", 0xd53b2420}} {
		for _, instruction := range []string{
			"MRS " + operation.name + ",R0",
			"MOVD " + operation.name + ",R0",
			fmt.Sprintf("WORD $%#08x", operation.word),
		} {
			source := "TEXT comparison(SB),516,$0-0\n" + instruction + "\nCSET EQ,R0\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			for _, api := range []string{"text", "module", "public-module", "Go"} {
				t.Run(api+"/"+instruction, func(t *testing.T) {
					present, err := arm64FPControlTargetAPI(t, api, source, "aarch64-unknown-linux-gnu")
					if !present || err != nil {
						t.Fatalf("original-Go RNG defines all NZCV bits for every spelling: output=%t err=%v", present, err)
					}
				})
			}
		}
	}
}

func TestARM64RNDRCompleteGoGrammarAndBytes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"MRS", "MOVD"} {
		row := `\{A` + operation + `,\s*C_SPR,\s*C_NONE,\s*C_NONE,\s*C_ZREG,\s*(?:C_NONE,\s*)?35,\s*4,\s*0,\s*0,\s*0\}`
		if !regexp.MustCompile(row).Match(data) {
			t.Fatalf("complete Go RNG read row changed: %s", row)
		}
	}
	var source strings.Builder
	source.WriteString("TEXT original(SB),516,$0-0\n")
	var words []uint32
	for index, name := range []string{"RNDR", "RNDRRS"} {
		spec, present := arm64GoSystemRegisters[name]
		if !present || !spec.readable || spec.writable || spec.encoding != uint16(0x5920+index) {
			t.Fatalf("Go RNG encoding/read-only role changed: %s %+v", name, spec)
		}
		for _, operation := range []string{"MRS", "MOVD"} {
			for bank := 0; bank < 32; bank++ {
				register := fmt.Sprintf("R%d", bank)
				switch bank {
				case 18:
					register = "R18_PLATFORM"
				case 28:
					register = "g"
				case 31:
					register = "ZR"
				}
				line := operation + " " + name + "," + register
				instruction := arm64ImmediateTestInstruction(t, line)
				form, matched, err := parseARM64RNDR(instruction)
				if !matched || err != nil || form.reg != bank || form.reseed != (index == 1) {
					t.Fatalf("named grammar %s: %+v %t %v", line, form, matched, err)
				}
				word := uint32(0xd53b2400 + index*32 + bank)
				raw, matched := decodeARM64RawRNDR(word)
				if !matched || form != raw {
					t.Fatalf("named/raw grammar mismatch %s / %#08x", line, word)
				}
				if features := inferFuncTargetFeaturesForGOARCH(ArchARM64, "arm64", Func{Instrs: []Instr{instruction}}); features != "+rand" {
					t.Fatalf("exact RNG feature inference %s: %q", line, features)
				}
				source.WriteString(line + "\n")
				words = append(words, word)
			}
		}
	}
	source.WriteString("RET\n")
	actual := arm64ImmediateOriginalGoBytes(t, source.String(), "linux")
	if len(words) != 128 || len(actual) < 4*len(words) {
		t.Fatal("incomplete Go RNG bank/spelling family", len(words), len(actual))
	}
	for index, word := range words {
		if got := binary.LittleEndian.Uint32(actual[4*index:]); got != word {
			t.Fatalf("actual Go word %d got %#08x want %#08x", index, got, word)
		}
	}
}

func TestARM64RNDRSourceErrorsBeforeTargetContext(t *testing.T) {
	invalid := []string{
		"MRS RNDR", "MRS RNDR,R0,R1", "MRS RNDR,F0", "MRS RNDR,RSP",
		"MRS RNDR,(R0)", "MRS RNDR,$0", "MRS.P RNDR,R0", "MRS rndr,R0",
		"MRS S3_3_C2_C4_0,R0", "MSR R0,RNDR", "MSR $0,RNDRRS",
		"MOVD R0,RNDR", "MOVD RNDRRS,F0", "MOVD RNDRRS,(R0)",
	}
	for _, line := range invalid {
		requireARM64GoAssemblerResult(t, "TEXT invalid(SB),516,$0-0\n"+line+"\nRET\n", false)
	}
	for _, api := range []string{"text", "module", "public-module", "Go"} {
		for _, target := range []string{"", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown", "aarch64_be-unknown-linux-gnu"} {
			for _, line := range []string{"MRS RNDR,R0", "MOVD RNDRRS,ZR", "WORD $0xd53b2420"} {
				for _, prefix := range []string{"", "RET\n"} {
					present, err := arm64FPControlTargetAPI(t, api, "TEXT comparison(SB),516,$0-0\n"+prefix+line+"\nRET\n", target)
					if present || !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("unbound native RNG: %s %s %s output=%t err=%v", api, target, line, present, err)
					}
				}
			}
			for _, line := range append(append([]string{}, invalid...), "WORD $0xffffffff", "WORD $(0.0)") {
				source := "TEXT comparison(SB),516,$0-0\nMRS RNDR,R0\nRET\n" + line + "\nRET\n"
				present, err := arm64FPControlTargetAPI(t, api, source, target)
				if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("invalid RNG source hidden by target context: %s %s %s output=%t err=%v", api, target, line, present, err)
				}
			}
		}
	}
}

func TestARM64RNDRDoesNotSupplyOtherEntryRoles(t *testing.T) {
	for _, body := range []string{
		"CBZ R0,done\nMRS RNDR,R1\ndone:\nCSET EQ,R0",
		"MRS RNDR,R18_PLATFORM", "MOVD RNDRRS,g", "MRS RNDR,R30",
		"WORD $0xd53b2412", "WORD $0xd53b243c",
		"MRS RNDR,R1\nMRS TPIDR_EL0,R2\nCSET EQ,R0",
		"MRS RNDR,R1\nADD R9,R0,R0",
	} {
		file, err := Parse(ArchARM64, arm64TypedNativeSource(body))
		if err != nil {
			t.Fatal(err)
		}
		if ir, err := Translate(file, arm64TypedNativeOptions(t, "aarch64-unknown-linux-gnu")); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("RNG acquired unrelated machine-entry role: %s: %v", body, err)
		}
	}
}
