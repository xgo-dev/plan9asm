package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// A complete, same-module DATA address value is distinct from an unknown
// incoming pointer or arbitrary bytes read through one. These tests require
// returning the actual relocated bits, not granting a dereference capability.
func x86RelocationResultSource(arch, form string) string {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	value := "box<>+8(SB)"
	if form == "address" {
		value = "$bytes<>+3(SB)"
	}
	return fmt.Sprintf("DATA bytes<>(SB)/8,$0x1122334455667788\nGLOBL bytes<>(SB),16,$16\n"+
		"DATA box<>+8(SB)/%d,$bytes<>+3(SB)\nGLOBL box<>(SB),16,$24\n"+
		"TEXT ·Value(SB),4,$0-%d\n%s %s,AX\n%s AX,ret+0(FP)\nRET\n",
		word, word, move, value, move)
}

func TestX86SameModuleRelocationValueOriginalGoObjects(t *testing.T) {
	for _, target := range dataRelocationTargets {
		if target.arch != ArchAMD64 {
			continue
		}
		for _, form := range []string{"load", "address"} {
			t.Run(target.triple+"/"+form, func(t *testing.T) {
				dataRelocationGoObject(t, x86RelocationResultSource(target.goarch, form), target.goos, target.goarch, true)
			})
		}
	}
}

func TestX86SameModuleRelocationValuesThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, form := range []string{"load", "address"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+form+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, x86RelocationResultSource(target.arch, form),
						"func Value() uintptr", target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete DATA relocation cannot publish its address value", err)
					}
					if !strings.Contains(ir, "ptrtoint") {
						t.Fatal("relocation lost its native address-valued initializer")
					}
				})
			}
		}
	}
}

func TestX86RelocationValueDoesNotGrantIncomingPointerOrPartialBytes(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, role := range []string{"incoming-pointer", "partial-address", "shifted-cell", "unknown-source"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+role+"/"+api, func(t *testing.T) {
					source := x86RelocationResultSource(target.arch, "load")
					declaration := "func Value() uintptr"
					switch role {
					case "incoming-pointer":
						source = fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\n%s AX,ret+%d(FP)\nRET\n", 2*word, move, move, word)
						declaration = "func Value(p *byte) uintptr"
					case "partial-address":
						source = strings.Replace(source, move+" box<>+8(SB),AX", "MOVB box<>+8(SB),AX", 1)
					case "shifted-cell":
						source = strings.Replace(source, move+" box<>+8(SB),AX", move+" box<>+9(SB),AX", 1)
					case "unknown-source":
						source = strings.Replace(source, move+" box<>+8(SB),AX", move+" unknown+8(SB),AX", 1)
					}
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err == nil || ir != "" {
						t.Fatal("literal address value manufactured broader numerical inputs", role, err)
					}
				})
			}
		}
	}
}

func TestX86StaticAddressValuesRequireWholeResultProof(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move := "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		for _, form := range []string{"load", "address"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+form+"/"+api, func(t *testing.T) {
					source := x86RelocationResultSource(target.arch, form)
					source = strings.Replace(source, move+" AX,ret+0(FP)\n", "", 1)
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uintptr", target.arch, target.triple, api); err == nil || ir != "" {
						t.Fatal("missing result acquired an initialized implementation alloca", err)
					}
				})
			}
		}
	}
}
