package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These fixtures need only a source-defined data register. They do not read
// physical BP, expose a frame address or use their allocated local storage.
// The real Go prologue/epilogue is observed separately below; a frame-size
// number by itself is not a reusable native-frame permission.
func amd64DataBPSource(frame int, setup, body string) string {
	return fmt.Sprintf("TEXT ·Value(SB),4,$%d-8\n%s\n%s\nRET\n", frame, setup, body)
}

func TestAMD64DataBPActualGoSavedFramePrologue(t *testing.T) {
	for _, frame := range []int{8, 16} {
		t.Run(fmt.Sprint(frame), func(t *testing.T) {
			source := amd64DataBPSource(frame, "MOVQ p+0(FP),BP",
				"MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)")
			listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
			if err != nil {
				t.Fatal(err)
			}
			style, err := amd64DataBPSavedFrameListing(listing, frame)
			if err != nil {
				t.Fatalf("original Go did not preserve the complete ordered BP/frame envelope: %v\n%s", err, listing)
			}
			t.Logf("original Go preserves its physical BP using %s; this observation grants no translator frame capability", style)
		})
	}
}

func TestAMD64SourceDefinedDataBPInitializedProgramsThreeAPIs(t *testing.T) {
	for _, row := range []struct {
		name, setup, body string
		frame             int
	}{
		{"direct", "MOVQ p+0(FP),BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"copied-pointer", "MOVQ p+0(FP),SI\nMOVQ SI,BP", "MOVL 4(BP),AX\nROLL $7,AX\nMOVL AX,8(BP)", 8},
		{"copied-back", "MOVQ p+0(FP),BP\nMOVQ BP,BX", "MOVL 8(BX),AX\nROLL $7,AX\nMOVL AX,12(BX)", 16},
		{"same-origin-join", "MOVL $1,CX\nCMPL CX,$0\nJE other\nMOVQ p+0(FP),BP\nJMP join\nother:\nMOVQ p+0(FP),BP\njoin:",
			"MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 16},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := amd64DataBPSource(row.frame, row.setup, row.body)
			for _, triple := range []string{
				"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc",
			} {
				t.Run(triple, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, "amd64", triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[4]uint32)\n", "amd64", triple, api)
							if err != nil || ir == "" {
								t.Fatalf("complete source-defined data BP lost its initialized input: %v", err)
							}
							if !strings.Contains(ir, "load volatile i32") || !strings.Contains(ir, "store volatile i32") {
								t.Fatal("source-defined data BP must retain the original exact native accesses")
							}
						})
					}
				})
			}
		})
	}
}

func TestAMD64SourceDefinedDataBPDoesNotGrantMissingInputsOrFrameRoles(t *testing.T) {
	for _, row := range []struct {
		name, setup, body string
		frame             int
	}{
		{"unknown-entry", "NOP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"partial-pointer", "MOVW p+0(FP),BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"truncated-pointer", "MOVL p+0(FP),BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"numeric-address", "MOVQ $7,BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"unknown-store-data", "MOVQ p+0(FP),BP", "MOVL AX,12(BP)\nROLL $7,AX", 8},
		{"lost-pointer", "MOVQ p+0(FP),BP\nMOVL $7,BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"missing-path", "MOVL $1,CX\nCMPL CX,$0\nJE join\nMOVQ p+0(FP),BP\njoin:",
			"MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"entry-physical-BP", "MOVQ BP,SI\nMOVQ p+0(FP),BP", "MOVL (SI),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"physical-SP", "MOVQ SP,BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"FP-address", "LEAQ p+0(FP),BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"unbound-AUTO", "MOVQ p+0(FP),BP\nMOVQ $7,slot-8(SP)", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 8},
		{"frameless-clobber", "MOVQ p+0(FP),BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)", 0},
		{"raw-RET", "MOVQ p+0(FP),BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)\nBYTE $0xc3", 8},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := amd64DataBPSource(row.frame, row.setup, row.body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[4]uint32)\n", "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("a data-register source view manufactured missing input or physical-frame authority: %v", err)
					}
				})
			}
		})
	}
}

func TestAMD64SourceDefinedDataBPRejectsUnusedFPAddressesThreeAPIs(t *testing.T) {
	for _, address := range []string{
		"LEAW n+8(FP),AX", "LEAL n+8(FP),AX", "LEAQ n+8(FP),AX",
		"MOVQ $n+8(FP),AX", "MOVD $n+8(FP),AX", "MOVDQ2Q $n+8(FP),AX",
	} {
		t.Run(address, func(t *testing.T) {
			for _, takeAddress := range []bool{false, true} {
				t.Run(fmt.Sprintf("take-address=%t", takeAddress), func(t *testing.T) {
					body := "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)"
					if takeAddress {
						// n is a real initialized numerical parameter, not a missing
						// slot or pointer. AX is overwritten before observation, so
						// unused-address transfer cannot conceal a missing input.
						body = address + "\n" + body
					}
					source := strings.Replace(amd64DataBPSource(8, "MOVQ p+0(FP),BP", body), "$8-8", "$8-16", 1)
					goAssemblerOracleOutput(t, "amd64", source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[4]uint32,n uint64)\n",
								"amd64", "x86_64-unknown-linux-gnu", api)
							if takeAddress {
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("an unused but actual FP address borrowed the data BP source scope", err)
								}
							} else if err != nil || ir == "" {
								t.Fatal("the same complete initialized program without FP-address observation must remain supported", err)
							}
						})
					}
				})
			}
		})
	}
}
