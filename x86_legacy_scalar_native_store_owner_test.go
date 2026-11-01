package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// No SETcc, packed move, mask, result or caller owner may accidentally supply
// the source proof for a legacy scalar store. Its own native-memory grammar
// must require that proof for both Void and an unused bool parameter.
func TestX86LegacyScalarNativeStoreOwnsPureVoidInputProof(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := 8, "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		triple := testTargetTriple("linux", arch)
		for _, row := range x86LegacyScalarNativeStoreRows {
			t.Run(arch+"/"+row.op+"/mandatory-owner", func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.op+" X0,(BX)")
				for _, sig := range []FuncSig{{Ret: Void}, {Args: []LLVMType{I1}, Ret: Void}} {
					if !x86TypedFPResultNeedsProof(Func{Instrs: []Instr{ins}}, sig, arch) {
						t.Error("native legacy scalar store borrowed another instruction's input-proof owner")
					}
				}
			})
			for _, unusedBool := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/unused-bool-%t", arch, row.op, unusedBool), func(t *testing.T) {
					args := word + row.bytes
					declaration := fmt.Sprintf("func Value(out *byte,value uint%d", row.bytes*8)
					if unusedBool {
						args++
						declaration += ",unused bool"
					}
					declaration += ")"
					pointer := move + " out+0(FP),BX\n"
					load := fmt.Sprintf("%s value+%d(FP),X0\n", row.op, word)
					store := row.op + " X0,(BX)\nRET\n"
					type control struct {
						name, body, declaration string
						valid                   bool
					}
					controls := []control{
						{"initialized", pointer + load + store, declaration, true},
						{"missing-source", pointer + store, declaration, false},
						{"missing-pointer", load + store, declaration, false},
						{"partial-pointer", "MOVW out+0(FP),BX\n" + load + store, declaration, false},
						{"numerical-pointer", pointer + load + store, strings.Replace(declaration, "out *byte", "out uintptr", 1), false},
						{"initialized-index", pointer + load + "MOVL $1,DX\n" + strings.Replace(store, "(BX)", "(BX)(DX*2)", 1), declaration, true},
						{"missing-index", pointer + load + strings.Replace(store, "(BX)", "(BX)(DX*2)", 1), declaration, false},
						{"partial-index", pointer + load + "MOVW $1,DX\n" + strings.Replace(store, "(BX)", "(BX)(DX*2)", 1), declaration, false},
					}
					for missing := 0; missing < row.bytes; missing++ {
						var partial strings.Builder
						partial.WriteString(pointer + "MOVL $7,CX\n")
						for b := 0; b < row.bytes; b++ {
							if b != missing {
								fmt.Fprintf(&partial, "PINSRB $%d,CX,X0\n", b)
							}
						}
						partial.WriteString(store)
						controls = append(controls, control{
							fmt.Sprintf("missing-source-byte-%d", missing), partial.String(), declaration, false,
						})
					}
					var original strings.Builder
					for index, test := range controls {
						fmt.Fprintf(&original, "TEXT ·Value%d(SB),4,$0-%d\n%s", index, args, test.body)
					}
					// Every source, including each partial-byte control, must first
					// be a real complete original Go object on its actual mode.
					x86LEAActualTargetGoObject(t, arch, triple, original.String())
					for _, test := range controls {
						for _, api := range []string{"text", "module", "Go", "default-text", "default-module"} {
							if arch == "386" && strings.HasPrefix(api, "default-") {
								continue // Empty Options.Goarch means amd64, never mode32.
							}
							t.Run(test.name+"/"+api, func(t *testing.T) {
								source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", args, test.body)
								var ir string
								var err error
								if strings.HasPrefix(api, "default-") {
									ir, err = x86IntegerFPDefaultAPI(t, source, test.declaration, triple, strings.TrimPrefix(api, "default-"))
								} else {
									ir, err = x86ScalarFPBitViewAPI(t, source, test.declaration, arch, triple, api)
								}
								if test.valid {
									if ir == "" || err != nil {
										t.Fatal("pure legacy initialized store lost its independent input owner", err)
									}
								} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("pure legacy store bypassed its own source/address byte proof", ir != "", err)
								}
							})
						}
					}
				})
			}
		}
	}
}
