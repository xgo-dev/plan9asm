package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86OrdinaryResultAddressFixture(arch, setup, body string) (string, string) {
	word, typ, width := "Q", "uint64", 8
	if arch == "386" {
		word, typ, width = "L", "uint32", 4
	}
	source := fmt.Sprintf(`TEXT ·First(SB),NOSPLIT,$0-%d
 MOV%s a+0(FP),SI
 LEA%s ret+%d(FP),DI
 %s
 %s
 RET
`, width*2, word, word, width, setup, body)
	source = strings.ReplaceAll(source, "WORD", word)
	source = strings.ReplaceAll(source, "RESULT", fmt.Sprint(width))
	return source, "func First(a " + typ + ") " + typ
}

func TestX86OrdinaryResultAddressWholeSource(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, test := range []struct{ name, setup, body string }{
			{"direct_no_probe", "NOP", "MOVWORD SI,(DI)"},
			{"copy", "MOVWORD DI,BX", "MOVWORD SI,(BX)"},
			{"overlap", "MOVWORD DI,BX\n MOVWORD BX,DI", "MOVWORD SI,(DI)"},
			{"interior", "LEAWORD 1(DI),BX\n LEAWORD -1(BX),BX", "MOVWORD SI,(BX)"},
			{"same_join", "CMPWORD SI,$0\n JEQ alternate\n MOVWORD DI,BX\n JMP join\nalternate:\n LEAWORD 0(DI),BX\njoin:", "MOVWORD SI,(BX)"},
			{"loop", "MOVL $2,CX\nloop:\n MOVWORD SI,(DI)\n DECL CX\n JNZ loop", "NOP"},
			{"read_written", "NOP", "MOVWORD SI,(DI)\n MOVWORD (DI),AX\n MOVWORD AX,(DI)"},
			{"overwritten_alias", "MOVWORD $7,DI", "MOVWORD DI,ret+RESULT(FP)"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.arch+"/"+target.triple+"/"+test.name+"/"+api, func(t *testing.T) {
					source, declaration := x86OrdinaryResultAddressFixture(target.arch, test.setup, test.body)
					if _, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86OrdinaryResultAddressNoProbeRejectsUnknown(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "i386-unknown-linux-gnu"
		if arch == "amd64" {
			triple = "x86_64-unknown-linux-gnu"
		}
		for _, test := range []struct{ name, setup, body string }{
			{"unknown_GP", "NOP", "MOVWORD AX,(DI)"},
			{"read_unwritten", "NOP", "MOVWORD (DI),AX\n MOVWORD AX,(DI)"},
			{"load_kills_alias", "NOP", "MOVWORD SI,(DI)\n MOVWORD (DI),DI\n MOVWORD $7,(DI)"},
			{"partial_copy", "MOVB DI,BL", "MOVWORD SI,(BX)"},
			{"different_join", "CMPWORD SI,$0\n JEQ alternate\n MOVWORD DI,BX\n JMP join\nalternate:\n LEAWORD 1(DI),BX\njoin:", "MOVWORD SI,(BX)"},
			{"address_NUM", "NOP", "MOVWORD DI,ret+RESULT(FP)"},
			{"address_vector", "MOVL DI,X0", "MOVWORD SI,(DI)"},
			{"address_compare", "CMPWORD DI,$0", "MOVWORD SI,(DI)"},
			{"escape_parameter", "MOVWORD DI,a+0(FP)", "MOVWORD SI,(DI)"},
			{"escape_native", "MOVWORD $0,BX", "MOVWORD DI,(BX)\n MOVWORD SI,(DI)"},
			{"indexed", "MOVWORD $0,CX", "MOVWORD SI,(DI)(CX*1)"},
			{"oob", "NOP", "MOVWORD SI,1(DI)"},
			{"negative", "NOP", "MOVWORD SI,-1(DI)"},
			{"overflow", "NOP", "MOVWORD SI,9223372036854775807(DI)"},
			{"cross_field", "LEAWORD 8(DI),DI", "MOVWORD SI,(DI)"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+test.name+"/"+api, func(t *testing.T) {
					source, declaration := x86OrdinaryResultAddressFixture(arch, test.setup, test.body)
					_, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("logical result alias accepted without complete proof: %v", err)
					}
				})
			}
		}
	}
}

func TestX86OrdinaryResultAddressScalarTransferWidths(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, offset, triple := "Q", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, offset, triple = "L", 4, "i386-unknown-linux-gnu"
		}
		for _, test := range []struct {
			typ, setup, store string
			bytes             int
		}{
			{"uint8", "NOP", "MOVB $7,(DI)", 1},
			{"uint16", "NOP", "MOVW $7,(DI)", 2},
			{"uint32", "MOVL $7,AX", "MOVL AX,(DI)", 4},
			{"uint32", "PXOR X0,X0", "MOVL X0,(DI)", 4},
			{"uint32", "PXOR X0,X0", "VMOVD X0,(DI)", 4},
			{"uint64", "PXOR X0,X0", "MOVQ X0,(DI)", 8},
			{"uint64", "PXOR X0,X0", "MOVD X0,(DI)", 8},
			{"uint64", "PXOR X0,X0", "MOVDQ2Q X0,(DI)", 8},
			{"uint64", "PXOR X0,X0", "VMOVQ X0,(DI)", 8},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+test.typ+"/"+test.store+"/"+api, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·First(SB),NOSPLIT,$0-%d\n LEA%s ret+%d(FP),DI\n %s\n %s\n RET\n", offset+test.bytes, word, offset, test.setup, test.store)
					if _, err := x86ScalarFPBitViewAPI(t, source, "func First(a uint8) "+test.typ, arch, triple, api); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86OrdinaryResultAddressPrivateProofNotPublicAuthority(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word := "Q"
		if arch == "386" {
			word = "L"
		}
		for _, move := range []string{"MOVQ", "MOVD", "MOVDQ2Q", "VMOVQ"} {
			t.Run(arch+"/"+move, func(t *testing.T) {
				body := fmt.Sprintf("LEA%s ret+0(FP),DI\n PXOR X0,X0\n %s X0,(DI)\n RET", word, move)
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() uint64", body)
				before, err := x86CallerSourceFingerprint(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("declaration query acquired logical/native storage authority: %v", err)
				}
				if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatal(err)
				}
				if after, err := x86CallerSourceFingerprint(file); err != nil || after != before {
					t.Fatal("result proof rewrote original Op/Raw/operand identity")
				}
			})
		}
	}
}

func TestX86OrdinaryResultAddressNativeAliasOrdering(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, typ, width, triple := "Q", "uint64", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, typ, width, triple = "L", "uint32", 4, "i386-unknown-linux-gnu"
		}
		for _, after := range []bool{false, true} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/after_%t/%s", arch, after, api), func(t *testing.T) {
					load, store := " MOVL (BX),AX\n", " MOV"+word+" SI,(DI)\n"
					body := load + store
					if after {
						body = store + load
					}
					source := fmt.Sprintf("TEXT ·First(SB),NOSPLIT,$0-%d\n MOV%s p+0(FP),BX\n MOV%s a+%d(FP),SI\n LEA%s ret+%d(FP),DI\n%s RET\n", width*3, word, word, width, word, width*2, body)
					_, err := x86ScalarFPBitViewAPI(t, source, "func First(p *uint32,a "+typ+") "+typ, arch, triple, api)
					if after && !errors.Is(err, ErrProbeNeedsContext) || !after && err != nil {
						t.Fatalf("logical/native alias ordering after=%t: %v", after, err)
					}
				})
			}
		}
	}
}

func TestX86OrdinaryResultAddressPhysicalBanksAndFieldBytes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, offset, triple := "Q", 8, "x86_64-unknown-linux-gnu"
		registers := strings.Fields("AX CX DX BX SI DI R8 R9 R10 R11 R12 R13 R15")
		if arch == "386" {
			word, offset, triple = "L", 4, "i386-unknown-linux-gnu"
			registers = strings.Fields("AX CX DX BX SI DI")
		}
		for _, register := range registers {
			for _, width := range []int{1, 2, 4, 8} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/bytes_%d/%s", arch, register, width, api), func(t *testing.T) {
						var body strings.Builder
						fmt.Fprintf(&body, "TEXT ·First(SB),NOSPLIT,$0-%d\n CMPB a+0(FP),$0\n LEA%s ret+%d(FP),%s\n", offset+width, word, offset, register)
						for current := 0; current < width; current++ {
							fmt.Fprintf(&body, " MOVB $7,%d(%s)\n", current, register)
						}
						// Address construction/copy/memory transport changes no FLAGS.
						fmt.Fprintf(&body, " JEQ done\n MOVB $8,(%s)\ndone:\n RET\n", register)
						if _, err := x86ScalarFPBitViewAPI(t, body.String(), fmt.Sprintf("func First(a uint8) uint%d", width*8), arch, triple, api); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}
		for _, register := range []string{"SP", "BP", "R14", "R16", "AL", "AH", "X0", "M0", "TLS", "FS"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/mode_address_bank/"+register+"/"+api, func(t *testing.T) {
					source, declaration := x86OrdinaryResultAddressFixture(arch, "NOP", "MOVWORD SI,(DI)")
					source = strings.ReplaceAll(source, ",DI", ","+register)
					source = strings.ReplaceAll(source, "(DI)", "("+register+")")
					_, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					ordinary := arch == "386" && register == "BP"
					if ordinary && err != nil || !ordinary && err == nil {
						t.Fatal("result address acquired physical/unknown bank role")
					}
				})
			}
		}
	}
}

func TestX86OrdinaryResultAddressKeepsUnclosedRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, test := range []struct{ name, setup, body string }{
			{"CALL", "CALL ·Other(SB)", "MOVWORD SI,(DI)"},
			{"SP_memory", "MOVL $7,0(SP)", "MOVWORD SI,(DI)"},
			{"raw", "BYTE $0x90", "MOVWORD SI,(DI)"},
			{"MMX", "MOVQ M0,(DI)", "MOVWORD SI,(DI)"},
			{"segment", "MOVW FS,(DI)", "MOVWORD SI,(DI)"},
			{"uninitialized_X", "MOVL X0,(DI)", "NOP"},
			{"partial_result", "MOVB $7,(DI)", "NOP"},
			{"partial_read", "MOVB $7,(DI)", "MOVWORD (DI),AX\n MOVWORD AX,(DI)"},
			{"unknown_flags", "JEQ done", "MOVWORD SI,(DI)\ndone:"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+test.name+"/"+api, func(t *testing.T) {
					source, declaration := x86OrdinaryResultAddressFixture(arch, test.setup, test.body)
					_, err := x86ScalarFPBitViewAPI(t, source, declaration+"\nfunc Other()", arch, triple, api)
					if err == nil {
						t.Fatal("logical result acquired an unclosed entry/store/source role")
					}
				})
			}
		}
		for _, address := range []string{"a+0(FP)", "padding+2(FP)", "ret+4095(FP)"} {
			source, declaration := x86OrdinaryResultAddressFixture(arch, "NOP", "MOVWORD SI,(DI)")
			offset := 8
			if arch == "386" {
				offset = 4
			}
			original := source
			source = strings.ReplaceAll(source, fmt.Sprintf("ret+%d(FP)", offset), address)
			pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sigs["First"], arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("parameter-only source acquired private result proof: %v", err)
			}
			// Keep the actual result-role instruction for this public consumer
			// class, then overwrite its carrier with the invalid field address.
			// Parameter-only consumers retain their independent existing route.
			resultLEA := fmt.Sprintf(" LEA%s ret+%d(FP),DI\n", map[string]string{"386": "L", "amd64": "Q"}[arch], offset)
			if !strings.Contains(original, resultLEA) {
				t.Fatal("missing actual result-role instruction")
			}
			source = strings.Replace(source, " MOV", resultLEA+" MOV", 1)
			if _, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, "text"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("non-result field address %s: %v", address, err)
			}
		}
		source, declaration := x86OrdinaryResultAddressFixture(arch, "NOP", "MOVWORD SI,(DI)")
		source = strings.ReplaceAll(source, "$0-", "$8-")
		if _, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, "text"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("framed root acquired zero-frame alias role: %v", err)
		}
	}
}

func TestX86OrdinaryResultAddressLayoutAndBudgetRemainExact(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, typ := "Q", "uint64"
		if arch == "386" {
			word, typ = "L", "uint32"
		}
		_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() "+typ, "LEA"+word+" ret+0(FP),DI\n MOV"+word+" $7,(DI)\n RET")
		for _, test := range []struct {
			name   string
			mutate func(*Func, *FuncSig)
		}{
			{"type", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Type = I8 }},
			{"index", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Index = 1 }},
			{"field", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Fields = []int{0} }},
			{"negative", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Offset = -1 }},
			{"extent", func(fn *Func, _ *FuncSig) { fn.ArgSize = 1 }},
			{"oversized_CFG", func(fn *Func, _ *FuncSig) { fn.Instrs = append(fn.Instrs, make([]Instr, 4097)...) }},
		} {
			t.Run(arch+"/"+test.name, func(t *testing.T) {
				fn, changed := file.Funcs[0], sig
				changed.Frame.Results = append([]FrameSlot(nil), sig.Frame.Results...)
				test.mutate(&fn, &changed)
				if err := checkX86ScalarFPResultInitialization(fn, changed, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("mutated actual layout/CFG acquired alias authority: %v", err)
				}
			})
		}
	}
}

func TestX86OrdinaryResultAddressDistinctFieldsAndRevocation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, offset, triple := "Q", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, offset, triple = "L", 4, "i386-unknown-linux-gnu"
		}
		for _, test := range []struct {
			name, body string
			accept     bool
		}{
			{"distinct", "MOVL $7,(DI)\n MOVL $8,(BX)", true},
			{"full_read", "MOVL $7,(DI)\n MOVL (DI),AX\n MOVL AX,(BX)", true},
			{"cross_field", "PXOR X0,X0\n MOVQ X0,(DI)", false},
			{"mixed_join", "CMPB a+0(FP),$0\n JEQ alternate\n MOVWORD DI,AX\n JMP join\nalternate:\n MOVWORD BX,AX\njoin:\n MOVL $7,(AX)\n MOVL $8,(BX)", false},
			{"missing_join", "CMPB a+0(FP),$0\n JEQ alternate\n MOVWORD DI,AX\n JMP join\nalternate:\n NOP\njoin:\n MOVL $7,(AX)\n MOVL $8,(BX)", false},
			{"numeric_revoke", "MOVL $0,DI\n MOVL $7,(DI)\n MOVL $8,(BX)", false},
			{"alias_index", "MOVL $7,(DI)(BX*1)\n MOVL $8,(BX)", false},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+test.name+"/"+api, func(t *testing.T) {
					body := strings.ReplaceAll(test.body, "WORD", word)
					source := fmt.Sprintf("TEXT ·First(SB),NOSPLIT,$0-%d\n LEA%s first+%d(FP),DI\n LEA%s second+%d(FP),BX\n %s\n RET\n", offset+8, word, offset, word, offset+4, body)
					_, err := x86ScalarFPBitViewAPI(t, source, "func First(a uint8) (first,second uint32)", arch, triple, api)
					if test.accept && err != nil || !test.accept && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("distinct-field alias accept=%t: %v", test.accept, err)
					}
				})
			}
		}
	}
}

func TestX86OrdinaryResultAddressConcurrentOriginalFile(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		source, declaration := x86OrdinaryResultAddressFixture(arch, "MOVWORD DI,BX", "MOVWORD SI,(BX)")
		pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		before, err := x86CallerSourceFingerprint(file)
		if err != nil {
			t.Fatal(err)
		}
		options := Options{Goarch: arch, TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
		// Translate uses LLVM's global context. Its caller must serialize that
		// context; concurrent module APIs below each own an independent context.
		if _, err := Translate(file, options); err != nil {
			t.Fatal(err)
		}
		var group sync.WaitGroup
		for index := 0; index < 6; index++ {
			group.Add(1)
			go func(index int) {
				defer group.Done()
				if index%3 == 0 {
					if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sigs[resolve(file.Funcs[0].Sym)], arch); err != nil {
						t.Error(err)
					}
					return
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				if index%3 == 1 {
					module, err := TranslateModuleInContext(ctx, file, options)
					if !module.IsNil() {
						module.Dispose()
					}
					if err != nil {
						t.Error(err)
					}
					return
				}
				module, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: arch, TargetTriple: triple, ResolveSym: resolve})
				if module != nil && !module.Module.IsNil() {
					module.Module.Dispose()
				}
				if err != nil {
					t.Error(err)
				}
			}(index)
		}
		group.Wait()
		if _, err := Translate(file, options); err != nil {
			t.Fatal(err)
		}
		if after, err := x86CallerSourceFingerprint(file); err != nil || after != before || file.x86DirectTails != nil || file.Funcs[0].x86DirectTailRoot != nil {
			t.Fatal("private result proof mutated/published state on shared original File")
		}
	}
}
