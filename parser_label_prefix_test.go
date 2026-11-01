package plan9asm

import (
	"reflect"
	"testing"
)

func TestParseLabelPrefixFamilyOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch, triple string
		arch           Arch
	}{
		{"386", "i386-unknown-linux-gnu", ArchAMD64},
		{"amd64", "x86_64-unknown-linux-gnu", ArchAMD64},
		{"arm", "armv7-unknown-linux-gnueabihf", ArchARM},
		{"arm64", "aarch64-unknown-linux-gnu", ArchARM64},
		{"wasm", "wasm32-unknown-unknown", ArchWASM},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			for _, test := range []struct {
				name, prefix, body string
				labels             []string
			}{
				{"inline", "", "first: next: tail: NOP\n", []string{"first", "next", "tail"}},
				{"physical_lines", "", "first:\nnext:\ntail:\nNOP\n", []string{"first", "next", "tail"}},
				{"comments", "", "first:\n// no instruction\nnext: /* still no instruction */ tail: NOP\n", []string{"first", "next", "tail"}},
				{"semicolons", "", "first:;next:;tail: NOP;", []string{"first", "next", "tail"}},
				{"object_macro", "#define LABELS first: next:\n", "LABELS tail: NOP\n", []string{"first", "next", "tail"}},
				{"function_macro", "#define LABELS(a,b) a: b:\n", "LABELS(first,next) tail: NOP\n", []string{"first", "next", "tail"}},
				{"opcode_names", "", "RET: NOP: tail: NOP\n", []string{"RET", "NOP", "tail"}},
				{"unicode", "", "一: 二: 三: NOP\n", []string{"一", "二", "三"}},
				{"internal_names", "", "reg_R0: reg_AX: flags_n: entry: anon_1: NOP\n", []string{"reg_R0", "reg_AX", "flags_n", "entry", "anon_1"}},
			} {
				t.Run(test.name, func(t *testing.T) {
					source := test.prefix + "TEXT ·Probe(SB),4,$0-0\n" + test.body + "RET\n"
					goAssemblerOracleOutput(t, target.goarch, source, "", true)
					expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{FileName: "labels.s"})
					if err != nil {
						t.Fatal(err)
					}
					goAssemblerOracleOutput(t, target.goarch, expanded, "", true)
					for index, input := range []string{source, expanded} {
						file, err := Parse(target.arch, input)
						if err != nil {
							t.Fatalf("label prefix path=%d: %v", index, err)
						}
						var labels []string
						var operations []Op
						for _, instruction := range file.Funcs[0].Instrs {
							if instruction.Op == OpLABEL {
								if len(instruction.Args) != 1 || instruction.Args[0].Kind != OpLabel {
									t.Fatalf("untyped label: %+v", instruction)
								}
								labels = append(labels, instruction.Args[0].Sym)
							} else {
								operations = append(operations, instruction.Op)
							}
						}
						if !reflect.DeepEqual(labels, test.labels) || !reflect.DeepEqual(operations, []Op{OpTEXT, "NOP", OpRET}) {
							t.Fatalf("Go-accepted label prefixes lost their identities: path=%d labels=%v operations=%v", index, labels, operations)
						}
						ir, err := Translate(file, Options{
							Goarch: target.goarch, TargetTriple: target.triple,
							Sigs: map[string]FuncSig{"·Probe": {Name: "·Probe", Ret: Void}},
						})
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, target.triple, "labels.ll", "labels.o", ir)
					}
				})
			}
		})
	}
}

func TestParseLabelPrefixOptionalSuffixAndFunctionScopeLikeGo(t *testing.T) {
	for _, target := range []struct {
		goarch string
		arch   Arch
	}{
		{"386", ArchAMD64}, {"amd64", ArchAMD64}, {"arm", ArchARM}, {"arm64", ArchARM64}, {"wasm", ArchWASM},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			t.Run("suffix", func(t *testing.T) {
				// cmd/asm consumes suffix tokens before a colon, then retains
				// only the original word as the pending label, not its suffix.
				const source = "TEXT Probe(SB),4,$0-0\nfirst.EQ.S: NOP\nRET\n"
				accepted := target.arch != ArchWASM
				goAssemblerOracleOutput(t, target.goarch, source, "", accepted)
				file, err := Parse(target.arch, source)
				if err != nil {
					if accepted {
						t.Fatal(err)
					}
					return
				}
				var labels []string
				for _, instruction := range file.Funcs[0].Instrs {
					if instruction.Op == OpLABEL {
						labels = append(labels, instruction.Args[0].Sym)
					}
				}
				if accepted && !reflect.DeepEqual(labels, []string{"first"}) || !accepted && len(labels) != 0 {
					t.Fatalf("label suffix differs from original Go grammar: accepted=%t labels=%v", accepted, labels)
				}
			})
			t.Run("function_scope", func(t *testing.T) {
				const source = "TEXT First(SB),4,$0-0\nlocal: NOP\nRET\nTEXT Second(SB),4,$0-0\nlocal: NOP\nRET\n"
				goAssemblerOracleOutput(t, target.goarch, source, "", true)
				file, err := Parse(target.arch, source)
				if err != nil || len(file.Funcs) != 2 {
					t.Fatalf("function-local labels were lost: %v", err)
				}
				for _, function := range file.Funcs {
					if function.Instrs[1].Op != OpLABEL || function.Instrs[1].Args[0].Sym != "local" {
						t.Fatalf("label escaped its original TEXT: %+v", function.Instrs)
					}
				}
			})
		})
	}
}

func TestParseLabelPrefixRejectsOriginalNonIdentifierAndDuplicateNames(t *testing.T) {
	for _, target := range []struct {
		goarch string
		arch   Arch
	}{
		{"386", ArchAMD64}, {"amd64", ArchAMD64}, {"arm", ArchARM}, {"arm64", ArchARM64}, {"wasm", ArchWASM},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			for _, test := range []struct{ name, body string }{
				{"numeric", "1: NOP\n"},
				{"string", "\"name\": NOP\n"},
				{"operator", "first+next: NOP\n"},
				{"missing_name", ": NOP\n"},
				{"duplicate", "first: first: NOP\n"},
			} {
				t.Run(test.name, func(t *testing.T) {
					source := "TEXT ·Probe(SB),4,$0-0\n" + test.body + "RET\n"
					goAssemblerOracleOutput(t, target.goarch, source, "", false)
					file, err := Parse(target.arch, source)
					if err != nil {
						return
					}
					for _, instruction := range file.Funcs[0].Instrs {
						if instruction.Op == OpLABEL {
							t.Fatalf("Go-rejected label syntax was admitted: %+v", instruction)
						}
					}
				})
			}
		})
	}
}

func TestParseLabelPrefixPendingInstructionBoundariesLikeGo(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch, triple string
		arch           Arch
	}{
		{"386", "i386-unknown-linux-gnu", ArchAMD64},
		{"amd64", "x86_64-unknown-linux-gnu", ArchAMD64},
		{"arm", "armv7-unknown-linux-gnueabihf", ArchARM},
		{"arm64", "aarch64-unknown-linux-gnu", ArchARM64},
		{"wasm", "wasm32-unknown-unknown", ArchWASM},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			const data = "DATA ·table(SB)/1,$1\nGLOBL ·table(SB),8,$1\n"
			for _, test := range []struct {
				name, source string
				labels       [][]string
			}{
				{"text_entry", "entry:\nTEXT Probe(SB),4,$0-0\nNOP\nRET\n", [][]string{{"entry"}}},
				{"unused_eof", "TEXT Probe(SB),4,$0-0\nNOP\nRET\nunused: unused:\n", [][]string{nil}},
				{"data_keeps_pending", "TEXT Probe(SB),4,$0-0\nentry:\n" + data + "NOP\nRET\n", [][]string{{"entry"}}},
				{"text_owns_pending", "TEXT First(SB),4,$0-0\nNOP\nRET\nentry:\n" + data + "TEXT Second(SB),4,$0-0\nNOP\nRET\n", [][]string{nil, {"entry"}}},
			} {
				t.Run(test.name, func(t *testing.T) {
					goAssemblerOracleOutput(t, target.goarch, test.source, "", true)
					file, err := Parse(target.arch, test.source)
					if err != nil {
						t.Fatal(err)
					}
					var labels [][]string
					signatures := make(map[string]FuncSig)
					for _, function := range file.Funcs {
						var names []string
						for _, instruction := range function.Instrs {
							if instruction.Op == OpLABEL {
								names = append(names, instruction.Args[0].Sym)
							}
							if instruction.Op != OpTEXT && instruction.Op != OpLABEL && instruction.Op != "NOP" && instruction.Op != OpRET {
								t.Fatalf("label or data became an instruction: %+v", instruction)
							}
						}
						labels = append(labels, names)
						signatures[function.Sym] = FuncSig{Name: function.Sym, Ret: Void}
					}
					if !reflect.DeepEqual(labels, test.labels) {
						t.Fatalf("pending label ownership differs from Go: actual=%v expected=%v", labels, test.labels)
					}
					ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: signatures})
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "pending.ll", "pending.o", ir)
				})
			}
		})
	}
}
