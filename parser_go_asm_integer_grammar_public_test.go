package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Every route sees the complete original source. In particular, a parser
// rejection on one route must not substitute for observing the GoModule route.
func goASMIntegerGrammarTranslate(ctx llvm.Context, pkg GoPackage, source string, arch Arch, goarch, triple, api string) (llvm.Module, string, error) {
	if api == "GoModule" {
		result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: goarch, TargetTriple: triple, ResolveSym: dataGlobalAlignmentResolve,
		})
		if result != nil {
			return result.Module, "", err
		}
		return llvm.Module{}, "", err
	}
	file, err := Parse(arch, source)
	if err != nil {
		return llvm.Module{}, "", err
	}
	options := Options{
		Goarch: goarch, TargetTriple: triple, ResolveSym: dataGlobalAlignmentResolve,
		Sigs: map[string]FuncSig{"Probe": {Name: "Probe", Ret: Void}},
	}
	if api == "text" {
		ir, err := Translate(file, options)
		if err != nil {
			return llvm.Module{}, ir, err
		}
		module, err := parseIRModuleInContext(ctx, ir)
		return module, ir, err
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	return module, "", err
}

func TestGoASMIntegerGrammarOriginalObjectsAndThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("the complete integer grammar object regression requires exact LLVM22")
	}
	for _, target := range dataGlobalAlignmentTargets {
		t.Run(target.goarch, func(t *testing.T) {
			pointerSize := 8
			if target.goarch == "386" || target.goarch == "arm" {
				pointerSize = 4
			}
			source, symbols := goASMIntegerGrammarCompleteSource(pointerSize)
			// The actual Go listing independently requires every complete
			// expression-(expected) displacement to identify the same bytes.
			globlZeroAddendGoObject(t, target.goos, target.goarch, source, symbols)
			pkg := x86AddSubLiteralPackage(t, target.goarch, "func Probe()\n")
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					module, _, err := goASMIntegerGrammarTranslate(ctx, pkg, source, target.arch, target.goarch, target.triple, api)
					if !module.IsNil() {
						defer module.Dispose()
					}
					if err != nil || module.IsNil() {
						t.Fatal("a complete original Go integer-grammar program must translate", err)
					}
					for index, row := range goASMIntegerGrammarValues {
						t.Run(row.name, func(t *testing.T) {
							var want [8]byte
							binary.LittleEndian.PutUint64(want[:], row.want)
							value := module.NamedGlobal(fmt.Sprintf("expr_value_%02d", index))
							if value.IsNil() || value.IsDeclaration() ||
								value.Initializer() != ctx.ConstString(string(want[:]), false) {
								t.Fatal("DATA initializer does not equal the independent original expression", row.expression)
							}
							zero := module.NamedGlobal(fmt.Sprintf("zero_globl_expr_%02d", index))
							if zero.IsNil() || zero.IsDeclaration() || !zero.IsGlobalConstant() ||
								zero.Linkage() != llvm.InternalLinkage ||
								zero.Initializer() != ctx.ConstString(string(globlZeroAddendInitialBytes()), false) {
								t.Fatal("a zero displacement changed the actual declaration identity or complete image")
							}
							address := module.NamedGlobal(fmt.Sprintf("expr_address_%02d", index))
							if address.IsNil() {
								t.Fatal("the complete original address initializer disappeared")
							}
							// wasm owns relocated DATA through module assembly, not
							// an ordinary LLVM initializer. Validate the same original
							// address through its shared relocation consumer instead.
							datum := DataStmt{Addr: symbols[index].sourceName + goASMIntegerZeroOffset(row.expression, row.want) + "(SB)"}
							name, offset, err := dataAddress(datum)
							if err != nil || name != symbols[index].sourceName || offset != 0 {
								t.Fatal("an actual zero SB relocation changed identity", name, offset, err)
							}
						})
					}
					for global := module.FirstGlobal(); !global.IsNil(); global = llvm.NextGlobal(global) {
						if strings.ContainsAny(global.Name(), "+-() \t") || strings.HasSuffix(global.Name(), "<>") {
							t.Errorf("an expression became a spurious data-symbol identity: %q", global.Name())
						}
					}
					compileLLVMToObject(t, llc, target.triple, "integer-grammar.ll", "integer-grammar.o", module.String())
				})
			}
		})
	}
}

func TestGoASMIntegerGrammarRejectedGLOBLIsAtomic(t *testing.T) {
	type rejection struct{ name, addend string }
	var rejected []rejection
	for _, row := range goASMIntegerGrammarValues {
		if row.want != 0 {
			rejected = append(rejected, rejection{"nonzero/" + row.name, "+(" + row.expression + ")"})
		}
	}
	for _, row := range goASMIntegerGrammarInvalid {
		rejected = append(rejected, rejection{"invalid/" + row.name, "+(" + row.expression + ")"})
	}
	rejected = append(rejected,
		rejection{"false-zero/right-shift-recursive-product", "+(8>>1*2)-8"},
		rejection{"false-zero/quoted-tilde", "+('~'-94)"},
		rejection{"false-zero/high-bit-division", "+((1<<63)/2)-(1<<62)"},
	)
	for _, row := range rejected {
		t.Run(row.name, func(t *testing.T) {
			source := "DATA literal<>(SB)/8,$0x1122334455667788\n" +
				"GLOBL literal<>" + row.addend + "(SB),8,$8\n" +
				"TEXT ·Probe(SB),4,$0-0\nRET\n"
			// The grammar is shared by all architectures. A normal, concrete,
			// source-bound AMD64 diagnostic establishes original rejection;
			// panic, timeout or an unknown failure is never rejection evidence.
			goAssemblerOracleOutput(t, "amd64", source, "", false)
			for _, target := range dataGlobalAlignmentTargets {
				t.Run(target.goarch, func(t *testing.T) {
					pkg := x86AddSubLiteralPackage(t, target.goarch, "func Probe()\n")
					for _, api := range []string{"text", "module", "GoModule"} {
						t.Run(api, func(t *testing.T) {
							ctx := llvm.NewContext()
							defer ctx.Dispose()
							module, ir, err := goASMIntegerGrammarTranslate(ctx, pkg, source, target.arch, target.goarch, target.triple, api)
							if !module.IsNil() {
								defer module.Dispose()
							}
							if err == nil || !module.IsNil() || ir != "" {
								t.Fatalf("original Go rejection created a real symbol/image or partial output: err=%v module=%v text-bytes=%d",
									err, !module.IsNil(), len(ir))
							}
						})
					}
				})
			}
		})
	}
}

func TestGoASMIntegerGrammarRejectsInvalidSharedConsumers(t *testing.T) {
	for _, row := range goASMIntegerGrammarInvalid {
		t.Run(row.name, func(t *testing.T) {
			t.Run("scalar", func(t *testing.T) {
				if value, ok := parseImmExpr(row.expression); ok {
					t.Fatalf("an expression rejected by the official grammar became a numeric value: %#x", value)
				}
			})
			t.Run("DATA-value", func(t *testing.T) {
				statement := "literal<>(SB)/8,$(" + row.expression + ")"
				goAssemblerOracleOutput(t, "amd64", "DATA "+statement+"\nGLOBL literal<>(SB),8,$8\n", "", false)
				if datum, err := parseDATAStmt(ArchAMD64, statement); err == nil {
					t.Fatal("a rejected expression became a DATA initializer", datum)
				}
			})
			t.Run("DATA-displacement", func(t *testing.T) {
				// Some cmd/asm errors continue into DATA allocation. Keep the
				// resulting offset bounded even after an expression diagnostic;
				// an assembler panic cannot stand in for source rejection.
				statement := "literal<>+(((" + row.expression + "))&0)(SB)/8,$17"
				goAssemblerOracleOutput(t, "amd64", "DATA "+statement+"\nGLOBL literal<>(SB),8,$8\n", "", false)
				if datum, err := parseDATAStmt(ArchAMD64, statement); err == nil && datum.Sym == "literal<>" {
					t.Fatal("a rejected displacement acquired a real DATA-symbol identity", datum)
				}
			})
			t.Run("SB-address", func(t *testing.T) {
				address := "literal<>+(" + row.expression + ")(SB)"
				source := "DATA holder<>(SB)/8,$" + address + "\nGLOBL holder<>(SB),8,$8\nGLOBL literal<>(SB),8,$8\n"
				goAssemblerOracleOutput(t, "amd64", source, "", false)
				if name, offset, err := dataAddress(DataStmt{Addr: address}); err == nil {
					t.Fatal("a rejected expression acquired a valid SB relocation", name, offset)
				}
			})
		})
	}
}
