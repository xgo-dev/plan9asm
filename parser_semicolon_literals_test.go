package plan9asm

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestSplitSemicolonsRetainsWholeGoQuotedTokens(t *testing.T) {
	for _, row := range []struct {
		source string
		want   []string
	}{
		{" ; RET; ;", []string{"", "RET", "", ""}},
		{`DATA value(SB)/4,$"a;b";RET`, []string{`DATA value(SB)/4,$"a;b"`, "RET"}},
		{`BYTE $';';RET`, []string{`BYTE $';'`, "RET"}},
		{`DATA value(SB)/8,$"a\";b";RET`, []string{`DATA value(SB)/8,$"a\";b"`, "RET"}},
		{`DATA value(SB)/8,$"a\\;b";RET`, []string{`DATA value(SB)/8,$"a\\;b"`, "RET"}},
		{`DATA value(SB)/8,$"unterminated;`, []string{`DATA value(SB)/8,$"unterminated;`}},
	} {
		t.Run(row.source, func(t *testing.T) {
			if got := splitSemicolons(row.source); !reflect.DeepEqual(got, row.want) {
				t.Fatalf("quoted token was split: got=%q want=%q", got, row.want)
			}
		})
	}
}

func TestParseSemicolonStringDataMatchesActualGoFiveArch(t *testing.T) {
	for _, target := range []struct {
		name string
		arch Arch
	}{
		{"386", ArchAMD64}, {"amd64", ArchAMD64}, {"arm", ArchARM},
		{"arm64", ArchARM64}, {"wasm", ArchWASM},
	} {
		t.Run(target.name, func(t *testing.T) {
			for _, payload := range []string{";", "a;b", "a\";b", "a\\;b", "//;/*;", "x;\x00;y"} {
				t.Run(strconv.Quote(payload), func(t *testing.T) {
					source := fmt.Sprintf("DATA text<>+0(SB)/8,$%s;GLOBL text<>(SB),8,$8\nTEXT Probe(SB),4,$0-0\nRET\n", strconv.Quote(payload))
					goAssemblerOracleOutput(t, target.name, source, "", true)
					file, err := Parse(target.arch, source)
					if err != nil || len(file.Data) != 1 || len(file.Globl) != 1 || len(file.Funcs) != 1 {
						t.Fatalf("actual Go-accepted quoted DATA lost statement boundaries: %v", err)
					}
					if string(file.Data[0].Payload) != payload || file.Data[0].Width != 8 {
						t.Fatalf("quoted DATA bytes changed: %+v", file.Data[0])
					}
				})
			}
		})
	}
}

func TestSemicolonStringDataThreeAPIsFiveLLVMTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
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
			pkg := x86AddSubLiteralPackage(t, target.goarch, "func Probe()\n")
			resolve := func(symbol string) string {
				return strings.TrimSuffix(strings.TrimPrefix(symbol, "·"), "<>")
			}
			for _, payload := range []string{";", "a;b", "a\";b", "a\\;b", "//;/*;", "x;\x00;y"} {
				t.Run(strconv.Quote(payload), func(t *testing.T) {
					source := fmt.Sprintf("DATA text<>+0(SB)/8,$%s;GLOBL text<>(SB),8,$8\nTEXT ·Probe(SB),4,$0-0\nRET\n", strconv.Quote(payload))
					goAssemblerOracleOutput(t, target.goarch, source, "", true)
					file, err := Parse(target.arch, source)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: target.goarch, TargetTriple: target.triple,
						ResolveSym: resolve, Sigs: map[string]FuncSig{"Probe": {Name: "Probe", Ret: Void}}}
					for _, api := range []string{"text", "module", "GoModule"} {
						t.Run(api, func(t *testing.T) {
							ctx := llvm.NewContext()
							defer ctx.Dispose()
							var module llvm.Module
							var err error
							switch api {
							case "text":
								var ir string
								ir, err = Translate(file, options)
								if err == nil {
									module, err = parseIRModuleInContext(ctx, ir)
								}
							case "module":
								module, err = TranslateModuleInContext(ctx, file, options)
							case "GoModule":
								var result *GoModuleTranslation
								result, err = translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
									GOARCH: target.goarch, TargetTriple: target.triple, ResolveSym: resolve})
								if result != nil {
									module = result.Module
								}
							}
							if !module.IsNil() {
								defer module.Dispose()
							}
							if err != nil || module.IsNil() {
								t.Fatalf("quoted DATA translation failed: %v", err)
							}
							global := module.NamedGlobal("text")
							if global.IsNil() || global.Initializer().IsNil() || !global.Initializer().IsConstantString() {
								t.Fatal("quoted DATA lost its initialized byte array")
							}
							want := payload + strings.Repeat("\x00", 8-len(payload))
							if got := global.Initializer().ConstGetAsString(); got != want {
								t.Fatalf("quoted DATA bytes changed: got=%q want=%q", got, want)
							}
							compileLLVMToObject(t, llc, target.triple, "quoted-data.ll", "quoted-data.o", module.String())
						})
					}
				})
			}
		})
	}
}
