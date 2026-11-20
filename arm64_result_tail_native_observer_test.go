package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type arm64NativeResultTailCase struct {
	op                    Op
	resultBits, storeBits int
}

// These are the complete wider-than-result combinations of Go's seven scalar
// memory moves. The assembler checks the original widths independently.
func arm64NativeResultTailCases() []arm64NativeResultTailCase {
	var cases []arm64NativeResultTailCase
	for _, row := range []struct {
		op   Op
		bits int
	}{
		{"MOVB", 8}, {"MOVBU", 8}, {"MOVH", 16}, {"MOVHU", 16},
		{"MOVW", 32}, {"MOVWU", 32}, {"MOVD", 64},
	} {
		for _, resultBits := range []int{8, 16, 32} {
			if row.bits > resultBits {
				cases = append(cases, arm64NativeResultTailCase{
					op: row.op, resultBits: resultBits, storeBits: row.bits,
				})
			}
		}
	}
	return cases
}

func (test arm64NativeResultTailCase) name() string {
	return fmt.Sprintf("%s_u%d", test.op, test.resultBits)
}

func (test arm64NativeResultTailCase) declaration() string {
	return fmt.Sprintf("func %s(input uint64) (result uint%d)\n", test.name(), test.resultBits)
}

func (test arm64NativeResultTailCase) source() string {
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n"+
		"MOVD input+0(FP),R0\n%s R0,result+8(FP)\nRET\n",
		test.name(), 8+test.resultBits/8, test.op)
}

func arm64NativeResultTailObserver(test arm64NativeResultTailCase) string {
	return fmt.Sprintf(`
TEXT ·observe_%s(SB),4,$48-32
    MOVD input+0(FP),R0
    MOVD R0,8(RSP)
    MOVD $0xfeedfacecafebeef,R1
    MOVD R1,16(RSP)
    MOVD $0x7ac35ef012345678,R1
    MOVD R1,24(RSP)
    CALL ·%s(SB)
    MOVD 16(RSP),R0
    MOVD R0,native+16(FP)
    %s 16(RSP),R0
    MOVD R0,value+8(FP)
    MOVD 24(RSP),R0
    MOVD R0,guard+24(FP)
    RET
`, test.name(), test.name(), map[int]string{8: "MOVBU", 16: "MOVHU", 32: "MOVWU"}[test.resultBits])
}

func TestARM64NativeResultTailExactDeclaredWidthObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	source := "TEXT ·Exact(SB),4,$0-16\n" +
		"MOVD input+0(FP),R0\nMOVD R0,result+8(FP)\nRET\n"
	requireARM64GoAssemblerResult(t, source, true)
	pkg := mustGoPackage(t, "tailobserve", "package tailobserve\nfunc Exact(input uint64) (result uint64)\n")
	resolve := testResolveSym(pkg.Path)
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				var ir string
				var failure error
				if api == "Go" {
					translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
						GOOS: "linux", GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
					})
					if translated != nil && !translated.Module.IsNil() {
						ir = translated.Module.String()
						translated.Module.Dispose()
					}
					failure = err
				} else {
					file, err := Parse(ArchARM64, source)
					if err != nil {
						t.Fatal(err)
					}
					signatures, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{
						Goarch: "arm64", TargetTriple: triple, ResolveSym: resolve, Sigs: signatures,
					}
					if api == "text" {
						ir, failure = Translate(file, options)
					} else {
						module, err := TranslateModuleInContext(ctx, file, options)
						if !module.IsNil() {
							ir = module.String()
							module.Dispose()
						}
						failure = err
					}
				}
				if failure != nil {
					t.Fatalf("exact declared native width lost its ordinary contract: %v", failure)
				}
				compileLLVMToObject(t, llc, triple, "exact-result.ll", "exact-result.o", ir)
			})
		}
	}
}

// A callee-only type snapshot cannot prove that the native result tail is
// unobservable. In particular KeepFunc must not make a caller disappear from
// the proof boundary. Neither a code address nor a DATA reference closes it.
func TestARM64NativeResultTailNeedsCallerContract(t *testing.T) {
	cases := arm64NativeResultTailCases()
	if len(cases) != 9 {
		t.Fatalf("complete scalar-width family changed: %d", len(cases))
	}
	for _, test := range cases {
		t.Run(test.name(), func(t *testing.T) {
			for _, scope := range []string{"isolated", "dropped-caller", "dropped-code-address", "data-code-address"} {
				declarations := "package tailobserve\n" + test.declaration()
				source := test.source()
				switch scope {
				case "dropped-caller":
					declarations += fmt.Sprintf("func observe_%s(input uint64) (value, native, guard uint64)\n", test.name())
					source += arm64NativeResultTailObserver(test)
				case "dropped-code-address":
					declarations += "func Address() (result uint64)\n"
					source += fmt.Sprintf("TEXT ·Address(SB),4,$0-8\n"+
						"MOVD $·%s(SB),R0\nMOVD R0,result+0(FP)\nRET\n", test.name())
				case "data-code-address":
					source += fmt.Sprintf("DATA root<>+0(SB)/8,$·%s(SB)\nGLOBL root<>(SB),8,$8\n", test.name())
				}
				t.Run(scope, func(t *testing.T) {
					requireARM64GoAssemblerResult(t, source, true)
					pkg := mustGoPackage(t, "tailobserve", declarations)
					resolve := testResolveSym(pkg.Path)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ctx := llvm.NewContext()
							defer ctx.Dispose()
							var failure error
							if api == "Go" {
								translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
									GOOS: "linux", GOARCH: "arm64", TargetTriple: arm64LinuxGNUTriple,
									ResolveSym: resolve,
									KeepFunc: func(symbol, _ string) bool {
										return symbol == "·"+test.name()
									},
								})
								if translated != nil && !translated.Module.IsNil() {
									translated.Module.Dispose()
								}
								failure = err
							} else {
								file, err := Parse(ArchARM64, source)
								if err != nil {
									t.Fatal(err)
								}
								signatures, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
								if err != nil {
									t.Fatal(err)
								}
								// The low-level API is likewise given only the selected root.
								// Dropping an observer never proves it cannot observe the tail.
								file.Funcs = file.Funcs[:1]
								options := Options{
									Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
									ResolveSym: resolve, Sigs: signatures,
								}
								if api == "text" {
									_, failure = Translate(file, options)
								} else {
									module, err := TranslateModuleInContext(ctx, file, options)
									if !module.IsNil() {
										module.Dispose()
									}
									failure = err
								}
							}
							if failure == nil {
								t.Fatal("callee-only declaration discarded an observable native result-tail write")
							}
							if !errors.Is(failure, ErrProbeNeedsContext) &&
								!(strings.Contains(failure.Error(), "FP frame range") &&
									strings.Contains(failure.Error(), "has no slot")) {
								t.Fatalf("unrelated rejection cannot prove the native-tail boundary: %v", failure)
							}
						})
					}
				})
			}
		})
	}
}
