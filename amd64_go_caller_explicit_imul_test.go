package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This directory is independent of the typed effect descriptor. It exercises
// all explicit yimul/yimul3 source classes; one-operand IMUL is not in it.
var x86CallerExplicitIMULRows = []struct {
	name, instruction string
	three             bool
}{
	{"register", "IMUL@ AX,BX", false},
	{"memory", "IMUL@ (DI),BX", false},
	{"immediate8", "IMUL@ $-7,BX", false},
	{"immediate32", "IMUL@ $65537,BX", false},
	{"three-register8", "IMUL3@ $-7,AX,BX", true},
	{"three-register32", "IMUL3@ $65537,AX,BX", true},
	{"three-memory8", "IMUL3@ $-7,(DI),BX", true},
	{"three-memory32", "IMUL3@ $65537,(DI),BX", true},
}

func x86CallerExplicitIMULFixture(t *testing.T, body string) (GoPackage, *File, string, Options) {
	t.Helper()
	declaration := strings.ReplaceAll(x86CallerFixtureSource, "float32", "uint64")
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX\nMOVL AX,(DX)", body+"\nMOVQ BX,(DX)", 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, file := x86CallerCoreFixture(t, declaration, assembly)
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// goSigsForAsmFile already binds the complete actual SourceSelection.
	if sigs["caller.kernel"].x86CallerRegions == nil {
		t.Fatalf("actual complete typed caller precondition failed: %v", err)
	}
	if !x86CallerRegionSourceMatches(sigs["caller.kernel"], file.Funcs[0], "amd64") {
		t.Fatal("actual complete typed caller does not match its original source/signature")
	}
	return pkg, file, assembly, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
}

func TestX86GoCallerExplicitIMULRawReturnRegisteredForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, suffix := range []string{"W", "L", "Q"} {
		for _, row := range x86CallerExplicitIMULRows {
			t.Run(suffix+"/"+row.name, func(t *testing.T) {
				body := "MOVQ $7,AX\n"
				// W preserves the old upper bytes. Two-operand IMUL also reads
				// the old low result; IMUL3L/Q must not require that old result.
				if suffix == "W" || !row.three {
					body += "MOVQ $3,BX\n"
				}
				body += strings.ReplaceAll(row.instruction, "@", suffix)
				pkg, file, assembly, options := x86CallerExplicitIMULFixture(t, body)
				for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
					// Separate format and API/target axes: two representative
					// rows cover all APIs/targets; every row covers text/Linux.
					allAPIs := suffix == "Q" && row.name == "register" || suffix == "L" && row.name == "three-memory32"
					if !allAPIs && triple != "x86_64-unknown-linux-gnu" {
						continue
					}
					options.TargetTriple = triple
					t.Run(triple+"/text", func(t *testing.T) {
						ir, err := Translate(file, options)
						if err != nil {
							t.Fatalf("Go-accepted explicit multiply lacks source/caller effect: %v", err)
						}
						compileLLVMToObject(t, llc, triple, "imul-caller.ll", "imul-caller.o", ir)
					})
					if !allAPIs {
						continue
					}
					t.Run(triple+"/module", func(t *testing.T) {
						ctx := llvm.NewContext()
						defer ctx.Dispose()
						module, err := TranslateModuleInContext(ctx, file, options)
						if !module.IsNil() {
							defer module.Dispose()
						}
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, triple, "imul-caller-module.ll", "imul-caller-module.o", module.String())
					})
					t.Run(triple+"/go", func(t *testing.T) {
						ctx := llvm.NewContext()
						defer ctx.Dispose()
						translated, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
							FileName: "kernel_amd64.s", GOARCH: "amd64", TargetTriple: triple, ResolveSym: options.ResolveSym,
						})
						if translated != nil && !translated.Module.IsNil() {
							defer translated.Module.Dispose()
						}
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, triple, "imul-caller-go.ll", "imul-caller-go.o", translated.Module.String())
					})
				}
			})
		}
	}
}

func TestX86SourceStackExplicitIMULKillsOldComparisonFlags(t *testing.T) {
	for _, op := range []string{"IMULW", "IMULL", "IMULQ", "IMUL3W", "IMUL3L", "IMUL3Q"} {
		t.Run(op, func(t *testing.T) {
			row := op + " AX,BX"
			if strings.HasPrefix(op, "IMUL3") {
				row = op + " $7,AX,BX"
			}
			ins := x86YMMReadSource(t, row)
			state := x86SourceStackState{numericFlags: true, callers: map[Reg]x86CallerPointerValue{}}
			if !x86SourceStackFlagsStep(ins, &state) || state.numericFlags {
				t.Fatal("IMUL retained complete old CMP flags instead of only CF/OF")
			}
			for _, branch := range []string{"JE", "JNE", "JLT", "JGE", "JLE", "JGT", "JMI", "JPL", "JHI", "JLS", "JPS", "JPC", "JCS", "JCC", "JOS", "JOC"} {
				accepted := x86SourceStackFlagsStep(Instr{Op: Op(branch)}, &state)
				want := branch == "JCS" || branch == "JCC" || branch == "JOS" || branch == "JOC"
				if accepted != want {
					t.Fatalf("%s after %s: accepted=%t want=%t", branch, op, accepted, want)
				}
			}
		})
	}
}

func TestX86GoCallerExplicitIMULRetainsContext(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"undefined-input", "MOVQ $7,BX\nIMULQ AX,BX"},
		{"undefined-old-destination", "MOVQ $7,AX\nIMULQ AX,BX"},
		{"partial-input", "MOVB $7,AX\nIMULQ AX,BX"},
		{"partial-word-result", "MOVQ $7,AX\nIMUL3W $7,AX,BX"},
		{"pointer-input", "MOVQ $7,BX\nIMULQ DI,BX"},
		{"pointer-old-destination", "MOVQ DI,BX\nIMULQ $7,BX"},
		{"pointer-survives-word-result", "MOVQ DI,BX\nMOVQ $7,AX\nIMUL3W $7,AX,BX"},
		{"unknown-memory", "MOVQ $7,BX\nIMULQ (R11),BX"},
		{"wide-length-read", "MOVQ $7,BX\nIMULQ 1(CX),BX"},
		{"native-return-pc", "MOVQ $7,BX\nIMULQ 8(BP),BX"},
		{"FP-pointer-input", "MOVQ $7,BX\nIMULQ a+0(FP),BX"},
		{"g-input", "MOVQ $7,BX\nIMULQ R14,BX"},
		{"g-unrestored", "MOVQ $7,AX\nIMUL3Q $7,AX,R14\nMOVQ R14,BX"},
		{"SP-destination", "MOVQ $7,BX\nIMULQ BX,SP"},
		{"BP-input", "MOVQ $7,BX\nIMULQ BP,BX"},
		{"implicit-IMUL", "MOVQ $7,AX\nMOVQ $7,BX\nIMULQ BX"},
		{"implicit-MUL", "MOVQ $7,AX\nMOVQ $7,BX\nMULQ BX"},
		{"implicit-DIV", "MOVQ $7,AX\nMOVQ $7,BX\nMOVQ $0,DX\nDIVQ BX"},
		{"implicit-IDIV", "MOVQ $7,AX\nMOVQ $7,BX\nMOVQ $0,DX\nIDIVQ BX"},
		{"unknown-CFG-input", "MOVQ $7,BX\nCMPQ BX,$0\nJE joined\nMOVQ $7,AX\njoined:\nIMULQ AX,BX"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg, file, assembly, options := x86CallerExplicitIMULFixture(t, test.body)
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved IMUL effect acquired authority: %v", err)
			}
			ctx := llvm.NewContext()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				module.Dispose()
			}
			ctx.Dispose()
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("module accepted unproved IMUL: %v", err)
			}
			ctx = llvm.NewContext()
			translated, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
				FileName: "kernel_amd64.s", GOARCH: "amd64", TargetTriple: options.TargetTriple, ResolveSym: options.ResolveSym,
			})
			if translated != nil && !translated.Module.IsNil() {
				translated.Module.Dispose()
			}
			ctx.Dispose()
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("Go API accepted unproved IMUL: %v", err)
			}
		})
	}
}

func TestX86GoCallerExplicitIMULActualInitializedLocalRead(t *testing.T) {
	// The retained actual caller declares `var res uint64`: Go initializes
	// those complete numerical bytes before the call. This is not an unknown
	// native entry region, nor permission to read an arbitrary result pointer.
	_, file, _, options := x86CallerExplicitIMULFixture(t, "MOVQ $7,BX\nIMULQ (DX),BX")
	if _, err := Translate(file, options); err != nil {
		t.Fatal(err)
	}
}

func TestX86GoCallerExplicitIMULFlagsAndSavedFlags(t *testing.T) {
	for _, condition := range []string{"CC", "CS", "EQ", "NE", "GE", "LT", "GT", "LE", "HI", "LS", "MI", "PL", "OC", "OS", "PC", "PS"} {
		for _, consumer := range []string{"SET", "CMOVQ", "J"} {
			t.Run(consumer+condition, func(t *testing.T) {
				body := "MOVQ $7,AX\nMOVQ $3,BX\nCMPQ AX,$0\nIMULQ AX,BX\n"
				switch consumer {
				case "SET":
					body += "SET" + condition + " BL"
				case "CMOVQ":
					body += "CMOVQ" + condition + " AX,BX"
				case "J":
					body += "J" + condition + " joined\njoined:"
				}
				_, file, _, options := x86CallerExplicitIMULFixture(t, body)
				_, err := Translate(file, options)
				defined := condition == "CC" || condition == "CS" || condition == "OC" || condition == "OS"
				if defined && err != nil || !defined && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("IMUL flag consumer defined=%t: %v", defined, err)
				}
			})
		}
	}
	for _, test := range []struct {
		name, body string
		accepted   bool
	}{
		{"restore-complete", "CMPQ AX,$0\nPUSHFQ\nIMULQ AX,BX\nPOPFQ\nSETEQ BL", true},
		{"restore-partial", "IMULQ AX,BX\nPUSHFQ\nCMPQ AX,$0\nPOPFQ\nSETEQ BL", false},
		{"restore-CF", "IMULQ AX,BX\nPUSHFQ\nCMPQ AX,$0\nPOPFQ\nSETCS BL", true},
		{"carry-after-multiply", "IMULQ AX,BX\nADCQ $1,BX", true},
		{"CMP-redefines-flags", "IMULQ AX,BX\nCMPQ AX,$0\nSETEQ BL", true},
		{"shift-does-not-resurrect-OF", "IMULQ AX,BX\nSHLQ $2,BX\nSETOS BL", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, file, _, options := x86CallerExplicitIMULFixture(t, "MOVQ $7,AX\nMOVQ $3,BX\n"+test.body)
			_, err := Translate(file, options)
			if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("FLAGS dependency accepted=%t: %v", test.accepted, err)
			}
		})
	}
}

func TestX86SourceStackExplicitIMULWithoutCallerRemainsContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, suffix := range []string{"W", "L", "Q"} {
			if arch == "386" && suffix == "Q" {
				continue // Independently Go-rejected Q rows are in the encoder oracle.
			}
			for _, three := range []bool{false, true} {
				body := "@MOV $7,AX\n@MOV $3,BX\nIMUL" + suffix + " AX,BX\n@MOV BX,@RESULT(SP)\nBYTE $0xc3"
				if three {
					body = strings.Replace(body, "IMUL"+suffix+" AX,BX", "IMUL3"+suffix+" $7,AX,BX", 1)
				}
				t.Run(fmt.Sprintf("%s/%s/three=%t", arch, suffix, three), func(t *testing.T) {
					source, sig, _ := x86SourceStackNumericalFixture(arch, body)
					goAssemblerOracleOutput(t, arch, source, "", true)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := Translate(file, x86SourceStackOptions(arch, "", sig)); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("declaration-only source acquired complete numerical input proof: %v", err)
					}
				})
			}
		}
	}
}
