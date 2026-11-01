package plan9asm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// A source inventory must retain every later instruction when a generated
// header has not supplied an earlier displacement. Retention is not permission
// to translate that displacement, even when a raw RET follows it.
func TestX86UnresolvedSourceMemoryPreservesSyntax(t *testing.T) {
	for _, row := range []struct {
		address string
		raw     string
		base    Reg
		index   Reg
		scale   int64
	}{
		{"UNKNOWN(AX)", "UNKNOWN", AX, "", 0},
		{"g_stackguard0(BP)", "g_stackguard0", BP, "", 0},
		{"g(CX)", "g", CX, "", 0},
		{"(UNKNOWN+4)(AX)", "(UNKNOWN+4)", AX, "", 0},
		{"UNKNOWN+4(AX)(CX*2)", "UNKNOWN+4", AX, CX, 2},
		{"UNKNOWN(AX)(CX)", "UNKNOWN", AX, CX, 0},
	} {
		t.Run(row.address, func(t *testing.T) {
			source := "TEXT one(SB),4,$0-0\nMOVL " + row.address + ",BX\nADDL $7,BX\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			var instructions []Instr
			for _, instruction := range file.Funcs[0].Instrs {
				if instruction.Op != OpTEXT && instruction.Op != OpLABEL {
					instructions = append(instructions, instruction)
				}
			}
			if len(instructions) != 3 || instructions[1].Op != "ADDL" {
				t.Fatal("source inventory lost the instruction after the unresolved operand")
			}
			memory := instructions[0].Args[0]
			if memory.Kind != OpMem || memory.Mem.OffRaw != row.raw || memory.Mem.Off != 0 ||
				memory.Mem.Base != row.base || memory.Mem.Index != row.index || memory.Mem.Scale != row.scale {
				t.Fatalf("lost unresolved syntax: %#v", memory)
			}
			for _, arch := range []string{"386", "amd64"} {
				if err := ProbeInstruction(ArchAMD64, arch, instructions[0]); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s unresolved memory acquired a lowering witness: %v", arch, err)
				}
			}
		})
	}
}

func TestX86UnresolvedSourceMemoryThreeAPIsRejectBeforeRawDecoding(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, opcode := range []string{"MOVL", "VMOVD", "PXOR", "LEAL"} {
			for _, raw := range []bool{false, true} {
				t.Run(target.triple+"/"+opcode+"/raw="+strconv.FormatBool(raw), func(t *testing.T) {
					destination := "BX"
					if opcode == "VMOVD" || opcode == "PXOR" {
						destination = "X0"
					}
					ending := "RET"
					if raw {
						ending = "BYTE $0xc3"
					}
					source := "TEXT ·Value(SB),4,$0-0\n" + opcode + " UNKNOWN(AX)," + destination + "\n" + ending + "\n"
					goAssemblerOracleOutput(t, target.arch, source, "", false)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
					options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve,
						Sigs: map[string]FuncSig{"Value": {Name: "Value", Ret: Void}}}
					pkg := mustGoPackage(t, "memory", "package memory\nfunc Value()\n")
					for _, api := range []string{"text", "module", "GoModule"} {
						t.Run(api, func(t *testing.T) {
							ctx := llvm.NewContext()
							defer ctx.Dispose()
							var err error
							switch api {
							case "text":
								var ir string
								ir, err = Translate(file, options)
								if ir != "" {
									t.Fatal("unresolved memory emitted IR")
								}
							case "module":
								var module llvm.Module
								module, err = TranslateModuleInContext(ctx, file, options)
								if !module.IsNil() {
									module.Dispose()
									t.Fatal("unresolved memory emitted a module")
								}
							case "GoModule":
								var result *GoModuleTranslation
								result, err = translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
									GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
								if result != nil && !result.Module.IsNil() {
									result.Module.Dispose()
									t.Fatal("unresolved memory emitted a Go module")
								}
							}
							if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "UNKNOWN") {
								t.Fatalf("%s lost the unresolved displacement diagnostic: %v", api, err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86UnresolvedSourceMemoryResolvedMacrosThreeAPIsFiveTargets(t *testing.T) {
	const source = `#define OFFSET (3*8)
TEXT ·Value(SB),4,$0-0
MOVL $32,AX
MOVL OFFSET(AX),BX
RET
`
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, ins := range file.Funcs[0].Instrs {
				for _, arg := range ins.Args {
					if arg.Kind == OpMem && (arg.Mem.OffRaw != "" || arg.Mem.Off != 24) {
						t.Fatalf("resolved macro lost its real displacement: %#v", arg)
					}
				}
			}
			resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
			options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve,
				Sigs: map[string]FuncSig{"Value": {Name: "Value", Ret: Void}}}
			// Resolving OFFSET proves its displacement, not that integer 32
			// denotes readable storage. Retain the original format object
			// separately from the three public source-context observations.
			format := x86ScalarFormatObjectUnit(t, file, options.Sigs, target.arch, target.triple, 0)
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, target.triple, format, level)
			}
			pkg := mustGoPackage(t, "memory", "package memory\nfunc Value()\n")
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					var ir string
					var err error
					switch api {
					case "text":
						ir, err = Translate(file, options)
					case "module":
						var module llvm.Module
						module, err = TranslateModuleInContext(ctx, file, options)
						if !module.IsNil() {
							defer module.Dispose()
							ir = module.String()
						}
					case "GoModule":
						var result *GoModuleTranslation
						result, err = translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
							GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
						if result != nil && !result.Module.IsNil() {
							defer result.Module.Dispose()
							ir = result.Module.String()
						}
					}
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("resolved displacement authorized an unbound numerical address: %v", err)
					}
				})
			}
			move, word := "MOVQ", 8
			if target.arch == "386" {
				move, word = "MOVL", 4
			}
			bound := fmt.Sprintf("#define OFFSET (3*8)\nTEXT ·Value(SB),4,$0-%d\n"+
				"%s p+0(FP),AX\nMOVL OFFSET(AX),BX\nRET\n", word, move)
			fixture := x86OriginalGPInitializedFormat{bound, "func Value(p *[32]byte)"}
			x86OriginalGPInitializedFormatObjects(t, []x86OriginalGPInitializedFormat{fixture}, target.arch, target.triple)
		})
	}
}

func TestX86UnresolvedSourceMemoryCannotHideMalformedPhysicalGroups(t *testing.T) {
	for _, address := range []string{
		"UNKNOWN(AX)(CX*3)", "UNKNOWN(AX)(CX*UNKNOWN)", "UNKNOWN(AX)(CX*1)(DX*1)",
	} {
		t.Run(address, func(t *testing.T) {
			// Resolve the displacement for the independent Go syntax rejection:
			// an undefined macro must not be the reason this negative control fails.
			for _, arch := range []string{"386", "amd64"} {
				resolved := "#define UNKNOWN 24\nTEXT one(SB),4,$0-0\nMOVL " + address + ",BX\nRET\n"
				goAssemblerOracleOutput(t, arch, resolved, "", false)
			}
			if _, err := Parse(ArchAMD64, "TEXT one(SB),4,$0-0\nMOVL "+address+",BX\nRET\n"); err == nil {
				t.Fatal("unresolved displacement hid a malformed physical register group")
			}
		})
	}
}

// NAME_AUTO's bare identifier is a descriptive stack name with offset zero,
// not an undefined displacement constant. Keep this independent of the
// unresolved-expression rejection, and bind it to Go's accepted objects.
func TestX86UnresolvedSourceMemoryBareStackNamesRemainResolved(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, name := range []string{"tmp", "UNKNOWN"} {
		for _, target := range x86RawReturnTargets {
			t.Run(name+"/"+target.triple, func(t *testing.T) {
				source := "TEXT ·view(SB),4,$16-0\nMOVL $7," + name + "(SP)\nMOVL " + name + "(SP),AX\nRET\n"
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				for _, ins := range file.Funcs[0].Instrs {
					for _, arg := range ins.Args {
						if arg.Kind == OpMem && (arg.Mem.Base != SP || arg.Mem.Off != 0 || arg.Mem.OffRaw != name) {
							t.Fatalf("bare AUTO syntax lost its name or resolved zero offset: %#v", arg)
						}
					}
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view()\n", target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatalf("resolved bare AUTO name lost its existing object path: %v", err)
						}
						compileLLVMToObject(t, llc, target.triple, "bare-auto.ll", "bare-auto.o", ir)
					})
				}
			})
		}
	}
}

func TestX86UnresolvedSourceMemoryStackNamesCannotResolveExpressions(t *testing.T) {
	for _, row := range []struct {
		name     string
		memory   MemRef
		resolved bool
	}{
		{"bare-auto", MemRef{Base: SP, OffRaw: "tmp"}, true},
		{"bare-upper-auto", MemRef{Base: SP, OffRaw: "UNKNOWN"}, true},
		{"named-constant", MemRef{Base: SP, OffRaw: "tmp+4", Off: 4}, true},
		{"named-expression", MemRef{Base: SP, OffRaw: "tmp-(2*4)", Off: -8}, true},
		{"missing-constant", MemRef{Base: SP, OffRaw: "tmp+UNKNOWN"}, false},
		{"malformed-name", MemRef{Base: SP, OffRaw: "tmp-dig"}, false},
		{"bare-nonzero", MemRef{Base: SP, OffRaw: "tmp", Off: 4}, false},
		{"wrong-resolved-offset", MemRef{Base: SP, OffRaw: "tmp+4", Off: 0}, false},
		{"ordinary-macro", MemRef{Base: AX, OffRaw: "tmp"}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := unresolvedX86MemoryOffsetError(row.memory)
			if row.resolved && err != nil || !row.resolved && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("resolved=%v, got %v", row.resolved, err)
			}
		})
	}
}

func TestX86UnresolvedSourceMemoryEveryDirectionRejectsBeforeRawDecoding(t *testing.T) {
	for _, address := range []string{
		"UNKNOWN(AX)", "(UNKNOWN+4)(AX)", "UNKNOWN(AX)(CX*2)", "UNKNOWN(AX)(FS)", "slot+UNKNOWN(SP)",
	} {
		for _, destination := range []bool{false, true} {
			for _, target := range x86RawReturnTargets {
				t.Run(address+"/destination="+strconv.FormatBool(destination)+"/"+target.triple, func(t *testing.T) {
					operands := address + ",BX"
					if destination {
						operands = "BX," + address
					}
					// The displacement-resolved control proves the physical groups
					// and direction independently; undefined constants are the only
					// source rejection used by this test.
					body := "TEXT ·view(SB),4,$16-0\nMOVL $7,BX\nMOVL " + operands + "\nBYTE $0xc3\n"
					goAssemblerOracleOutput(t, target.arch, "#define UNKNOWN 24\n"+body, "", true)
					goAssemblerOracleOutput(t, target.arch, body, "", false)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, body, "func view()\n", target.arch, target.triple, api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "UNKNOWN") {
								t.Fatalf("%s granted an unresolved memory effect: %v", api, err)
							}
						})
					}
				})
			}
		}
	}
}
