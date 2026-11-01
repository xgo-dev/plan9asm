package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type x86ScalarPrecisionRawCase struct {
	row        x86ScalarPrecisionOracleRow
	code       []byte
	generation string
}

func x86ScalarPrecisionRawCases() []x86ScalarPrecisionRawCase {
	var cases []x86ScalarPrecisionRawCase
	for _, spec := range rawScalarPrecisionConvertSpecs {
		for _, generation := range []string{"legacy", "VEX", "EVEX"} {
			for _, memory := range []bool{false, true} {
				row := x86ScalarPrecisionOracleRow{op: string(spec.legacy), input: spec.inputBytes,
					output: 12 - spec.inputBytes, source: "register"}
				code := encodeX86RawLegacyScalarPrecisionConvert(spec, 0, 2)
				if generation != "legacy" {
					row.op, row.vector, row.mode = string(spec.vector), true, "plain"
					code = encodeX86RawVEXScalarPrecisionConvert(spec, 0, 1, 2)
				}
				if generation == "EVEX" {
					code = encodeX86RawEVEXScalarPrecisionConvert(spec, -1, 0, false, 0, 1, 2)
				}
				if memory {
					row.source, code[len(code)-1] = "native", 0x10 // Exact (AX), not a fabricated FP backing.
				}
				cases = append(cases, x86ScalarPrecisionRawCase{row, code, generation})
			}
		}
		for _, mode := range []string{"plain", "merge", "zero"} {
			controls := []int{-1, 0}
			if spec.inputBytes == 8 {
				controls = []int{-1, 0, 1, 2, 3}
			}
			for _, control := range controls {
				for _, memory := range []bool{false, true} {
					if mode == "plain" && control < 0 || memory && control >= 0 {
						continue // Already listed, or absent from the physical ISA.
					}
					row := x86ScalarPrecisionOracleRow{op: string(spec.vector), input: spec.inputBytes,
						output: 12 - spec.inputBytes, source: "register", vector: true, mode: mode}
					mask := 0
					if mode != "plain" {
						mask = 1
					}
					if control >= 0 {
						row.control = "SAE"
						if spec.inputBytes == 8 {
							row.control = []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}[control]
						}
					}
					code := encodeX86RawEVEXScalarPrecisionConvert(spec, control, mask, mode == "zero", 0, 1, 2)
					if memory {
						row.source, code[len(code)-1] = "native", 0x10
					}
					cases = append(cases, x86ScalarPrecisionRawCase{row, code, "EVEX"})
				}
			}
		}
	}
	return cases
}

func x86ScalarPrecisionRawRegisterSource(name string, row x86ScalarPrecisionRawCase) string {
	source := "TEXT ·" + name + "(SB),4,$0-0\nXORPS X0,X0\nXORPS X1,X1\nXORPS X2,X2\n"
	if row.row.mode == "merge" || row.row.mode == "zero" {
		source += "MOVL $1,AX\nKMOVD AX,K1\n"
	}
	return source + x86RawDisplacementDirectives(row.code) + "RET\n"
}

func TestX86ScalarPrecisionRawGenerationAndWholeSourceIdentity(t *testing.T) {
	rows := x86ScalarPrecisionRawCases()
	if len(rows) != 35 {
		t.Fatal("complete independent low-bank physical precision directory changed", len(rows))
	}
	for _, arch := range []string{"amd64", "386"} {
		for index, row := range rows {
			if row.row.source != "register" || arch == "386" && (row.row.mode == "merge" || row.row.mode == "zero") {
				continue // Native pointers and Go's mode32 mask cap are independent scopes.
			}
			name := fmt.Sprint("RawPrecision", index)
			t.Run(arch+"/"+row.generation+"/"+row.row.instruction(), func(t *testing.T) {
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86ScalarPrecisionRawRegisterSource(name, row)), arch)
				if err != nil {
					t.Fatal(err)
				}
				function := file.Funcs[0]
				ordinal := len(function.Instrs) - 2
				instruction := function.Instrs[ordinal]
				check := func(function Func, targetArch string) error {
					triple := "x86_64-unknown-linux-gnu"
					if targetArch == "386" {
						triple = "i386-unknown-linux-gnu"
					}
					consumer := newX86Ctx(new(strings.Builder), function, FuncSig{Name: name, Ret: Void}, nil, nil, targetArch, triple, false)
					return consumer.checkLoweredScalarFPResultInitialization()
				}
				namedSource := strings.Replace(x86ScalarPrecisionRawRegisterSource(name, row),
					x86RawDisplacementDirectives(row.code), row.row.instruction()+"\n", 1)
				named := mustParseX86RawReturn(t, namedSource)
				if named.Funcs[0].x86RawReplay != nil || check(named.Funcs[0], arch) != nil {
					t.Fatal("physical-origin negative rejected the independently initialized named control")
				}
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{instruction}})
				if strings.Contains(features, "+avx512f") != (row.generation == "EVEX") {
					t.Fatal("isolated native instruction lost its physical EVEX generation", row.generation, features)
				}
				if err := check(function, arch); err != nil {
					t.Fatal("actual initialized whole-source raw conversion lost its paired native continuation", err)
				}
				for _, mutation := range []struct {
					name string
					edit func(*Func)
				}{
					{"missing replay", func(fn *Func) { fn.x86RawReplay = nil }},
					{"producer changed", func(fn *Func) { fn.Instrs[1].Raw += " " }},
					{"origin only", func(fn *Func) { fn.Instrs[ordinal].x86SourceRaw = nil }},
					{"encoded only", func(fn *Func) { fn.Instrs[ordinal].x86Encoded = false }},
					{"physical generation", func(fn *Func) {
						fn.Instrs[ordinal].x86ScalarPrecisionEVEX = !fn.Instrs[ordinal].x86ScalarPrecisionEVEX
					}},
					{"snapshot generation", func(fn *Func) {
						origin := fn.Instrs[ordinal].x86SourceRaw
						origin.scalarPrecision.evex = !origin.scalarPrecision.evex
					}},
					{"snapshot mode", func(fn *Func) { fn.Instrs[ordinal].x86SourceRaw.scalarPrecision.arch = "arm64" }},
					{"missing snapshot", func(fn *Func) {
						fn.Instrs[ordinal].x86SourceRaw.scalarPrecision = x86RawScalarPrecisionIdentity{}
					}},
					{"named laundering", func(fn *Func) {
						fn.Instrs[ordinal].x86Encoded, fn.Instrs[ordinal].x86SourceRaw = false, nil
					}},
					{"physical width", func(fn *Func) { fn.Instrs[ordinal].x86VectorBytes = 32 }},
					{"physical address", func(fn *Func) { fn.Instrs[ordinal].x86AddressBits = 32 }},
					{"operand", func(fn *Func) { fn.Instrs[ordinal].Args[0].Reg = "X3" }},
				} {
					changed := function
					changed.Instrs = cloneX86ReplayInstrs(function.Instrs)
					mutation.edit(&changed)
					if err := check(changed, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("mutable origin or changed complete source acquired raw native rights", mutation.name, err)
					}
				}
				foreign := "386"
				if arch == "386" {
					foreign = "amd64"
				}
				if err := check(function, foreign); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("same low banks borrowed a different source architecture", err)
				}
				if err := function.x86RawReplay.validate(function, arch); err != nil {
					t.Fatal("negative clone mutated original complete-source identity", err)
				}
			})
		}
	}
}

func TestX86ScalarPrecisionRawInitializedGenerationThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete raw scalar precision objects require LLVM22")
	}
	var source, declarations strings.Builder
	functions, generations := make(map[string][]string), make(map[string]bool)
	for index, row := range x86ScalarPrecisionRawCases() {
		body, declaration, name := x86ScalarPrecisionInitializedProgram(index, row.row)
		if strings.Count(body, row.row.instruction()+"\n") != 1 {
			t.Fatal("raw encoding must replace exactly its independently typed original instruction", index)
		}
		source.WriteString(strings.Replace(body, row.row.instruction()+"\n", x86RawDisplacementDirectives(row.code), 1))
		declarations.WriteString(declaration)
		functions[name], generations[name] = []string{row.row.op}, row.generation == "EVEX"
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
					if err != nil {
						t.Fatal("complete initialized physical conversion lost its actual native owner", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86ScalarPrecisionRequireNativeEffects(t, text, functions)
						context := llvm.NewContext()
						module, err := parseIRModuleInContext(context, text)
						if err != nil {
							if !module.IsNil() {
								module.Dispose()
							}
							context.Dispose()
							t.Fatal(err)
						}
						for name, evex := range generations {
							body := module.NamedFunction(name).String()
							if strings.Contains(body, "{evex}") != evex {
								module.Dispose()
								context.Dispose()
								t.Fatal("actual function replaced its original physical encoding generation", name, evex, body)
							}
						}
						module.Dispose()
						context.Dispose()
						compileLLVMToObject(t, llc, triple, "raw-precision-generation.ll", "raw-precision-generation.o", text)
					}
				})
			}
		})
	}
}
