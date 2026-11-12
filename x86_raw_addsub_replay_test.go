package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86RawReplayNormalizationModeAliases(t *testing.T) {
	const source = "TEXT Value(SB),4,$0-0\nBYTE $0x90\nRET\n"
	for _, first := range []string{"", "amd64", "386"} {
		original := mustParseX86RawReturn(t, source)
		normalized, err := normalizeX86RawFile(original, first)
		if err != nil || normalized.Funcs[0].x86RawReplay == nil {
			t.Fatal("original raw mode prerequisite", first, err)
		}
		for _, second := range []string{"", "amd64", "386"} {
			t.Run(first+"/to/"+second, func(t *testing.T) {
				_, err := normalizeX86RawFile(normalized, second)
				compatible := (first == "386") == (second == "386")
				if compatible && err != nil || !compatible && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("default AMD64 alias or explicit source-mode identity changed", first, second, err)
				}
				if normalized.Funcs[0].x86RawReplay.goarch != first {
					t.Fatal("normalization rewrote the retained source mode")
				}
			})
		}
	}
}

func TestX86RawAddSubPublicWholeProducerReplay(t *testing.T) {
	// Exact source and by-value declaration from the independently initialized
	// raw positive. Both vectors are actual typed numeric inputs, not pointers.
	const source = "TEXT Value(SB),4,$0-48\nMOVUPD a+0(FP),X0\nMOVUPD b+16(FP),X1\n" +
		"LONG $0xc1d0f9c5\nMOVUPD X0,ret+32(FP)\nRET\n"
	const declaration = "func Value(a,b [16]byte) [16]byte"
	pkg := mustGoPackage(t, "addsubreplay", "package addsubreplay\n"+declaration)
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	for _, target := range x86RawReturnTargets {
		requireX86GoAssemblerResult(t, target.arch, source, true)
		parsed := mustParseX86RawReturn(t, source)
		signatures, err := goSigsForAsmFile(pkg, parsed, resolve, target.arch, nil, nil, nil)
		if err != nil {
			t.Fatal("actual by-value declaration/frame prerequisite", err)
		}
		normalized, err := normalizeX86RawFile(parsed, target.arch)
		if err != nil || len(normalized.Funcs) != 1 {
			t.Fatal("original raw producer normalization prerequisite", err)
		}
		original, ordinal := normalized.Funcs[0], -1
		for index, ins := range original.Instrs {
			if ins.Op == "VADDSUBPD" && ins.x86SourceRaw != nil {
				if ordinal >= 0 {
					t.Fatal("ambiguous original raw arithmetic")
				}
				ordinal = index
			}
		}
		if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, target.arch) != nil {
			t.Fatal("original producer lost its independently sealed source replay")
		}
		for _, change := range []string{"valid", "origin", "origin-and-opcode", "origin-and-operand", "missing-replay"} {
			for _, api := range []string{"text", "module"} {
				t.Run(target.triple+"/"+change+"/"+api, func(t *testing.T) {
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					ins := &candidate.Instrs[ordinal]
					if strings.HasPrefix(change, "origin") {
						ins.x86SourceRaw = nil
						if !x86ResultNamedPredicateInstruction(*ins) {
							t.Fatal("origin mutation did not isolate the otherwise named instruction")
						}
					}
					switch change {
					case "origin-and-opcode":
						ins.Op = "VADDSUBPS" // Same initialized input/output carriers.
					case "origin-and-operand":
						ins.Args[0].Reg = "X0" // X0 is fully defined by a, unlike an invented X7.
					case "missing-replay":
						candidate.x86RawReplay = nil
					}
					if err := x86LoweredNumericalProducerReplay(candidate, target.arch); (change == "valid" && err != nil) ||
						(change != "valid" && !errors.Is(err, ErrProbeNeedsContext)) {
						t.Fatal("whole producer replay precondition changed", err)
					}
					file := *normalized
					file.Funcs = []Func{candidate}
					options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: signatures}
					var ir string
					var callErr error
					if api == "text" {
						ir, callErr = Translate(&file, options)
					} else {
						context := llvm.NewContext()
						module, err := TranslateModuleInContext(context, &file, options)
						callErr = err
						if !module.IsNil() {
							ir = module.String()
							module.Dispose()
						}
						context.Dispose()
					}
					if change == "valid" {
						if callErr != nil || ir == "" {
							t.Fatal("independently initialized original raw producer rejected", callErr)
						}
					} else if ir != "" || !errors.Is(callErr, ErrProbeNeedsContext) {
						t.Fatal("public API accepted an erased or edited original raw producer", callErr)
					}
					if original.x86RawReplay.validate(original, target.arch) != nil {
						t.Fatal("candidate mutation corrupted the retained original replay")
					}
				})
			}
		}
	}
}
