package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func x86RawStaticReplayScalar(width int, addressTaken bool) []byte {
	read := []byte{0x8b, 0x05, 1, 0, 0, 0}
	if width == 8 {
		read = append([]byte{0x48}, read...)
	}
	var code []byte
	if addressTaken {
		// LEAQ pool,BX, retaining the same pool as the following scalar read.
		code = append(code, 0x48, 0x8d, 0x1d, byte(len(read)+1), 0, 0, 0)
	}
	code = append(code, read...)
	code = append(code, 0xc3)
	for index := 0; index < width; index++ {
		code = append(code, byte(index*17+1))
	}
	return code
}

func TestX86RawStaticReplayCapturesDecoderBeforeSymbolRebinding(t *testing.T) {
	cases := []struct {
		name string
		code []byte
	}{
		{"scalar32", x86RawStaticReplayScalar(4, false)},
		{"scalar64", x86RawStaticReplayScalar(8, false)},
		{"address32", x86RawStaticReplayScalar(4, true)},
		{"address64", x86RawStaticReplayScalar(8, true)},
		{"legacy-vector", x86RawLegacyPackedMoveConstant(0xf3, 0x6f)},
		{"vex-vector", x86RawPackedMoveLiteral(false, 32)},
		{"evex-vector", x86RawPackedMoveLiteral(true, 64)},
		{"nonfirst-source", x86RawCLMULLiteral("legacy", 16)},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			original := mustParseX86RawReturn(t, x86StaticReturnSource("Bound", row.code))
			decoded, err := decodeX86RawDirectives(original.Funcs[0], "amd64")
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := NormalizeRawFileForTranslation(original, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			fn := prepared.Funcs[0]
			replay := fn.x86RawReplay
			if replay == nil || len(prepared.Data) != 1 {
				t.Fatal("complete raw source or its one materialized pool was lost")
			}
			if !reflect.DeepEqual(replay.decoded, decoded.Instrs) {
				t.Error("decoder checkpoint already contains file-local symbol rebinding")
			}
			if !reflect.DeepEqual(replay.normalized, fn.Instrs) {
				t.Error("final checkpoint lost the complete materialized source")
			}
			if err := replay.validate(fn, "amd64"); err != nil {
				t.Error("authentic decoder and final source do not replay", err)
			}
			for name, mutate := range map[string]func(*Func){
				"symbol": func(fn *Func) { fn.Sym += "Changed" },
				"frame":  func(fn *Func) { fn.FrameSize = 8 },
				"args":   func(fn *Func) { fn.ArgSize = 8 },
				"opcode": func(fn *Func) { fn.Instrs[1].Op = "NOP" },
				"raw":    func(fn *Func) { fn.Instrs[1].Raw += " changed" },
				"operand": func(fn *Func) {
					fn.Instrs[1].Args[0] = Operand{Kind: OpReg, Reg: AX}
				},
			} {
				changed := fn
				changed.Instrs = cloneX86ReplayInstrs(fn.Instrs)
				mutate(&changed)
				if !errors.Is(replay.validate(changed, "amd64"), ErrProbeNeedsContext) {
					t.Error("rebound decoder snapshot authorized a changed source", name)
				}
			}
		})
	}
}

func TestX86RawStaticReplayScalarResultsThreeAPIs(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, addressTaken := range []bool{false, true} {
			source := x86StaticReturnSource("Bound", x86RawStaticReplayScalar(width, addressTaken))
			requireX86GoAssemblerResult(t, "amd64", source, true)
			for _, target := range x86RawReturnTargets {
				if target.arch != "amd64" {
					continue // These physical encodings use 64-bit RIP addressing.
				}
				t.Run(fmt.Sprintf("%s/width%d/address%t", target.triple, width, addressTaken), func(t *testing.T) {
					typ := I32
					if width == 8 {
						typ = I64
					}
					options := Options{Goarch: "amd64", TargetTriple: target.triple,
						Sigs: map[string]FuncSig{"Bound": {Name: "Bound", Ret: typ}}}
					for _, prepared := range []bool{false, true} {
						file := mustParseX86RawReturn(t, source)
						if prepared {
							var err error
							file, err = NormalizeRawFileForTranslation(file, "amd64")
							if err != nil {
								t.Fatal(err)
							}
						}
						for _, api := range []string{"text", "module", "owned-module"} {
							ir, err := x86X87UnboundOriginalAPI(t, file, options, api)
							if err != nil || ir == "" {
								t.Error("complete raw scalar result was rejected", prepared, api, err)
							}
						}
					}
				})
			}
		}
	}
}

// Execute the lowered scalar/data semantics on the actual host. The unchanged
// native cross-runtime owner separately executes the original Go instructions.
func TestX86RawStaticReplayPortableValuesAndMutablePool(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang are required")
	}
	var source, declarations, checks strings.Builder
	declarations.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	options := Options{Goarch: "amd64", TargetTriple: testTargetTriple(runtime.GOOS, runtime.GOARCH),
		Sigs: make(map[string]FuncSig), ResolveSym: func(symbol string) string {
			if strings.HasPrefix(symbol, "·__plan9asm_raw_address_") {
				return "MutablePool"
			}
			return symbol
		}}
	values := []uint64{0, 1, 0x80000001, 0xffffffff, 0x89abcdef01234567, 0xfedcba9876543210}
	for _, width := range []int{4, 8} {
		for index, value := range values {
			name := fmt.Sprintf("Scalar%d_%d", width, index)
			code := x86RawStaticReplayScalar(width, false)
			typ, cType := I32, "uint32_t"
			if width == 4 {
				value = uint64(uint32(value))
				binary.LittleEndian.PutUint32(code[len(code)-width:], uint32(value))
			} else {
				typ, cType = I64, "uint64_t"
				binary.LittleEndian.PutUint64(code[len(code)-width:], value)
			}
			source.WriteString(x86StaticReturnSource(name, code))
			options.Sigs[name] = FuncSig{Name: name, Ret: typ}
			fmt.Fprintf(&declarations, "extern %s %s(void);\n", cType, name)
			fmt.Fprintf(&checks, "if(%s()!=0x%xULL){fprintf(stderr,\"%s wrong\\n\");return 1;}\n",
				name, value, name)
		}
	}
	mutable := x86RawStaticReplayScalar(8, true)
	binary.LittleEndian.PutUint64(mutable[len(mutable)-8:], 0x89abcdef01234567)
	source.WriteString(x86StaticReturnSource("Mutable", mutable))
	options.Sigs["Mutable"] = FuncSig{Name: "Mutable", Ret: I64}
	declarations.WriteString("extern uint64_t Mutable(void);\nextern uint64_t MutablePool[];\n")
	checks.WriteString("if(Mutable()!=0x89abcdef01234567ULL){fprintf(stderr,\"initial pool wrong\\n\");return 1;}\n")
	checks.WriteString("MutablePool[0]=0xfedcba9876543210ULL;\n")
	checks.WriteString("if(Mutable()!=0xfedcba9876543210ULL){fprintf(stderr,\"changed pool folded\\n\");return 1;}\n")
	if len(options.Sigs) != 13 {
		t.Fatal("complete scalar value and mutable-pool denominator changed")
	}
	reference := declarations.String() + "int main(void){\n" + checks.String() + "return 0;}\n"
	file := mustParseX86RawReturn(t, source.String())
	for _, api := range []string{"text", "module", "owned-module"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86X87UnboundOriginalAPI(t, file, options, api)
			if err != nil || ir == "" {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				input := ir
				if optimized {
					input = x86DwordProductIROptimize(t, ir)
				}
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend-O%d", optimized, level), func(t *testing.T) {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang},
							"raw-static-replay", options.TargetTriple, input, reference, nil, level)
					})
				}
			}
		})
	}
}
