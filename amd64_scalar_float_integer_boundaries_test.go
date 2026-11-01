package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarFloatIntegerHelperOwnership(t *testing.T) {
	for _, operation := range []Op{"ADDQ", "MOVQ", "UNKNOWN.CVTSS2SL", "CVTSS2SL"} {
		var ir strings.Builder
		ctx := amd64Ctx{b: &ir, goarch: "amd64", targetTriple: "x86_64-unknown-linux-gnu"}
		ins := x86ScalarLaneInstruction(t, "MOVQ AX,BX")
		known, terminated, err := ctx.lowerScalarFloatToInteger(operation, ins)
		_, effectKnown, effectErr := x86TypedScalarFloatIntegerByteEffect(operation, ins, "amd64")
		want := operation == "CVTSS2SL"
		if known != want || effectKnown != want || (err != nil) != want || (effectErr != nil) != want || terminated || ir.Len() != 0 {
			t.Fatal("family helper claimed foreign dispatch or emitted before validation", operation, known, effectKnown, err, effectErr, ir.String())
		}
	}
}

func TestX86ScalarFloatIntegerTypedEveryByteAndFlags(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86ScalarFloatIntegerOracleNames() {
			if arch == "386" && !strings.HasPrefix(name, "V") && strings.HasSuffix(name, "Q") {
				continue
			}
			width := 4
			if strings.Contains(name, "SD") {
				width = 8
			}
			for missing := -1; missing < 64; missing++ {
				ins := x86ScalarLaneInstruction(t, name+" X1,AX")
				state := &x86ResultState{flags: 0x3f}
				known := ^uint64(0)
				if missing >= 0 {
					known &^= 1 << uint(missing)
				}
				state.writeVector(1, 64, known, false)
				state.pointerGP[0] = true
				accepted := x86ResultTransfer(ins, state, nil, 0, arch)
				want := missing < 0 || missing >= width
				if accepted != want || state.flags != 0x3f || state.vectorBytes(1) != known ||
					accepted && (state.gp[0] != 0xff || state.pointerGP[0]) {
					t.Fatal("scalar read/write/flags boundary", arch, name, missing, accepted, state)
				}
			}
			for _, kind := range []string{"FP", "AUTO", "SB", "pointer"} {
				for missing := -1; missing < width; missing++ {
					owned := make([]bool, 16)
					state := &x86ResultState{fp: make([]bool, 16), auto: make([]bool, 16)}
					for i := range owned {
						owned[i], state.fp[i], state.auto[i] = i != missing, i != missing, i != missing
					}
					operand := "value+0(FP)"
					switch kind {
					case "AUTO":
						operand = "local-16(SP)"
					case "SB":
						operand = "external(SB)"
					case "pointer":
						operand = "(BX)"
						state.pointerGP[3] = true
					}
					accepted := x86ResultTransfer(x86ScalarLaneInstruction(t, name+" "+operand+",AX"), state, owned, 0, arch)
					want := (kind == "FP" || kind == "AUTO") && missing == -1
					if accepted != want {
						t.Fatal("memory role acquired unwritten bytes", arch, name, kind, missing, accepted)
					}
				}
			}
		}
	}
}

func TestX86ScalarFloatIntegerSourceAndRawBoundaries(t *testing.T) {
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		for _, text := range []string{"Y0,AX", "Z0,AX", "M0,AX", "K1,AX", "$1,AX", "X0,X1", "X0,AH", "X0,K1", "X0,(BX)"} {
			if _, known, err := x86ScalarFloatIntegerProperties(x86ScalarLaneInstruction(t, name+" "+text), "amd64"); !known || err == nil {
				t.Fatal("bad operand accepted", name, text, err)
			}
		}
		for _, suffix := range []string{".", ".Z", ".BCST", ".SAE.SAE", ".RN_SAE.Z"} {
			if _, _, err := x86ScalarFloatIntegerProperties(x86ScalarLaneInstruction(t, name+suffix+" X0,AX"), "amd64"); err == nil {
				t.Fatal("bad suffix accepted", name, suffix)
			}
		}
		for _, change := range []string{"offset", "index", "scale", "base", "SP index", "symbol address"} {
			ins := x86ScalarLaneInstruction(t, name+" (BX),AX")
			switch change {
			case "offset":
				ins.Args[0].Mem.OffRaw = "missing"
			case "index":
				ins.Args[0].Mem.IndexExt = "missing"
			case "scale":
				ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 3
			case "base":
				ins.Args[0].Mem.Base = "X0"
			case "SP index":
				ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = SP, 1
			case "symbol address":
				ins.Args[0] = Operand{Kind: OpSym, Sym: "$data(SB)"}
			}
			if _, _, err := x86ScalarFloatIntegerProperties(ins, "amd64"); err == nil {
				t.Fatal("constructed memory accepted", name, change)
			}
		}
	}
	for _, mode := range []int{32, 64} {
		for _, w := range []byte{0, 0x80} {
			for _, ll := range []byte{0, 0x20, 0x40, 0x60} {
				for _, opcode := range []byte{0x2c, 0x2d, 0x78, 0x79} {
					code := []byte{0x62, 0xf1, 0x7e | w, 0x08 | ll, opcode, 0x81, 1, 0, 0, 0}
					ins, length, known, err := decodedX86ScalarFloatToIntegerInstruction(code, mode)
					if !known || err != nil || length != len(code) || !ins.x86ScalarFloatIntegerEVEX {
						t.Fatal("EVEX WIG/LLIG byte identity", mode, code, ins, length, err)
					}
					for end := 0; end < len(code); end++ {
						_, consumed, recognized, err := decodedX86ScalarFloatToIntegerInstruction(code[:end], mode)
						if recognized && err == nil || consumed > end {
							t.Fatal("truncated full encoding accepted", code, end, err)
						}
					}
				}
			}
		}
	}
}

func TestX86ScalarFloatIntegerWholeFileTargetAndResultBoundaries(t *testing.T) {
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		for _, api := range []string{"text", "module", "Go"} {
			for _, dead := range []bool{false, true} {
				before := ""
				if dead {
					before = "RET\n"
				}
				for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown", "i386-unknown-linux-gnu", "x86_64madeup-unknown-linux-gnu"} {
					source := "TEXT ·view(SB),4,$0-0\n" + before + name + " X0,AX\nRET\n"
					if _, err := x86ScalarFPBitViewAPI(t, source, "func view()\n", "amd64", triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("missing native target was not rejected", name, api, dead, triple, err)
					}
				}
			}
			for _, initialized := range []bool{false, true} {
				setup := ""
				if initialized {
					setup = "XORPS X0,X0\n"
				}
				source := "TEXT ·view(SB),4,$0-4\n" + setup + name + " X0,AX\nMOVL AX,X1\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n"
				_, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", "amd64", "x86_64-unknown-linux-gnu", api)
				if initialized && err != nil || !initialized && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("result initialization boundary", name, api, initialized, err)
				}
			}
		}
	}
}

func TestX86ScalarFloatIntegerFiveTargetsThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, decl strings.Builder
			count := 0
			for _, row := range x86ScalarFloatIntegerFormRows(target.arch) {
				ins := x86ScalarLaneInstruction(t, row)
				if _, _, err := x86ScalarFloatIntegerProperties(ins, target.arch); err != nil {
					continue // Already asserted separately as high-bank Context.
				}
				// Physical stack writes and logical FP/AUTO have independent
				// ABI storage tests; this object axis is ordinary registers/mem.
				if strings.Contains(row, "FP)") || strings.Contains(row, "SP)") || ins.Args[1].Reg == SP || strings.Contains(row, "(FS)") || strings.Contains(row, "(GS)") {
					continue
				}
				fmt.Fprintf(&source, "TEXT ·probe%d(SB),4,$0-0\n%s\nRET\n", count, row)
				fmt.Fprintf(&decl, "func probe%d()\n", count)
				count++
			}
			ir := x86UnboundVoidRawScalarFormatObject(t, source.String(), target.arch, target.triple)
			for _, optimized := range []bool{false, true} {
				input := ir
				if optimized {
					input = x86MulDivRoundOptimize(t, input)
				}
				compileLLVMToObject(t, llc, target.triple, "scalar-float-int.ll", "scalar-float-int.o", input)
			}
			t.Logf("%d unchanged original Go formats; 3 public APIs require input Context; 2 private emitter IR object pipelines, no initialized/native claim", count)
		})
	}
}

func TestX86ScalarFloatIntegerLogicalFPByteBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, name := range x86ScalarFloatIntegerOracleNames() {
			if target.arch == "386" && !strings.HasPrefix(name, "V") && strings.HasSuffix(name, "Q") {
				continue
			}
			bits, parameters, result := 32, "a,b,c,d uint8", 4
			if strings.Contains(name, "SD") {
				bits, parameters, result = 64, "a,b,c,d uint16", 8
			}
			if target.arch == "amd64" {
				result = 8 // ABI0 aligns the input/result boundary to a word.
			}
			for _, api := range []string{"text", "module", "Go"} {
				for _, invalid := range []string{"", "past end", "pointer", "padding"} {
					params, offset := parameters, 0
					switch invalid {
					case "past end":
						offset = 1
					case "pointer":
						params = "a *uint64"
					case "padding":
						params = "a uint8,b uint32"
					}
					source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s a+%d(FP),AX\nMOVL AX,X1\nPEXTRD $0,X1,AX\nMOVL AX,ret+%d(FP)\nRET\n", result+4, name, offset, result)
					_, err := x86ScalarFPBitViewAPI(t, source, "func view("+params+") uint32\n", target.arch, target.triple, api)
					if invalid == "" && err != nil || invalid != "" && err == nil {
						t.Fatal("logical FP conversion byte boundary", target.triple, name, bits, api, invalid, err)
					}
				}
			}
		}
	}
}
