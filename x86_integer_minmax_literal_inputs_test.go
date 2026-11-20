package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86IntegerMinMaxInitializedLiteralPrograms(t *testing.T) []string {
	t.Helper()
	var programs []string
	for _, op := range x86MinMaxTestOps {
		qword := strings.HasSuffix(op, "Q")
		for _, evex := range []bool{false, true} {
			if !evex && qword {
				continue
			}
			for _, width := range []int{16, 32, 64} {
				if !evex && width == 64 {
					continue
				}
				for _, broadcast := range []bool{false, true} {
					if broadcast && (!evex || !qword && !strings.HasSuffix(op, "D")) {
						continue
					}
					for mode := 0; mode < 3; mode++ {
						if !evex && mode != 0 {
							continue
						}
						mask := 0
						if mode != 0 {
							mask = 7
						}
						code := x86RawMinMaxLiteral(op, evex, width, mask, mode == 2, broadcast)
						programs = append(programs, fmt.Sprintf("TEXT ·Literal%d(SB),4,$0-0\n"+
							"VPXORD Z0,Z0,Z0\nMOVL $85,CX\nKMOVD CX,K7\n%s",
							len(programs), x86RawDisplacementDirectives(code)))
					}
				}
			}
		}
	}
	if len(programs) != 240 {
		t.Fatal("incomplete VEX/EVEX width, mask and broadcast literal family", len(programs))
	}
	return programs
}

func TestX86IntegerMinMaxInitializedLiteralInputsAndReturn(t *testing.T) {
	programs := x86IntegerMinMaxInitializedLiteralPrograms(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("initialized min/max literal objects require LLVM22")
	}
	for start := 0; start < len(programs); start += 48 {
		source := strings.Join(programs[start:start+48], "\n")
		var declarations strings.Builder
		for index := start; index < start+48; index++ {
			fmt.Fprintf(&declarations, "func Literal%d()\n", index)
		}
		x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("batch-%03d/%s/%s", start, triple, api), func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized RIP constant and canonical raw RET regressed", err)
					}
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						x86PackedStringCompileObject(t, llc, triple, pipeline.ir, pipeline.level)
					}
				})
			}
		}
	}
}

func TestX86IntegerMinMaxLiteralExactTupleAndMaskRemainRequired(t *testing.T) {
	for _, source := range x86IntegerMinMaxInitializedLiteralPrograms(t) {
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[4]
		form, known, err := x86IntegerMinMaxProperties(ins.Op, ins, "amd64")
		address, static := x86StaticSBReadAddress(ins.Args[0], "amd64")
		if err != nil || !known || !static || len(file.Data) != 1 || len(file.Data[0].Payload) != form.memoryBytes {
			t.Fatal("original literal lost its whole exact tuple", ins.Raw, err)
		}
		for _, mutation := range []string{"none", "tuple", "origin", "encoded", "address", "mask", "short data"} {
			if mutation == "mask" && form.mask < 0 {
				continue
			}
			changed := ins
			state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
			state.writeVector(0, 64, ^uint64(0), false)
			state.masks[7] = mutation != "mask"
			state.loweredStaticReads = map[x86StaticSBAddress]int64{address: int64(form.memoryBytes)}
			switch mutation {
			case "tuple":
				changed.x86RIPMemoryRead.width--
			case "origin":
				changed.x86SourceRaw = nil
			case "encoded":
				changed.x86Encoded = false
			case "address":
				changed.x86AddressBits = 32
			case "short data":
				state.loweredStaticReads[address]--
			}
			before := state.clone()
			accepted, recognized := x86ResultIntegerMinMaxStep(changed, &state, nil, "amd64", false)
			state.loweredStaticReads = nil
			if !recognized || accepted != (mutation == "none") || !accepted && !reflect.DeepEqual(state, before) {
				t.Fatal("literal supplied a missing mask, stale identity or incomplete tuple", mutation, ins.Raw)
			}
		}
		missing := strings.Replace(source, "KMOVD CX,K7\n", "", 1)
		if form.mask >= 0 {
			if ir, err := x86ScalarFPBitViewAPI(t, missing,
				"func "+strings.TrimPrefix(file.Funcs[0].Sym, "·")+"()",
				"amd64", "x86_64-unknown-linux-gnu", "text"); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("canonical raw return supplied an uninitialized mask", err)
			}
		}
	}
}
