package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent family inventory: do not derive expected permissions or widths
// from the production registry whose completeness these tests check.
var x86PackedMoveResultOracle = []struct {
	name             string
	bits             int
	aligned, vexOnly bool
}{
	{"VMOVDQA", 8, true, true}, {"VMOVDQU", 8, false, true},
	{"VMOVAPD", 64, true, false}, {"VMOVAPS", 32, true, false},
	{"VMOVUPD", 64, false, false}, {"VMOVUPS", 32, false, false},
	{"VMOVDQA32", 32, true, false}, {"VMOVDQA64", 64, true, false},
	{"VMOVDQU8", 8, false, false}, {"VMOVDQU16", 16, false, false},
	{"VMOVDQU32", 32, false, false}, {"VMOVDQU64", 64, false, false},
}

func TestX86PackedMoveResultEveryByteAndWriteEncoding(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		for axis, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue // The independent Go table has no VEX.512 row.
			}
			width := 16 << axis
			for _, mode := range []string{"plain", "merge", "zero"} {
				if row.vexOnly && mode != "plain" {
					continue
				}
				name, mask := row.name, ""
				if mode != "plain" {
					mask = ",K1"
				}
				if mode == "zero" {
					name += ".Z"
				}
				instruction := fmt.Sprintf("%s %s0%s,%s1", name, bank, mask, bank)
				ins := x86ScalarLaneInstruction(t, instruction)
				for missing := 0; missing < 64; missing++ {
					for source := 0; source < 2; source++ {
						state := x86ResultState{flags: x86ByteFlagsAll, masks: [8]bool{1: true}}
						state.writeVector(0, 64, ^uint64(0), false)
						state.writeVector(1, 64, ^uint64(0), false)
						state.writeVector(source, 64, ^(uint64(1) << uint(missing)), false)
						before := state.clone()
						if !x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64") {
							t.Fatalf("typed packed move is missing: %s", instruction)
						}
						want := ^uint64(0)
						if missing < width && (source == 0 || mode == "merge") {
							want &^= uint64(1) << uint(missing)
						}
						if state.vectorBytes(1) != want || state.vectorBytes(0) != before.vectorBytes(0) || state.flags != before.flags {
							t.Fatalf("%s source%d missing%d: got %016x want %016x", instruction, source, missing, state.vectorBytes(1), want)
						}
					}
				}
			}
		}
	}
}

func TestX86PackedMoveResultMemoryAndMaskBoundaries(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		for axis, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue
			}
			width := 16 << axis
			for _, memory := range []string{"in+0(FP)", fmt.Sprintf("local-%d(SP)", width)} {
				ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s %s,%s1", row.name, memory, bank))
				owned := make([]bool, width)
				for i := range owned {
					owned[i] = true
				}
				for missing := -1; missing < width; missing++ {
					state := x86ResultState{fp: append([]bool(nil), owned...), auto: append([]bool(nil), owned...)}
					if missing >= 0 {
						state.fp[missing], state.auto[missing] = false, false
					}
					got := x86ScalarFPResultTransfer(ins, &state, owned, 0, "amd64")
					if got != (!row.aligned && missing < 0) {
						t.Fatalf("%s %s missing%d: accepted=%t", row.name, memory, missing, got)
					}
				}
			}
			if row.vexOnly {
				continue
			}
			for _, suffix := range []string{"", ".Z"} {
				state := x86ResultState{}
				state.writeVector(0, 64, ^uint64(0), false)
				state.writeVector(1, 64, ^uint64(0), false)
				ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s%s %s0,K1,%s1", row.name, suffix, bank, bank))
				if x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64") {
					t.Fatal("undefined mask acquired a numerical value", ins)
				}
			}
		}
	}
}

func TestX86PackedMoveResultFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, pointerMove := 8, "MOVQ"
			if target.arch == "386" {
				word, pointerMove = 4, "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86PackedMoveResultOracle {
				for _, bank := range []string{"X", "Y", "Z"} {
					if row.vexOnly && bank == "Z" {
						continue
					}
					for _, memory := range []bool{false, true} {
						for _, mode := range []string{"plain", "merge", "zero"} {
							if row.vexOnly && mode != "plain" {
								continue
							}
							name, mask, input := row.name, "", bank+"0"
							if memory {
								input = "(SI)"
							}
							if mode != "plain" {
								mask = ",K1"
							}
							if mode == "zero" {
								name += ".Z"
							}
							fmt.Fprintf(&declarations, "func view%d(p *[64]byte) uint32\n", count)
							fmt.Fprintf(&source, "TEXT ·view%d(SB),4,$0-%d\n%s p+0(FP),SI\nMOVL $1,AX\nKMOVD AX,K1\nVPXORQ %s0,%s0,%s0\nVPXORQ %s1,%s1,%s1\n%s %s%s,%s1\nPEXTRD $3,X1,AX\nMOVL AX,ret+%d(FP)\nRET\n",
								count, word+4, pointerMove, bank, bank, bank, bank, bank, bank, name, input, mask, bank, word)
							count++
						}
					}
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				compileLLVMToObject(t, llc, target.triple, "packed-result.ll", "packed-result.o", ir)
			}
		})
	}
}

func TestX86PackedMoveResultPointerReadIsLoweringOnly(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		for _, arch := range []string{"amd64", "386"} {
			word, move := 8, "MOVQ"
			if arch == "386" {
				word, move = 4, "MOVL"
			}
			body := fmt.Sprintf("%s p+0(FP),AX\n%s (AX),X1\nPEXTRD $0,X1,CX\nMOVL CX,ret0+%d(FP)\nRET", move, row.name, word)
			_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(p *[64]byte) uint32", body)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("declaration-only observer acquired a physical read", row.name, arch, err)
				}
			}
		}
	}
}

func TestX86PackedMoveUnalignedDeadReadIsObservable(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		if row.aligned {
			continue
		}
		for axis, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue
			}
			width := 16 << axis
			source := fmt.Sprintf("TEXT ·view(SB),4,$0-8\nMOVQ p+0(FP),AX\n%s (AX),%s0\nRET\n", row.name, bank)
			ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *[64]byte)\n", "amd64", "x86_64-unknown-linux-gnu", "text")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, fmt.Sprintf("load volatile <%d x i8>", width)) {
				t.Fatal("dead full-tuple native read is removable", row.name, bank)
			}
		}
	}
}

func TestX86PackedMoveMaskedUnalignedReadIsObservable(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		if row.aligned || row.vexOnly {
			continue
		}
		for axis, bank := range []string{"X", "Y", "Z"} {
			width := 16 << axis
			source := fmt.Sprintf("TEXT ·view(SB),4,$0-16\nMOVQ p+0(FP),AX\nMOVQ mask+8(FP),CX\nKMOVQ CX,K1\n%s.Z (AX),K1,%s0\nRET\n", row.name, bank)
			ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *[64]byte, mask uint64)\n", "amd64", "x86_64-unknown-linux-gnu", "text")
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ir, fmt.Sprintf("load volatile i%d,", row.bits)); got != width*8/row.bits {
				t.Fatalf("%s %s masked dead read has %d observable lanes; want %d", row.name, bank, got, width*8/row.bits)
			}
		}
	}
}

func TestX86PackedMoveResultStoreAndStaticExtentBoundaries(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		for axis, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue
			}
			width := 16 << axis
			for _, destination := range []string{"ret+0(FP)", fmt.Sprintf("local-%d(SP)", width)} {
				for _, masked := range []bool{false, true} {
					if row.vexOnly && masked {
						continue
					}
					mask := ""
					if masked {
						mask = "K1,"
					}
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s %s0,%s%s", row.name, bank, mask, destination))
					for _, oldKnown := range []bool{false, true} {
						for missing := -1; missing < width; missing++ {
							owned := make([]bool, width)
							state := x86ResultState{fp: make([]bool, width), auto: make([]bool, width), masks: [8]bool{1: true}}
							for i := range owned {
								owned[i], state.fp[i], state.auto[i] = true, oldKnown, oldKnown
							}
							known := ^uint64(0)
							if missing >= 0 {
								known &^= uint64(1) << uint(missing)
							}
							state.writeVector(0, 64, known, false)
							want := !row.aligned && missing < 0 && (!masked || oldKnown)
							if got := x86ScalarFPResultTransfer(ins, &state, owned, 0, "amd64"); got != want {
								t.Fatal("store borrowed source or inactive destination bytes", ins, oldKnown, missing, got, want)
							}
						}
					}
				}
			}
			ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s table<>+16(SB),%s1", row.name, bank))
			for _, available := range []int64{int64(width - 1), int64(width)} {
				state := x86ResultState{loweredStaticReads: map[x86StaticSBAddress]int64{{symbol: "table<>", offset: 16}: available}}
				if got := x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64"); got != (available == int64(width)) {
					t.Fatal("static read ignored complete extent", row.name, bank, available, got)
				}
			}
		}
	}
}

func TestX86PackedMoveResultSourceBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, row := range x86PackedMoveResultOracle {
			load := move + " p+0(FP),AX\n"
			read := row.name + " (AX),X1\n"
			bodies := map[string]string{
				"unknown base":         read,
				"numeric base":         "MOVL $1,AX\n" + read,
				"lost identity":        load + "MOVL $1,AX\n" + read,
				"unknown index":        load + row.name + " (AX)(DI*1),X1\n",
				"pointer index":        load + row.name + " (AX)(AX*1),X1\n",
				"unknown store source": load + row.name + " X1,(AX)\n",
				"unknown store base":   load + read + row.name + " X1,(DI)\n",
				"pointer store index":  load + read + row.name + " X1,(AX)(AX*1)\n",
				"unknown static":       row.name + " ·foreign(SB),X1\n",
				"unknown path":         load + "MOVL $1,CX\nCMPL CX,$0\nJE done\n" + read + "done:\n",
			}
			if !row.vexOnly {
				bodies["undefined mask"] = load + row.name + ".Z (AX),K1,X1\n"
				bodies["undefined merge"] = load + "MOVL $1,CX\nKMOVD CX,K1\n" + row.name + " (AX),K1,X1\n"
				bodies["undefined store mask"] = load + read + row.name + " X1,K1,(AX)\n"
			}
			for name, body := range bodies {
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%sPEXTRD $0,X1,CX\nMOVL CX,ret+%d(FP)\nRET\n", word+4, body, word)
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, "func view(p *[64]byte) uint32\n", arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("source closure or incoming identity bypass", arch, row.name, name, api, err)
					}
				}
			}
		}
	}
}

func x86PackedMoveInitializedInstruction(name, arch, initialization, instruction, observation string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $7,CX\nKMOVD CX,K1\n%s%s\n"+
		"%s\nMOVL CX,ret+%d(FP)\nRET\n", name, word+4, move, initialization, instruction, observation, word)
	return source, fmt.Sprintf("func %s(p *[64]byte) uint32\n", name)
}

func TestX86PackedMoveInitializedNativeStoresWholeFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			var names []string
			for _, row := range x86PackedMoveResultOracle {
				for _, bank := range []string{"X", "Y", "Z"} {
					if row.vexOnly && bank == "Z" {
						continue
					}
					for _, masked := range []bool{false, true} {
						if row.vexOnly && masked {
							continue
						}
						predicate := ""
						if masked {
							predicate = "K1,"
						}
						name := fmt.Sprintf("view%d", len(names))
						names = append(names, name)
						// Keep the original initialized load/store pair, including
						// native alignment effects. Its result is independent of the
						// store and cannot be supplied by a fresh logical allocation.
						body, declaration := x86PackedMoveInitializedInstruction(name, target.arch,
							fmt.Sprintf("%s (AX),%s1\n", row.name, bank), fmt.Sprintf("%s %s1,%s(AX)", row.name, bank, predicate), "PEXTRD $0,X1,CX")
						source.WriteString(body)
						declarations.WriteString(declaration)
					}
				}
			}
			if len(names) != 64 {
				t.Fatal("complete initialized native-store denominator changed", len(names))
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized native-store sequence rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					for _, optimized := range []bool{false, true} {
						text := ir
						if optimized {
							text = x86DwordProductIROptimize(t, ir)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR-O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, text, level)
							})
						}
					}
				})
			}
		})
	}
}

func TestX86PackedMoveResultRawOriginBoundaries(t *testing.T) {
	_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *[64]byte) uint32",
		"MOVQ p+0(FP),AX\nVMOVDQU64 (AX),Z1\nPEXTRD $0,X1,CX\nMOVL CX,ret0+8(FP)\nRET")
	for _, mutation := range []string{"decoded", "address size", "raw text", "source stack", "fixed local", "segment", "symbol"} {
		fn := file.Funcs[0]
		fn.Instrs = append([]Instr(nil), fn.Instrs...)
		fn.Instrs[2].Args = append([]Operand(nil), fn.Instrs[2].Args...)
		switch mutation {
		case "decoded":
			fn.Instrs[2].x86Encoded = true
		case "address size":
			fn.Instrs[2].x86AddressBits = 32
		case "raw text":
			fn.X86RawText = []byte{0xc3}
		case "source stack":
			fn.x86SourceStack = new(x86SourceStackProof)
		case "fixed local":
			fn.x86FixedLocal = new(x86FixedLocalProof)
		case "segment":
			fn.Instrs[2].Args[0].Mem.Segment = "FS"
		case "symbol":
			fn.Instrs[2].Args[0].Mem.Sym = "table<>(SB)"
		}
		ctx := &amd64Ctx{fpScalarSource: fn, sig: sig, goarch: "amd64"}
		if err := ctx.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("raw/source role acquired ordinary conditional byte availability", mutation, err)
		}
	}
}

func TestX86PackedMoveResultStaticSourceThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		var source, declarations strings.Builder
		source.WriteString("DATA table<>+0(SB)/8,$0x76543210abcdef01\nGLOBL table<>(SB),8,$64\n")
		count := 0
		for _, row := range x86PackedMoveResultOracle {
			for _, bank := range []string{"X", "Y", "Z"} {
				if row.vexOnly && bank == "Z" {
					continue
				}
				addresses := []string{"table<>(SB)"}
				if target.arch == "386" {
					for _, annotation := range []string{"AX", "BX", "CX", "DX", "SI", "DI", "SP", "BP"} {
						addresses = append(addresses, "table<>(SB)("+annotation+")")
					}
				}
				for _, address := range addresses {
					fmt.Fprintf(&declarations, "func view%d() uint32\n", count)
					fmt.Fprintf(&source, "TEXT ·view%d(SB),4,$0-4\n%s %s,%s1\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n", count, row.name, address, bank)
					count++
				}
			}
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
			if err != nil {
				t.Fatal("complete DATA directory did not compose with physical reads", target, api, err)
			}
			compileLLVMToObject(t, llc, target.triple, "packed-data.ll", "packed-data.o", ir)
		}
	}
}
