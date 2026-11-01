package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawSegmentInitializedLoadForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			forms := 0
			for _, segment := range []struct {
				prefix byte
			}{{0x64}, {0x65}} {
				for _, width := range []int{1, 2, 4, 8} {
					if target.arch == "386" && width == 8 {
						continue
					}
					for _, address := range []string{"absolute", "base", "indexed"} {
						name := fmt.Sprintf("Segment%d", forms)
						fmt.Fprintf(&declarations, "func %s()\n", name)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\nMOVL $0,AX\nMOVL $1,CX\n", name)
						code := []byte{segment.prefix}
						if width == 2 {
							code = append(code, 0x66)
						} else if width == 8 {
							code = append(code, 0x48)
						}
						opcode := byte(0x8b)
						if width == 1 {
							opcode = 0x8a
						}
						code = append(code, opcode)
						switch address {
						case "absolute":
							if target.arch == "386" {
								code = append(code, 0x15)
							} else {
								code = append(code, 0x14, 0x25)
							}
							code = append(code, 48, 0, 0, 0)
						case "base":
							code = append(code, 0x50, 48)
						case "indexed":
							code = append(code, 0x54, 0x48, 48)
						}
						source.WriteString(x86RawDisplacementDirectives(code))
						source.WriteString("RET\n")
						forms++
					}
				}
			}
			want := 24
			if target.arch == "386" {
				want = 18
			}
			if forms != want {
				t.Fatal("complete raw segment load inventory changed", forms, want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("initialized physical segment load lost its paired native read", api, err)
				}
				for _, output := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					if strings.Count(output, "load volatile ") != want {
						t.Fatal("dead-result physical segment read was lost or duplicated", api, output)
					}
					for _, space := range []int{256, 257} {
						for _, width := range []int{1, 2, 4, 8} {
							if target.arch == "386" && width == 8 {
								continue
							}
							read := fmt.Sprintf("load volatile i%d, ptr addrspace(%d)", width*8, space)
							if strings.Count(output, read) != 3 {
								t.Fatal("physical segment read width or address space changed", api, read, output)
							}
						}
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, output, level)
					}
				}
				for _, foreign := range []string{"aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, foreign, api); err == nil || ir != "" {
						t.Fatal("physical segment source acquired a foreign backend", api, foreign, err)
					}
				}
			}
		})
	}
}

func TestX86RawSegmentLoadRetainsInputsAndSourceIdentity(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		mode, word := 32, int64(4)
		if arch == "amd64" {
			mode, word = 64, 8
		}
		for _, prefix := range []byte{0x64, 0x65} {
			instructions := x86AddressOverrideDecoded(t, mode, []byte{prefix, 0x8b, 0x54, 0x48, 48})
			if len(instructions) != 3 || instructions[0].Op != OpTEXT || instructions[2].Op != OpRET {
				t.Fatal("single physical segment load lost identity", instructions)
			}
			original := instructions[1]
			if !x86RawScalarSegmentLoadSource(original, arch) {
				t.Fatal("exact physical segment load lacks decoder-bound identity", arch, original)
			}
			for _, register := range []Reg{AX, CX} {
				index, _, _ := x86ResultGP(register, word, arch)
				for missing := 0; missing <= int(word); missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0], state.gp[1] = 0xff, 0xff
					if missing < int(word) {
						state.gp[index] &^= 1 << uint(missing)
					} else {
						state.pointerGP[index] = true
					}
					before := state.clone()
					if accepted, known := x86LoweredScalarNativeLoad(original, &state, nil, 0, arch); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("physical segment offset acquired missing NUM or pointer bits", arch, register, missing)
					}
				}
			}
			for _, mutation := range []struct {
				name   string
				change func(*Instr)
			}{
				{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
				{"encoding", func(ins *Instr) { ins.x86Encoded = false }},
				{"absent-mode", func(ins *Instr) { ins.x86SourceRaw.scalarSegmentLoad.arch = "" }},
				{"foreign-mode", func(ins *Instr) { ins.x86SourceRaw.scalarSegmentLoad.arch = "other" }},
				{"physical-mode", func(ins *Instr) {
					ins.x86SourceRaw.scalarSegmentLoad.arch = "386"
					if arch == "386" {
						ins.x86SourceRaw.scalarSegmentLoad.arch = "amd64"
					}
				}},
				{"width", func(ins *Instr) { ins.x86SourceRaw.scalarSegmentLoad.bytes++ }},
				{"prefix", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
				{"origin-prefix", func(ins *Instr) { ins.x86SourceRaw.scalarSegmentLoad.segmentPrefix = 0x65 }},
				{"address", func(ins *Instr) { ins.x86AddressBits = 16 }},
				{"override", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
				{"opcode", func(ins *Instr) { ins.Op = "MOVW" }},
				{"source", func(ins *Instr) { ins.Args[0].Mem.Off++ }},
				{"destination", func(ins *Instr) { ins.Args[1].Reg = BX }},
				{"segment", func(ins *Instr) { ins.Args[0].Mem.Segment = GS }},
			} {
				if mutation.name == "segment" && prefix == 0x65 {
					continue // The FS case independently changes the actual segment.
				}
				changed := cloneX86ReplayInstrs([]Instr{original})[0]
				mutation.change(&changed)
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.gp[0], state.gp[1] = 0xff, 0xff
				before := state.clone()
				if x86RawScalarSegmentLoadSource(changed, arch) {
					t.Fatal("edited raw segment source reused its decoder identity", arch, mutation.name)
				}
				if accepted, _ := x86LoweredScalarNativeLoad(changed, &state, nil, 0, arch); accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("edited raw segment source obtained a numerical continuation", arch, mutation.name)
				}
			}
		}
	}
	assembly := "TEXT ·Segment(SB),4,$0-0\nMOVL $0,AX\n" + x86RawDisplacementDirectives([]byte{0x64, 0x8b, 0x40, 48}) + "RET\n"
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	file, err = normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"operand", "receipt", "replay"} {
		changed := *file
		changed.Funcs = append([]Func(nil), file.Funcs...)
		changed.Funcs[0].Instrs = cloneX86ReplayInstrs(file.Funcs[0].Instrs)
		switch mutation {
		case "operand":
			changed.Funcs[0].Instrs[2].Args[0].Mem.Off++
		case "receipt":
			changed.Funcs[0].Instrs[2].x86SourceRaw = nil
		case "replay":
			replay := *changed.Funcs[0].x86RawReplay
			replay.source = strings.Replace(replay.source, "MOVL $0,AX", "MOVL $1,AX", 1)
			changed.Funcs[0].x86RawReplay = &replay
		}
		ir, err := Translate(&changed, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			Sigs:       map[string]FuncSig{"Segment": {Name: "Segment", Ret: Void}},
			ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }})
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("edited complete raw source bypassed its sealed replay", mutation, err)
		}
	}
}
