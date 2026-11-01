package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86RawMaskMoveCompleteGo127Family(t *testing.T) {
	// Go 1.27's shared _ykmovb table gives KMOVB/W/D/Q the same four
	// encoding rows: K->memory, K->GP, K-or-memory->K, and GP->K. Cover
	// every row at every width, plus the extended GP form reported by
	// github.com/minio/sha256-simd.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "b k to k", code: []byte{0xc5, 0xf9, 0x90, 0xcd}, want: "KMOVB K5, K1"},
		{name: "b memory to k", code: []byte{0xc5, 0xf9, 0x90, 0x08}, want: "KMOVB 0(AX), K1"},
		{name: "b k to memory", code: []byte{0xc5, 0xf9, 0x91, 0x00}, want: "KMOVB K0, 0(AX)"},
		{name: "b k to gp", code: []byte{0xc5, 0xf9, 0x93, 0xc5}, want: "KMOVB K5, AX"},
		{name: "b gp to k", code: []byte{0xc5, 0xf9, 0x92, 0xe8}, want: "KMOVB AX, K5"},
		{name: "w k to k", code: []byte{0xc5, 0xf8, 0x90, 0xcd}, want: "KMOVW K5, K1"},
		{name: "w memory to k", code: []byte{0xc5, 0xf8, 0x90, 0x08}, want: "KMOVW 0(AX), K1"},
		{name: "w k to memory", code: []byte{0xc5, 0xf8, 0x91, 0x00}, want: "KMOVW K0, 0(AX)"},
		{name: "w k to gp", code: []byte{0xc5, 0xf8, 0x93, 0xc5}, want: "KMOVW K5, AX"},
		{name: "w gp to k", code: []byte{0xc5, 0xf8, 0x92, 0xe8}, want: "KMOVW AX, K5"},
		{name: "d k to k", code: []byte{0xc4, 0xe1, 0xf9, 0x90, 0xcd}, want: "KMOVD K5, K1"},
		{name: "d memory to k", code: []byte{0xc4, 0xe1, 0xf9, 0x90, 0x08}, want: "KMOVD 0(AX), K1"},
		{name: "d k to memory", code: []byte{0xc4, 0xe1, 0xf9, 0x91, 0x00}, want: "KMOVD K0, 0(AX)"},
		{name: "d k to gp", code: []byte{0xc5, 0xfb, 0x93, 0xc5}, want: "KMOVD K5, AX"},
		{name: "d gp to k", code: []byte{0xc5, 0xfb, 0x92, 0xe8}, want: "KMOVD AX, K5"},
		{name: "q k to k", code: []byte{0xc4, 0xe1, 0xf8, 0x90, 0xcd}, want: "KMOVQ K5, K1"},
		{name: "q memory to k", code: []byte{0xc4, 0xe1, 0xf8, 0x90, 0x08}, want: "KMOVQ 0(AX), K1"},
		{name: "q k to memory", code: []byte{0xc4, 0xe1, 0xf8, 0x91, 0x00}, want: "KMOVQ K0, 0(AX)"},
		{name: "q k to gp", code: []byte{0xc4, 0xe1, 0xfb, 0x93, 0xc5}, want: "KMOVQ K5, AX"},
		{name: "q gp to k", code: []byte{0xc4, 0xe1, 0xfb, 0x92, 0xe8}, want: "KMOVQ AX, K5"},
		{name: "q reported extended gp to k", code: []byte{0xc4, 0xc1, 0xfb, 0x92, 0xce}, want: "KMOVQ R14, K1"},
		{name: "q extended k to gp", code: []byte{0xc4, 0x61, 0xfb, 0x93, 0xd7}, want: "KMOVQ K7, R10"},
		{name: "q extended sib memory to k", code: []byte{0xc4, 0x81, 0xf8, 0x90, 0x4c, 0x88, 0x20}, want: "KMOVQ 32(R8)(R9*4), K1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := Func{}
			for _, value := range test.code {
				fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
			}
			got, err := decodeX86RawDirectives(fn, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Instrs) != 1 || !strings.HasPrefix(got.Instrs[0].Raw, test.want+" ") {
				t.Fatalf("decoded %#x as %#v, want %q", test.code, got.Instrs, test.want)
			}
		})
	}

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
	} {
		t.Run(target.goarch+"/lower", func(t *testing.T) {
			var unbound strings.Builder
			unbound.WriteString("TEXT raw_mask_move(SB),NOSPLIT,$0-0\n")
			for _, test := range tests[:20] {
				unbound.WriteString(x86RawDisplacementDirectives(test.code))
			}
			unbound.WriteString("RET\n")
			// Preserve the original complete source as a Go-format object and
			// public Context control. Unknown AX/K inputs are not an ABI.
			x86UnboundVoidFormatSources(t, unbound.String(), target.goarch, target.triple)
			for index, test := range tests[:20] {
				t.Run(test.name, func(t *testing.T) {
					name := fmt.Sprintf("rawMask%d", index)
					word, move := 8, "MOVQ"
					if target.goarch == "386" {
						word, move = 4, "MOVL"
					}
					arguments, extent := "", 0
					setup := "MOVL $21,AX\n"
					if strings.Contains(test.want, "(AX)") {
						arguments, extent = "p *uint64", word
						setup = move + " p+0(FP),AX\n"
					}
					// Each original opcode gets an independent function: a K->AX
					// result must never become the next row's memory address.
					source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nMOVL $91,CX\nKMOVD CX,K0\nKMOVD CX,K5\n%s%sRET\n",
						name, extent, setup, x86RawDisplacementDirectives(test.code))
					declaration := fmt.Sprintf("func %s(%s)", name, arguments)
					x86LEAActualTargetGoObject(t, target.goarch, target.triple, source)
					// GP transfers ignore encoded W in 32-bit mode: these
					// original KMOVQ bytes transfer 32 bits. K/memory Q
					// transfers retain their independent 64-bit width.
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.goarch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("independently initialized original raw mask-move rejected", err)
							}
							for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								if arguments != "" {
									bits := []int{8, 16, 32, 64}[index/5]
									operation := "load"
									if strings.Contains(test.name, "k to memory") {
										operation = "store"
									}
									if !strings.Contains(body, fmt.Sprintf("%s volatile i%d", operation, bits)) {
										t.Fatal("dead raw mask access lost its exact volatile width after optimization", operation, bits)
									}
								}
								compileLLVMToObject(t, llc, target.triple, "raw-mask-move.ll", "raw-mask-move.o", body)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86RawMaskMoveWholeProducerIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := 8, "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, store := range []bool{false, true} {
			code := []byte{0xc4, 0xe1, 0xf8, 0x90, 0x08} // KMOVQ 0(AX),K1.
			if store {
				code[3], code[4] = 0x91, 0x00 // KMOVQ K0,0(AX).
			}
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nMOVL $91,CX\nKMOVD CX,K0\n%s p+0(FP),AX\n%sRET\n",
				word, move, x86RawDisplacementDirectives(code))
			check := x86LegacyFloatReplayCheck(t, arch, source, "func Value(p *uint64)")
			file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
			if err != nil {
				t.Fatal(err)
			}
			original := file.Funcs[0]
			ordinal := len(original.Instrs) - 2
			for _, mutation := range []string{
				"valid", "origin", "missing-replay", "producer", "opcode", "operand", "original-bytes", "snapshot",
			} {
				t.Run(fmt.Sprintf("%s/store=%t/%s", arch, store, mutation), func(t *testing.T) {
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					ins := &candidate.Instrs[ordinal]
					switch mutation {
					case "origin":
						ins.x86SourceRaw = nil
					case "missing-replay":
						candidate.x86RawReplay = nil
					case "producer":
						candidate.Instrs[1].Raw += " changed"
					case "opcode":
						ins.Op = "KMOVW"
					case "operand":
						index := 0
						if store {
							index = 1
						}
						ins.Args[index].Mem.Off = 1
					case "original-bytes", "snapshot":
						replay := *original.x86RawReplay
						if mutation == "original-bytes" {
							replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
						} else {
							replay.normalized = cloneX86ReplayInstrs(replay.normalized)
							replay.normalized[ordinal].Raw += " changed"
						}
						candidate.x86RawReplay = &replay
					}
					err := check(candidate)
					if mutation == "valid" {
						if err != nil {
							t.Fatal("initialized original mask source lost its native continuation", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("edited original raw mask source acquired native access", err)
					}
					if err := original.x86RawReplay.validate(original, arch); err != nil {
						t.Fatal("mutation damaged the unchanged original producer", err)
					}
				})
			}
		}
	}
}
