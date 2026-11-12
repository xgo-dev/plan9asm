package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func arm64NanosleepWithStores(stores string) string {
	source := strings.Replace(arm64NanosleepInputSource, "\tMOVD R3,8(RSP)\n", "", 1)
	source = strings.Replace(source, "\tMOVD R5,16(RSP)\n", "", 1)
	return strings.Replace(source, "\tADD $8,RSP,R0\n", stores+"\tADD $8,RSP,R0\n", 1)
}

func arm64NanosleepByteStores(omitted int) string {
	var stores strings.Builder
	for offset := 0; offset < int(arm64NanosleepRequestBytes); offset++ {
		if offset != omitted {
			fmt.Fprintf(&stores, "\tMOVB ZR,%d(RSP)\n", 8+offset)
		}
	}
	return stores.String()
}

func TestARM64NanosleepInitializedEnvelopeFamily(t *testing.T) {
	stores := map[string]string{
		"bytes": arm64NanosleepByteStores(-1),
		"halfwords": "MOVH ZR,8(RSP)\nMOVH ZR,10(RSP)\nMOVH ZR,12(RSP)\nMOVH ZR,14(RSP)\n" +
			"MOVH ZR,16(RSP)\nMOVH ZR,18(RSP)\nMOVH ZR,20(RSP)\nMOVH ZR,22(RSP)\n",
		"words":              "MOVW ZR,8(RSP)\nMOVW ZR,12(RSP)\nMOVW ZR,16(RSP)\nMOVW ZR,20(RSP)\n",
		"doublewords":        "MOVD R3,8(RSP)\nMOVD R5,16(RSP)\n",
		"word-pairs":         "STPW (R3,R5),8(RSP)\nSTPW (R3,R5),16(RSP)\n",
		"doubleword-pair":    "STP (R3,R5),8(RSP)\n",
		"literal-zero-alias": "MOVD $0,8(RSP)\nMOVD $0,16(RSP)\n",
		"derived-address":    "ADD $8,RSP,R17\nSTP (R3,R5),(R17)\n",
		"indexed-address": "ADD $8,RSP,R17\nMOVD $0,R19\nMOVD R3,(R17)(R19)\n" +
			"MOVD $8,R19\nMOVD R5,(R17)(R19)\n",
		"post-writeback": "ADD $8,RSP,R17\nMOVD.P R3,8(R17)\nMOVD.P R5,8(R17)\n",
		"pre-writeback":  "ADD $8,RSP,R17\nMOVD.W R3,0(R17)\nMOVD.W R5,8(R17)\n",
		"complete-predecessors": "CBZ R3,other\nSTP (R3,R5),8(RSP)\nJMP joined\n" +
			"other:\nMOVD R3,8(RSP)\nMOVD R5,16(RSP)\njoined:\n",
	}
	for name, stores := range stores {
		t.Run(name, func(t *testing.T) {
			source := arm64NanosleepWithStores(stores)
			requireARM64GoAssemblerResult(t, source, true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					if _, err := arm64NanosleepInputAPI(t, api, "aarch64-unknown-linux-gnu", source); err != nil {
						t.Fatal("complete initialized envelope lost its existing typed store grammar", err)
					}
				})
			}
		})
	}
}

func TestARM64NanosleepEveryMissingByteRemainsContext(t *testing.T) {
	for omitted := 0; omitted < int(arm64NanosleepRequestBytes); omitted++ {
		t.Run(fmt.Sprintf("byte-%02d", omitted), func(t *testing.T) {
			source := arm64NanosleepWithStores(arm64NanosleepByteStores(omitted))
			requireARM64GoAssemblerResult(t, source, true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					if _, err := arm64NanosleepInputAPI(t, api, "aarch64-unknown-linux-gnu", source); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("uninitialized byte %d acquired a kernel input role: %v", omitted, err)
					}
				})
			}
		})
	}
}

func TestARM64NanosleepUndefinedOrEscapedInitializerRemainsContext(t *testing.T) {
	for name, stores := range map[string]string{
		"undefined-GP":        "MOVD R6,8(RSP)\nMOVD R6,16(RSP)\n",
		"undefined-vector":    "FMOVQ F0,8(RSP)\n",
		"external-load":       "MOVD (R6),R3\nSTP (R3,R5),8(RSP)\n",
		"caller-link-value":   "MOVD R30,8(RSP)\nMOVD R5,16(RSP)\n",
		"caller-frame-value":  "MOVD R29,8(RSP)\nMOVD R5,16(RSP)\n",
		"missing-predecessor": "CBZ R3,joined\nSTP (R3,R5),8(RSP)\njoined:\n",
	} {
		t.Run(name, func(t *testing.T) {
			source := arm64NanosleepWithStores(stores)
			requireARM64GoAssemblerResult(t, source, true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					if _, err := arm64NanosleepInputAPI(t, api, "aarch64-unknown-linux-gnu", source); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unbound/native initializer acquired a byte-defined kernel contract: %v", err)
					}
				})
			}
		})
	}
}

func arm64NanosleepProofContext(t *testing.T) *arm64Ctx {
	t.Helper()
	requireARM64GoAssemblerResult(t, arm64NanosleepInputSource, true)
	file, err := Parse(ArchARM64, arm64NanosleepInputSource)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "example.invalid/sleepinput", "package sleepinput\nfunc sleep(usec uint32)\n")
	resolve := testResolveSym(pkg.Types.Path())
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	c := newARM64CtxWithTarget(&output, file.Funcs[0], sigs[resolve(file.Funcs[0].Sym)], resolve, sigs,
		"aarch64-unknown-linux-gnu", false)
	if err := c.prepareLocalControl(); err != nil {
		t.Fatal("complete original-source CFG prerequisite", err)
	}
	return c
}

func TestARM64NanosleepInputProofExactIdentity(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*arm64Ctx, [2]int) *arm64Ctx
	}{
		{"unaltered", func(c *arm64Ctx, _ [2]int) *arm64Ctx { return c }},
		{"context-copy", func(c *arm64Ctx, _ [2]int) *arm64Ctx { copy := *c; return &copy }},
		{"proof-copy", func(c *arm64Ctx, _ [2]int) *arm64Ctx {
			copy := *c.nanosleepInput
			c.nanosleepInput = &copy
			return c
		}},
		{"wrong-owner", func(c *arm64Ctx, _ [2]int) *arm64Ctx { c.nanosleepInput.owner = nil; return c }},
		{"target", func(c *arm64Ctx, _ [2]int) *arm64Ctx { c.targetTriple = "aarch64-unknown-linux-musl"; return c }},
		{"signature", func(c *arm64Ctx, _ [2]int) *arm64Ctx { c.sig.Args[0] = I64; return c }},
		{"frame-declaration", func(c *arm64Ctx, _ [2]int) *arm64Ctx { c.sig.Frame.Params[0].Offset = 8; return c }},
		{"current-source", func(c *arm64Ctx, _ [2]int) *arm64Ctx { c.normalizedSource.Instrs[1].Raw += " changed"; return c }},
		{"original-source", func(c *arm64Ctx, _ [2]int) *arm64Ctx { c.nanosleepOriginalSource.Instrs[1].Raw += " changed"; return c }},
		{"original-proof", func(c *arm64Ctx, _ [2]int) *arm64Ctx { c.nanosleepOriginal = nil; return c }},
		{"changed-CFG", func(c *arm64Ctx, point [2]int) *arm64Ctx {
			c.blocks[point[0]].instrs[point[1]].Args = []Operand{{Kind: OpImm, Imm: 1}}
			return c
		}},
		{"span", func(c *arm64Ctx, point [2]int) *arm64Ctx {
			input := c.nanosleepInput.inputs[point]
			input.span.low--
			c.nanosleepInput.inputs[point] = input
			return c
		}},
		{"descriptor", func(c *arm64Ctx, point [2]int) *arm64Ctx {
			input := c.nanosleepInput.inputs[point]
			input.form.number = "R16"
			c.nanosleepInput.inputs[point] = input
			return c
		}},
		{"ordinal", func(c *arm64Ctx, point [2]int) *arm64Ctx {
			c.nanosleepInput.inputs[[2]int{point[0], point[1] + 1}] = c.nanosleepInput.inputs[point]
			delete(c.nanosleepInput.inputs, point)
			return c
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			c := arm64NanosleepProofContext(t)
			if c.nanosleepInput == nil || len(c.nanosleepInput.inputs) != 1 {
				t.Fatal("actual initialized source did not create a unique input point")
			}
			var point [2]int
			for point = range c.nanosleepInput.inputs {
			}
			c = change.apply(c, point)
			_, valid := c.nanosleepInputAt(point)
			if valid != (change.name == "unaltered") {
				t.Fatal("copied/changed source, owner, frame or point acquired an exact kernel input certificate")
			}
		})
	}
}

func TestARM64NanosleepSealedReplayRequiresOriginalDeclaration(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*FuncSig)
	}{
		{"original", func(*FuncSig) {}},
		{"wider-input", func(sig *FuncSig) { sig.Args[0] = I64 }},
		{"changed-frame-input", func(sig *FuncSig) { sig.Frame.Params[0].Offset = 8 }},
		{"new-result", func(sig *FuncSig) { sig.Ret = I64 }},
		{"different-declaration", func(sig *FuncSig) { sig.Name += ".other" }},
		{"register-entry", func(sig *FuncSig) { sig.ArgRegs = []Reg{"R3"} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			c := arm64NanosleepProofContext(t)
			sig := arm64NanosleepCloneSignature(c.sig)
			change.apply(&sig)
			transport := &arm64PrivateFrameTransport{
				entry: sig, resolve: c.resolve, sigs: c.sigs, nanosleep: c.nanosleepInput,
			}
			_, err := arm64PrivateDataProofDetails(c.normalizedSource, transport)
			if (err == nil) != (change.name == "original") {
				t.Fatalf("a sealed memory input was replayed with another declaration: %v", err)
			}
		})
	}
}
