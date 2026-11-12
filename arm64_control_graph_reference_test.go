package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// This file is copied unchanged into the frozen map-reference source. It uses
// only the existing whole analysis and public translator, not set internals.
func arm64ControlFiniteGraph(seed int64) string {
	random := rand.New(rand.NewSource(seed))
	var source strings.Builder
	source.WriteString("TEXT controlGraph(SB),4,$64-0\nMOVD R30,R19\nMOVD $0,R0\n")
	source.WriteString("CBZ R0,left\nADR right,R2\nMOVD R2,24(RSP)\nB joined\nleft:\nADR helper,R2\nMOVD R2,24(RSP)\njoined:\n")
	if seed%3 == 0 {
		source.WriteString("MOVD 24(RSP),R3\nCALL (R3)\n")
	} else {
		for calls := 1 + random.Intn(5); calls > 0; calls-- {
			source.WriteString("CALL helper\n")
		}
	}
	switch seed % 5 {
	case 0:
		source.WriteString("MOVD $1,R0\nagain:\nCBZ R0,finished\nSUB $1,R0\nB again\n")
	case 1:
		source.WriteString("MOVD R2,(R4)\n")
	case 2:
		// Object/analysis only: an unproved indirect native destination is
		// deliberately never executed by this first-party receipt test.
		source.WriteString("MOVD $0,R5\nCALL (R5)\n")
	case 3:
		source.WriteString("CBZ R0,address_left\nADD $8,RSP,R5\nB address_join\naddress_left:\nADD $16,RSP,R5\naddress_join:\nMOVD R2,(R5)\n")
	case 4:
		source.WriteString("MOVD R2,32(RSP)\nMOVW 32(RSP),R6\nMOVD R6,40(RSP)\n")
	}
	source.WriteString("finished:\nMOVD R19,R30\nRET\nright:\nMOVD $17,R7\nRET\nhelper:\nMOVD $19,R7\nRET\n")
	return source.String()
}

func TestARM64ControlFiniteGraphFrozenReceipts(t *testing.T) {
	for seed := int64(0); seed < 30; seed++ {
		t.Run(fmt.Sprintf("seed_%02d", seed), func(t *testing.T) {
			source := arm64ControlFiniteGraph(seed)
			goAssemblerOracleOutput(t, "arm64", source, "", true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			fn := file.Funcs[0]
			ctx := &arm64Ctx{
				blocks: arm64SplitBlocks(fn), normalizedSource: fn,
				sig:     FuncSig{Name: "controlGraph", Ret: Void},
				resolve: func(name string) string { return name },
			}
			if err := ctx.prepareLocalControl(); err != nil {
				t.Fatal(err)
			}
			type point struct {
				Block, Instruction  int
				Before, Stack, Link arm64ControlValue
			}
			var points []point
			for block, body := range ctx.blocks {
				for instruction := range body.instrs {
					key := [2]int{block, instruction}
					points = append(points, point{block, instruction,
						ctx.localControl.before[key], ctx.localControl.stackBefore[key], ctx.localControl.linkBefore[key]})
				}
			}
			ir, translateErr := Translate(file, Options{
				Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"controlGraph": {Name: "controlGraph", Ret: Void}},
			})
			var diagnostic string
			if translateErr != nil {
				if !errors.Is(translateErr, ErrProbeNeedsContext) {
					t.Fatalf("unexpected non-context source failure: %v", translateErr)
				}
				diagnostic = translateErr.Error()
			}
			receipt := struct {
				Original   Func
				Reachable  []bool
				Outer      string
				AutoFrame  bool
				Points     []point
				Diagnostic string
				IR         string
			}{fn, ctx.localControl.reachable, ctx.localControl.outer, ctx.localControl.autoFrame, points, diagnostic, ir}
			encoded, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("finite-graph-complete-receipt %s", encoded)
		})
	}
}
