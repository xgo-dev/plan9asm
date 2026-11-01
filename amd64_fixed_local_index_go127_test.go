//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalConstantIndexFunction(name, body string) string {
	return fmt.Sprintf("TEXT ·%s(SB),4,$64-16\nMOVQ a+0(FP),AX\nMOVQ AX,0(SP)\n%s\nMOVQ AX,ret+8(FP)\nRET\n", name, body)
}

func TestGoAMD64FixedLocalConstantIndexObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var assembly, declarations strings.Builder
	assembly.WriteString(fixedLocalAddressData)
	cases := fixedLocalConstantIndexCases()
	if len(cases) != 30 {
		t.Fatal("two origins by complete non-SP GP bank changed", len(cases))
	}
	for index, row := range cases {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalConstantIndexFunction(name, row.body))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(), target.name, target.triple)
			var names []string
			for index := range cases {
				names = append(names, fmt.Sprintf("%s.Value%d", pkg.Path, index))
			}
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("original constant-index private/DATA source rejected", err)
					}
					if !strings.Contains(ir, "internal constant [32 x i8]") {
						t.Fatal("private readonly DATA was not retained")
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					compileLLVMToObject(t, llc, target.triple, "constant-index.ll", "constant-index.o", ir)
					compileLLVMToObject(t, llc, target.triple, "constant-index-opt.ll", "constant-index-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
	t.Log("30 original-Go functions cover 15 non-SP index registers, four scales, private store/RMW/load and readonly DATA reads; three APIs at O0/O2")
}

func TestGoAMD64FixedLocalConstantIndexGuards(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, literal := range []bool{false, true} {
		name, acquire, size := "private", "MOVQ SP,DI\n", 64
		if literal {
			name, acquire, size = "literal", "LEAQ literal<>(SB),DI\n", 32
		}
		for _, row := range []struct {
			name, body string
			valid      bool
		}{
			{"first byte via negative index", "MOVQ $-1,SI\nMOVQ 8(DI)(SI*8),AX", true},
			{"last byte", fmt.Sprintf("MOVQ $%d,SI\nMOVQ $0,AX\nMOVB (DI)(SI*1),AX", size-1), true},
			{"last word", fmt.Sprintf("MOVQ $%d,SI\nMOVQ $0,AX\nMOVW (DI)(SI*1),AX", size-2), true},
			{"last dword", fmt.Sprintf("MOVQ $%d,SI\nMOVL (DI)(SI*1),AX", size-4), true},
			{"last qword", fmt.Sprintf("MOVQ $%d,SI\nMOVQ (DI)(SI*8),AX", size/8-1), true},
			{"last vector", fmt.Sprintf("MOVQ $%d,SI\nMOVOU (DI)(SI*1),X0\nMOVQ X0,AX", size-16), true},
			{"indexed full spill round trip", "MOVQ DI,16(SP)\nMOVQ $2,SI\nMOVQ (SP)(SI*8),R8\nMOVQ (R8),AX", true},
			{"before allocation", "MOVQ $-1,SI\nMOVQ (DI)(SI*1),AX", false},
			{"past allocation", fmt.Sprintf("MOVQ $%d,SI\nMOVQ 1(DI)(SI*8),AX", size/8-1), false},
			{"positive multiply wraps to base", "MOVQ $9223372036854775807,SI\nMOVQ 2(DI)(SI*2),AX", literal},
			{"negative multiply wraps to base", "MOVQ $-9223372036854775808,SI\nMOVQ (DI)(SI*2),AX", literal},
			{"displacement overflow", "MOVQ $9223372036854775807,SI\nMOVQ 1(DI)(SI*1),AX", false},
			{"unaligned vector", "MOVQ $1,SI\nMOVO (DI)(SI*1),X0", false},
			{"dynamic numerical index", "MOVQ a+0(FP),SI\nMOVQ (DI)(SI*1),AX", literal},
			{"unknown upper index bytes", "MOVW $0,SI\nMOVQ (DI)(SI*1),AX", false},
			{"defined partial index overwrite", "MOVQ $0,SI\nMOVB $1,SI\nMOVQ (DI)(SI*1),AX", literal},
			{"pointer used as index", "MOVQ DI,SI\nMOVQ (DI)(SI*1),AX", false},
			{"numeric base loses origin", "MOVQ $0,DI\nMOVQ $0,SI\nMOVQ (DI)(SI*1),AX", false},
			{"different constants at join", "MOVQ $77,8(SP)\nMOVQ $0,SI\nCMPQ AX,$0\nJEQ joined\nMOVQ $1,SI\njoined:\nMOVQ (DI)(SI*8),AX", literal},
			{"loaded numerical index", "MOVQ $0,SI\nMOVQ (DI)(SI*1),SI\nMOVQ (DI)(SI*1),AX", literal},
		} {
			t.Run(name+"/"+row.name, func(t *testing.T) {
				body := "MOVQ $77,48(SP)\nMOVQ $77,56(SP)\n" + acquire + row.body
				assembly := fixedLocalAddressData + fixedLocalConstantIndexFunction("Value", body)
				pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
					"func Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
				// The actual Go capture is a prerequisite, not evidence that an
				// invalid extent or provenance was rejected by our translator.
				source := requireGoAMD64FrameCapture(t, pkg, request)
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				_, err := source.BindFixedLocal(ctx, pkg, file, options)
				if row.valid && err != nil {
					t.Fatal("valid constant-index boundary rejected", err)
				}
				if !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unproved constant-index bytes or origin accepted", err)
				}
			})
		}
	}
	for _, row := range []struct{ name, body string }{
		{"readonly store", "LEAQ literal<>(SB),DI\nMOVQ $1,SI\nMOVQ AX,(DI)(SI*8)"},
		{"readonly RMW", "LEAQ literal<>(SB),DI\nMOVQ $1,SI\nADDQ AX,(DI)(SI*8)"},
		{"uninitialized private bytes", "MOVQ $1,SI\nMOVQ (SP)(SI*8),AX"},
		{"partial private initialization", "MOVQ $1,SI\nMOVL AX,(SP)(SI*8)\nMOVQ (SP)(SI*8),AX"},
		{"indexed write revokes spilled origin", "MOVQ SP,R8\nMOVQ R8,16(SP)\nMOVQ $2,SI\nMOVL $0,(SP)(SI*8)\nMOVQ 16(SP),DI\nMOVQ (DI),AX"},
		{"index cannot borrow unindexed private spill", "MOVQ SP,R8\nMOVQ R8,0(SP)\nMOVQ $1,SI\nMOVQ (SP)(SI*8),DI\nMOVQ $77,(DI)\nMOVQ $0,AX"},
		{"index cannot borrow unindexed literal spill", "LEAQ literal<>(SB),DI\nMOVQ DI,0(SP)\nMOVQ $1,SI\nMOVQ (SP)(SI*8),DI\nMOVQ (DI),AX"},
		{"mixed private and literal index", "LEAQ literal<>(SB),SI\nMOVQ (SP)(SI*1),AX"},
		{"mixed literal and private index", "LEAQ literal<>(SB),DI\nMOVQ SP,SI\nMOVQ (DI)(SI*1),AX"},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalAddressData + fixedLocalConstantIndexFunction("Value", row.body)
			pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
				"func Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("indexed access acquired uninitialized/mutable/address permission", err)
			}
		})
	}
}
