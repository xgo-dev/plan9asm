package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ResultBlockNativeInsertReadCompleteSourceForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var source, declarations strings.Builder
	count := 0
	for _, row := range x86InsertExtractFormats() {
		if !strings.HasPrefix(row, "VINSERT") || strings.HasSuffix(strings.Fields(row)[0], "PS") || !strings.Contains(row, "(BX)") {
			continue
		}
		ins := x86ScalarLaneInstruction(t, row)
		destination := ins.Args[len(ins.Args)-1].Reg
		fmt.Fprintf(&declarations, "func load%d(p *[32]byte, mask uint32) uint32\n", count)
		fmt.Fprintf(&source, `TEXT ·load%d(SB),4,$0-20
MOVQ p+0(FP),AX
MOVL mask+8(FP),CX
KMOVW CX,K1
VPXORQ Z1,Z1,Z1
VPXORQ Z2,Z2,Z2
%s
PEXTRD $0,X%s,AX
MOVL AX,ret+16(FP)
RET
`, count, strings.Replace(row, "(BX)", "(AX)", 1), string(destination)[1:])
		// These source rows have four/five operands; mode32's rejection is
		// an independent Go frontend axis, not an omitted object target.
		goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		count++
	}
	if count == 0 {
		t.Fatal("missing independent memory-insertion formats")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				if strings.Count(ir, "load volatile <") < count {
					t.Fatal("conditional byte availability lost its paired native tuple read", api)
				}
				compileLLVMToObject(t, llc, triple, "native-insert.ll", "native-insert.o", ir)
			}
		})
	}
}

func TestX86ResultBlockNativeInsertReadDoesNotGrantOtherAuthority(t *testing.T) {
	for _, row := range []string{
		"VINSERTF32X4 $1,(AX),Z1,Z2",
		"VINSERTI64X4.Z $1,(AX),Z1,K1,Z2",
	} {
		body := "MOVQ p+0(FP),AX\nVPXORQ Z1,Z1,Z1\nMOVL $0,CX\nKMOVW CX,K1\n" + row +
			"\nPEXTRD $0,X2,AX\nMOVL AX,ret0+8(FP)\nRET"
		_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *[32]byte) uint32", body)
		for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
			if err := check(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("standalone observer acquired a native-memory certificate", row, err)
			}
		}
		for _, bad := range []string{
			strings.Replace(body, "(AX)", "(DX)", 1),
			strings.Replace(body, "(AX)", "(AX)(DX*1)", 1),
			strings.Replace(body, "MOVQ p+0(FP),AX", "MOVQ $1,AX", 1),
			strings.Replace(body, "KMOVW CX,K1", "NOP", 1),
		} {
			if !strings.Contains(row, "K1") && strings.Contains(bad, "NOP") {
				continue
			}
			source := "TEXT ·Value(SB),4,$0-12\n" + bad + "\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[32]byte) uint32\n", "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unknown native address/index/mask was laundered", row, api, err)
				}
			}
		}
	}
}

func TestX86ResultBlockNativeInsertReadRawOriginStaysStrict(t *testing.T) {
	_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *[32]byte) uint32",
		"MOVQ p+0(FP),AX\nVPXORQ Z1,Z1,Z1\nVINSERTF32X4 $0,(AX),Z1,Z2\nPEXTRD $0,X2,CX\nMOVL CX,ret0+8(FP)\nRET")
	for _, mutation := range []string{"decoded", "address size", "unknown address size", "raw TEXT", "source stack", "fixed local"} {
		t.Run(mutation, func(t *testing.T) {
			fn := file.Funcs[0]
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			switch mutation {
			case "decoded":
				fn.Instrs[3].x86Encoded = true
			case "address size":
				fn.Instrs[3].x86AddressBits = 32
			case "unknown address size":
				fn.Instrs[3].x86UnboundAddressOverride = true
			case "raw TEXT":
				fn.X86RawText = []byte{0xc3}
			case "source stack":
				fn.x86SourceStack = new(x86SourceStackProof)
			case "fixed local":
				fn.x86FixedLocal = new(x86FixedLocalProof)
			}
			context := &amd64Ctx{fpScalarSource: fn, sig: sig, goarch: "amd64"}
			if err := context.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("raw entry acquired the ordinary paired native read", mutation, err)
			}
		})
	}
}
