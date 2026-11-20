package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func x86PackedPrecisionOriginal(t *testing.T) (string, string) {
	t.Helper()
	const path = "amd64_raw_packed_precision_convert_test.go"
	const root = "TestX86RawPackedPrecisionConvertRuntimeSemantics"
	source := x86X87FunctionLiteral(t, path, root, "namedSource")
	reference := x86X87FunctionLiteral(t, path, root, "mainC")
	if fmt.Sprintf("%x", sha256.Sum256([]byte(source))) != "9164082e7bcb642692d756b595fdd38094cbfd07a24511a609dcfef1dce345cf" ||
		fmt.Sprintf("%x", sha256.Sum256([]byte(reference))) != "5fc9a3c35dd0d671f5e4fc458e874b3a49344831fa215be1a06a83fd78b8b1f3" {
		t.Fatal("complete original initialized packed precision ASM/C or observations changed")
	}
	return source, reference
}

func x86PackedPrecisionRawOriginal(source string) string {
	return strings.NewReplacer(
		"VCVTPS2PD (BX), Y1", "BYTE $0xc5; BYTE $0xfc; BYTE $0x5a; BYTE $0x0b",
		"VCVTPD2PSY (CX), X2", "BYTE $0xc5; BYTE $0xfd; BYTE $0x5a; BYTE $0x11",
	).Replace(source)
}

func TestX86PackedPrecisionOriginalInitializedThreeAPIObjects(t *testing.T) {
	original, _ := x86PackedPrecisionOriginal(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete original packed precision objects require LLVM22")
	}
	const declaration = "func packedprecision(out *[48]byte,singles *[4]float32,doubles *[4]float64)\n"
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", triple, raw), func(t *testing.T) {
				source := original
				if raw {
					source = x86PackedPrecisionRawOriginal(source)
				}
				x86LEAActualTargetGoObject(t, "amd64", triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
						if err != nil || ir == "" {
							t.Fatal("the original fully initialized packed precision source remains unclosed", err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							x86ScalarPrecisionRequireNativeEffects(t, text,
								map[string][]string{"packedprecision": {"VCVTPS2PD", "VCVTPD2PS"}})
							compileLLVMToObject(t, llc, triple, "original-packed-precision.ll", "original-packed-precision.o", text)
						}
					})
				}
			})
		}
	}
}

// The first 64 bytes are separately declared scalar fields, not an array
// allocation or native stack backing. The same source observes every output
// byte, nonzero old aliases, CF and MXCSR without introducing a DF host axis.
func x86PackedPrecisionProgram(row x86PackedPrecisionOracleRow, index int, arch string) (source, declaration, name string) {
	word, move := int(goWordSize(arch)), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	name = fmt.Sprint("PackedPrecision", index)
	var fields []string
	fields = append(fields, "value byte")
	for at := 1; at < 64; at++ {
		fields = append(fields, fmt.Sprintf("a%d byte", at))
	}
	declaration = fmt.Sprintf("func %s(%s,out *[80]byte,input,old *[64]byte,mask uint64)\n", name, strings.Join(fields, ","))
	prepare := ""
	if row.source == "register" {
		prepare = "VMOVDQU64 (BX),Z0\n"
	}
	source = fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+64(FP),DI\n%s input+%d(FP),BX\n"+
		"%s old+%d(FP),DX\n%sVMOVDQU64 (DX),Z1\n"+
		"MOVL mask+%d(FP),AX\nKMOVD AX,K1\nSTC\n%s\nVMOVDQU64 Z1,(DI)\nSETCS 64(DI)\nSTMXCSR 68(DI)\nRET\n",
		name, 64+3*word+8, move, move, 64+word, move, 64+2*word, prepare, 64+3*word, row.instruction())
	return source, declaration, name
}

func x86PackedPrecisionNativeName(op string) string {
	if op == "VCVTPD2PSX" || op == "VCVTPD2PSY" {
		return "VCVTPD2PS"
	}
	return op
}

func TestX86PackedPrecisionOrthogonalInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("packed precision objects require LLVM22")
	}
	rows := x86PackedPrecisionOracleRows()
	if len(rows) != 53 || len(rows) > 64 {
		t.Fatal("orthogonal complete object directory changed", len(rows))
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			functions := make(map[string][]string)
			for index, row := range rows {
				body, declaration, name := x86PackedPrecisionProgram(row, index, target.arch)
				source.WriteString(body)
				declarations.WriteString(declaration)
				functions[name] = []string{x86PackedPrecisionNativeName(row.op)}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized packed precision directory remains unclosed", err)
					}
					for _, pipeline := range []struct{ name, level, ir string }{
						{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir},
						{"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							x86ScalarPrecisionRequireNativeEffects(t, pipeline.ir, functions)
							x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
						})
					}
				})
			}
		})
	}
}
