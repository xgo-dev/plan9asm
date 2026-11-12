package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64PaddingCase struct {
	name, body string
	parameter  int
	resultBits int
	signed     bool
}

func arm64PaddingCases() []arm64PaddingCase {
	var cases []arm64PaddingCase
	for _, parameter := range []int{8, 16, 32} {
		for _, load := range []Op{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
			width, _ := arm64ScalarMemoryBits(load)
			if width < parameter {
				continue
			}
			for _, signed := range []bool{false, true} {
				truncate := map[int]string{8: "MOVB", 16: "MOVH", 32: "MOVW"}[parameter]
				if !signed {
					truncate += "U"
				}
				cases = append(cases, arm64PaddingCase{
					name: fmt.Sprintf("narrow%d", len(cases)), parameter: parameter,
					resultBits: 64, signed: signed,
					body: fmt.Sprintf("%s rhs+0(FP),R2\n%s R2,R0\n", load, truncate),
				})
			}
		}
		for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"} {
			width := map[byte]int{'B': 8, 'H': 16, 'S': 32, 'D': 64}[arrangement[0]]
			if width < parameter {
				continue
			}
			body := fmt.Sprintf("MOVD rhs+0(FP),R2\nVDUP R2,V0.%s\n", arrangement)
			if shift := width - parameter; shift != 0 {
				// Go1.20 has no named VSSHR; use the same architectural raw
				// SSHR route as the original Arrow source, not a version switch.
				full := len(arrangement) > 1 && (arrangement == "B16" || arrangement == "H8" || arrangement == "S4" || arrangement == "D2")
				word := encodeARM64ImmediateShiftRight(0x0f000400, width, shift, full, 0, 0)
				body += fmt.Sprintf("VSHL $%d,V0.%s,V0.%s\nWORD $%#08x\n", shift, arrangement, arrangement, word)
			}
			body += fmt.Sprintf("VMOV V0.%c[0],R0\n", arrangement[0])
			cases = append(cases, arm64PaddingCase{
				name: fmt.Sprintf("narrow%d", len(cases)), parameter: parameter,
				body: body, resultBits: width, signed: true,
			})
		}
	}
	// Match the raw extension/flag use in Arrow independently of vector paths.
	cases = append(cases, arm64PaddingCase{
		name: fmt.Sprintf("narrow%d", len(cases)), parameter: 16, resultBits: 64,
		body: "MOVD rhs+0(FP),R2\nMOVW $0,R11\nWORD $0x6b22a17f\nCSET GT,R0\n",
	})
	return cases
}

func arm64PaddingSource(cases []arm64PaddingCase) (source, declarations string) {
	var asm, goSource strings.Builder
	goSource.WriteString("package padbits\n")
	for _, test := range cases {
		fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$0-16\n%sMOVD R0,res+8(FP)\nRET\n", test.name, test.body)
		fmt.Fprintf(&goSource, "func %s(rhs int%d) (res uint64)\n", test.name, test.parameter)
	}
	return asm.String(), goSource.String()
}

func arm64PaddingExpected(test arm64PaddingCase, input uint64) uint64 {
	var value int64
	switch test.parameter {
	case 8:
		value = int64(int8(input))
	case 16:
		value = int64(int16(input))
	case 32:
		value = int64(int32(input))
	}
	if strings.Contains(test.body, "CSET") {
		if value < 0 {
			return 1 // CMP 0, rhs.SXTH: zero > negative.
		}
		return 0
	}
	if !test.signed {
		return input & arm64PaddingMask(test.parameter)
	}
	return uint64(value) & arm64PaddingMask(test.resultBits)
}

func TestARM64FPPaddingScalarAndVectorCompleteObjects(t *testing.T) {
	cases := arm64PaddingCases()
	source, declarations := arm64PaddingSource(cases)
	requireARM64GoAssemblerResult(t, source, true)
	pkg := mustGoPackage(t, "padbits", declarations)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc", "aarch64-pc-windows-gnu"} {
		t.Run(triple, func(t *testing.T) {
			translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{GOOS: "linux", GOARCH: "arm64", TargetTriple: triple, ResolveSym: testResolveSym(pkg.Path)})
			if err != nil {
				t.Fatal(err)
			}
			defer translated.Module.Dispose()
			compileLLVMToObject(t, llc, triple, "padding.ll", "padding.o", translated.Module.String())
		})
	}
	t.Logf("%d typed source cases; seven scalar load aliases and all seven SIMD arrangements", len(cases))
}

func TestARM64FPPaddingBitMasksDoNotLoseRotationOrSignDependence(t *testing.T) {
	for _, width := range []int{8, 16, 32, 64} {
		for shift := 1; shift <= width; shift++ {
			for _, signed := range []bool{false, true} {
				mask := uint64(1) << uint(width-1)
				got := arm64PaddingShift(mask, width, int64(shift), true, signed)
				if signed && got == 0 {
					t.Fatalf("unknown sign bit disappeared: width=%d shift=%d", width, shift)
				}
				if !signed && shift == width && got != 0 {
					t.Fatalf("complete unsigned truncation retained bits: %#x", got)
				}
			}
		}
	}
	state := arm64PaddingState{"R2": {0xffffffffffff0000, 0}}
	for _, word := range []bool{false, true} {
		for shift := int64(1); shift < 32; shift++ {
			arg := Operand{Kind: OpRegShift, Reg: "R2", ShiftOp: ShiftRotate, ShiftAmount: shift}
			if state.operand(arg, word) == 0 {
				t.Fatalf("rotation washed away padding: word=%t shift=%d", word, shift)
			}
		}
	}
}
