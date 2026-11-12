package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

type arm64PrivateDataCase struct {
	name, store, load string
	width, count      int
	signed, floating  bool
	zero              string
	mode              string
}

func arm64PrivateDataCases() []arm64PrivateDataCase {
	var cases []arm64PrivateDataCase
	for _, shape := range []arm64PrivateDataCase{
		{store: "MOVB", load: "MOVBU", width: 1, count: 1},
		{store: "MOVBU", load: "MOVBU", width: 1, count: 1},
		{store: "MOVH", load: "MOVHU", width: 2, count: 1},
		{store: "MOVHU", load: "MOVHU", width: 2, count: 1},
		{store: "MOVW", load: "MOVWU", width: 4, count: 1},
		{store: "MOVWU", load: "MOVWU", width: 4, count: 1},
		{store: "MOVD", load: "MOVD", width: 8, count: 1},
		{store: "MOVB", load: "MOVB", width: 1, count: 1, signed: true},
		{store: "MOVH", load: "MOVH", width: 2, count: 1, signed: true},
		{store: "MOVW", load: "MOVW", width: 4, count: 1, signed: true},
		{store: "FMOVS", load: "FMOVS", width: 4, count: 1, floating: true},
		{store: "FMOVD", load: "FMOVD", width: 8, count: 1, floating: true},
		{store: "FMOVQ", load: "FMOVQ", width: 16, count: 1, floating: true},
		{store: "STPW", load: "LDPW", width: 4, count: 2},
		{store: "STPW", load: "LDPSW", width: 4, count: 2, signed: true},
		{store: "STP", load: "LDP", width: 8, count: 2},
		{store: "FSTPS", load: "FLDPS", width: 4, count: 2, floating: true},
		{store: "FSTPD", load: "FLDPD", width: 8, count: 2, floating: true},
		{store: "FSTPQ", load: "FLDPQ", width: 16, count: 2, floating: true},
	} {
		modes := []string{"offset", "pre_post", "post_pre"}
		if shape.count == 1 {
			modes = append(modes, "unscaled")
			if shape.width < 16 {
				modes = append(modes, "indexed", "indexed_scaled")
			}
		}
		for _, mode := range modes {
			current := shape
			current.mode = mode
			current.name = fmt.Sprintf("Data%d", len(cases))
			cases = append(cases, current)
		}
		if shape.count == 1 && !shape.floating && !shape.signed {
			for _, zero := range []string{"ZR", "$0"} {
				for _, mode := range []string{"offset", "pre_post", "post_pre", "indexed", "indexed_scaled"} {
					current := shape
					current.zero, current.mode = zero, mode
					current.name = fmt.Sprintf("Data%d", len(cases))
					cases = append(cases, current)
				}
			}
		}
	}
	return cases
}

func arm64PrivateDataFamilyFixture() (string, string, []arm64PrivateDataCase) {
	cases := arm64PrivateDataCases()
	var source, declarations strings.Builder
	source.WriteString("#include \"textflag.h\"\n")
	for _, tc := range cases {
		fmt.Fprintf(&declarations, "func %s(src,dst *byte)\n", tc.name)
		fmt.Fprintf(&source, `TEXT ·%s(SB),NOSPLIT,$128-16
    CALL ·Noop(SB)
    MOVD src+0(FP),R6
    MOVD dst+8(FP),R7
    ADD $32,RSP,R17
`, tc.name)
		input, output := "R4", "R9"
		if tc.floating {
			source.WriteString("    FMOVQ (R6),F0\n    FMOVQ 16(R6),F1\n")
			input, output = "F0", "F2"
		} else {
			source.WriteString("    MOVD (R6),R4\n    MOVD 8(R6),R5\n")
		}
		if tc.zero != "" {
			input = tc.zero
		}
		if tc.count == 2 {
			input, output = "(R4,R5)", "(R9,R10)"
			if tc.floating {
				input, output = "(F0,F1)", "(F2,F3)"
			}
		}
		storeOp, loadOp := tc.store, tc.load
		storeAddress, loadAddress := "16(R17)", "16(R17)"
		switch tc.mode {
		case "pre_post":
			storeOp, loadOp = tc.store+".W", tc.load+".P"
			storeAddress, loadAddress = "16(R17)", "-16(R17)"
		case "post_pre":
			storeOp, loadOp = tc.store+".P", tc.load+".W"
			storeAddress, loadAddress = "16(R17)", "-16(R17)"
		case "unscaled":
			storeAddress, loadAddress = "9(R17)", "9(R17)"
		case "indexed":
			source.WriteString("    MOVD $7,R11\n")
			storeAddress, loadAddress = "(R17)(R11)", "(R17)(R11)"
		case "indexed_scaled":
			source.WriteString("    MOVD $7,R11\n")
			shift := map[int]int{1: 0, 2: 1, 4: 2, 8: 3}[tc.width]
			storeAddress = fmt.Sprintf("(R17)(R11<<%d)", shift)
			loadAddress = storeAddress
		}
		fmt.Fprintf(&source, "    %s %s,%s\n    %s %s,%s\n", storeOp, input, storeAddress, loadOp, loadAddress, output)
		if tc.floating {
			outputOp := map[int]string{4: "FMOVS", 8: "FMOVD", 16: "FMOVQ"}[tc.width]
			fmt.Fprintf(&source, "    %s F2,(R7)\n", outputOp)
			if tc.count == 2 {
				fmt.Fprintf(&source, "    %s F3,%d(R7)\n", outputOp, tc.width)
			}
		} else {
			source.WriteString("    MOVD R9,(R7)\n")
			if tc.count == 2 {
				source.WriteString("    MOVD R10,8(R7)\n")
			}
		}
		source.WriteString("    RET\n")
	}
	source.WriteString("TEXT ·Noop(SB),NOSPLIT|NOFRAME,$0-0\n    RET\n")
	return source.String(), declarations.String(), cases
}

func arm64PrivateDataExpected(tc arm64PrivateDataCase, input [32]byte) [32]byte {
	var expected [32]byte
	for index := range expected {
		expected[index] = 0xa7
	}
	if tc.floating {
		for index := 0; index < tc.count; index++ {
			copy(expected[index*tc.width:(index+1)*tc.width], input[index*16:index*16+tc.width])
		}
		return expected
	}
	for index := 0; index < tc.count; index++ {
		value := binary.LittleEndian.Uint64(input[index*8 : (index+1)*8])
		if tc.width < 8 {
			mask := uint64(1)<<uint(tc.width*8) - 1
			value &= mask
			if tc.signed && value&(uint64(1)<<uint(tc.width*8-1)) != 0 {
				value |= ^mask
			}
		}
		if tc.zero != "" {
			value = 0
		}
		binary.LittleEndian.PutUint64(expected[index*8:(index+1)*8], value)
	}
	return expected
}

func TestARM64PrivateDataMemoryFamilyObjects(t *testing.T) {
	source, declarations, cases := arm64PrivateDataFamilyFixture()
	arm64PrivateDataBoundObjects(t, source, declarations, "private-data-family")
	t.Logf("%d named scalar/pair GP/FP widths, sign, zero aliases and offset/pre/post/unscaled/indexed forms: actual Go + 3 APIs x 4 targets", len(cases))
}

func TestCrossLinuxRuntimeMatrixARM64PrivateDataMemoryFamily(t *testing.T) {
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	source, declarations, cases := arm64PrivateDataFamilyFixture()
	var goSource, cSource strings.Builder
	goSource.WriteString("package main\n" + declarations + "func Noop()\nfunc main() {\n")
	cSource.WriteString("#include <stdint.h>\n#include <string.h>\n")
	for _, tc := range cases {
		fmt.Fprintf(&cSource, "extern void %s(const uint8_t *,uint8_t *);\n", tc.name)
	}
	cSource.WriteString("int main(void) {\n")
	// These are ordinary numeric data and output buffers. No physical caller
	// stack or return address is inspected or modified by either oracle.
	for pattern := 0; pattern < 3; pattern++ {
		var input [32]byte
		for index := range input {
			input[index] = byte(index*71 + 0x8f + pattern*97)
		}
		for _, tc := range cases {
			expected := arm64PrivateDataExpected(tc, input)
			fmt.Fprintf(&goSource, `    {
        input := %#v
        expected := %#v
        var output [48]byte
        for i := range output { output[i] = 0xa7 }
        %s(&input[0],&output[8])
        for i := range output {
            want := byte(0xa7)
            if i>=8 && i<40 { want=expected[i-8] }
            if output[i]!=want { panic(%q) }
        }
    }
`, input, expected, tc.name, "private data family value/canary "+tc.name)
			fmt.Fprintf(&cSource, `    {
        const uint8_t input[] = {%s};
        const uint8_t expected[] = {%s};
        uint8_t output[48];
        memset(output,0xa7,sizeof(output));
        %s(input,output+8);
        for(unsigned i=0;i<sizeof(output);i++) {
            uint8_t want=(i>=8 && i<40)?expected[i-8]:UINT8_C(0xa7);
            if(output[i]!=want) return %d;
        }
    }
`, arm64PrivateDataCBytes(input[:]), arm64PrivateDataCBytes(expected[:]), tc.name, pattern+1)
		}
	}
	goSource.WriteString("}\n")
	cSource.WriteString("    return 0;\n}\n")
	runARM64LocalRegisterGoOracle(t, source, goSource.String(), len(runner) != 0, "1.20")
	ir := arm64PrivateIndexedModule(t, source, declarations, target)
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "private_data_family", target, ir, cSource.String(), runner)
	t.Logf("actual Go and LLVM/C passed %d initialized numerical/full-canary cases", len(cases)*3)
}

func arm64PrivateDataCBytes(data []byte) string {
	values := make([]string, len(data))
	for index, value := range data {
		values[index] = fmt.Sprintf("%d", value)
	}
	return strings.Join(values, ",")
}
