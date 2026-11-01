package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedDoubleDwordMode uint8

const (
	amd64PackedDwordToDouble amd64PackedDoubleDwordMode = iota
	amd64PackedDoubleToDword
)

type amd64PackedDoubleDwordSpec struct {
	mode         amd64PackedDoubleDwordMode
	legacy       bool
	truncate     bool
	sourceBytes  int
	destBytes    int
	resultLanes  int
	explicitMode string
}

// This table is both the translation dispatch and the source of truth used by
// cmd/plan9asmll's supported-opcode extractor.
var amd64PackedDoubleDwordOps = map[string]amd64PackedDoubleDwordSpec{
	"CVTPD2PL":    {mode: amd64PackedDoubleToDword, legacy: true, sourceBytes: 16, destBytes: 16, resultLanes: 2},
	"CVTTPD2PL":   {mode: amd64PackedDoubleToDword, legacy: true, truncate: true, sourceBytes: 16, destBytes: 16, resultLanes: 2},
	"VCVTDQ2PD":   {mode: amd64PackedDwordToDouble},
	"VCVTPD2DQ":   {mode: amd64PackedDoubleToDword, sourceBytes: 64, destBytes: 32, resultLanes: 8, explicitMode: "rounding"},
	"VCVTPD2DQX":  {mode: amd64PackedDoubleToDword, sourceBytes: 16, destBytes: 16, resultLanes: 2},
	"VCVTPD2DQY":  {mode: amd64PackedDoubleToDword, sourceBytes: 32, destBytes: 16, resultLanes: 4},
	"VCVTTPD2DQ":  {mode: amd64PackedDoubleToDword, truncate: true, sourceBytes: 64, destBytes: 32, resultLanes: 8, explicitMode: "sae"},
	"VCVTTPD2DQX": {mode: amd64PackedDoubleToDword, truncate: true, sourceBytes: 16, destBytes: 16, resultLanes: 2},
	"VCVTTPD2DQY": {mode: amd64PackedDoubleToDword, truncate: true, sourceBytes: 32, destBytes: 16, resultLanes: 4},
}

type amd64PackedDoubleDwordSuffix struct {
	broadcast bool
	rounding  string
	sae       bool
	zeroing   bool
}

func parseAMD64PackedDoubleDwordSuffix(rawOp, baseOp string) (amd64PackedDoubleDwordSuffix, error) {
	var result amd64PackedDoubleDwordSuffix
	if rawOp == baseOp {
		return result, nil
	}
	suffixes := strings.Split(strings.TrimPrefix(rawOp, baseOp+"."), ".")
	for index, suffix := range suffixes {
		switch suffix {
		case "BCST":
			if result.broadcast || result.rounding != "" || result.sae || result.zeroing || index != 0 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .BCST suffix", baseOp)
			}
			result.broadcast = true
		case "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE":
			if result.broadcast || result.rounding != "" || result.sae || result.zeroing || index != 0 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .%s suffix", baseOp, suffix)
			}
			result.rounding = suffix
		case "SAE":
			if result.broadcast || result.rounding != "" || result.sae || result.zeroing || index != 0 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .SAE suffix", baseOp)
			}
			result.sae = true
		case "Z":
			if result.zeroing || index != len(suffixes)-1 {
				return result, fmt.Errorf("amd64 %s has invalid or misplaced .Z suffix", baseOp)
			}
			result.zeroing = true
		default:
			return result, fmt.Errorf("amd64 %s has unsupported suffix .%s", baseOp, suffix)
		}
	}
	return result, nil
}

// Dword-to-double retains its reviewed source/caller grammar; the remaining
// eight names use the complete packed numeric conversion family.
func (c *amd64Ctx) lowerPackedDoubleDword(op Op, ins Instr) (bool, bool, error) {
	if _, known, _ := x86SignedPackedFloatProperties(ins, c.goarch); known {
		return c.lowerSignedPackedIntegerFloat(op, ins)
	}
	return c.lowerPackedNumericConversion(op, ins)
}

func (c *amd64Ctx) lowIntegerLanes(value string, physicalLanes, resultLanes, laneBits int) string {
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> poison, <%d x i32> <", low, physicalLanes, laneBits, value, physicalLanes, laneBits, resultLanes)
	for lane := 0; lane < resultLanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", lane)
	}
	c.b.WriteString(">\n")
	return "%" + low
}
