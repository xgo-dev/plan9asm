package plan9asm

import (
	"fmt"
	"strings"
)

type amd64TwoSourcePermuteSuffixes struct {
	broadcast bool
	zeroing   bool
}

func amd64ParseTwoSourcePermuteSuffixes(rawOp, baseOp string) (amd64TwoSourcePermuteSuffixes, error) {
	var suffixes amd64TwoSourcePermuteSuffixes
	dot := strings.IndexByte(rawOp, '.')
	if dot < 0 {
		return suffixes, nil
	}
	parts := strings.Split(rawOp[dot+1:], ".")
	for index, part := range parts {
		switch part {
		case "BCST":
			if suffixes.broadcast || suffixes.zeroing || index != 0 {
				return suffixes, fmt.Errorf("amd64 %s has invalid or duplicate .BCST suffix", baseOp)
			}
			suffixes.broadcast = true
		case "Z":
			if suffixes.zeroing || index != len(parts)-1 {
				return suffixes, fmt.Errorf("amd64 %s has invalid or duplicate .Z suffix", baseOp)
			}
			suffixes.zeroing = true
		default:
			return suffixes, fmt.Errorf("amd64 %s has unsupported suffix .%s", baseOp, part)
		}
	}
	return suffixes, nil
}
