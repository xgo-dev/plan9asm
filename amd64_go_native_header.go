package plan9asm

import (
	"regexp"
	"strconv"
)

// This is listing metadata, not native entry, local backing or ABI authority.
// Preserve absent fields and the two official writer alignment positions.
type goAMD64NativeHeader struct {
	Symbol                                             string
	Kind                                               uint8
	Static, DupOK, CFunc, NoSplit, TopFrame, ASM, Leaf bool
	Size, Locals, Align                                uint64
	Args                                               int64
	ArgsKnown, HasAlign, HasFuncID, LegacyAlign        bool
	FuncID                                             uint8
}

var goAMD64NativeHeaderPattern = regexp.MustCompile(`^(\S+) (STEXT|STEXTFIPS)(?: (static))?(?: (dupok))?(?: (cfunc))?(?: (nosplit))?(?: (topframe))?(?: (asm))? size=([0-9]+)(?: align=0x([0-9a-f]+))? args=0x([0-9a-f]+) locals=0x([0-9a-f]+)(?: funcid=0x([0-9a-f]+))?(?: align=0x([0-9a-f]+))?(?: (leaf))?$`)

func parseGoAMD64NativeHeader(line string) (goAMD64NativeHeader, bool) {
	var header goAMD64NativeHeader
	fields := goAMD64NativeHeaderPattern.FindStringSubmatch(line)
	if fields == nil || fields[10] != "" && fields[14] != "" {
		return header, false
	}
	size, sizeErr := strconv.ParseUint(fields[9], 10, 63)
	args, argsErr := strconv.ParseUint(fields[11], 16, 64)
	locals, localsErr := goAMD64FrameSignedLocals(fields[12])
	if sizeErr != nil || argsErr != nil || localsErr != nil || uint64(int64(int32(args))) != args ||
		int64(args) < 0 && int64(args) != -0x80000000 {
		return header, false
	}
	header = goAMD64NativeHeader{Symbol: fields[1], Kind: 1, Static: fields[3] != "", DupOK: fields[4] != "",
		CFunc: fields[5] != "", NoSplit: fields[6] != "", TopFrame: fields[7] != "", ASM: fields[8] != "", Leaf: fields[15] != "",
		Size: size, Args: int64(args), Locals: uint64(locals), ArgsKnown: int64(args) != -0x80000000,
		HasAlign: fields[10] != "" || fields[14] != "", HasFuncID: fields[13] != "", LegacyAlign: fields[14] != ""}
	if fields[2] == "STEXTFIPS" {
		header.Kind = 2
	}
	if header.HasFuncID {
		funcID, err := strconv.ParseUint(fields[13], 16, 8)
		if err != nil {
			return goAMD64NativeHeader{}, false
		}
		header.FuncID = uint8(funcID)
	}
	if header.HasAlign {
		raw, bits := fields[10], 15 // Current LSym.Align is a nonnegative int16.
		if header.LegacyAlign {
			raw, bits = fields[14], 31 // Older FuncInfo.Align is int32.
		}
		align, err := strconv.ParseUint(raw, 16, bits)
		if err != nil {
			return goAMD64NativeHeader{}, false
		}
		header.Align = align
	}
	return header, true
}

func (header goAMD64NativeHeader) objectFlags() uint8 {
	var flags uint8
	if header.DupOK {
		flags |= 0x01
	}
	if header.Leaf {
		flags |= 0x08
	}
	if header.NoSplit {
		flags |= 0x10
	}
	return flags
}

// Special runtime/linker roles remain observations, outside the existing
// ordinary ABI0 and same-source private leaf entry contracts.
func (header goAMD64NativeHeader) ordinaryFrameRole() bool {
	return header.ASM && header.HasFuncID && header.FuncID == 0 &&
		!header.DupOK && !header.CFunc && !header.TopFrame && !header.Leaf
}
