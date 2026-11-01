package plan9asm

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"golang.org/x/arch/x86/x86asm"
)

func goAMD64FrameSplitListing(listing []byte) bool {
	for len(listing) != 0 {
		var line []byte
		line, listing, _ = bytes.Cut(listing, []byte{'\n'})
		if len(line) == 0 || line[0] == '\t' || line[0] == ' ' {
			continue
		}
		if header, valid := parseGoAMD64NativeHeader(string(line)); valid && !header.NoSplit {
			return true
		}
	}
	return false
}

func goAMD64FrameListingWithSplitObject(listing []byte, file *File, pkg GoPackage, origins map[string]int,
	texts []gostaticstorage.TextRecord, unwind *gostaticstorage.WindowsAMD64AssemblyUnwind, target, directory, root string) (map[string]goAMD64FrameFunction, error) {
	if len(texts) == 0 || target != "linux/amd64" && target != "darwin/amd64" && target != "windows/amd64" {
		return nil, goAMD64FrameContext("automatic split layout lacks its complete object/target")
	}
	return goAMD64FrameListingRecords(listing, file, pkg, origins, texts, unwind, nil, target, directory, root)
}

// Listing identity is necessary but not sufficient: the complete relocation
// inventory must subsequently match the exact generated instruction fields.
func goAMD64FrameSplitRelocationLine(r gostaticstorage.TextRelocation, target string) string {
	if r.Size != 4 || r.Add != 0 {
		return ""
	}
	kind, name := "", r.Target.Name
	switch {
	case r.Type == 15 && target != "windows/amd64" && r.Target == (gostaticstorage.TextReference{}):
		kind, name = "R_TLS_LE", "TLS"
	case r.Type == 14 && target == "windows/amd64" && name == "runtime.tls_g" && r.Target.ABIKnown && r.Target.ABI == 0:
		kind = "R_PCREL"
	case r.Type == 7 && name == "runtime.morestack_noctxt" && r.Target.ABIKnown && r.Target.ABI == 0:
		kind = "R_CALL"
	default:
		return ""
	}
	return fmt.Sprintf("rel %d+4 t=%s %s+0", r.Offset, kind, name)
}

// Go's ABI0 stack check runs before any source instruction and retries the
// entry after growth. LLVM owns a different function frame: only the ordinary
// body layout is projected for BP/SP validation, never a runtime call. Original
// bytes, positions and relocations remain in the live complete source owner.
// After either entry path, private bytes are SP+[0,frame), saved BP is at frame,
// return PC at frame+8 and FP arguments at frame+16. Generated R12/R14/FLAGS
// values are not supplied to the source body's existing typed input proof.
func goAMD64FrameSplitProjection(fn goAMD64FrameFunction, text gostaticstorage.TextRecord, frame int64,
	target, directory, root string, data *gostaticstorage.AMD64AssemblyData) (goAMD64FrameFunction, error) {
	phase := "entry identity"
	fail := func() (goAMD64FrameFunction, error) {
		return goAMD64FrameFunction{}, goAMD64FrameContext("unrecognized original automatic split layout/source/relocation: %s", phase)
	}
	if !fn.split || text.ABI != 0 || text.Flags != fn.nativeFlags() || !bytes.Equal(fn.code, text.Code) ||
		frame <= 0 || frame > 4096-8 {
		return fail()
	}
	phase = "TEXT source position"
	entry := goAMD64FrameSourcePosition{}
	for _, row := range strings.Split(fn.positions[0], "\n") {
		position, instruction, ok := strings.Cut(row, "\t")
		if !ok || !strings.HasPrefix(instruction, "TEXT\t") {
			continue
		}
		separator := strings.LastIndexByte(position, ':')
		if separator < 0 || entry.file != "" {
			return fail()
		}
		entry.file = position[:separator]
		entry.line, _ = strconv.Atoi(position[separator+1:])
	}
	if entry.file == "" || entry.line <= 0 {
		return fail()
	}
	entryPath := goAMD64FrameSourcePath(entry.file, directory, root)
	if entryPath == "" {
		return fail()
	}
	pc := 0
	read := func(op x86asm.Op, args ...x86asm.Arg) bool {
		if pc >= len(fn.code) {
			return false
		}
		ins, err := x86asm.Decode(fn.code[pc:], 64)
		if err != nil || ins.Len <= 0 || ins.Op != op {
			return false
		}
		if ins.Op == x86asm.LEA && ins.AddrSize == 64 {
			// x/arch retains disp32 as unsigned, unlike disp8. Share the
			// decoder's physical-field normalization before exact RSP matching.
			ins = normalizeDecodedX86MemoryDisplacements(ins)
		}
		for index, arg := range args {
			if ins.Args[index] != arg {
				return false
			}
		}
		pc += ins.Len
		return true
	}
	// The exact ABI0 TLS materialization differs by OS. None of these reads
	// is source-visible or grants the body permission to read TLS or entry R14.
	phase = "generated TLS load"
	tlsOffset := int64(5)
	segment := x86asm.FS
	if target == "darwin/amd64" {
		segment = x86asm.GS
	}
	if target == "windows/amd64" {
		tlsOffset = 3
		if !read(x86asm.MOV, x86asm.R14, x86asm.Mem{Base: x86asm.RIP}) ||
			!read(x86asm.MOV, x86asm.R14, x86asm.Mem{Segment: x86asm.GS, Base: x86asm.R14}) ||
			!read(x86asm.MOV, x86asm.R14, x86asm.Mem{Base: x86asm.R14}) {
			return fail()
		}
	} else if target != "linux/amd64" && target != "darwin/amd64" ||
		!read(x86asm.MOV, x86asm.R14, x86asm.Mem{Segment: segment, Scale: 1}) {
		return fail()
	}
	phase = "generated stack comparison"
	compare := x86asm.RSP
	if frame+8 > 128 {
		if !read(x86asm.LEA, x86asm.R12, x86asm.Mem{Base: x86asm.RSP, Scale: 1, Disp: 128 - frame - 8}) {
			return fail()
		}
		compare = x86asm.R12
	}
	if !read(x86asm.CMP, compare, x86asm.Mem{Base: x86asm.R14, Disp: 16}) {
		return fail()
	}
	phase = "generated slow-path branch"
	if pc >= len(fn.code) {
		return fail()
	}
	branch, err := x86asm.Decode(fn.code[pc:], 64)
	jump, ok := branch.Args[0].(x86asm.Rel)
	if err != nil || branch.Op != x86asm.JBE || !ok {
		return fail()
	}
	pc += branch.Len
	start, end := pc, pc+int(jump)
	if end <= start || end+5 >= len(fn.code) || fn.code[end] != 0xe8 || !bytes.Equal(fn.code[end+1:end+5], make([]byte, 4)) {
		return fail()
	}
	phase = "generated runtime retry"
	pc = end + 5
	retry, err := x86asm.Decode(fn.code[pc:], 64)
	relative, ok := retry.Args[0].(x86asm.Rel)
	if err != nil || retry.Op != x86asm.JMP || !ok || pc+retry.Len != len(fn.code) || pc+retry.Len+int(relative) != 0 {
		return fail()
	}
	// Generated fields take precedence over ordinary DATA references, including
	// Windows' ABI0 R_PCREL runtime.tls_g. Every other field must belong wholly
	// to the body and retain the same complete DATA object's identity rules.
	phase = "generated/body relocation partition"
	generated := 0
	var previousRelocationEnd int64
	for _, relocation := range text.Relocations {
		if relocation.Size != 4 || relocation.Offset < previousRelocationEnd || relocation.Offset > int64(len(fn.code))-relocation.Size {
			return fail()
		}
		previousRelocationEnd = relocation.Offset + relocation.Size
		switch relocation.Offset {
		case tlsOffset:
			if relocation.Type == 7 || goAMD64FrameSplitRelocationLine(relocation, target) == "" {
				return fail()
			}
			generated |= 1
		case int64(end + 1):
			if relocation.Type != 7 || goAMD64FrameSplitRelocationLine(relocation, target) == "" {
				return fail()
			}
			generated |= 2
		default:
			if data == nil || relocation.Offset < int64(start) || relocation.Offset > int64(end)-relocation.Size ||
				goAMD64FrameDataRelocationLine(relocation, data) == "" {
				return fail()
			}
		}
	}
	if generated != 3 {
		return fail()
	}
	// Actual object PC intervals, not just printed instruction names, bind
	// every generated byte to the original TEXT directive's source position.
	phase = "generated source-PC intervals"
	var previous int64
	for _, span := range text.Positions {
		if span.Start != previous || span.End <= span.Start || span.End > int64(len(fn.code)) {
			return fail()
		}
		previous = span.End
		if span.Start < int64(start) || span.End > int64(end) {
			if goAMD64FrameSourcePath(span.File, directory, root) != entryPath || int(span.Line) != entry.line {
				return fail()
			}
		}
	}
	if previous != int64(len(fn.code)) {
		return fail()
	}
	projected := fn
	projected.code = fn.code[start:end]
	projected.prologue = start
	projected.positions = make(map[int]string)
	for position, rows := range fn.positions {
		if position >= start && position < end {
			projected.positions[position-start] = rows
		}
	}
	return projected, nil
}
