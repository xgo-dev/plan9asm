package plan9asm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"golang.org/x/arch/x86/x86asm"
)

type x86TLSRuntimeModel uint8

const (
	x86TLSRuntimeLocalExec x86TLSRuntimeModel = iota + 1
	x86TLSRuntimeInitialExec
	x86TLSRuntimeWindows
)

const (
	x86ELFTLSSlot     = "runtime.tlsg"
	x86WindowsTLSSlot = "runtime.tls_g"
)

type x86TLSRuntimeRead struct {
	Model  x86TLSRuntimeModel
	Reg    Reg
	Offset int64
}

type x86TLSRuntimeSite struct {
	Function, Instruction int
	PC                    int64
	Read                  x86TLSRuntimeRead
}

func x86TLSRuntimeReadShape(ins Instr, arch string) (x86TLSRuntimeRead, bool) {
	if arch != "386" || ins.Op != "MOVL" || !x86ResultNamedPredicateInstruction(ins) {
		return x86TLSRuntimeRead{}, false
	}
	form, known, err := x86TLSMoveProperties(ins, arch)
	if err != nil || !known || form.memory != 0 || !form.gp {
		return x86TLSRuntimeRead{}, false
	}
	mem, dst := ins.Args[0].Mem, ins.Args[1].Reg
	_, _, valid := x86ResultGP(dst, 4, arch)
	if !valid || mem.Base != TLS || mem.Index != "" || mem.Scale != 0 ||
		mem.Sym != "" || mem.Segment != "" || mem.OffRaw != "" || mem.IndexExt != "" ||
		mem.Off < -1<<31 || mem.Off >= 1<<31 {
		return x86TLSRuntimeRead{}, false
	}
	return x86TLSRuntimeRead{Reg: dst, Offset: mem.Off}, true
}

// The observed code belongs to one exact source statement. Check all native
// register, segment, displacement, and relocation roles before selecting the
// runtime access. No decision comes from a target name or a listing alone.
func x86TLSObservedRuntimeRead(ins Instr, arch, target string, text gostaticstorage.TextRecord, start, end int64) (x86TLSRuntimeRead, bool) {
	read, valid := x86TLSRuntimeReadShape(ins, arch)
	if !valid || start < 0 || end <= start || end > int64(len(text.Code)) ||
		(target != "linux/386" && target != "windows/386") {
		return x86TLSRuntimeRead{}, false
	}
	index, _, _ := x86ResultGP(read.Reg, 4, arch)
	reg := x86asm.EAX + x86asm.Reg(index)
	code := text.Code[start:end]
	var relocs []gostaticstorage.TextRelocation
	for _, reloc := range text.Relocations {
		if reloc.Offset < end && reloc.Offset+reloc.Size > start {
			relocs = append(relocs, reloc)
		}
	}
	pc := start
	move := func(mem x86asm.Mem) bool {
		next, err := x86asm.Decode(code, 32)
		if err != nil || next.Len <= 0 || next.Len > len(code) || next.Op != x86asm.MOV ||
			next.DataSize != 32 || next.AddrSize != 32 || next.Args[0] != reg || next.Args[1] != mem {
			return false
		}
		code, pc = code[next.Len:], pc+int64(next.Len)
		return true
	}
	relocate := func(kind uint16, addend int64, symbol string) bool {
		if len(relocs) == 0 {
			return false
		}
		reloc := relocs[0]
		if reloc.Type != kind || reloc.Offset != pc-4 || reloc.Size != 4 ||
			reloc.Add != addend || reloc.Target.Name != symbol {
			return false
		}
		relocs = relocs[1:]
		return true
	}
	// Go x86 shared text acquires its own PC before a TLS or runtime symbol
	// access. Verify the exact injected call and its register-specific target.
	thunk := len(code) >= 5 && code[0] == 0xe8
	if thunk {
		if string(code[:5]) != "\xe8\x00\x00\x00\x00" {
			return x86TLSRuntimeRead{}, false
		}
		code, pc = code[5:], pc+5
		if !relocate(7, 0, "__x86.get_pc_thunk."+strings.ToLower(string(read.Reg))) { // R_CALL
			return x86TLSRuntimeRead{}, false
		}
	}
	switch {
	case target == "linux/386" && !thunk:
		valid = move(x86asm.Mem{Segment: x86asm.GS}) && move(x86asm.Mem{Base: reg}) &&
			relocate(15, read.Offset, "") // R_TLS_LE
		read.Model = x86TLSRuntimeLocalExec
	case target == "linux/386":
		valid = move(x86asm.Mem{Base: reg}) && relocate(16, 2, "") && // R_TLS_IE and its PC bias
			move(x86asm.Mem{Segment: x86asm.GS, Base: reg, Disp: read.Offset})
		read.Model = x86TLSRuntimeInitialExec
	default:
		if thunk {
			valid = move(x86asm.Mem{Base: reg}) && relocate(14, 6, x86WindowsTLSSlot) // R_PCREL
		} else {
			valid = move(x86asm.Mem{}) && relocate(1, 0, x86WindowsTLSSlot) // R_ADDR
		}
		valid = valid && move(x86asm.Mem{Segment: x86asm.FS, Base: reg}) &&
			move(x86asm.Mem{Base: reg, Disp: read.Offset})
		read.Model = x86TLSRuntimeWindows
	}
	return read, valid && len(code) == 0 && len(relocs) == 0
}

func x86CertifiedTLSRuntimeRead(ins Instr, arch string) (x86TLSRuntimeRead, bool) {
	if ins.x86TLSRuntimeRead == nil {
		return x86TLSRuntimeRead{}, false
	}
	read, valid := x86TLSRuntimeReadShape(ins, arch)
	observed := *ins.x86TLSRuntimeRead
	read.Model = observed.Model
	return read, valid && read == observed && observed.Model >= x86TLSRuntimeLocalExec && observed.Model <= x86TLSRuntimeWindows
}

func x86TLSRuntimeReadResult(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
	_, valid := x86CertifiedTLSRuntimeRead(ins, arch)
	return valid && x86ResultStore(ins.Args[1], 4, state, owned, resultOffset, arch)
}

func (c *amd64Ctx) lowerTLSRuntimeRead(ins Instr) error {
	read, valid := x86CertifiedTLSRuntimeRead(ins, c.goarch)
	if !valid {
		return x86TLSMoveContext("runtime read lost its originating source")
	}
	var address string
	if read.Model == x86TLSRuntimeWindows {
		slot, segment, base := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load volatile i32, ptr %s, align 1\n", slot, llvmGlobal(x86WindowsTLSSlot))
		fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %%%s to ptr addrspace(257)\n", segment, slot)
		fmt.Fprintf(c.b, "  %%%s = load volatile ptr, ptr addrspace(257) %%%s, align 1\n", base, segment)
		address = "%" + base
	} else {
		base := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call ptr @llvm.threadlocal.address.p0(ptr %s)\n", base, llvmGlobal(x86ELFTLSSlot))
		address = "%" + base
	}
	offset, loaded, extended := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i32 %d\n", offset, address, read.Offset)
	fmt.Fprintf(c.b, "  %%%s = load volatile i32, ptr %%%s, align 1\n", loaded, offset)
	fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", extended, loaded)
	return c.storeReg(read.Reg, "%"+extended)
}

func emitX86TLSRuntimeDeclaration(b *strings.Builder, model x86TLSRuntimeModel) string {
	if model == x86TLSRuntimeWindows {
		fmt.Fprintf(b, "%s = external global i32\n", llvmGlobal(x86WindowsTLSSlot))
		return x86WindowsTLSSlot
	}
	mode := "localexec"
	if model == x86TLSRuntimeInitialExec {
		mode = "initialexec"
	}
	fmt.Fprintf(b, "%s = external thread_local(%s) global i32\n", llvmGlobal(x86ELFTLSSlot), mode)
	b.WriteString("declare ptr @llvm.threadlocal.address.p0(ptr)\n")
	return x86ELFTLSSlot
}
