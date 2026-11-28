package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// goTLSInstructions expands cmd/asm's target-dependent TLS register and
// TLS*1 index. Linux uses the runtime.tlsg ELF local-exec relocation, Darwin
// uses the Go runtime's GS-relative slot, and Windows obtains its TEB offset
// from runtime.tls_g. The caller supplies the target selected for this file.
func goTLSInstructions(ins asm.Instr, goarch, target string, legacyWindowsTLS bool) ([]asm.Instr, error) {
	index := -1
	for i, arg := range ins.Args {
		if !isTLSMemoryOperand(arg) {
			continue
		}
		if index >= 0 {
			return nil, fmt.Errorf("%w: multiple memory TLS operands in %s", asm.ErrProbeNeedsContext, ins.Raw)
		}
		index = i
	}
	if index >= 0 {
		arg := ins.Args[index]
		if strings.HasSuffix(arg.Sym, "(TLS*1)") {
			mem, ok := asm.ParseMem(strings.TrimSuffix(arg.Sym, "(TLS*1)"))
			if !ok || mem.Base == "" || mem.Index != "" || mem.Segment != "" || mem.Sym != "" {
				return nil, fmt.Errorf("invalid Go TLS reference %q", arg.Sym)
			}
			switch target {
			case "linux":
				mem.GoTLSOffset = true
				if goarch == "amd64" {
					mem.Base = ""
				}
			case "darwin":
				mem.Base = ""
				mem.Segment = asm.GS
				mem.Off += 0x30
			case "windows": // The base already holds the address of the TLS block.
			default:
				return nil, fmt.Errorf("%w: indexed Go TLS needs a modeled target", asm.ErrProbeNeedsContext)
			}
			ins.Args = append([]asm.Operand(nil), ins.Args...)
			ins.Args[index] = asm.Operand{Kind: asm.OpMem, Mem: mem}
			return []asm.Instr{ins}, nil
		}
		if target != "linux" && target != "darwin" {
			if target != "windows" || index != 0 || len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
				return nil, fmt.Errorf("%w: Go TLS operand needs a modeled target addressing mode", asm.ErrProbeNeedsContext)
			}
		} else {
			mem := asm.MemRef{GoTLSOffset: true}
			if d := strings.TrimSuffix(arg.Sym, "(TLS)"); d != "" {
				n, ok := asm.ParseImmExpr(d)
				if !ok {
					return nil, fmt.Errorf("unresolved TLS displacement %s", d)
				}
				mem.Off = int64(n)
			}
			if target == "darwin" {
				mem.GoTLSOffset = false
				mem.Segment = asm.GS
				mem.Off += 0x30
			}
			ins.Args = append([]asm.Operand(nil), ins.Args...)
			ins.Args[index] = asm.Operand{Kind: asm.OpMem, Mem: mem}
			return []asm.Instr{ins}, nil
		}
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return nil, nil
	}
	src, dst := ins.Args[0], ins.Args[1]
	explicitBase := src.Kind == asm.OpIdent && src.Ident == "TLS"
	direct := src.Kind == asm.OpSym && strings.HasSuffix(src.Sym, "(TLS)")
	if !explicitBase && !direct {
		return nil, nil
	}
	if target == "" {
		return nil, fmt.Errorf("%w: Go TLS base requires a modeled target", asm.ErrProbeNeedsContext)
	}
	width, seg := asm.OpMOVL, asm.FS
	if goarch == "amd64" {
		width, seg = asm.OpMOVQ, asm.GS
	}
	if ins.Op != width {
		return nil, fmt.Errorf("%w: unexpected Go TLS access width: %s", asm.ErrProbeNeedsContext, ins.Raw)
	}
	mov := func(src asm.Operand) asm.Instr {
		return asm.Instr{Op: width, Args: []asm.Operand{src, dst}, Raw: ins.Raw}
	}
	var disp int64
	if direct {
		off := strings.TrimSuffix(src.Sym, "(TLS)")
		if off != "" {
			n, ok := asm.ParseImmExpr(off)
			if !ok {
				return nil, fmt.Errorf("%w: unresolved TLS offset %s", asm.ErrProbeNeedsContext, off)
			}
			disp = int64(n)
		}
	}
	if target == "linux" || target == "darwin" {
		if goarch == "386" {
			return []asm.Instr{mov(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Segment: asm.GS}})}, nil
		}
		// Non-shared Go amd64 code uses single-instruction TLS accesses.
		// cmd/asm removes the companion MOVQ TLS,reg for these targets.
		return []asm.Instr{{Op: "NOP", Raw: ins.Raw}}, nil
	}
	var reads []asm.Instr
	if legacyWindowsTLS {
		// This runtime source uses the fixed 386 TEB slot throughout,
		// including functions outside the dispatch adapter.
		reads = []asm.Instr{mov(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Segment: asm.FS, Off: 0x14}})}
	} else {
		reads = []asm.Instr{
			mov(asm.Operand{Kind: asm.OpSym, Sym: "runtime·tls_g(SB)"}),
			mov(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: dst.Reg, Segment: seg}}),
		}
	}
	if direct {
		reads = append(reads, mov(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: dst.Reg, Off: disp}}))
	}
	return reads, nil
}

func isTLSMemoryOperand(arg asm.Operand) bool {
	return arg.Kind == asm.OpSym && (strings.HasSuffix(arg.Sym, "(TLS)") || strings.HasSuffix(arg.Sym, "(TLS*1)"))
}
