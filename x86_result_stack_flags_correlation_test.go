package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// These are independent numerical programs, not replacements for the original
// eighteen-TEXT Windows fixture. Two copies of the same FLAGS bits must cancel
// after XOR even when their entry values are unknown. No unknown bit becomes
// available to an unrelated read, branch, pointer or return.
func x86StackFlagsCorrelationBody(width, register string, mask uint32) string {
	return fmt.Sprintf("PUSHF%s\nPUSHF%s\nXOR%s $%d,0(SP)\nPOPF%s\n"+
		"PUSHF%s\nPOP%s %s\nXOR%s 0(SP),%s\nPOPF%s\n",
		width, width, width, mask, width, width, width, register, width, register, width)
}

func TestX86Mode32PrivateFlagsCopiesCancelUnknownInputs(t *testing.T) {
	for _, row := range []struct {
		width, typ string
		bytes      int
		masks      []uint32
	}{
		{"W", "uint16", 2, []uint32{0, 1, 0x40, 0x400, 0x8d5}},
		{"L", "uint32", 4, []uint32{0, 1, 0x400, 0x200000, 0x200cd5}},
	} {
		for _, register := range []string{"AX", "BX", "CX", "DX", "BP", "SI", "DI"} {
			for _, mask := range row.masks {
				body := x86StackFlagsCorrelationBody(row.width, register, mask)
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sMOV%s %s,ret+0(FP)\nRET\n",
					row.bytes, body, row.width, register)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/%x/%s", row.width, register, mask, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() "+row.typ,
							"386", "i386-unknown-linux-gnu", api)
						if err != nil || ir == "" {
							t.Fatal("balanced private FLAGS copies did not cancel their same unknown bits", err)
						}
					})
				}
			}
		}
	}
}

func TestX86Mode32PrivateFlagsSubwordCopiesCancel(t *testing.T) {
	for _, carrier := range []struct {
		width, typ string
		bytes      int
	}{
		{"W", "uint16", 2}, {"L", "uint32", 4},
	} {
		for _, access := range []struct {
			width string
			bytes int
		}{
			{"B", 1}, {"W", 2}, {"L", 4},
		} {
			for offset := 0; offset+access.bytes <= carrier.bytes; offset++ {
				mask := uint32(0x200cd5) >> uint(offset*8)
				if access.bytes < 4 {
					mask &= uint32(1)<<uint(access.bytes*8) - 1
				}
				body := x86StackFlagsCorrelationBody(carrier.width, "AX", 0)
				body = strings.Replace(body, "XOR"+carrier.width+" $0,0(SP)",
					fmt.Sprintf("XOR%s $%d,%d(SP)", access.width, mask, offset), 1)
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sMOV%s AX,ret+0(FP)\nRET\n",
					carrier.bytes, body, carrier.width)
				requireX86GoAssemblerResult(t, "386", source, true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/%d/%s", carrier.width, access.width, offset, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() "+carrier.typ,
							"386", "i386-unknown-linux-gnu", api)
						if err != nil || ir == "" {
							t.Fatal("bounded B/W/L XOR lost the copied FLAGS bit identities", err)
						}
					})
				}
			}
		}
	}
}

func TestX86Mode32PrivateFlagsCorrelationCannotInventValues(t *testing.T) {
	const prefix = "TEXT ·Value(SB),4,$0-4\n"
	const suffix = "MOVL AX,ret+0(FP)\nRET\n"
	base := x86StackFlagsCorrelationBody("L", "AX", 0x200000)
	for _, row := range []struct{ name, before, after string }{
		{"uncancelled", "XORL 0(SP),AX\n", ""},
		{"different-unknown", "XORL 0(SP),AX", "XORL BX,AX"},
		{"unwritten-upper", "POPL AX", "POPW AX\nPOPW BX"},
		{"outside-live-stack", "XORL 0(SP),AX", "XORL 4(SP),AX"},
		{"partial-outside-live-stack", "XORL 0(SP),AX", "XORL 1(SP),AX"},
		{"before-live-stack", "XORL 0(SP),AX", "XORL -4(SP),AX"},
		{"indexed-stack", "XORL 0(SP),AX", "XORL 0(SP)(CX*1),AX"},
		{"symbolic-stack", "XORL 0(SP),AX", "XORL saved+0(SP),AX"},
		{"changed-stack-pointer", "XORL 0(SP),AX", "MOVL $0,SP\nXORL 0(SP),AX"},
		{"unbalanced-return", "XORL 0(SP),AX\nPOPFL", "XORL 0(SP),AX"},
	} {
		if strings.Count(base, row.before) != 1 {
			t.Fatal("independent mutation is not unique", row.name)
		}
		source := prefix + strings.Replace(base, row.before, row.after, 1) + suffix
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32",
					"386", "i386-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("private FLAGS identity invented a value or backing stack extent", err)
				}
			})
		}
	}
}

func TestX86Mode32PrivateFlagsCorrelationOriginalGoAndLLVMObjects(t *testing.T) {
	var source, declarations strings.Builder
	for _, row := range []struct {
		width, typ string
		bytes      int
		mask       uint32
	}{
		{"W", "uint16", 2, 0xcd5},
		{"L", "uint32", 4, 0x200cd5},
	} {
		for index, register := range []string{"AX", "BX", "CX", "DX", "BP", "SI", "DI"} {
			name := fmt.Sprintf("flags%s%d", row.width, index)
			fmt.Fprintf(&declarations, "func %s() %s\n", name, row.typ)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%sMOV%s %s,ret+0(FP)\nRET\n",
				name, row.bytes, x86StackFlagsCorrelationBody(row.width, register, row.mask), row.width, register)
		}
	}
	// Actual Go owns the independent W/L stack and yaddl operand grammar.
	// The LLVM objects below retain the complete source, without seeding flags.
	requireX86GoAssemblerResult(t, "386", source.String(), true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("private FLAGS objects require LLVM 22 llc")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "386", triple, api)
				if err != nil || ir == "" {
					t.Fatal("complete original private FLAGS program", err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			})
		}
	}
}

func TestX86Mode32PrivateFlagsSourceAndQueryBoundaries(t *testing.T) {
	source := "TEXT ·Value(SB),4,$0-4\n" + x86StackFlagsCorrelationBody("L", "AX", 0x200000) + "MOVL AX,ret+0(FP)\nRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Name: "Value", Ret: I32, Frame: FrameLayout{
		Results: []FrameSlot{{Type: I32, Index: 0, Field: -1}},
	}}
	if !errors.Is(CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "386"), ErrProbeNeedsContext) ||
		!errors.Is(checkX86ScalarFPResultInitialization(file.Funcs[0], sig, "386"), ErrProbeNeedsContext) {
		t.Fatal("standalone queries acquired private lowering storage")
	}
	for name, change := range map[string]func(*Func){
		"operand": func(fn *Func) {
			for index := range fn.Instrs {
				if fn.Instrs[index].Op == "XORL" {
					fn.Instrs[index].Args[1].Mem.Off = 1
					return
				}
			}
		},
		"frame": func(fn *Func) { fn.FrameSize = 8 },
		"literal": func(fn *Func) {
			for index := range fn.Instrs {
				if fn.Instrs[index].Op == "XORL" {
					fn.Instrs[index].Raw = "XORL $1,0(SP)"
					return
				}
			}
		},
		"raw": func(fn *Func) { fn.Instrs[1].x86Encoded = true },
	} {
		t.Run(name, func(t *testing.T) {
			fn := x86DirectTailSnapshot(file).Funcs[0]
			change(&fn)
			if _, err := x86ResultPrivateFlagsSource(fn, "386"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed original source retained private storage identity", err)
			}
		})
	}
}

func TestX86Mode32PrivateFlagsCloneAndJoinIdentity(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+x86StackFlagsCorrelationBody("L", "AX", 1)+"RET\n")
	if err != nil {
		t.Fatal(err)
	}
	stack, err := x86ResultPrivateFlagsSource(file.Funcs[0], "386")
	if err != nil || stack == nil {
		t.Fatal("independent private source", err)
	}
	left := x86ResultState{valueStack: stack}
	push := x86ScalarLaneInstruction(t, "PUSHFL")
	if !x86ResultTransfer(push, &left, nil, 0, "386") {
		t.Fatal("private FLAGS copy")
	}
	before := left.clone()
	right := left.clone()
	right.valueStack.correlation.flags[0] = 255
	right.valueStack.correlation.bytes[3][0] = 255
	right.valueStack.correlation.popped[0] = 1
	merged := left.intersect(right)
	if !reflect.DeepEqual(before, left) || merged.valueStack.correlation == nil ||
		merged.valueStack.correlation.flags[0] != 255 || merged.valueStack.correlation.bytes[3][0] != 255 ||
		merged.valueStack.correlation.popped[0] != 255 {
		t.Fatal("clone/join retained an unequal relation or mutated a predecessor")
	}
	if got := left.intersect(left); !reflect.DeepEqual(got, left) {
		t.Fatal("identical CFG paths lost their original relation")
	}
}

func TestX86Mode32PrivateFlagsXOROriginTruthTable(t *testing.T) {
	for _, left := range []uint8{0, 1, 2, 3, 255} {
		for _, right := range []uint8{0, 1, 2, 3, 255} {
			// Enumerate independent input bits. Untracked left/right values
			// deliberately use different variables even for the same tag.
			first, constant := uint8(0), true
			for input := uint8(0); input < 32; input++ {
				value := func(origin uint8, untracked uint8) uint8 {
					if origin == 0 {
						return 0
					}
					if origin == 255 {
						origin = untracked
					}
					return input >> (origin - 1) & 1
				}
				got := value(left, 4) ^ value(right, 5)
				if input == 0 {
					first = got
				}
				constant = constant && got == first
			}
			if (x86FlagsXOROrigin(left, right) == 0) != constant {
				t.Fatal("XOR dependency disagrees with exhaustive independent bit assignments", left, right)
			}
		}
	}
}

func TestX86Mode32PrivateFlagsCompleteXORRows(t *testing.T) {
	for _, row := range []struct{ width, register string }{
		{"B", "AL"}, {"B", "AH"}, {"W", "AX"}, {"L", "AX"},
	} {
		for _, address := range []string{"(SP)", "0(SP)", "0x0(SP)"} {
			for _, modify := range []string{
				"XOR" + row.width + " $1," + address,
				"MOVL $1,AX\nXOR" + row.width + " " + row.register + "," + address,
			} {
				body := "PUSHFL\nPUSHFL\n" + modify + "\nPOPFL\nPUSHFL\nPOPL AX\nXORL " + address + ",AX\nPOPFL\n"
				source := "TEXT ·Value(SB),4,$0-4\n" + body + "MOVL AX,ret+0(FP)\nRET\n"
				requireX86GoAssemblerResult(t, "386", source, true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", row.width, row.register, modify, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", "386", "i386-unknown-linux-gnu", api)
						if err != nil || ir == "" {
							t.Fatal("complete typed XOR row lost its private storage dependency", err)
						}
					})
				}
			}
		}
	}
}
