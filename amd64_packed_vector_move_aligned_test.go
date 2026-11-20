package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86PackedMoveAlignedNativeOpcodeAndFeatures(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		if !row.aligned {
			continue
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue
			}
			for _, mode := range []string{"load", "store", "merge", "zero", "masked-store"} {
				masked := mode != "load" && mode != "store"
				if row.vexOnly && masked {
					continue
				}
				t.Run(row.name+"/"+bank+"/"+mode, func(t *testing.T) {
					op, mask := row.name, ""
					if masked {
						mask = "K7,"
					}
					if mode == "zero" {
						op += ".Z"
					}
					operation := fmt.Sprintf("%s (AX),%s%s0", op, mask, bank)
					if strings.HasSuffix(mode, "store") {
						operation = fmt.Sprintf("%s %s0,%s(AX)", op, bank, mask)
					}
					source := "TEXT ·view(SB),4,$0-8\nMOVQ p+0(FP),AX\nMOVL $3,CX\nKMOVD CX,K7\nVPXORQ Z0,Z0,Z0\n" + operation + "\nRET\n"
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *[64]byte)\n", "amd64", "x86_64-unknown-linux-gnu", "text")
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(ir, "asm sideeffect") || !strings.Contains(ir, strings.ToLower(row.name)+" ") {
						t.Fatal("aligned memory lost its original observable opcode", operation)
					}
					feature := "+avx"
					if masked || bank == "Z" || strings.HasPrefix(row.name, "VMOVDQA3") || row.name == "VMOVDQA64" {
						feature = "+avx512f"
					}
					if !strings.Contains(ir, feature) {
						t.Fatal("missing required native feature", feature)
					}
				})
			}
		}
	}
}

func TestX86PackedMoveAlignedVirtualMemoryNeedsContext(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		if !row.aligned {
			continue
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue
			}
			for _, memory := range []string{"a+0(FP)", "local-64(SP)", "(BP)"} {
				for _, operands := range []string{memory + "," + bank + "0", bank + "0," + memory} {
					source := fmt.Sprintf("TEXT ·view(SB),4,$64-64\n%s %s\nRET\n", row.name, operands)
					_, err := x86ScalarFPBitViewAPI(t, source, "func view(a,b,c,d,e,f,g,h uint64)\n", "amd64", "x86_64-unknown-linux-gnu", "text")
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s %s acquired native alignment/backing: %v", row.name, operands, err)
					}
				}
			}
		}
	}
}

func TestX86PackedMoveAlignedResultFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86PackedMoveResultOracle {
				if !row.aligned {
					continue
				}
				for _, bank := range []string{"X", "Y", "Z"} {
					if row.vexOnly && bank == "Z" {
						continue
					}
					for _, mode := range []string{"plain", "merge", "zero"} {
						if row.vexOnly && mode != "plain" {
							continue
						}
						name, mask := row.name, ""
						if mode != "plain" {
							mask = "K1,"
						}
						if mode == "zero" {
							name += ".Z"
						}
						fmt.Fprintf(&declarations, "func view%d(p *[64]byte) uint32\n", count)
						fmt.Fprintf(&source, "TEXT ·view%d(SB),4,$0-%d\n%s p+0(FP),SI\nMOVL $1,AX\nKMOVD AX,K1\nVPXORQ Z1,Z1,Z1\n%s (SI),%s%s1\nPEXTRD $3,X1,AX\nMOVL AX,ret+%d(FP)\nRET\n", count, word+4, move, name, mask, bank, word)
						count++
					}
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				compileLLVMToObject(t, llc, target.triple, "aligned-result.ll", "aligned-result.o", ir)
			}
		})
	}
}

func TestX86PackedMoveAlignedNativeCompleteMemoryAxes(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("GLOBL table<>(SB),8,$128\n")
			count := 0
			add := func(instruction string) {
				name := fmt.Sprintf("aligned%d", count)
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s\nRET\n", name, instruction)
				count++
			}
			for _, row := range x86PackedMoveResultOracle {
				if !row.aligned {
					continue
				}
				for _, bank := range []string{"X", "Y", "Z"} {
					if row.vexOnly && bank == "Z" {
						continue
					}
					// Every mask register, both directions, merge and zero.
					for mask := 0; mask <= 7; mask++ {
						if row.vexOnly && mask != 0 {
							continue
						}
						predicate := ""
						if mask != 0 {
							predicate = fmt.Sprintf("K%d,", mask)
						}
						add(fmt.Sprintf("%s (AX),%s%s7", row.name, predicate, bank))
						add(fmt.Sprintf("%s %s7,%s(AX)", row.name, bank, predicate))
						if mask != 0 {
							add(fmt.Sprintf("%s.Z (AX),%s%s7", row.name, predicate, bank))
						}
					}
					// Orthogonal address-space and high-bank encoding classes.
					indexes := []int{0, 7}
					if target.arch == "amd64" {
						indexes = append(indexes, 8, 15)
						if !row.vexOnly {
							indexes = append(indexes, 16, 31)
						}
					}
					for _, index := range indexes {
						for _, address := range []string{"16(AX)(CX*2)", "table<>+16(SB)", "16(FS)", "16(GS)"} {
							add(fmt.Sprintf("%s %s,%s%d", row.name, address, bank, index))
							add(fmt.Sprintf("%s %s%d,%s", row.name, bank, index, address))
						}
					}
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			ir := x86UnboundVoidVectorMoveFormatObject(t, source.String(), target.arch, target.triple)
			for _, segment := range []string{"%fs:", "%gs:", "ptr addrspace(256)", "ptr addrspace(257)"} {
				if !strings.Contains(ir, segment) {
					t.Fatal("native address-space lost", segment)
				}
			}
			if got := strings.Count(ir, "asm sideeffect"); got != count {
				t.Fatalf("native memory witness count got %d want %d", got, count)
			}
			compileLLVMToObject(t, llc, target.triple, "aligned-memory.ll", "aligned-memory.o", ir)
			t.Logf("%d actual-Go/LLVM aligned memory forms", count)
		})
	}
}

func TestX86PackedMoveAlignedNativeAddressSizeBoundary(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		if !row.aligned {
			continue
		}
		for _, addressBits := range []int{16, 32, 64} {
			ins := x86ScalarLaneInstruction(t, row.name+" (AX),X0")
			ins.x86AddressBits = addressBits
			ctx := &amd64Ctx{goarch: "amd64"}
			if _, _, err := ctx.lowerPackedVectorMove(ins.Op, ins); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unbound original address width borrowed ordinary memory", row.name, addressBits, err)
			}
		}
	}
}

func TestX86PackedMoveAlignedDATAReadIsNotWriteAuthority(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		if !row.aligned {
			continue
		}
		for _, masked := range []bool{false, true} {
			if row.vexOnly && masked {
				continue
			}
			predicate := ""
			if masked {
				predicate = "K1,"
			}
			source := "DATA table<>+0(SB)/8,$1\nGLOBL table<>(SB),8,$64\nTEXT ·view(SB),4,$0-4\nMOVL $1,AX\nKMOVD AX,K1\n" +
				row.name + " table<>(SB),X1\n" + row.name + " X1," + predicate + "table<>(SB)\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n"
			for _, api := range []string{"text", "module", "Go"} {
				_, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", "amd64", "x86_64-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("readable DATA gained write authority", row.name, masked, api, err)
				}
			}
		}
	}
}

func TestX86PackedMoveAlignedRawSourceCannotBorrowConditionalRead(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		if !row.aligned {
			continue
		}
		_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *[64]byte) uint32",
			"MOVQ p+0(FP),AX\n"+row.name+" (AX),X1\nPEXTRD $0,X1,CX\nMOVL CX,ret0+8(FP)\nRET")
		for _, mutation := range []string{"decoded", "address size", "unbound address", "raw text", "source stack", "fixed local", "segment", "symbol"} {
			fn := file.Funcs[0]
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			fn.Instrs[2].Args = append([]Operand(nil), fn.Instrs[2].Args...)
			switch mutation {
			case "decoded":
				fn.Instrs[2].x86Encoded = true
			case "address size":
				fn.Instrs[2].x86AddressBits = 32
			case "unbound address":
				fn.Instrs[2].x86UnboundAddressOverride = true
			case "raw text":
				fn.X86RawText = []byte{0xc3}
			case "source stack":
				fn.x86SourceStack = new(x86SourceStackProof)
			case "fixed local":
				fn.x86FixedLocal = new(x86FixedLocalProof)
			case "segment":
				fn.Instrs[2].Args[0].Mem.Segment = "FS"
			case "symbol":
				fn.Instrs[2].Args[0].Mem.Sym = "table<>(SB)"
			}
			ctx := &amd64Ctx{fpScalarSource: fn, sig: sig, goarch: "amd64"}
			if err := ctx.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("aligned read bypassed source identity", row.name, mutation, err)
			}
		}
	}
}

func TestX86PackedMoveAlignedRegisterCopyRemainsPortable(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		if !row.aligned {
			continue
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue
			}
			ins := x86ScalarLaneInstruction(t, row.name+" "+bank+"0,"+bank+"1")
			if features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", Func{Instrs: []Instr{ins}}); features != "" {
				t.Fatal("register bit-copy acquired physical memory ISA", ins, features)
			}
		}
	}
}
