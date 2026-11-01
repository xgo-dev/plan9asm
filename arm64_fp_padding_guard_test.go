package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func arm64PaddingTestInput(t *testing.T, declaration, body string) (Func, FuncSig) {
	t.Helper()
	pkg := mustGoPackage(t, "example.invalid/padbits", "package padbits\n"+declaration+"\n")
	fn := pkg.Types.Scope().Lookup("Narrow").(*types.Func)
	sig, err := DeriveGoFuncABI0Signature("Narrow", fn, "arm64", types.SizesFor("gc", "arm64"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchARM64, "TEXT Narrow(SB),4,$0-16\n"+body+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	function, err := normalizeARM64ScalarMemoryFrame(file.Funcs[0])
	if err != nil {
		t.Fatal(err)
	}
	return function, sig
}

func TestARM64FPPaddingEveryObservableUseStaysContext(t *testing.T) {
	for name, body := range map[string]string{
		"result":          "MOVD R2,res+8(FP)",
		"copy-result":     "MOVD R2,R3\nMOVD R3,res+8(FP)",
		"flags":           "CMP $0,R2\nMOVD $0,R0\nMOVD R0,res+8(FP)",
		"extended-flags":  "CMP R2.UXTW,R0\nMOVD R0,res+8(FP)",
		"branch":          "CBZ R2,done\ndone:\nMOVD $0,R0\nMOVD R0,res+8(FP)",
		"address":         "MOVD (R2),R0\nMOVD R0,res+8(FP)",
		"index":           "MOVD (R0)(R2),R0\nMOVD R0,res+8(FP)",
		"store":           "MOVD R2,(R0)\nMOVD $0,R0\nMOVD R0,res+8(FP)",
		"vector-store":    "VDUP R2,V0.D2\nVST1 [V0.D2],(R0)\nMOVD $0,R0\nMOVD R0,res+8(FP)",
		"vector-alias":    "VDUP R2,V0.D2\nVMOV V0.D[0],V0\nVMOV V0.D[0],R0\nMOVD R0,res+8(FP)",
		"scalar-fp-alias": "VDUP R2,V0.D2\nFMOVD F0,R0\nMOVD R0,res+8(FP)",
		"rotate":          "AND R2@>16,R0,R0\nMOVD R0,res+8(FP)",
		"local-call":      "CALL helper\nMOVH R2,R0\nMOVD R0,res+8(FP)\nRET\nhelper:\nRET",
		"external-call":   "CALL other(SB)\nMOVH R2,R0\nMOVD R0,res+8(FP)",
		"native":          "SVC $0\nMOVH R2,R0\nMOVD R0,res+8(FP)",
		"unknown":         "WHATEVER\nMOVH R2,R0\nMOVD R0,res+8(FP)",
		"unknown-word":    "WORD $0xffffffff\nMOVH R2,R0\nMOVD R0,res+8(FP)",
		"return-link":     "MOVD R2,R30\nMOVH R2,R0\nMOVD R0,res+8(FP)",
		"fixed-g":         "MOVD R2,R28\nMOVH R2,R0\nMOVD R0,res+8(FP)",
		"one-path":        "CBZ R0,joined\nMOVH R2,R2\njoined:\nMOVD R2,res+8(FP)",
		"loop-join":       "loop:\nMOVD R2,R3\nMOVH R2,R2\nCBNZ R0,loop\nMOVD R3,res+8(FP)",
		"dead-use":        "MOVH R2,R0\nMOVD R0,res+8(FP)\nRET\ndead:\nMOVD rhs+0(FP),R2\nMOVD R2,res+8(FP)",
	} {
		t.Run(name, func(t *testing.T) {
			fn, sig := arm64PaddingTestInput(t, "func Narrow(rhs int16) (res uint64)", "MOVD rhs+0(FP),R2\n"+body)
			if _, err := arm64FPPaddingReadProof(fn, fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("observable/unknown use obtained representative: %v", err)
			}
		})
	}
}

func TestARM64FPPaddingTypedIdentityAndBothCFGsAreMandatory(t *testing.T) {
	fn, sig := arm64PaddingTestInput(t, "func Narrow(rhs int16) (res uint64)", "MOVD rhs+0(FP),R2\nMOVH R2,R0\nMOVD R0,res+8(FP)")
	if sig.arm64FPReadDeclaration == nil {
		t.Fatal("complete GC ARM64 declaration did not produce private witness")
	}
	for name, mutate := range map[string]func(*FuncSig){
		"arg":      func(s *FuncSig) { s.Args = []LLVMType{I32} },
		"ret":      func(s *FuncSig) { s.Ret = I32 },
		"frame":    func(s *FuncSig) { s.Frame.Params = []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}} },
		"result":   func(s *FuncSig) { s.Frame.Results = []FrameSlot{{Offset: 6, Type: I64, Index: 0, Field: -1}} },
		"register": func(s *FuncSig) { s.ArgRegs = []Reg{"R2"} },
		"name":     func(s *FuncSig) { s.Name = "Different" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := sig
			mutate(&changed)
			if _, err := arm64FPPaddingReadProof(fn, fn, changed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed signature retained authority: %v", err)
			}
		})
	}
	bad, _ := arm64PaddingTestInput(t, "func Narrow(rhs int16) (res uint64)", "MOVD rhs+0(FP),R2\nMOVD R2,res+8(FP)")
	for _, pair := range [][2]Func{{fn, bad}, {bad, fn}} {
		if _, err := arm64FPPaddingReadProof(pair[0], pair[1], sig); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("one certified CFG hid other bad use: %v", err)
		}
	}
	bad = fn
	bad.Instrs = append([]Instr(nil), fn.Instrs...)
	bad.Instrs[0].Op = "MOVW"
	if _, err := arm64FPPaddingReadProof(fn, bad, sig); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("changed native load width retained exact source identity: %v", err)
	}
}

func TestARM64FPPaddingNoGeneralHoleAddressOrStoreAuthority(t *testing.T) {
	pkg := mustGoPackage(t, "example.invalid/padbits", "package padbits\ntype Row struct { a byte; b uint64 }\nfunc Narrow(rhs int16) (res uint64)\nfunc Internal(row Row) (res uint64)\n")
	for _, source := range []string{
		"TEXT ·Narrow(SB),4,$0-16\nMOVD rhs+2(FP),R0\nMOVD R0,res+8(FP)\nRET\n",
		"TEXT ·Narrow(SB),4,$0-16\nMOVD R0,rhs+0(FP)\nMOVD R0,res+8(FP)\nRET\n",
		"TEXT ·Narrow(SB),4,$0-16\nMOVD rhs+0(FP),R2\nMOVD $rhs+2(FP),R0\nMOVH R2,R1\nMOVD R1,res+8(FP)\nRET\n",
		"TEXT ·Internal(SB),4,$0-24\nMOVD row+0(FP),R2\nMOVB R2,R0\nMOVD R0,res+16(FP)\nRET\n",
	} {
		translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{GOOS: "linux", GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path)})
		if err == nil {
			translated.Module.Dispose()
			t.Fatalf("generic padding/address/store permission appeared for %s", source)
		}
		if !strings.Contains(err.Error(), "FP") && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unexpected failure: %v", err)
		}
	}
}

func TestARM64FPPaddingSevenScalarStoresStillNeedDeclaredBytes(t *testing.T) {
	pkg := mustGoPackage(t, "padbits", "package padbits\nfunc Narrow(rhs int8) (res uint64)\n")
	for _, op := range []Op{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		t.Run(string(op), func(t *testing.T) {
			source := fmt.Sprintf("TEXT ·Narrow(SB),4,$0-16\nMOVD rhs+0(FP),R2\nMOVB R2,R0\n%s R0,rhs+1(FP)\nMOVD R0,res+8(FP)\nRET\n", op)
			translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOOS: "linux", GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path),
			})
			if err == nil {
				translated.Module.Dispose()
				t.Fatal("read-only bit certificate created a writable padding slot")
			}
			if !strings.Contains(err.Error(), "FP") {
				t.Fatalf("unrelated store rejection: %v", err)
			}
		})
	}
}

func TestARM64FPPaddingConsumerRechecksEveryBoundInput(t *testing.T) {
	fn, sig := arm64PaddingTestInput(t, "func Narrow(rhs int16) (res uint64)", "MOVD rhs+0(FP),R2\nMOVH R2,R0\nMOVD R0,res+8(FP)")
	reads, err := arm64FPPaddingReadProof(fn, fn, sig)
	if err != nil || len(reads) != 1 {
		t.Fatalf("source proof: %v; reads=%d", err, len(reads))
	}
	var key [2]int
	for k := range reads {
		key = k
	}
	for _, name := range []string{"missing-producer", "changed-signature", "changed-read", "changed-instruction", "changed-operand-in-place", "changed-frame-offset", "changed-decoded-origin", "negative-index"} {
		t.Run(name, func(t *testing.T) {
			copyFunc := fn
			copyFunc.Instrs = append([]Instr(nil), fn.Instrs...)
			for i := range copyFunc.Instrs {
				copyFunc.Instrs[i].Args = append([]Operand(nil), fn.Instrs[i].Args...)
			}
			context, _ := newARM64CtxWithFuncForTest(t, copyFunc, sig, nil)
			context.blocks = arm64SplitBlocks(copyFunc)
			context.currentBlock, context.currentInstruction = key[0], key[1]
			read := reads[key]
			context.fpPaddingReads = map[[2]int]arm64FPPaddingRead{key: read}
			if _, err := context.loadFPFrameBits(0, 8); err != nil {
				t.Fatalf("unaltered complete consumer fixture: %v", err)
			}
			switch name {
			case "missing-producer":
				context.sig.arm64FPReadDeclaration = nil
			case "changed-signature":
				context.sig.Name = "Different"
			case "changed-read":
				read.declared--
				context.fpPaddingReads[key] = read
			case "changed-instruction":
				context.blocks[key[0]].instrs = append([]Instr(nil), context.blocks[key[0]].instrs...)
				context.blocks[key[0]].instrs[key[1]].Op = "MOVW"
			case "changed-operand-in-place":
				context.blocks[key[0]].instrs[key[1]].Args[1].Reg = "R3"
			case "changed-frame-offset":
				offset := int64(4096)
				context.blocks[key[0]].instrs[key[1]].arm64ScalarMemoryFrameOffset = &offset
			case "changed-decoded-origin":
				context.blocks[key[0]].instrs[key[1]].arm64Encoded = true
			case "negative-index":
				context.currentBlock = -1
				context.fpPaddingReads[[2]int{-1, key[1]}] = read
			}
			if _, err := context.loadFPFrameBits(0, 8); err == nil {
				t.Fatal("stale/private fabricated consumer record authorized padding")
			}
		})
	}
}
