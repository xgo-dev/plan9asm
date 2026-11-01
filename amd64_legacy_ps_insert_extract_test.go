package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86LegacyPSIndependentFPFields(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	const source = "TEXT fields(SB),4,$0-12\nPXOR X0,X0\nINSERTPS $0,a+0(FP),X0\nEXTRACTPS $0,X0,ret+8(FP)\nRET\n" +
		"TEXT stores(SB),4,$0-12\nMOVL $0x87654321,CX\nMOVD CX,X1\nEXTRACTPS $0,X1,a+0(FP)\nMOVBLZX a+0(FP),AX\nMOVBLZX b+1(FP),BX\nSHLL $8,BX\nORL BX,AX\nMOVBLZX c+2(FP),BX\nSHLL $16,BX\nORL BX,AX\nMOVBLZX d+3(FP),BX\nSHLL $24,BX\nORL BX,AX\nMOVL AX,ret+8(FP)\nRET\n"
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	pkg := mustGoPackage(t, "oracle", "package oracle\nfunc fields(a,b,c,d byte) uint32\nfunc stores(a,b,c,d byte) uint32\n")
	sigs := map[string]FuncSig{}
	for _, name := range []string{"fields", "stores"} {
		decl := pkg.Types.Scope().Lookup(name).(*types.Func)
		sig, err := DeriveGoFuncABI0Signature(name, decl, "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		if len(sig.Frame.Params) != 4 || len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Offset != 8 {
			t.Fatalf("actual AMD64 ABI0 four-byte fields/result layout changed: %+v", sig.Frame)
		}
		sigs[name] = sig
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const reference = `#include <stdint.h>
#include <stdio.h>
extern uint32_t fields(uint8_t,uint8_t,uint8_t,uint8_t);
extern uint32_t stores(uint8_t,uint8_t,uint8_t,uint8_t);
int main(void) {
 unsigned failures=0;
 for(unsigned i=0;i<256;i++) {
  uint8_t a=i,b=i*37,c=i*59,d=i*71;
  uint32_t want=(uint32_t)a|((uint32_t)b<<8)|((uint32_t)c<<16)|((uint32_t)d<<24);
  uint32_t got=fields(a,b,c,d);
  if(got!=want){if(!(failures&1))fprintf(stderr,"legacy FP fields got=%x want=%x\n",got,want);failures|=1;}
  got=stores(a,b,c,d);
  if(got!=UINT32_C(0x87654321)){if(!(failures&2))fprintf(stderr,"legacy FP stores got=%x\n",got);failures|=2;}
 }
 return failures;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "legacy-ps-independent-fp", triple, ir, reference, prefix)
}

func TestX86LegacyPSInsertExtractSourceCallerReachesObjects(t *testing.T) {
	for _, body := range []string{
		"VMOVUPS (DI),Z0\nVMOVUPS (SI),X1\nINSERTPS $64,X1,X0\nVMOVSS X0,(DX)",
		"VMOVUPS (DI),X0\nEXTRACTPS $3,X0,AX\nMOVL AX,(DX)",
	} {
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
		goAssemblerOracleOutput(t, "amd64", assembly, "", true)
		pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
	}
}

func TestX86LegacyPSInsertedByteKnowledgePreservesUpper(t *testing.T) {
	for _, missing := range []int{-1, 0, 12, 16, 31, 63} {
		const row = "INSERTPS $0,X0,X1"
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		f, recognized, err := x86InsertExtractProperties(ins, "amd64")
		if !recognized || err != nil {
			t.Fatalf("legacy shared grammar missing: %t/%v", recognized, err)
		}
		state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": 15, "Z1": ^uint64(0)}, masks: map[Reg]bool{}}
		if missing >= 0 {
			state.vectors["Z1"] &^= uint64(1) << uint(missing)
		}
		if !x86CallerInsertExtractStep(&ins, f, &state, nil) {
			t.Fatal("defined inserted bytes rejected")
		}
		want := ^uint64(0)
		if missing >= 4 {
			want &^= uint64(1) << uint(missing)
		}
		if got := state.vectors["Z1"]; got != want {
			t.Fatal(fmt.Sprintf("legacy upper knowledge %d: got%x want%x", missing, got, want))
		}
	}
}

func TestX86LegacyPSCallerUnknownInputsAndPermissions(t *testing.T) {
	for name, body := range map[string]string{
		"unknown inserted lane":         "VMOVUPS (DI),X1\nINSERTPS $64,X0,X1\nVMOVSS X1,(DX)",
		"unknown retained base":         "VMOVUPS (DI),X0\nINSERTPS $16,X0,X1\nVMOVSS X1,(DX)",
		"unknown extract lane":          "EXTRACTPS $0,X0,AX\nMOVL AX,(DX)",
		"unknown memory even all clear": "INSERTPS $15,(BX),X0\nVMOVSS X0,(DX)",
		"pointer FP source":             "VMOVUPS (DI),X1\nINSERTPS $0,a+0(FP),X1\nVMOVSS X1,(DX)",
		"source SP":                     "VMOVUPS (DI),X1\nINSERTPS $0,(SP),X1\nVMOVSS X1,(DX)",
		"input write":                   "VMOVUPS (DI),X0\nEXTRACTPS $0,X0,(DI)",
		"g write":                       "VMOVUPS (DI),X0\nEXTRACTPS $0,X0,R14",
		"missing CFG source":            "CMPQ AX,$0\nJE join\nVMOVUPS (DI),X0\njoin:\nEXTRACTPS $0,X0,AX\nMOVL AX,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("legacy unknown source acquired caller permission: %v", err)
			}
		})
	}
}
