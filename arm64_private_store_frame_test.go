package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64PrivateFrameIncomingPointerStorePreservesCallerLink(t *testing.T) {
	source := strings.Replace(arm64PrivateCallCopySource, "\tMOVD R5, 8(RSP)", "\tMOVD $90,R9\n\tMOVB R9,(R6)\n\tMOVD R5, 8(RSP)", 1)
	arm64PrivateCallGoObject(t, source)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if !arm64CallFrameUnexposed(file.Funcs[0]) {
		t.Fatal("an ordinary incoming-pointer store exposed the private stack address")
	}
	_, err = Translate(file, arm64PrivateCallCopyOptions(arm64LinuxGNUTriple))
	if err != nil {
		t.Fatalf("unknown incoming-pointer store cannot overwrite this fresh unexposed saved caller link: %v", err)
	}
}

func TestARM64PrivateFrameUnknownStoreProofIsSPOnly(t *testing.T) {
	for _, tc := range []struct {
		name, escaped, baseToken string
		proof, intact            bool
	}{
		{name: "fresh", proof: true, intact: true},
		{name: "fresh_code_escape", proof: true, escaped: "label:continuation", intact: true},
		{name: "zero_default"},
		{name: "legacy_code_escape", escaped: "label:continuation"},
		{name: "sp_escape", proof: true, escaped: "sp:8"},
		{name: "fp_escape", proof: true, escaped: "fp:0"},
		{name: "fp_address_escape", proof: true, escaped: "fpa:0"},
		{name: "unknown_escape", proof: true, escaped: "unknown-address"},
		{name: "collapsed_frame_escape", proof: true},
		{name: "sp_alias", proof: true, baseToken: "sp:0"},
		{name: "sp_index_alias", proof: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &arm64ControlState{
				unexposedSP: tc.proof,
				regs: map[Reg]arm64ControlValue{
					SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R6": arm64ControlFromMap(map[string]bool{tc.baseToken: true}),
				},
				memory: map[string]arm64ControlValue{
					"sp:0": arm64ControlFromMap(map[string]bool{"label:caller": true}), "fp:0": arm64ControlFromMap(map[string]bool{"label:local": true}),
				},
			}
			if tc.escaped != "" {
				state.escaped = arm64ControlFromMap(map[string]bool{tc.escaped: true})
			}
			if tc.name == "collapsed_frame_escape" {
				state.escaped = arm64ControlUnion(arm64ControlFromMap(map[string]bool{"sp:8": true}), arm64ControlFromMap(map[string]bool{"sp:16": true}))
			}
			if tc.name == "sp_index_alias" {
				state.regs["R7"] = arm64ControlFromMap(map[string]bool{"sp:0": true})
			}
			// An indexed store has no exact cell even if its base is a known SP alias.
			state.write(Operand{Kind: OpMem, Mem: MemRef{Base: "R6", Index: "R7"}}, arm64ControlExternal(), false)
			if arm64ControlHas(state.memory["sp:0"], "") == tc.intact {
				t.Errorf("private-SP preservation mismatch: %v", state.memory["sp:0"])
			}
			if !arm64ControlHas(state.memory["fp:0"], "") {
				t.Fatal("incoming FP contents can alias this store and must remain clobbered")
			}
			value := state.source(Operand{Kind: OpMem, Mem: MemRef{Base: SP}}, false)
			if tc.intact && !arm64ControlEqual(value, arm64ControlFromMap(map[string]bool{"label:caller": true})) {
				t.Errorf("unknown heap/code stores contaminated the proven private SP read: %v", value)
			}
			cloned := state.clone()
			if cloned.unexposedSP != tc.proof {
				t.Fatal("clone lost the source proof")
			}
			if tc.proof && (!cloned.merge(&arm64ControlState{}) || cloned.unexposedSP) {
				t.Fatal("a CFG join must not upgrade an unproved incoming state")
			}
		})
	}
}

func TestARM64PrivateFrameIncomingPointerAliasesAndConditionalStores(t *testing.T) {
	for _, instructions := range []string{
		"ADD $1,R6,R9\nMOVB R10,(R9)",
		"CBZ R7,nostore\nMOVB R9,(R6)\nnostore:",
		"MOVD R6,R9\nMOVB R10,(R9)(R7)",
	} {
		source := arm64PrivateFrameStoreSource(instructions)
		arm64PrivateCallGoObject(t, source)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, arm64PrivateCallCopyOptions(arm64LinuxGNUTriple)); err != nil {
			t.Fatalf("ordinary pointer transform/conditional store exposed fresh SP: %v", err)
		}
	}
}

func TestARM64PrivateFrameUnknownSPIndexAndPartialStoresRemainRejected(t *testing.T) {
	for _, instruction := range []string{
		"MOVB R9,7(RSP)", "MOVH R9,7(RSP)", "MOVW R9,7(RSP)",
		"MOVD R9,(RSP)(R7)", "MOVD.P R9,8(RSP)", "MOVD.W R9,-8(RSP)",
		"MOVD RSP,R9\nMOVB R10,(R9)(R7)",
		"MOVD $8(RSP),R9\nMOVB R10,(R9)",
	} {
		source := arm64PrivateFrameStoreSource(instruction)
		arm64PrivateCallGoObject(t, source)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if instruction == "MOVD $8(RSP),R9\nMOVB R10,(R9)" {
			// Keep this exact byte source as a source-only negative. With
			// typed call transport, its byte store is now proved wholly in
			// private DATA [8,9), not the saved caller link. This is only
			// object coverage: the original R10 is not initialized. The
			// separate PrivateDataMemoryFamily runtime initializes data
			// and checks complete output canaries for every scalar width.
			if arm64CallFrameUnexposed(file.Funcs[0]) {
				t.Fatal("nil transport acquired a private data store proof")
			}
			if _, err := Translate(file, arm64PrivateCallCopyOptions(arm64LinuxGNUTriple)); err != nil {
				t.Errorf("explicit typed private DATA byte: %v", err)
			}
			continue
		}
		if _, err := Translate(file, arm64PrivateCallCopyOptions(arm64LinuxGNUTriple)); !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("explicit/moving/partial/escaped SP write must stay unproved: %q: %v", instruction, err)
		}
	}
}

func TestARM64PrivateFrameCoalescedCallRetainsOriginalSourceProof(t *testing.T) {
	for _, escape := range []bool{false, true} {
		source := strings.Replace(arm64PrivateCallCopySource, "\tCALL runtime·memmove(SB)", "\tMOVD $1,R9\n\tCALL helper<>(SB)\n\tMOVB R9,(R6)", 1)
		if escape {
			source = strings.Replace(source, "\tMOVD R5, 8(RSP)", "\tMOVD RSP,R10\n\tMOVD R10,(R6)\n\tMOVD R5, 8(RSP)", 1)
		}
		source += "TEXT helper<>(SB),NOSPLIT,$0\nADD $1,R9\nRET\n"
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		coalesced, err := coalesceARM64PrivateRegisterHelpers(file)
		if err != nil {
			t.Fatal(err)
		}
		fn := coalesced.Funcs[0]
		if fn.arm64PrivateUnexposedFrame == escape || arm64CallFrameUnexposed(fn) == escape {
			t.Fatalf("coalescing erased the original source's escape=%v decision", escape)
		}
		_, err = Translate(coalesced, arm64PrivateCallCopyOptions(arm64LinuxGNUTriple))
		if escape && !errors.Is(err, ErrProbeNeedsContext) || !escape && err != nil {
			t.Fatalf("coalesced heap store/RET source escape=%v: %v", escape, err)
		}
	}
	file, err := Parse(ArchARM64, "TEXT local(SB),4,$16-0\nCALL label\nRET\nlabel:\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if arm64CallFrameUnexposed(file.Funcs[0]) {
		t.Fatal("an unregistered source local call acquired a private helper proof")
	}
}

const arm64PrivateFrameRepeatedStoreSource = `#include "textflag.h"
TEXT ABI0Copy(SB),NOSPLIT,$32-24
	MOVD dst+0(FP),R5
	MOVD src+8(FP),R6
	MOVD n+16(FP),R7
	MOVD $90,R9
	MOVB R9,(R6)
	MOVD R5,8(RSP)
	MOVD R6,16(RSP)
	MOVD R7,24(RSP)
	CALL runtime·memmove(SB)
	MOVD dst+0(FP),R5
	MOVD src+8(FP),R6
	MOVD n+16(FP),R7
	MOVD $165,R9
	MOVB R9,1(R6)
	MOVD R5,8(RSP)
	MOVD R6,16(RSP)
	MOVD R7,24(RSP)
	CALL runtime·memmove(SB)
	RET
`

func TestCrossLinuxRuntimeMatrixARM64PrivateFrameRepeatedPointerStores(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	goSource := strings.Replace(arm64PrivateFrameRepeatedStoreSource, "TEXT ABI0Copy(SB)", "TEXT ·ABI0Copy(SB)", 1)
	runARM64LocalRegisterGoOracle(t, goSource, `package main
import "unsafe"
func ABI0Copy(dst,src unsafe.Pointer,n uintptr)
func main() {
 for _,dst:=range []int{0,1,9,17,31} { for _,src:=range []int{0,1,9,17,31} { for _,n:=range []int{0,1,2,3,8,17,32,33} {
  var data, want [96]byte
  for i:=range data { data[i]=byte(i*37+dst*7+src*11+n); want[i]=data[i] }
  for stage:=0;stage<2;stage++ {
   want[src+stage]=[]byte{90,165}[stage]
   var snapshot [33]byte
   for i:=0;i<n;i++ { snapshot[i]=want[src+i] }
   for i:=0;i<n;i++ { want[dst+i]=snapshot[i] }
  }
  ABI0Copy(unsafe.Pointer(&data[dst]),unsafe.Pointer(&data[src]),uintptr(n))
  if data!=want { panic("actual Go private-frame repeated store/call/canary mismatch") }
 } } }
}
`, len(runner) != 0)
	t.Log("actual Go source passed 200 repeated-store/call overlap/unaligned/full-canary cases")
	file, err := Parse(ArchARM64, arm64PrivateFrameRepeatedStoreSource)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, arm64PrivateCallCopyOptions(triple))
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	const driver = `#include <stdint.h>
extern void ABI0Copy(void *, const void *, uint64_t);
int main(void) {
 const int offsets[]={0,1,9,17,31}, sizes[]={0,1,2,3,8,17,32,33};
 for(int d=0;d<5;d++) for(int s=0;s<5;s++) for(int z=0;z<8;z++) {
  unsigned char data[96], want[96], snapshot[33];
  int dst=offsets[d],src=offsets[s],n=sizes[z];
  for(int i=0;i<96;i++) data[i]=want[i]=(unsigned char)(i*37+dst*7+src*11+n);
  for(int stage=0;stage<2;stage++) {
   want[src+stage]=(unsigned char)(stage==0 ? 90 : 165);
   for(int i=0;i<n;i++) snapshot[i]=want[src+i];
   for(int i=0;i<n;i++) want[dst+i]=snapshot[i];
  }
  ABI0Copy(data+dst,data+src,(uint64_t)n);
  for(int i=0;i<96;i++) if(data[i]!=want[i]) return 1;
 }
 return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "private_frame_repeated_stores", triple, module.String(), driver, runner)
}

func arm64PrivateFrameStoreForms() []string {
	forms := []string{
		"MOVB R9,(R6)", "MOVBU R9,(R6)", "MOVH R9,(R6)", "MOVHU R9,(R6)",
		"MOVW R9,(R6)", "MOVWU R9,(R6)", "MOVD R9,(R6)",
		"MOVD.P R9,8(R6)", "MOVD.W R9,8(R6)",
		"FMOVS F0,(R6)", "FMOVD F0,(R6)",
		"STP (R9,R10),(R6)", "STPW (R9,R10),(R6)",
		"STP.P (R9,R10),16(R6)", "STP.W (R9,R10),16(R6)",
		"FSTPS (F0,F1),(R6)", "FSTPD (F0,F1),(R6)", "FSTPQ (F0,F1),(R6)",
		"FSTPQ.P (F0,F1),32(R6)", "FSTPQ.W (F0,F1),32(R6)",
		"VST1 [V0.B16],(R6)", "VST1 [V0.H8,V1.H8],(R6)",
		"VST1 [V0.S4,V1.S4,V2.S4],(R6)", "VST1 [V0.D2,V1.D2,V2.D2,V3.D2],(R6)",
		"VST1.P [V0.B16],16(R6)",
		"CASPW (R10,R11),(R6),(R12,R13)", "CASPD (R10,R11),(R6),(R12,R13)",
	}
	for _, width := range []string{"B", "H", "W", ""} {
		forms = append(forms, "STLR"+width+" R9,(R6)")
		for _, prefix := range []string{"STXR", "STLXR"} {
			forms = append(forms, prefix+width+" R9,(R6),R10")
		}
	}
	for _, op := range []string{"STXPW", "STXP", "STLXPW", "STLXP"} {
		forms = append(forms, op+" (R9,R10),(R6),R11")
	}
	for _, order := range []string{"", "A", "L", "AL"} {
		for _, width := range []string{"B", "H", "W", "D"} {
			if order == "" || order == "AL" || width == "W" || width == "D" {
				forms = append(forms, "CAS"+order+width+" R9,(R6),R10")
			}
			for _, op := range []string{"LDADD", "LDCLR", "LDEOR", "LDOR", "SWP"} {
				forms = append(forms, op+order+width+" R9,(R6),R10")
			}
		}
	}
	return forms
}

func arm64PrivateFrameStoreSource(instruction string) string {
	return strings.Replace(arm64PrivateCallCopySource, "\tMOVD R5, 8(RSP)", "\t"+instruction+"\n\tMOVD src+8(FP),R6\n\tMOVD R5, 8(RSP)", 1)
}

func TestARM64PrivateFrameAllNamedStoreFamilies(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for index, instruction := range arm64PrivateFrameStoreForms() {
		t.Run(instruction, func(t *testing.T) {
			source := arm64PrivateFrameStoreSource(instruction)
			arm64PrivateCallGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range arm64TypedNativeTargets {
				ir, err := Translate(file, arm64PrivateCallCopyOptions(target))
				if err != nil {
					t.Errorf("%s: store through incoming pointer cannot name the fresh private frame: %v", target, err)
					continue
				}
				compileLLVMToObject(t, llc, target, fmt.Sprintf("store-%d.ll", index), fmt.Sprintf("store-%d.o", index), ir)
			}
		})
	}
}

func TestARM64PrivateFramePhysicalSPStoresRemainRejected(t *testing.T) {
	for _, instruction := range arm64PrivateFrameStoreForms() {
		t.Run(instruction, func(t *testing.T) {
			// Every width and conditional atomic store can overwrite saved LR.
			// Being an actual physical-SP destination must defeat the exception.
			source := arm64PrivateFrameStoreSource(strings.ReplaceAll(instruction, "R6", "RSP"))
			arm64PrivateCallGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, arm64PrivateCallCopyOptions(arm64LinuxGNUTriple)); !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("a store to physical SP must not retain caller LR: %v", err)
			}
		})
	}
}

func TestARM64PrivateFrameRepeatedCallAndPointerStorePreservesCallerLink(t *testing.T) {
	source := strings.Replace(arm64PrivateCallCopySource, "\tRET", `
	MOVD src+8(FP),R6
	MOVB R0,(R6)
	MOVD dst+0(FP),R5
	MOVD n+16(FP),R7
	MOVD R5,8(RSP)
	MOVD R6,16(RSP)
	MOVD R7,24(RSP)
	CALL runtime·memmove(SB)
	RET`, 1)
	arm64PrivateCallGoObject(t, source)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if !arm64CallFrameUnexposed(file.Funcs[0]) {
		t.Fatal("ordinary incoming-pointer stores and repeated calls exposed the private stack address")
	}
	if _, err := Translate(file, arm64PrivateCallCopyOptions(arm64LinuxGNUTriple)); err != nil {
		t.Fatalf("call-result code-address taint cannot expose the fresh private stack address: %v", err)
	}
}
