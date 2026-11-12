package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64PrivateFrameLocalAffineReadPreservesCallerLink(t *testing.T) {
	for _, read := range []string{
		"ADD $8,RSP,R9\nVLD1 (R9),[V0.B16,V1.B16]\nMOVD $0,R9",
		"MOVD RSP,R9\nADD $8,R9\nMOVD R9,R10\nMOVD (R10),R11\nMOVD $0,R9\nMOVD $0,R10",
		"MOVD $8(RSP),R9\nFMOVD (R9),F0\nMOVD $0,R9",
		"CBZ R7,alternate\nADD $8,RSP,R9\nB joined\nalternate:\nMOVD $8(RSP),R9\njoined:\nVLD1 (R9),[V0.B16]\nMOVD $0,R9",
	} {
		source := arm64PrivateFrameStoreSource(read + "\nMOVB R11,(R6)")
		arm64PrivateCallGoObject(t, source)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if !arm64CallFrameUnexposed(file.Funcs[0]) {
			t.Errorf("a bounded local read followed by a proven full overwrite escaped the fresh frame: %s", read)
			continue
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		for index, target := range arm64TypedNativeTargets {
			ir, err := Translate(file, arm64PrivateCallCopyOptions(target))
			if err != nil {
				t.Fatalf("%s local affine read: %v", target, err)
			}
			compileLLVMToObject(t, llc, target, fmt.Sprintf("read-%d.ll", index), fmt.Sprintf("read-%d.o", index), ir)
		}
	}
}

func TestARM64PrivateFrameAffineLatticeRetainsMayFrameAtJoins(t *testing.T) {
	for _, incoming := range []arm64PrivateFrameAddresses{
		{}, {"R9": {offset: 16, exact: true}}, {"R9": {}},
	} {
		state := arm64PrivateFrameAddresses{"R9": {offset: 8, exact: true}}
		if !state.merge(incoming) {
			t.Fatal("mixed/different-offset join did not retain an unknown frame address")
		}
		if value, frame := state.address("R9"); !frame || value.exact {
			t.Fatal("join erased frame taint or invented an exact displacement")
		}
		copy := state.clone()
		if !copy.assign("R10", copy["R9"], true) {
			t.Fatal("copy failed")
		}
		if value, frame := copy.address("R10"); !frame || value.exact {
			t.Fatal("copy washed mixed frame taint")
		}
		if !copy.assign("R9", arm64PrivateFrameAddress{}, false) {
			t.Fatal("known full overwrite failed")
		}
		if _, frame := copy.address("R9"); frame || len(state) != 1 {
			t.Fatal("overwrite did not kill exactly its destination or clone changed the source")
		}
	}
	state := arm64PrivateFrameAddresses{"R9": {offset: 8, exact: true}}
	if state.merge(state.clone()) || state["R9"] != (arm64PrivateFrameAddress{offset: 8, exact: true}) {
		t.Fatal("identical affine paths must keep their exact offset")
	}
}

func TestARM64PrivateFrameLocalReadNativeEffectsCannotConsumeTemporaries(t *testing.T) {
	for _, op := range []string{"SVC $0", "HVC $0", "SMC $0", "BRK $0", "HLT $0", "DCPS1 $0", "DCPS2 $0", "DCPS3 $0", "DRPS", "ERET", "UNDEF"} {
		source := arm64PrivateFrameStoreSource("ADD $8,RSP,R0\n" + op + "\nMOVD $0,R0")
		arm64PrivateCallGoObject(t, source)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64CallFrameUnexposed(file.Funcs[0]) {
			t.Fatalf("unmodelled native/exception transport borrowed a local-read proof: %s", op)
		}
	}
}

func TestARM64PrivateFrameLocalReadFamilyObjects(t *testing.T) {
	loads := []string{}
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		loads = append(loads, op+" (R9),R11")
	}
	for _, op := range []string{"FMOVS", "FMOVD", "FMOVQ"} {
		loads = append(loads, op+" (R9),F0")
	}
	for _, op := range []string{"LDP", "LDPW", "LDPSW"} {
		loads = append(loads, op+" (R9),(R11,R12)")
	}
	for _, op := range []string{"FLDPS", "FLDPD", "FLDPQ"} {
		loads = append(loads, op+" (R9),(F0,F1)")
	}
	for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D1", "D2"} {
		registers := []string{}
		for count := 0; count < 4; count++ {
			registers = append(registers, fmt.Sprintf("V%d.%s", count, arrangement))
			loads = append(loads, "VLD1 (R9),["+strings.Join(registers, ",")+"]")
		}
	}
	for _, lane := range []struct {
		kind  string
		count int
	}{{kind: "B", count: 16}, {kind: "H", count: 8}, {kind: "S", count: 4}, {kind: "D", count: 2}} {
		for index := 0; index < lane.count; index++ {
			loads = append(loads, fmt.Sprintf("VLD1 (R9),V0.%s[%d]", lane.kind, index))
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for index, load := range loads {
		t.Run(load, func(t *testing.T) {
			source := arm64PrivateFrameStoreSource("ADD $8,RSP,R9\n" + load + "\nMOVD $0,R9\nMOVB R11,(R6)")
			source = strings.Replace(source, "$32-24", "$80-24", 1)
			arm64PrivateCallGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if !arm64CallFrameUnexposed(file.Funcs[0]) {
				t.Fatal("a known local read acquired frame-address escape")
			}
			for _, target := range arm64TypedNativeTargets {
				ir, err := Translate(file, arm64PrivateCallCopyOptions(target))
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target, fmt.Sprintf("load-%d.ll", index), fmt.Sprintf("load-%d.o", index), ir)
			}
		})
	}
}

func TestARM64PrivateFrameLocalReadEscapesAndUnknownEffectsRejected(t *testing.T) {
	for _, effect := range []string{
		"MOVD RSP,R9\nMOVD R9,holder(SB)\nMOVD $0,R9",
		"ADD $8,RSP,R9\nMOVD R9,R10\nMOVD R10,(R6)\nMOVD $0,R9\nMOVD $0,R10",
		"MOVD RSP,R9\nMOVD R9,dst+0(FP)\nMOVD $0,R9",
		"MOVD RSP,R9\nMOVD R9,32(RSP)\nMOVD $0,R9",
		"ADD $8,RSP,R9\nVLD1 (R9),[V0.B16]", // live at call
		"ADD $8,RSP,R9\nVMOV R9,V0.D[0]\nMOVD $0,R9",
		"ADD $8,RSP,R9\nEOR $8,R9,R10\nMOVD $0,R9",
		"ADD $8,RSP,R9\nEOR R9,R9\nMOVD $0,R9",
		"ADD $8,RSP,R9\nMOVK $1,R9\nMOVD $0,R9",
		"ADD $8,RSP,R9\nMOVD (R6)(R9),R9\nMOVD $0,R9",
		"ADD $8,RSP,R9\nMOVD (R9)(R7),R11\nMOVD $0,R9",
		"ADD $8,RSP,R9\nVLD1.P 16(R9),[V0.B16]\nMOVD $0,R9",
		"ADD $8,RSP,R9\nMOVD.W 8(R9),R11\nMOVD $0,R9",
		"MOVD.P 8(RSP),R11\nMOVD.W -8(RSP),R11\nADD $8,RSP,R9\nVLD1 (R9),[V0.B16]\nMOVD $0,R9",
		"MOVD (RSP)(R7),R11\nADD $8,RSP,R9\nVLD1 (R9),[V0.B16]\nMOVD $0,R9",
		"ADD $8,RSP,R9\nMOVD R11,(R9)\nMOVD $0,R9",
		"MOVD $-8(RSP),R9\nMOVD (R9),R11\nMOVD $0,R9",
		"ADD $32,RSP,R9\nVLD1 (R9),[V0.B16]\nMOVD $0,R9",
		"CBZ R7,alternate\nADD $8,RSP,R9\nB joined\nalternate:\nMOVD R6,R9\njoined:\nVLD1 (R9),[V0.B16]\nMOVD $0,R9",
		"CBZ R7,alternate\nADD $8,RSP,R9\nB joined\nalternate:\nADD $16,RSP,R9\njoined:\nVLD1 (R9),[V0.B16]\nMOVD $0,R9",
		"CBZ R7,alternate\nADD $8,RSP,R9\nB joined\nalternate:\nADD $16,RSP,R9\njoined:\nMOVD R9,R10\nMOVD R10,holder(SB)\nMOVD $0,R9\nMOVD $0,R10",
		"ADD $8,RSP,R9\nloop:\nADD $8,R9\nCBNZ R7,loop\nVLD1 (R9),[V0.B16]\nMOVD $0,R9",
	} {
		t.Run(effect, func(t *testing.T) {
			source := arm64PrivateFrameStoreSource(effect) + "\nGLOBL holder(SB),NOPTR,$8\n"
			arm64PrivateCallGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if arm64CallFrameUnexposed(file.Funcs[0]) {
				t.Fatal("unproved/escaped frame address obtained a no-escape proof")
			}
			for _, target := range arm64TypedNativeTargets {
				_, err := Translate(file, arm64PrivateCallCopyOptions(target))
				switch effect {
				case "ADD $8,RSP,R9\nVLD1 (R9),[V0.B16]",
					"ADD $8,RSP,R9\nMOVD.W 8(R9),R11\nMOVD $0,R9",
					"ADD $8,RSP,R9\nMOVD R11,(R9)\nMOVD $0,R9":
					// Preserve the original source-only negative above. The
					// explicit typed LLVM call does not consume this unused GP
					// address. Every certified store/read/writeback lies in
					// private DATA, not sp0. This is object coverage, not an
					// execution claim for this fixture's undefined R11 data;
					// PrivateDataMemoryFamily supplies initialized numerical
					// and full-canary runtime counterparts.
					if err != nil {
						t.Fatalf("%s typed bounded data/scratch: %v", target, err)
					}
					continue
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s unproved local frame use did not remain context-required: %v", target, err)
				}
			}
		})
	}
	for _, effect := range []string{
		"ADD $8,RSP,R9\nMOVD R9,R0\nMOVD $0,R9",
		"ADD $8,RSP,R9\nMOVD R9,8(RSP)\nMOVD $0,R9",
	} {
		source := strings.Replace(arm64PrivateCallCopySource, "\tCALL runtime·memmove(SB)", effect+"\nCALL runtime·memmove(SB)", 1)
		arm64PrivateCallGoObject(t, source)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64CallFrameUnexposed(file.Funcs[0]) {
			t.Fatal("a live/call-transport frame address crossed a real CALL")
		}
	}
	for _, effect := range []string{"ADD $8,RSP,R9", "ADD $8,RSP,R9\nMOVD R9,R0\nMOVD $0,R9"} {
		source := strings.Replace(arm64PrivateCallCopySource, "\tRET", effect+"\nRET", 1)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64CallFrameUnexposed(file.Funcs[0]) {
			t.Fatal("a live/result-register frame address crossed RET")
		}
	}
}

func TestARM64PrivateFrameLocalReadSurvivesAuditedHelperCoalescing(t *testing.T) {
	source := strings.Replace(arm64PrivateCallCopySource, "\tCALL runtime·memmove(SB)", "\tMOVD $1,R11\nCALL helper<>(SB)\nADD $8,RSP,R9\nVLD1 (R9),[V0.B16]\nMOVD $0,R9\nMOVB R11,(R6)", 1)
	source += "TEXT helper<>(SB),NOSPLIT,$0\nADD $1,R11\nRET\n"
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	coalesced, err := coalesceARM64PrivateRegisterHelpers(file)
	if err != nil {
		t.Fatal(err)
	}
	if !coalesced.Funcs[0].arm64PrivateUnexposedFrame || !arm64CallFrameUnexposed(coalesced.Funcs[0]) {
		t.Fatal("audited helper rewriting lost the original affine-read/no-escape decision")
	}
	if _, err := Translate(coalesced, arm64PrivateCallCopyOptions(arm64LinuxGNUTriple)); err != nil {
		t.Fatal(err)
	}
}

func TestCrossLinuxRuntimeMatrixARM64PrivateFrameLocalAffineRead(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source := strings.Replace(arm64PrivateCallCopySource, "$32-24", "$80-24", 1)
	source = strings.Replace(source, "\tRET", `
	MOVD $0x0706050403020100,R10
	MOVD R10,32(RSP)
	MOVD $0x0f0e0d0c0b0a0908,R10
	MOVD R10,40(RSP)
	MOVD $0x1716151413121110,R10
	MOVD R10,48(RSP)
	MOVD $0x1f1e1d1c1b1a1918,R10
	MOVD R10,56(RSP)
	MOVD n+16(FP),R7
	CBZ R7,alternate
	MOVD RSP,R9
	ADD $32,R9
	B joined
alternate:
	MOVD $32(RSP),R9
joined:
	MOVD R9,R11
	MOVD $0,R9
	VLD1 (R11),[V0.B16,V1.B16]
	MOVD $0,R11
	MOVD dst+0(FP),R5
	VST1 [V0.B16,V1.B16],(R5)
	RET`, 1)
	goSource := strings.Replace(source, "TEXT ABI0Copy(SB)", "TEXT ·ABI0Copy(SB)", 1)
	runARM64LocalRegisterGoOracle(t, goSource, `package main
import "unsafe"
func ABI0Copy(dst,src unsafe.Pointer,n uintptr)
func main() {
 for _,dst:=range []int{0,1,9,17,31} { for _,src:=range []int{0,1,9,17,31} { for _,n:=range []int{0,1,2,3,8,17,32,33} {
  var data, want [96]byte
  for i:=range data { data[i]=byte(i*37+dst*7+src*11+n); want[i]=data[i] }
  var snapshot [33]byte
  for i:=0;i<n;i++ { snapshot[i]=want[src+i] }
  for i:=0;i<n;i++ { want[dst+i]=snapshot[i] }
  for i:=0;i<32;i++ { want[dst+i]=byte(i) }
  ABI0Copy(unsafe.Pointer(&data[dst]),unsafe.Pointer(&data[src]),uintptr(n))
  if data!=want { panic("actual Go affine local-read/frame/call/canary mismatch") }
 } } }
}
`, len(runner) != 0)
	t.Log("actual Go passed 200 local-read/call/overlap/unaligned/full-canary cases")
	file, err := Parse(ArchARM64, source)
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
  for(int i=0;i<n;i++) snapshot[i]=want[src+i];
  for(int i=0;i<n;i++) want[dst+i]=snapshot[i];
  for(int i=0;i<32;i++) want[dst+i]=(unsigned char)i;
  ABI0Copy(data+dst,data+src,(uint64_t)n);
  for(int i=0;i<96;i++) if(data[i]!=want[i]) return 1;
 }
 return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "private_frame_local_reads", triple, module.String(), driver, runner)
}
