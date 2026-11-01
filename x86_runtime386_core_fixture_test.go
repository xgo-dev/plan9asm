package plan9asm

import (
	"strings"
	"testing"
)

// Shared verbatim source, manual transport signatures and native C driver.
// Portable object observations do not turn this fixture into a Go ABI0 body.
const runtime386CoreAssembly = `
TEXT addCarry(SB),NOSPLIT,$0-12
	MOVL a+0(FP), AX
	MOVL b+4(FP), BX
	CMPL AX, $0
	ADCL BX, AX
	MOVL AX, ret+8(FP)
	RET

TEXT cpuidProbe(SB),NOSPLIT,$0-0
	PUSHFL
	PUSHFL
	XORL $0x200000, 0(SP)
	POPFL
	PUSHFL
	POPL AX
	XORL 0(SP), AX
	POPFL
	TESTL $0x200000, AX
	JNE cpuidAvailable
	MOVL $0, AX
	RET
cpuidAvailable:
	MOVL $1, AX
	RET

TEXT frameAddress(SB),NOSPLIT,$0-12
	LEAL a+0(FP), SI
	MOVL $41, 4(SI)
	MOVL b+4(FP), AX
	MOVL AX, ret+8(FP)
	RET

TEXT copyForward(SB),NOSPLIT,$0-12
	MOVL dst+0(FP), DI
	MOVL src+4(FP), SI
	MOVL n+8(FP), CX
	CLD
	REP; MOVSB
	RET

TEXT copyBackward(SB),NOSPLIT,$0-12
	MOVL dst+0(FP), DI
	MOVL src+4(FP), SI
	MOVL n+8(FP), CX
	ADDL CX, DI
	ADDL CX, SI
	DECL DI
	DECL SI
	STD
	REP; MOVSB
	CLD
	RET

TEXT copyBackwardRestoredDF(SB),NOSPLIT,$0-12
	MOVL dst+0(FP), DI
	MOVL src+4(FP), SI
	MOVL n+8(FP), CX
	ADDL CX, DI
	ADDL CX, SI
	DECL DI
	DECL SI
	STD
	PUSHFL
	CLD
	POPFL
	REP; MOVSB
	CLD
	RET

TEXT fillWords(SB),NOSPLIT,$0-12
	MOVL dst+0(FP), DI
	MOVL value+4(FP), AX
	MOVL n+8(FP), CX
	CLD
	REP; STOSL
	RET

TEXT findByte(SB),NOSPLIT,$0-16
	MOVL data+0(FP), DI
	MOVL n+4(FP), CX
	MOVL value+8(FP), AX
	CLD
	REPN; SCASB
	MOVL CX, ret+12(FP)
	RET

TEXT zeroLengthScanPreservesZF(SB),NOSPLIT,$0-8
	MOVL data+0(FP), DI
	MOVL $0, CX
	CMPL AX, AX
	REPN; SCASB
	JNE zfLost
	MOVL $1, AX
	MOVL AX, ret+4(FP)
	RET
zfLost:
	MOVL $0, AX
	MOVL AX, ret+4(FP)
	RET

TEXT negateHasCarry(SB),NOSPLIT,$0-8
	MOVL value+0(FP), AX
	NEGL AX
	SETCS BX
	MOVL BX, ret+4(FP)
	RET

TEXT floorValue(SB),NOSPLIT,$0-16
	FMOVD value+0(FP), F0
	FSTCW -2(SP)
	MOVW -2(SP), AX
	ANDW $0xf3ff, AX
	ORW $0x0400, AX
	MOVW AX, -4(SP)
	FLDCW -4(SP)
	FRNDINT
	FLDCW -2(SP)
	FMOVDP F0, ret+8(FP)
	RET

TEXT uint32ToFloat64(SB),NOSPLIT,$0-12
	MOVL value+0(FP), AX
	MOVL AX, 0(SP)
	MOVL $0, 4(SP)
	FMOVV 0(SP), F0
	FMOVDP F0, ret+4(FP)
	RET

TEXT cas64(SB),NOSPLIT,$0-0
	LOCK
	CMPXCHG8B (SI)
	SETEQ AX
	RET

TEXT xadd32(SB),NOSPLIT,$0-12
	MOVL ptr+0(FP), BX
	MOVL delta+4(FP), AX
	MOVL AX, CX
	LOCK
	XADDL AX, 0(BX)
	ADDL CX, AX
	MOVL AX, ret+8(FP)
	RET

TEXT identity64(SB),NOSPLIT,$0-16
	MOVL value_lo+0(FP), AX
	MOVL AX, ret_lo+8(FP)
	MOVL value_hi+4(FP), AX
	MOVL AX, ret_hi+12(FP)
	RET

TEXT identityFloat64(SB),NOSPLIT,$0-16
	MOVL value_lo+0(FP), AX
	MOVL AX, ret_lo+8(FP)
	MOVL value_hi+4(FP), AX
	MOVL AX, ret_hi+12(FP)
	RET

TEXT readFS(SB),NOSPLIT,$0-4
	MOVL 0x18(FS), AX
	MOVL AX, ret+0(FP)
	RET

TEXT roundNearest(SB),NOSPLIT,$0-16
	FMOVD value+0(FP), F0
	FRNDINT
	FMOVDP F0, ret+8(FP)
	RET
`

// Keep the original complete counterexample above. SETCS writes only BL;
// explicitly extend that byte before the corrected runtime fixture returns
// all of BX. No other TEXT, transport signature or native observation changes.
func runtime386CoreCorrectedAssembly(t *testing.T) string {
	t.Helper()
	const before = "\tSETCS BX\n\tMOVL BX, ret+4(FP)"
	const after = "\tSETCS BX\n\tMOVBLZX BX,BX\n\tMOVL BX, ret+4(FP)"
	if strings.Count(runtime386CoreAssembly, before) != 1 {
		t.Fatal("original carry-result path is not uniquely identified")
	}
	return strings.Replace(runtime386CoreAssembly, before, after, 1)
}

func runtime386CoreOptions() Options {
	sig := FuncSig{
		Name: "addCarry", Args: []LLVMType{I32, I32}, Ret: I32,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
		},
	}
	frameSig := func(name string, args []LLVMType, ret LLVMType, params, results []FrameSlot) FuncSig {
		return FuncSig{
			Name: name, Args: args, Ret: ret,
			Frame: FrameLayout{Params: params, Results: results},
		}
	}
	return Options{
		TargetTriple: "i686-pc-windows-msvc",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"addCarry":   sig,
			"cpuidProbe": {Name: "cpuidProbe", Ret: I32},
			"frameAddress": frameSig("frameAddress", []LLVMType{I32, I32}, I32,
				[]FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}}),
			"copyForward": frameSig("copyForward", []LLVMType{Ptr, Ptr, I32}, Void,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: Ptr, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}}, nil),
			"copyBackward": frameSig("copyBackward", []LLVMType{Ptr, Ptr, I32}, Void,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: Ptr, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}}, nil),
			"copyBackwardRestoredDF": frameSig("copyBackwardRestoredDF", []LLVMType{Ptr, Ptr, I32}, Void,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: Ptr, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}}, nil),
			"fillWords": frameSig("fillWords", []LLVMType{Ptr, I32, I32}, Void,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}}, nil),
			"findByte": frameSig("findByte", []LLVMType{Ptr, I32, I32}, I32,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}},
				[]FrameSlot{{Offset: 12, Type: I32, Index: 0, Field: -1}}),
			"zeroLengthScanPreservesZF": frameSig("zeroLengthScanPreservesZF", []LLVMType{Ptr}, I32,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}}),
			"negateHasCarry": frameSig("negateHasCarry", []LLVMType{I32}, I32,
				[]FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}}),
			"floorValue": frameSig("floorValue", []LLVMType{LLVMType("double")}, LLVMType("double"),
				[]FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: LLVMType("double"), Index: 0, Field: -1}}),
			"uint32ToFloat64": frameSig("uint32ToFloat64", []LLVMType{I32}, LLVMType("double"),
				[]FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 4, Type: LLVMType("double"), Index: 0, Field: -1}}),
			"cas64": {
				Name: "cas64", Args: []LLVMType{Ptr, I32, I32, I32, I32}, Ret: I1,
				ArgRegs: []Reg{SI, AX, DX, BX, CX},
			},
			"xadd32": frameSig("xadd32", []LLVMType{Ptr, I32}, I32,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}}),
			"identity64": frameSig("identity64", []LLVMType{I64}, I64,
				[]FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}}),
			"identityFloat64": frameSig("identityFloat64", []LLVMType{LLVMType("double")}, LLVMType("double"),
				[]FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: LLVMType("double"), Index: 0, Field: -1}}),
			"readFS": frameSig("readFS", nil, I32, nil,
				[]FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}),
			"roundNearest": frameSig("roundNearest", []LLVMType{LLVMType("double")}, LLVMType("double"),
				[]FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: LLVMType("double"), Index: 0, Field: -1}}),
		},
	}
}

const runtime386CoreCSource = `
int _fltused;
extern int addCarry(int, int);
extern int cpuidProbe(void);
extern int frameAddress(int, int);
extern void copyForward(unsigned char *, const unsigned char *, unsigned int);
extern void copyBackward(unsigned char *, const unsigned char *, unsigned int);
extern void copyBackwardRestoredDF(unsigned char *, const unsigned char *, unsigned int);
extern void fillWords(unsigned int *, unsigned int, unsigned int);
extern unsigned int findByte(const unsigned char *, unsigned int, unsigned int);
extern unsigned int zeroLengthScanPreservesZF(const unsigned char *);
extern unsigned int negateHasCarry(unsigned int);
extern double floorValue(double);
extern double uint32ToFloat64(unsigned int);
extern _Bool cas64(unsigned long long *, unsigned int, unsigned int, unsigned int, unsigned int);
extern unsigned int xadd32(unsigned int *, unsigned int);
extern unsigned long long identity64(unsigned long long);
extern double identityFloat64(double);
extern unsigned int readFS(void);
extern double roundNearest(double);
int main(void) {
    unsigned int i;
    const unsigned char source[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char copied[8] = {0};
    unsigned char overlap[9] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char restoredOverlap[9] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char forwardOverlap[5] = {1, 2, 3, 4, 5};
    unsigned int words[4] = {0};
    __declspec(align(8)) unsigned long long word = 0x1122334455667788ULL;
    unsigned int atomicWord = 10;
    if (addCarry(20, 22) != 42) return 11;
    if (cpuidProbe() != 1) return 12;
    if (frameAddress(20, 22) != 41) return 13;
    copyForward(copied, source, 8);
    for (i = 0; i < 8; i++) if (copied[i] != source[i]) return 14;
    copyBackward(overlap + 1, overlap, 8);
    for (i = 0; i < 8; i++) if (overlap[i + 1] != i) return 15;
    copyBackwardRestoredDF(restoredOverlap + 1, restoredOverlap, 8);
    for (i = 0; i < 8; i++) if (restoredOverlap[i + 1] != i) return 31;
    fillWords(words, 0x89abcdefU, 4);
    for (i = 0; i < 4; i++) if (words[i] != 0x89abcdefU) return 16;
    if (findByte(source, 8, 4) != 4) return 17;
    if (findByte(source, 8, 9) != 0) return 18;
    if (zeroLengthScanPreservesZF(source) != 1) return 32;
    if (negateHasCarry(0) != 0 || negateHasCarry(7) != 1) return 33;
    if (floorValue(3.75) != 3.0 || floorValue(-3.25) != -4.0) return 19;
    if (uint32ToFloat64(0xffffffffU) != 4294967295.0) return 20;
    if (!cas64(&word, 0x55667788U, 0x11223344U, 0xaabbccddU, 0x99aabbccU)) return 21;
    if (word != 0x99aabbccaabbccddULL) return 22;
    if (cas64(&word, 0, 0, 1, 2) || word != 0x99aabbccaabbccddULL) return 23;
    if (xadd32(&atomicWord, 5) != 15 || atomicWord != 15) return 24;
    if (identity64(0x8877665544332211ULL) != 0x8877665544332211ULL) return 25;
    if (identityFloat64(-123.75) != -123.75) return 26;
    copyForward(forwardOverlap + 1, forwardOverlap, 4);
    for (i = 0; i < 5; i++) if (forwardOverlap[i] != 1) return 27;
    if (readFS() == 0) return 28;
    if (roundNearest(2.5) != 2.0 || roundNearest(3.5) != 4.0 || roundNearest(-1.5) != -2.0) return 29;
    {
        union { double f; unsigned long long u; } rounded;
        rounded.f = roundNearest(-0.5);
        if (rounded.u != 0x8000000000000000ULL) return 30;
    }
    return 0;
}
`
