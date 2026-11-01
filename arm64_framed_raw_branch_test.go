package plan9asm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

type arm64FramedRawBranchCase struct {
	name string
	word uint32
	bit  int
	op   string
}

// Every branch skips one four-byte instruction. Encoding fields are independent
// of the translator's decoder; the Go assembler oracle checks the native bytes.
func arm64FramedRawBranches() []arm64FramedRawBranchCase {
	cases := []arm64FramedRawBranchCase{{name: "B", word: 0x14000002, op: "B"}}
	conditions := []struct {
		op        string
		condition uint32
	}{
		{"BEQ", 0}, {"BNE", 1}, {"BCS", 2}, {"BHS", 2},
		{"BCC", 3}, {"BLO", 3}, {"BMI", 4}, {"BPL", 5},
		{"BVS", 6}, {"BVC", 7}, {"BHI", 8}, {"BLS", 9},
		{"BGE", 10}, {"BLT", 11}, {"BGT", 12}, {"BLE", 13},
	}
	for _, condition := range conditions {
		cases = append(cases, arm64FramedRawBranchCase{
			name: condition.op, word: 0x54000040 | condition.condition, op: condition.op,
		})
	}
	for _, form := range []struct {
		op   string
		base uint32
	}{
		{"CBZW", 0x34000000}, {"CBNZW", 0x35000000},
		{"CBZ", 0xb4000000}, {"CBNZ", 0xb5000000},
	} {
		cases = append(cases, arm64FramedRawBranchCase{
			name: form.op, word: form.base | 0x40 | 2, op: form.op,
		})
	}
	for _, form := range []struct {
		op   string
		base uint32
	}{{"TBZ", 0x36000000}, {"TBNZ", 0x37000000}} {
		for _, bit := range []int{0, 31, 32, 63} {
			word := form.base | uint32(bit&31)<<19 | uint32(bit>>5)<<31 | 0x40 | 2
			cases = append(cases, arm64FramedRawBranchCase{
				name: fmt.Sprintf("%s%d", form.op, bit), word: word, bit: bit, op: form.op,
			})
		}
	}
	return cases
}

func arm64FramedRawBranchSource(name, branch string) string {
	return fmt.Sprintf(`TEXT ·%s(SB),4,$496-16
MOVD input+0(FP),R0
MOVD output+8(FP),R1
MOVD (R0),R2
MOVD $5,R3
CMP $0,R2
%s
WORD $0xd28000e3 // movz x3,#7: exact four-byte source width.
MOVD R3,(R1)
MOVD R20,R9
MOVD $0,R9
MOVD 0(RSP),R30
RET
`, name, branch)
}

func arm64FramedRawBranchProof(t *testing.T, source string) bool {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	fn := file.Funcs[0]
	fn, err = normalizeARM64ScalarMemoryFrame(fn)
	if err != nil {
		t.Fatal(err)
	}
	return arm64FramedRawBranchFunctionProof(t, fn)
}

func arm64FramedRawBranchFunctionProof(t *testing.T, fn Func) bool {
	t.Helper()
	name := strings.TrimPrefix(fn.Sym, "·")
	pkg := mustGoPackage(t, "framedbranches", "package framedbranches\nfunc "+name+"(*uint64,*uint64)\n")
	resolve := testResolveSym(pkg.Path)
	sig, err := DeriveGoFuncABI0Signature(resolve(fn.Sym), pkg.Types.Scope().Lookup(name).(*types.Func), "arm64", types.SizesFor("gc", "arm64"))
	if err != nil {
		t.Fatal(err)
	}
	return arm64CallFrameUnexposedTyped(fn, sig, resolve, map[string]FuncSig{sig.Name: sig})
}

func TestARM64FramedRawBranchesHaveExactSourceCFG(t *testing.T) {
	for _, branch := range arm64FramedRawBranches() {
		t.Run(branch.name, func(t *testing.T) {
			source := arm64FramedRawBranchSource("raw"+branch.name, fmt.Sprintf("WORD $%#08x", branch.word))
			requireARM64GoAssemblerResult(t, source, true)
			if !arm64FramedRawBranchProof(t, source) {
				t.Fatal("Go-accepted same-source raw branch lost the complete framed proof")
			}
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			fn, err := normalizeARM64ScalarMemoryFrame(file.Funcs[0])
			if err != nil {
				t.Fatal(err)
			}
			prepared, blobs, err := prepareARM64RawPCRelative(fn)
			if err != nil || len(blobs) != 0 {
				t.Fatalf("raw-PC registration changed executable source role: %v, %d blobs", err, len(blobs))
			}
			if !arm64FramedRawBranchFunctionProof(t, prepared) {
				t.Fatal("actual normalized CFG lost its independent complete proof")
			}
		})
	}
}

func TestARM64FramedRawBranchCFGDoesNotEraseUnprovedSource(t *testing.T) {
	const safe = "WORD $0xb4000042"
	for _, test := range []struct {
		name, branch string
	}{
		{"unknown_word", "WORD $0xffffffff"},
		{"unregistered_al_condition", "WORD $0x5400004e"},
		{"unregistered_nv_condition", "WORD $0x5400004f"},
		{"raw_local_call", "WORD $0x94000002"},
		{"raw_native_call", "WORD $0xd63f0040"},
		{"source_unknown_call", "CALL unknown(SB)"},
		{"raw_native_return", "WORD $0xd65f03c0"},
		{"indirect_branch", "WORD $0xd61f0040"},
		{"far_target", "WORD $0x1407ffff"},
		{"unknown_source_width", "WORD $0x14000002\nMOVD $0x123456789abcdef0,R9"},
		{"target_inside_ret_epilogue", "WORD $0x14000002\nRET"},
		{"native_address", "WORD $0x10000042"},
		{"frame_predicate", "MOVD R20,R2\n" + safe},
		{"mixed_frame_predicate", "MOVD R20,R2\nWORD $0xb4000040\nMOVD $0,R2\n" + safe},
		{"prefix_escape", "MOVD R20,(R1)\n" + safe},
		{"prefix_fixed_g_corruption", "MOVD R20,g\n" + safe},
		{"prefix_fixed_os_corruption", "WORD $0xaa1403f2\n" + safe},
		{"prefix_link_corruption", "MOVB R2,1(RSP)\n" + safe},
		{"branch_sp_delta", "WORD $0xb4000042\nSUB $16,RSP"},
		{"unknown_sp_index", "MOVD (RSP)(R2),R9\n" + safe},
		{"dead_escape", "WORD $0x14000002\nMOVD R20,(R1)"},
		{"dead_native_call", "WORD $0x14000002\nWORD $0xd63f0040"},
		{"dead_unknown_word", "WORD $0x14000002\nWORD $0xffffffff"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := arm64FramedRawBranchSource("refused", test.branch)
			if arm64FramedRawBranchProof(t, source) {
				t.Fatal("raw-PC registration erased an unsafe, dead or unknown component")
			}
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			fn, err := normalizeARM64ScalarMemoryFrame(file.Funcs[0])
			if err != nil {
				t.Fatal(err)
			}
			prepared, blobs, err := prepareARM64RawPCRelative(fn)
			if err == nil && len(blobs) == 0 && arm64FramedRawBranchFunctionProof(t, prepared) {
				t.Fatal("normalized CFG independently granted an unproved component a frame")
			}
		})
	}
	for _, change := range []struct{ from, to string }{
		{"4,$496-16", "516,$496-16"},
		{"4,$496-16", "4,$496"},
		{"4,$496-16", "4,$496-8"},
		{"4,$496-16", "Unknown,$496-16"},
	} {
		source := strings.Replace(arm64FramedRawBranchSource("refused", safe), change.from, change.to, 1)
		if arm64FramedRawBranchProof(t, source) {
			t.Fatalf("changed source/entry metadata acquired an implicit frame: %+v", change)
		}
	}
}

func TestARM64FramedRawBranchesLoopsAndJoins(t *testing.T) {
	for _, branch := range []string{
		"WORD $0xb4000002",                          // CBZ X2,current-PC: both the loop and exit are real.
		"WORD $0x34000002",                          // The original Arrow instruction's W form.
		"loop:\nWORD $0xd1000442\nWORD $0xb5ffffe2", // SUB X2,#1; CBNZ X2,previous instruction.
		"WORD $0xb4000042\nWORD $0xaa1403e9\nWORD $0xd2800009",
	} {
		if !arm64FramedRawBranchProof(t, arm64FramedRawBranchSource("looped", branch)) {
			t.Fatalf("safe complete loop/join lost its source proof: %s", branch)
		}
	}
}

func TestARM64FramedRawBranchOriginalGoEncodingFields(t *testing.T) {
	// This encoding oracle is separate from framed permission: the complete
	// register fields include platform/control registers and ZR, which do not
	// acquire a frame-read permission merely because Go accepts their encoding.
	var source strings.Builder
	var expected bytes.Buffer
	source.WriteString("TEXT fields(SB),4,$0-0\n")
	forms := 0
	appendBranch := func(text string, word uint32) {
		separator := ","
		if !strings.Contains(text, " ") {
			separator = " "
		}
		// A real NOP at the target prevents Go's branch-chain optimization
		// from following the next test's unconditional branch instead.
		fmt.Fprintf(&source, "%s%starget%d\nWORD $0xd503201f\ntarget%d:\nWORD $0xd503201f\n", text, separator, forms, forms)
		for _, value := range []uint32{word, 0xd503201f, 0xd503201f} {
			if err := binary.Write(&expected, binary.LittleEndian, value); err != nil {
				t.Fatal(err)
			}
		}
		forms++
	}
	appendBranch("B", 0x14000002)
	appendBranch("JMP", 0x14000002)
	for _, branch := range arm64FramedRawBranches()[1:17] {
		appendBranch(branch.op, branch.word)
	}
	for reg := 0; reg < 32; reg++ {
		name := fmt.Sprintf("R%d", reg)
		if reg == 18 {
			name = "R18_PLATFORM"
		} else if reg == 28 {
			name = "g"
		} else if reg == 31 {
			name = "ZR"
		}
		for _, form := range []struct {
			op   string
			base uint32
		}{
			{"CBZW", 0x34000000}, {"CBNZW", 0x35000000},
			{"CBZ", 0xb4000000}, {"CBNZ", 0xb5000000},
		} {
			appendBranch(form.op+" "+name, form.base|0x40|uint32(reg))
		}
		for bit := 0; bit < 64; bit++ {
			for _, form := range []struct {
				op   string
				base uint32
			}{{"TBZ", 0x36000000}, {"TBNZ", 0x37000000}} {
				word := form.base | uint32(bit&31)<<19 | uint32(bit>>5)<<31 | 0x40 | uint32(reg)
				appendBranch(fmt.Sprintf("%s $%d,%s", form.op, bit, name), word)
			}
		}
	}
	source.WriteString("RET\n")
	if err := binary.Write(&expected, binary.LittleEndian, uint32(0xd65f03c0)); err != nil {
		t.Fatal(err)
	}
	// obj7.span7 pads TEXT bytes with zero words to its 16-byte funcAlign.
	// These bytes follow the actual RET and are not another source instruction.
	for expected.Len()%16 != 0 {
		if err := binary.Write(&expected, binary.LittleEndian, uint32(0)); err != nil {
			t.Fatal(err)
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		actual := arm64ImmediateOriginalGoBytes(t, source.String(), goos)
		if !bytes.Equal(actual, expected.Bytes()) {
			for offset := 0; offset+4 <= len(actual) && offset+4 <= expected.Len(); offset += 4 {
				if !bytes.Equal(actual[offset:offset+4], expected.Bytes()[offset:offset+4]) {
					t.Fatalf("%s original Go branch word at byte %d: got %x want %x", goos, offset, actual[offset:offset+4], expected.Bytes()[offset:offset+4])
				}
			}
			t.Fatalf("%s original Go branch byte lengths: got %d want %d", goos, len(actual), expected.Len())
		}
	}
	t.Logf("%d original Go encodings per OS: aliases, all 32 register fields and all 64 test-bit fields", forms)
}
