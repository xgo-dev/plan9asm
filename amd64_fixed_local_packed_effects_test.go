package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalPackedMasksAndUpperAliases(t *testing.T) {
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"legacy preserves unknown upper", "MOVOU 64(BP),X0\nVMOVDQU Y0,128(BP)", false},
		{"VEX zeroes upper", "VMOVDQU 64(BP),X0\nVMOVDQU64 Z0,128(BP)", true},
		{"EVEX zeroes upper", "VMOVDQU64 64(BP),Y31\nVMOVDQU64 Z31,128(BP)", true},
		{"legacy retains known upper", "VMOVDQU64 64(BP),Z0\nMOVOU 64(BP),X0\nVMOVDQU64 Z0,128(BP)", true},
		{"merge needs old bytes", "KMOVQ AX,K1\nVMOVDQA64 64(BP),K1,Z0\nVMOVDQA64 Z0,128(BP)", false},
		{"zero needs no old bytes", "KMOVQ AX,K1\nVMOVDQA64.Z 64(BP),K1,Z0\nVMOVDQA64 Z0,128(BP)", true},
		{"zero cannot bless unknown source", "KMOVQ AX,K1\nVMOVDQA64.Z Z1,K1,Z0\nVMOVDQA64 Z0,128(BP)", false},
		{"mask is undefined", "VMOVDQA64.Z 64(BP),K1,Z0\nVMOVDQA64 Z0,128(BP)", false},
		{"unknown source store", "VMOVDQA64 Z0,128(BP)", false},
		{"Go zero store traps", "VMOVDQA64 64(BP),Z0\nKMOVQ AX,K1\nVMOVDQA64.Z Z0,K1,128(BP)", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg, _, file, options := fixedLocalPackedFixture(t, row.body)
			requireX86GoAssemblerResult(t, "amd64", fixedLocalPackedAssembly(row.body), true)
			_, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"])
			if row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private byte transfer valid=%v: %v", row.valid, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalPackedMaskedStoreCannotInitializeUnknownBytes(t *testing.T) {
	const body = "VMOVDQA64 64(BP),Z0\nKMOVQ AX,K1\nVMOVDQA64 Z0,K1,128(BP)"
	pkg, _, _, options := fixedLocalPackedFixture(t, body)
	sig := options.Sigs[pkg.Path+".Value"]
	for missing := 0; missing < 64; missing++ {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			assembly := fixedLocalPackedAssembly(body)
			var stores strings.Builder
			for index := 0; index < 8; index++ {
				if index != missing%8 {
					fmt.Fprintf(&stores, "MOVB $1,%d(BP)\n", 128+missing/8*8+index)
				}
			}
			assembly = strings.Replace(assembly, fmt.Sprintf("MOVQ AX,%d(BP)\n", 128+missing/8*8), stores.String(), 1)
			assembly = strings.Replace(assembly, "MOVQ 128(BP),AX", fmt.Sprintf("MOVQ %d(BP),AX", 128+missing/8*8), 1)
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("dynamic mask initialized retained byte %d: %v", missing, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalPackedMaskMovesCompleteLocalRoles(t *testing.T) {
	for _, opcode := range []string{"KMOVB", "KMOVW", "KMOVD", "KMOVQ"} {
		t.Run(opcode, func(t *testing.T) {
			body := fmt.Sprintf("%s AX,K0\n%s K0,K7\n%s K7,128(BP)\n%s 64(BP),K1\n%s K1,CX\nVMOVDQA64.Z 64(BP),K1,Z0\nVMOVDQA64 Z0,128(BP)", opcode, opcode, opcode, opcode, opcode)
			pkg, _, file, options := fixedLocalPackedFixture(t, body)
			requireX86GoAssemblerResult(t, "amd64", fixedLocalPackedAssembly(body), true)
			sig := options.Sigs[pkg.Path+".Value"]
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
				t.Fatal("complete local mask transfer", err)
			}
			for name, changed := range map[string]string{
				"private pointer": strings.Replace(body, opcode+" AX,K0", opcode+" BP,K0", 1),
				"unknown GP":      strings.Replace(body, opcode+" AX,K0", opcode+" DX,K0", 1),
				"unknown K":       strings.Replace(body, opcode+" AX,K0", opcode+" K2,K0", 1),
				"BP output":       strings.Replace(body, opcode+" K1,CX", opcode+" K1,BP", 1),
				"SP output":       strings.Replace(body, opcode+" K1,CX", opcode+" K1,SP", 1),
				"outside frame":   strings.Replace(body, "128(BP)", "256(BP)", 1),
				"global output":   strings.Replace(body, "128(BP)", "external(SB)", 1),
			} {
				t.Run(name, func(t *testing.T) {
					file, err := Parse(ArchAMD64, fixedLocalPackedAssembly(changed))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("mask move acquired another native role", err)
					}
				})
			}
		})
	}
}

func TestGoAMD64FixedLocalPackedCFGMergeMasksAndBytes(t *testing.T) {
	for name, body := range map[string]string{
		"mask omitted on one path":   "CMPQ AX,AX\nJEQ joined\nKMOVQ AX,K1\njoined:\nVMOVDQA64.Z 64(BP),K1,Z0\nVMOVDQA64 Z0,128(BP)",
		"vector omitted on one path": "CMPQ AX,AX\nJEQ joined\nVMOVDQA64 64(BP),Z0\njoined:\nVMOVDQA64 Z0,128(BP)",
		"BP differs on one path":     "CMPQ AX,AX\nJEQ joined\nADDQ $64,BP\njoined:\nVMOVDQA64 64(BP),Z0\nVMOVDQA64 Z0,128(BP)",
	} {
		t.Run(name, func(t *testing.T) {
			pkg, _, file, options := fixedLocalPackedFixture(t, body)
			if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("predecessor lost its must-defined/source role", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalPackedMaskedStoreRevokesPrivatePointerSpills(t *testing.T) {
	for _, mask := range []string{"AX", "$0", "$1", "$-1"} {
		for _, use := range []string{"MOVQ 32(BP),R11\nMOVQ 64(R11),AX", "MOVQ 32(BP),AX"} {
			t.Run(mask+"/"+use, func(t *testing.T) {
				body := "VMOVDQU64 64(BP),Z0\nMOVQ BP,32(BP)\nMOVQ " + mask + ",DX\nKMOVQ DX,K1\nVMOVDQU64 Z0,K1,32(BP)\n" + use
				pkg, _, file, options := fixedLocalPackedFixture(t, body)
				requireX86GoAssemblerResult(t, "amd64", fixedLocalPackedAssembly(body), true)
				if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("partial store preserved pointer authority or invented numerical bytes", err)
				}
			})
		}
	}
	// This domain proves mask definedness, not constant mask values. Even a
	// zero mask must conservatively revoke the overlapping pointer certificate.
	state := x86FixedLocalState{bytes: newFixedLocalByteSet(96), booleanBytes: newFixedLocalByteSet(96), addresses: map[int64]int64{32: 8, 80: 16}}
	fixedLocalNumericalStore(&state, 36, 16, false)
	if _, found := state.addresses[32]; found || state.addresses[80] != 16 {
		t.Fatal("partial overlap did not revoke exactly the overlapping pointer spill")
	}
	for index := int64(0); index < 96; index++ {
		if state.bytes.has(index) {
			t.Fatalf("masked store invented initialized byte %d", index)
		}
	}
}

func TestGoAMD64FixedLocalPackedMergeRequiresEveryDestinationByte(t *testing.T) {
	for _, bank := range []struct {
		name  string
		width int64
	}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
		file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$256-0\nVMOVDQU8 "+bank.name+"1,K1,"+bank.name+"0\nVMOVDQU8 "+bank.name+"0,0(BP)\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for missing := int64(0); missing < bank.width; missing++ {
			t.Run(fmt.Sprintf("%s/%d", bank.name, missing), func(t *testing.T) {
				state := x86FixedLocalState{
					pointers: map[Reg]int64{BP: 0}, masks: map[Reg]bool{"K1": true},
					vectors: map[Reg]uint64{"Z0": ^(uint64(1) << uint(missing)), "Z1": ^uint64(0)},
					bytes:   newFixedLocalByteSet(256), addresses: make(map[int64]int64),
				}
				proof := &x86FixedLocalProof{frame: 256, accesses: make(map[int]map[int]x86FixedLocalAccess)}
				copy := file.Funcs[0].Instrs[1]
				if known, err := fixedLocalPackedMoveStep(&copy, &state, proof, 0); !known || err != nil {
					t.Fatalf("register merge: known=%v error=%v", known, err)
				}
				if got, want := state.vectors["Z0"], ^(uint64(1) << uint(missing)); got != want {
					t.Fatalf("merge/upper-zero bytes=%016x want=%016x", got, want)
				}
				store := file.Funcs[0].Instrs[2]
				if _, err := fixedLocalPackedMoveStep(&store, &state, proof, 0); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("merge result exposed an undefined destination byte", err)
				}
			})
		}
	}
}
