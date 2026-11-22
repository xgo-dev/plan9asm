package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalAESWidthMemoryObjects(t *testing.T) {
	type testCase struct{ operation, setup string }
	rows := []testCase{
		{"VAESDEC (SP), X7, X31", "LEAQ 128(CX),R10\nMOVQ R10,SP\n"},
		{"VAESDECLAST -17(BP)(SI*8), Y27, Y28", "LEAQ 74(CX),BP\nMOVQ $1,SI\n"},
		{"VAESDECLAST -17(BP)(SI*8), Z23, Z23", "LEAQ 74(CX),BP\nMOVQ $1,SI\n"},
		{"VAESKEYGENASSIST $-1,65(CX),X2", ""},
	}
	for _, name := range x86AESOracleNames {
		for _, bank := range []string{"X", "Y", "Z"} {
			if bank != "X" && (!strings.HasPrefix(name, "V") || strings.Contains(name, "IMC") || strings.Contains(name, "KEYGEN")) {
				continue
			}
			address := "65(CX)"
			if !strings.HasPrefix(name, "V") {
				address = "128(CX)"
			}
			operation, _ := x86AESOracleRow(name, address, bank)
			rows = append(rows, testCase{operation: operation})
			if strings.HasPrefix(name, "V") && !strings.Contains(name, "IMC") && !strings.Contains(name, "KEYGEN") {
				high := strings.NewReplacer(bank+"1", bank+"17", bank+"2", bank+"18").Replace(operation)
				rows = append(rows, testCase{operation: high})
			}
		}
	}
	if len(rows) != 36 {
		t.Fatal("incomplete AES memory opcode and carrier matrix", len(rows))
	}
	var assembly, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalAlignedAddressAssembly(t, name, row.operation, row.setup))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalAESWidthAndAlignment(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		operation, setup string
		valid            bool
	}{
		{"AESENC 128(CX),X2", "", true},
		{"AESENC 8(SP),X2", "MOVQ AX,8(SP)\nMOVQ AX,16(SP)\n", false},
		{"VAESENC 8(SP),X1,X2", "MOVQ AX,8(SP)\nMOVQ AX,16(SP)\n", true},
		{"VAESDEC 160(CX),Y1,Y2", "", true},
		{"VAESDEC 161(CX),Y1,Y2", "", false},
		{"VAESDECLAST 127(CX),Z1,Z2", "", true},
		{"VAESDECLAST 129(CX),Z1,Z2", "", false},
	} {
		t.Run(row.operation, func(t *testing.T) {
			source := fixedLocalAlignedAddressAssembly(t, "Value", row.operation, row.setup)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("valid=%t: %v", row.valid, err)
			}
		})
	}
}

func TestX86AESFamilyActualBoundFixedLocalConsumers(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	var assembly, declarations strings.Builder
	count := 0
	for _, name := range x86AESOracleNames {
		for _, source := range []string{"16(SP)", "tmp-144(SP)"} {
			row, _ := x86AESOracleRow(name, source, "X")
			if strings.HasPrefix(name, "V") && !strings.Contains(name, "IMC") && !strings.Contains(name, "KEYGEN") {
				row = name + " " + source + ",X0,X0"
			} else if strings.Contains(name, "KEYGEN") {
				row = name + " $27," + source + ",X0"
			} else {
				row = name + " " + source + ",X0"
			}
			body, _, _ := x86PrivateAlignedFrameAuditFixture(t, row)
			fn := fmt.Sprintf("F%d", count)
			count++
			assembly.WriteString(strings.Replace(body, "·Value", "·"+fn, 1))
			fmt.Fprintf(&declarations, "func %s(a,b,c,d uint64) uint64\n", fn)
		}
	}
	for _, target := range []struct{ name, triple string }{{"linux/amd64", "x86_64-unknown-linux-gnu"}, {"darwin/amd64", "x86_64-apple-darwin"}} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := x86CMOVFixedLocalFixture(t, assembly.String(), declarations.String(), target.name, target.triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "aes-native-local.ll", "aes-native-local.o", ir)
			})
		})
	}
}
