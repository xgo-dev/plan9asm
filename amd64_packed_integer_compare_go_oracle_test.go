package plan9asm

import (
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func x86PackedIntegerCompareRunOriginalGo(t *testing.T, declaration, assembly, testSource string) {
	x86PackedIntegerCompareOriginalGoDriver(t, declaration, assembly, testSource, false)
}

func x86PackedIntegerCompareOriginalGoDriver(t *testing.T, declaration, assembly, testSource string, buildOnly bool) {
	t.Helper()
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declaration,
		"value_amd64.s": assembly, "value_test.go": testSource,
	} {
		data := []byte(source)
		if strings.HasSuffix(name, ".go") {
			var err error
			data, err = format.Source(data)
			if err != nil {
				t.Fatalf("first-party original fixture syntax: %v", err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	driver, _ := x86LEAActualSDKDriver(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	arguments := []string{"test", "-p=2", "-vet=off", "-count=1"}
	executable := filepath.Join(dir, "original-compare.test")
	if buildOnly {
		arguments = append(arguments, "-c", "-o", executable)
	}
	arguments = append(arguments, ".")
	command := exec.CommandContext(ctx, driver, arguments...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if buildOnly {
		// These native Linux fixtures may contain Unix fault probes. Compile
		// their actual target independently of the host; never execute them.
		command.Env = append(command.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual original Go packed compare driver (build-only=%t): %v\n%s", buildOnly, err, output)
	}
	if buildOnly {
		if amd64, err := x86OriginalGoLinkedAMD64(executable); err != nil || !amd64 {
			t.Fatal("build-only driver lost its actual linked SDK/AMD64 executable", err)
		}
	}
}

func x86PackedIntegerCompareOriginalWideSources() (string, string, string) {
	rows := x86PackedIntegerCompareCases("amd64")
	declaration, assembly, _ := x86PackedIntegerCompareRuntimeFixture(rows)
	var checks strings.Builder
	for index, row := range rows {
		maskResult := !row.legacy && strings.Contains(row.operands, "K")
		fmt.Fprintf(&checks, "    checkWide(t,compare%d,%q,%d,%d,%t,%t,%t,%t,%t,%t,%t,%d,%d,%d)\n",
			index, fmt.Sprintf("compare%d", index), row.width, row.bits/8, strings.Contains(row.op, "GT"), row.legacy, row.mmx,
			maskResult, row.mask, row.memory, row.broadcast, row.first, row.second, row.destination)
	}
	tests := `package oracle

import (
    "encoding/binary"
    "testing"
    "unsafe"
)

func wideLane(p []byte, bytes int) uint64 {
    var result uint64
    for j := 0; j < bytes; j++ { result |= uint64(p[j]) << uint(8*j) }
    return result
}

func checkWide(t *testing.T,fn func(*byte,*byte,*byte,uint64,uint32,uint64),name string,
               width,bytes int,greater,legacy,mmx,maskResult,masked,memory,broadcast bool,
               firstBank,secondBank,destination int) {
    t.Helper()
    masks := [4]uint64{0,1,0x55aa55aa55aa55aa,^uint64(0)}
    for round := 0; round < 12; round++ {
        for _,mask := range masks {
            var aStorage,bStorage [96]byte
            aOffset := int((16-uintptr(unsafe.Pointer(&aStorage[0]))%16)%16)
            bOffset := int((16-uintptr(unsafe.Pointer(&bStorage[0]))%16)%16)
            for i := range aStorage { aStorage[i],bStorage[i] = 0xa7,0xb9 }
            a,b := aStorage[aOffset:aOffset+64],bStorage[bOffset:bOffset+64]
            for i := range a { a[i],b[i] = byte(i*17+round*31),byte(i*23+round*53) }
            if round < 4 {
                patterns := [4][2]byte{{0xff,1},{0x80,0x7f},{1,0},{0,0xff}}
                for i := range a { a[i],b[i] = patterns[round][0],patterns[round][1] }
            }
            originalA,originalB := aStorage,bStorage
            var out [424]byte
            for i := range out { out[i] = 0xc3 }
            csr := uint32(0x1f80 | (round%4)<<13 | round)
            expectedFlags := uint64(0x895)
            if mask&3 == 0 { expectedFlags = 0 }
            if mask&3 == 1 { expectedFlags = 0x55 }
            fn(&out[1],&a[0],&b[0],mask,csr,2|expectedFlags)
            if binary.LittleEndian.Uint64(out[409:417])&0x8d5 != expectedFlags || out[417] != byte(2|(expectedFlags&0xd5)) ||
               binary.LittleEndian.Uint32(out[418:422]) != csr || out[0] != 0xc3 ||
               out[422] != 0xc3 || out[423] != 0xc3 || originalA != aStorage || originalB != bStorage {
                t.Fatalf("%s flags/CSR/full input/output canaries: %x",name,out)
            }
            var expected [3][64]byte
            copy(expected[0][:],a)
            copy(expected[1][:],b)
            copy(expected[2][:],b)
            first,second := a,b
            if !memory && firstBank != 0 { first = b }
            if secondBank == 0 { second = a }
            var result [64]byte
            var resultMask uint64
            for i := 0; i < width; i += bytes {
                offset := i
                if broadcast { offset = 0 }
                left,right := wideLane(first[offset:],bytes),wideLane(second[i:],bytes)
                selected := left == right
                if greater {
                    sign := uint64(1) << uint(bytes*8-1)
                    selected = (right^sign) > (left^sign)
                }
                if selected {
                    for j := 0; j < bytes; j++ { result[i+j] = 0xff }
                    if !masked || (mask>>uint(i/bytes))&1 != 0 { resultMask |= uint64(1)<<uint(i/bytes) }
                }
            }
            if !maskResult && !mmx {
                copy(expected[destination][:width],result[:width])
                if !legacy { for i := width; i < 64; i++ { expected[destination][i] = 0 } }
            }
            for bank := 0; bank < 3; bank++ {
                for view := 0; view < 3; view++ {
                    offset,length := bank*112,16
                    if view == 1 { offset,length = offset+16,32 }
                    if view == 2 { offset,length = offset+48,64 }
                    for i := 0; i < length; i++ {
                        if out[1+offset+i] != expected[bank][i] {
                            t.Fatalf("%s round%d mask%x bank%d view%d byte%d",name,round,mask,bank,view,i)
                        }
                    }
                }
            }
            for k := 0; k < 8; k++ {
                want := mask
                if maskResult && k == destination { want = resultMask }
                if binary.LittleEndian.Uint64(out[337+k*8:345+k*8]) != want { t.Fatalf("%s K%d",name,k) }
            }
            for i := 0; i < 8; i++ {
                want := byte(0)
                if mmx { want = result[i] }
                if out[401+i] != want { t.Fatalf("%s MMX result",name) }
            }
        }
    }
}

func TestOriginalWideCompare(t *testing.T) {
` + checks.String() + "}\n"
	return "package oracle\n" + declaration, assembly, tests
}

func TestX86PackedIntegerCompareOriginalWideNativeDriverBuildOnly(t *testing.T) {
	declaration, assembly, tests := x86PackedIntegerCompareOriginalWideSources()
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", assembly)
	x86PackedIntegerCompareOriginalGoDriver(t, declaration, assembly, tests, true)
	t.Log("original wide Go driver was actually linked but not executed; required Linux native ISA counterpart remains independent")
}

func TestCrossLinuxRuntimeMatrixX86PackedIntegerCompareOriginalGoSSEAndMMXBits(t *testing.T) {
	x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, checks strings.Builder
	declarations.WriteString("package oracle\n")
	count := 0
	for _, row := range x86PackedIntegerCompareCases("amd64") {
		if !row.legacy {
			continue
		}
		name := fmt.Sprintf("original%d", count)
		count++
		fmt.Fprintf(&declarations, "func %s(a,b *byte,out *[32]byte,csr uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-28\nSTMXCSR saved-4(SP)\nLDMXCSR csr+24(FP)\nMOVQ a+0(FP),BX\nMOVQ b+8(FP),CX\nMOVQ out+16(FP),DI\n", name)
		if row.mmx {
			assembly.WriteString("MOVQ (BX),M0\nMOVQ (CX),M1\n")
		} else {
			assembly.WriteString("MOVOU (BX),X0\nMOVOU (CX),X1\n")
		}
		assembly.WriteString("MOVL $0x7fffffff,SI\nADDL $1,SI\nSTC\n")
		fmt.Fprintf(&assembly, "%s %s\n", row.op, row.operands)
		if row.mmx {
			assembly.WriteString("MOVQ M1,0(DI)\nEMMS\n")
		} else {
			fmt.Fprintf(&assembly, "MOVOU X%d,0(DI)\n", row.destination)
		}
		assembly.WriteString("PUSHFQ\nPOPQ DX\nMOVQ DX,16(DI)\nLAHF\nMOVB AH,24(DI)\nSTMXCSR 25(DI)\nLDMXCSR saved-4(SP)\nRET\n")
		fmt.Fprintf(&checks, "\n    check(t,%s,%q,%d,%d,%t,%d,%d,%t)\n", name, name, row.width, row.bits/8, strings.Contains(row.op, "GT"), row.first, row.second, row.memory)
	}
	x86LEAActualTargetGoObject(t, "amd64", testTargetTriple("linux", "amd64"), assembly.String())
	tests := `package oracle

import (
    "encoding/binary"
    "testing"
    "unsafe"
)

func value(p []byte, bytes int) uint64 {
    var result uint64
    for j := 0; j < bytes; j++ {
        result |= uint64(p[j]) << uint(8*j)
    }
    return result
}

func check(t *testing.T, fn func(*byte,*byte,*[32]byte,uint32), name string,
           width, bytes int, greater bool, firstBank, secondBank int, memory bool) {
    t.Helper()
    for round := 0; round < 12; round++ {
        var aStorage, bStorage [96]byte
        aOffset := int((16-uintptr(unsafe.Pointer(&aStorage[0]))%16)%16)
        bOffset := int((16-uintptr(unsafe.Pointer(&bStorage[0]))%16)%16)
        for i := range aStorage {
            aStorage[i] = 0xa7
            bStorage[i] = 0xb9
        }
        a, b := aStorage[aOffset:aOffset+64], bStorage[bOffset:bOffset+64]
        for i := range a {
            a[i] = byte(i*17+round*31)
            b[i] = byte(i*23+round*53)
        }
        if round < 4 {
            patterns := [4][2]byte{{0xff,1},{0x80,0x7f},{1,0},{0,0xff}}
            for i := range a {
                a[i],b[i] = patterns[round][0],patterns[round][1]
            }
        }
        originalA, originalB := aStorage, bStorage
        var out [32]byte
        for i := range out { out[i] = 0xc3 }
        csr := uint32(0x1f80 | (round%4)<<13 | round)
        fn(&a[0],&b[0],&out,csr)
        if binary.LittleEndian.Uint64(out[16:24])&0x8d5 != 0x895 ||
           out[24] != 0x97 || binary.LittleEndian.Uint32(out[25:29]) != csr ||
           out[29] != 0xc3 || out[30] != 0xc3 || out[31] != 0xc3 ||
           originalA != aStorage || originalB != bStorage {
            t.Fatalf("%s flags/CSR/whole-input/canary mismatch: %x",name,out)
        }
        first,second := a,b
        if !memory && firstBank != 0 { first = b }
        if secondBank == 0 { second = a }
        for i := 0; i < width; i += bytes {
            left,right := value(first[i:],bytes),value(second[i:],bytes)
            selected := left == right
            if greater {
                sign := uint64(1) << uint(bytes*8-1)
                selected = (right^sign) > (left^sign)
            }
            want := byte(0)
            if selected { want = 0xff }
            for j := 0; j < bytes; j++ {
                if out[i+j] != want {
                    t.Fatalf("%s round%d byte%d got%x want%x",name,round,i+j,out[i+j],want)
                }
            }
        }
        for i := width; i < 16; i++ {
            if out[i] != 0xc3 { t.Fatalf("%s narrow write changed canary",name) }
        }
    }
}

func TestOriginalCompare(t *testing.T) {
` + checks.String() + "}\n"
	x86PackedIntegerCompareRunOriginalGo(t, declarations.String(), assembly.String(), tests)
	t.Logf("%d actual original Go SSE/MMX kernels ×12 initialized numerical/6flag/LAHF/MXCSR/full-buffer cases; MMX bit results do not certify x87 native state", count)
}
