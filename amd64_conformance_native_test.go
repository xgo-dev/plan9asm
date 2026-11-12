package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// The same complete first-party original Go/ASM bytes are compiled under the
// actual selected driver. This program is executed only after the mandatory
// native AVX512 preflight; the historical NativeGo test never called this TEXT.
func amd64ConformanceOriginalWideGo(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("original wide conformance requires its actual native Linux AMD64 counterpart")
	}
	dir := amd64ConformanceOriginalWidePackage(t)
	command := exec.Command("go", "test", "-p=2", "-count=1", "-run", "^TestOriginal(SameWidthPackedConversion|PackedFloatMoveMasks)$", "-v", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOARCH=amd64", "GOOS=linux")
	t.Logf("actual original Go full-source wide conformance: %s", x86FloatCompareCaptureCommand(t, command))
}

func amd64ConformanceOriginalWidePackage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"conformance.go", "conformance_amd64.s"} {
		contents, err := os.ReadFile(filepath.Join("testdata", "conformance", "amd64", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, source := range map[string]string{
		"go.mod":       "module nativewideconformance\n\ngo 1.20\n",
		"wide_test.go": amd64ConformanceOriginalWideTest,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestAMD64ConformanceOriginalWideSourceCompiles(t *testing.T) {
	dir := amd64ConformanceOriginalWidePackage(t)
	command := exec.Command("go", "test", "-p=2", "-c", "-o", filepath.Join(dir, "wide"), ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOARCH=amd64", "GOOS=linux")
	x86FloatCompareCaptureCommand(t, command)
	t.Log("complete original Go/ASM and new original wide oracle compile for Linux AMD64; object is not executed on this portable axis")
}

const amd64ConformanceOriginalWideTest = `package amd64conformance

import (
    "encoding/binary"
    "math"
    "testing"
    "unsafe"
)

func TestOriginalPackedFloatMoveMasks(t *testing.T) {
    aligned := func(size, phase int) ([]byte, []byte, int) {
        storage := make([]byte, size+128)
        for i := range storage {
            storage[i] = 0xa7
        }
        base := uintptr(unsafe.Pointer(&storage[0]))
        offset := int((64-base%64)%64) + phase
        return storage, storage[offset:offset+size], offset
    }
    _, src, _ := aligned(64, 0)
    _, old, _ := aligned(64, 0)
    storage, out, offset := aligned(688, 16)
    for i := range src {
        src[i] = byte(3 + 17*i)
        old[i] = byte(0xf0 - 3*i)
    }
    packedFloatMoveMaskSemantics((*[688]byte)(out), (*[64]byte)(src), (*[64]byte)(old))

    forms := []struct { offset, width, lane int; zero bool }{
        {0,16,4,false}, {16,16,4,true}, {32,16,4,false}, {48,16,4,false},
        {64,16,8,false}, {80,16,8,true}, {96,16,8,false},
        {112,32,4,false}, {144,32,4,true}, {176,32,4,false},
        {208,32,8,false}, {240,32,8,true}, {272,32,8,false},
        {304,64,4,false}, {368,64,4,true}, {432,64,4,false},
        {496,64,8,false}, {560,64,8,true}, {624,64,8,false},
    }
    for _, form := range forms {
        for i := 0; i < form.width; i++ {
            want := old[i]
            if (0xa55a >> (i / form.lane)) & 1 != 0 {
                want = src[i]
            } else if form.zero {
                want = 0
            }
            if got := out[form.offset+i]; got != want {
                t.Fatalf("original move offset=%d byte=%d: got=%02x want=%02x", form.offset, i, got, want)
            }
        }
    }
    for i, value := range storage {
        if (i < offset || i >= offset+len(out)) && value != 0xa7 {
            t.Fatalf("original move output canary changed at %d", i)
        }
    }
}

func TestOriginalSameWidthPackedConversion(t *testing.T) {
    var ints [16]int32
    floats := [16]float32{
        1.5,-1.5,2.75,-2.75,0.5,-0.5,3.25,-3.25,
        4.5,-4.5,5.75,-5.75,6.5,-6.5,7.25,-7.25,
    }
    var squares32 [16]float32
    var squares64 [8]float64
    for i:=0;i<16;i++ {
        ints[i]=int32(i-8)
        squares32[i]=float32((i+1)*(i+1))
    }
    for i:=0;i<8;i++ {
        squares64[i]=float64((i+1)*(i+1))
    }
    nearest := [16]int32{2,-2,3,-3,0,0,3,-3,4,-4,6,-6,6,-6,7,-7}
    truncated := [16]int32{1,-1,2,-2,0,0,3,-3,4,-4,5,-5,6,-6,7,-7}
    down := [16]int32{1,-2,2,-3,0,-1,3,-4,4,-5,5,-6,6,-7,7,-8}
    up := [16]int32{2,-1,3,-2,1,0,4,-3,5,-4,6,-5,7,-6,8,-7}
    var guarded [578]byte
    guarded[0],guarded[577]=0xa7,0xb9
    output:=guarded[1:577]
    sameWidthPackedConversionSemantics((*[576]byte)(output),&ints,&floats,&squares32,&squares64)
    if guarded[0]!=0xa7 || guarded[577]!=0xb9 {
        t.Fatal("original wide conversion output canary changed")
    }
    single := func(offset int) float32 {
        return math.Float32frombits(binary.LittleEndian.Uint32(output[offset:]))
    }
    integer := func(offset int) int32 {
        return int32(binary.LittleEndian.Uint32(output[offset:]))
    }
    for i:=0;i<16;i++ {
        if single(4*i)!=float32(ints[i]) || integer(64+4*i)!=nearest[i] ||
            integer(128+4*i)!=truncated[i] || single(192+4*i)!=float32(i+1) ||
            integer(320+4*i)!=nearest[i] || integer(384+4*i)!=down[i] ||
            integer(448+4*i)!=up[i] || integer(512+4*i)!=truncated[i] {
            t.Fatalf("original wide conversion lane %d output=%x",i,output)
        }
    }
    for i:=0;i<8;i++ {
        value:=math.Float64frombits(binary.LittleEndian.Uint64(output[256+8*i:]))
        if value!=float64(i+1) {
            t.Fatalf("original wide sqrt lane %d value=%v",i,value)
        }
    }
}
`
