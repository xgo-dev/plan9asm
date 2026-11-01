package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The old runtime fixture observed i8/i16 slots with MOVD while its C reference
// read only one/two bytes. Keep the original source and establish its real Go
// eight-byte reads before changing any fixture or reference.
func TestARM64FPPairOriginalGoScalarObservation(t *testing.T) {
	arm64FPPairGoScalarObservation(t, true)
}

func TestARM64FPPairCorrectedGoScalarObservation(t *testing.T) {
	arm64FPPairGoScalarObservation(t, false)
}

func arm64FPPairGoScalarObservation(t *testing.T, originalWideObservation bool) {
	t.Helper()
	_, triple, _, runner := arm64FPPairRuntimeTools(t)
	_, _, source, _ := arm64FPPairFamilyRuntimeWithObservation(t, triple, originalWideObservation)
	var assembly, declarations, calls strings.Builder
	for _, op := range []string{"stp", "stpw"} {
		for _, width := range []int{1, 2} {
			name := fmt.Sprintf("%s_scalar%d", op, width*8)
			start := strings.Index(source, "TEXT "+name+"(SB)")
			if start < 0 {
				t.Fatalf("original fixture %s missing", name)
			}
			body := source[start:]
			if end := strings.Index(body[1:], "TEXT "); end >= 0 {
				body = body[:end+1]
			}
			count := 24 / width
			move := map[int]string{1: "MOVBU", 2: "MOVHU"}[width]
			if originalWideObservation {
				move = "MOVD"
			}
			for i := 0; i < count; i++ {
				read := fmt.Sprintf("%s frame+%d(FP), R5\n", move, i*width)
				if !strings.Contains(body, read) {
					t.Fatalf("%s no longer has its %s observation %d", name, move, i)
				}
			}
			assembly.WriteString(strings.Replace(body, "TEXT "+name, "TEXT ·"+name, 1))
			fmt.Fprintf(&declarations, "func %s(", name)
			for i := 0; i < count; i++ {
				fmt.Fprintf(&declarations, "a%d uint%d, ", i, width*8)
			}
			fmt.Fprintf(&declarations, "left, right uint64, out *[%d]uint64)\n", count)
			fmt.Fprintf(&calls, "\tcheck(%q, %d, %d, func(values []uint64, left, right uint64) []uint64 {\n", name, width, map[string]int{"stp": 8, "stpw": 4}[op])
			fmt.Fprintf(&calls, "\t\tvar observed struct { before uint64; data [%d]uint64; after uint64 }\n", count)
			calls.WriteString("\t\tobserved.before = sentinel\n\t\tobserved.after = sentinel\n")
			fmt.Fprintf(&calls, "\t\t%s(\n", name)
			for i := 0; i < count; i++ {
				fmt.Fprintf(&calls, "\t\t\tuint%d(values[%d]),\n", width*8, i)
			}
			calls.WriteString("\t\t\tleft, right, &observed.data,\n\t\t)\n")
			calls.WriteString("\t\tif observed.before != sentinel || observed.after != sentinel {\n\t\t\tpanic(\"original pair canary changed\")\n\t\t}\n\t\treturn observed.data[:]\n\t})\n")
		}
	}
	program := arm64FPPairOriginalObservationGo + fmt.Sprintf("const wideObservation = %t\n", originalWideObservation) + declarations.String() + "func main() {\n" + calls.String() + `
	if wideObservation {
		if oldReferenceMismatches == 0 {
			panic("original slot-width reference unexpectedly matched MOVD")
		}
		fmt.Fprintf(os.Stderr, "original slot-width reference rejected: %d mismatches; actual MOVD eight-byte results and canaries passed\n", oldReferenceMismatches)
		os.Exit(19)
	}
	if oldReferenceMismatches != 0 {
		panic("corrected byte/half observation disagrees with slot-width reference")
	}
	fmt.Fprintln(os.Stderr, "corrected MOVBU/MOVHU slot-width results and canaries passed")
}
`
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":           "module originalfppairobservation\n\ngo 1.20\n",
		"main.go":          program,
		"original_arm64.s": assembly.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "original-fp-pair")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if runtime.GOARCH != "arm64" {
		command.Env = append(command.Env, "GOOS=linux", "GOARCH=arm64")
	}
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("original Go pair compile failed: %v\n%s", err, output)
	}
	ctx, cancel = runtimeOracleStageContext(t)
	defer cancel()
	if len(runner) == 0 {
		command = exec.CommandContext(ctx, binary)
	} else {
		args := append(append([]string(nil), runner[1:]...), binary)
		command = exec.CommandContext(ctx, runner[0], args...)
	}
	output, err = runtimeOracleCombinedOutput(ctx, command)
	if originalWideObservation {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 19 ||
			!strings.Contains(string(output), "actual MOVD eight-byte results and canaries passed") {
			t.Fatalf("original Go did not establish the stale slot reference: %v\n%s", err, output)
		}
	} else if err != nil || !strings.Contains(string(output), "corrected MOVBU/MOVHU slot-width results and canaries passed") {
		t.Fatalf("corrected Go pair observation failed: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

const arm64FPPairOriginalObservationGo = `package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

const sentinel = uint64(0xd7a91ce458b2630f)
var oldReferenceMismatches int
var samples = [8]uint64{
	0, 1, ^uint64(0), 0x8000000000000000,
	0x7fffffff80000000, 0x800000007fffffff,
	0x0123456789abcdef, 0xfedcba9876543210,
}

func check(name string, width, pairWidth int, call func([]uint64, uint64, uint64) []uint64) {
	count := 24 / width
	for iteration := 0; iteration < len(samples); iteration++ {
		values := make([]uint64, count)
		var frame [48]byte
		for i := range values {
			values[i] = samples[(iteration+i)%len(samples)]
			for b := 0; b < width; b++ {
				frame[i*width+b] = byte(values[i] >> uint(8*b))
			}
		}
		left := samples[(iteration+5)%len(samples)]
		right := samples[(iteration+7)%len(samples)]
		binary.LittleEndian.PutUint64(frame[24:], left)
		binary.LittleEndian.PutUint64(frame[32:], right)
		for b := 0; b < pairWidth; b++ {
			frame[b] = byte(left >> uint(8*b))
			frame[pairWidth+b] = byte(right >> uint(8*b))
		}
		observed := call(values, left, right)
		for i, got := range observed {
			want := binary.LittleEndian.Uint64(frame[i*width:])
			var oldWant uint64
			for b := 0; b < width; b++ {
				oldWant |= uint64(frame[i*width+b]) << uint(8*b)
			}
			if !wideObservation {
				want = oldWant
			}
			if got != want {
				fmt.Fprintf(os.Stderr, "%s iteration=%d slot=%d got=%016x expected read=%016x\n", name, iteration, i, got, want)
				os.Exit(73)
			}
			if got != oldWant {
				oldReferenceMismatches++
			}
		}
	}
}
`
