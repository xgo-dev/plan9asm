package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalConversionOperations() []string {
	var operations []string
	seen := make(map[string]bool)
	for _, row := range append(x86PackedConversionOracleRows("amd64"), x86SignedPackedFloatRows("amd64")...) {
		// Keep the complete independent register/mask/rounding inventory and
		// one private address representative. Physical MMX stays unbound.
		if strings.Contains(row, "M0") || strings.Contains(row, "M7") {
			continue
		}
		_, operands, _ := strings.Cut(row, " ")
		source, _, _ := strings.Cut(operands, ",")
		if source == "(AX)" || source == "3(AX)" {
			row = strings.Replace(row, source, "64(BP)", 1)
		} else if strings.Contains(row, "(") || strings.Contains(row, " 256,") {
			continue
		}
		if !seen[row] {
			seen[row] = true
			operations = append(operations, row)
		}
	}
	return operations
}

func fixedLocalConversionOperation(row string) string {
	// Every source and merge byte is independently numerical, including
	// legacy upper aliases. Conversion output is then observed by a store.
	prefix := "KMOVQ AX,K1\nKMOVQ AX,K3\nKMOVQ AX,K7\n"
	for _, index := range []int{0, 7, 15, 20, 21, 31} {
		prefix += fmt.Sprintf("VMOVDQU64 64(BP),Z%d\n", index)
	}
	parts := strings.Split(row, ",")
	destination := strings.TrimSpace(parts[len(parts)-1])
	return prefix + row + "\nVMOVDQU64 Z" + destination[1:] + ",128(BP)"
}

func TestGoAMD64FixedLocalConversionCompleteFamilyProof(t *testing.T) {
	var original strings.Builder
	names := make(map[string]bool)
	for index, row := range fixedLocalConversionOperations() {
		t.Run(row, func(t *testing.T) {
			op := strings.Fields(row)[0]
			name, _, _ := strings.Cut(op, ".")
			names[name] = true
			operation := fixedLocalConversionOperation(row)
			pkg, _, file, options := fixedLocalPackedFixture(t, operation)
			assembly := fixedLocalPackedAssembly(operation)
			original.WriteString(strings.Replace(assembly, "·Value", fmt.Sprintf("·Value%d", index), 1))
			if strings.Contains(row, "(BP)") && !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
				t.Error("native conversion memory did not request a complete original frame binding")
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); err != nil {
				t.Fatalf("initialized private conversion rejected: %v", err)
			}
		})
	}
	if len(names) != 42 {
		t.Fatalf("complete independent conversion namespace = %d, want 42", len(names))
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalConversionWholeSourceNegatives(t *testing.T) {
	operation := "VCVTDQ2PD 64(BP),Y0\nVMOVDQU Y0,128(BP)"
	pkg, _, _, options := fixedLocalPackedFixture(t, operation)
	original := fixedLocalPackedAssembly(operation)
	for name, source := range map[string]string{
		"input hole":                strings.Replace(original, "MOVQ AX,64(BP)", "MOVB AX,64(BP)", 1),
		"outside frame":             strings.Replace(original, "VCVTDQ2PD 64(BP)", "VCVTDQ2PD 256(BP)", 1),
		"incoming pointer":          strings.Replace(original, "MOVQ SP,BP", "MOVQ AX,BP", 1),
		"unknown mask":              strings.Replace(original, "64(BP),Y0", "64(BP),K1,Y0", 1),
		"unknown merge":             strings.Replace(original, operation, "KMOVQ AX,K1\nVCVTDQ2PD 64(BP),K1,Y0\nVMOVDQU Y0,128(BP)", 1),
		"zero mask missing storage": strings.Replace(original, operation, "MOVQ $0,DX\nKMOVQ DX,K1\nVCVTDQ2PD.Z 256(BP),K1,Y0\nVMOVDQU Y0,128(BP)", 1),
		"unknown source vector":     strings.Replace(original, "VCVTDQ2PD 64(BP)", "VCVTDQ2PD X0", 1),
		"legacy m128 alignment":     strings.Replace(original, operation, "CVTPL2PS 65(BP),X0\nMOVOU X0,128(BP)", 1),
		"MMX input":                 strings.Replace(original, operation, "CVTPL2PD M0,X0\nMOVOU X0,128(BP)", 1),
		"MMX output":                strings.Replace(original, operation, "CVTPS2PL X0,M0", 1),
		"private escape":            strings.Replace(original, "MOVQ AX,ret+8(FP)", "MOVQ BP,ret+8(FP)", 1),
	} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unclosed native conversion accepted: %v", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalConversionSparseByteEffects(t *testing.T) {
	// Independent representatives of every width, alias and mask rule. The
	// complete family test separately binds all encoder forms to these rules.
	for _, row := range []struct {
		instruction        string
		input, active      int
		legacy, mask, zero bool
	}{
		{"CVTPL2PD X0,X1", 8, 16, true, false, false},
		{"CVTPS2PL X0,X1", 16, 16, true, false, false},
		{"CVTPD2PL X0,X1", 16, 8, true, false, false},
		{"VCVTDQ2PD X0,Y1", 16, 32, false, false, false},
		{"VCVTPD2DQY Y0,X1", 32, 16, false, false, false},
		{"VCVTPD2DQ Z0,Y1", 64, 32, false, false, false},
		{"VCVTPS2QQ X0,Y1", 16, 32, false, false, false},
		{"VCVTQQ2PSY Y0,X1", 32, 16, false, false, false},
		{"VCVTPS2DQ.Z X0,K1,X1", 16, 16, false, true, true},
		{"VCVTPS2DQ X0,K1,X1", 16, 16, false, true, false},
		{"VCVTPD2DQX X0,K1,X1", 16, 8, false, true, false},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT value(SB),4,$0-0\n"+row.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			source := x86CallerVectorRoot(ins.Args[0].Reg)
			destination := x86CallerVectorRoot(ins.Args[len(ins.Args)-1].Reg)
			fresh := func() x86FixedLocalState {
				return x86FixedLocalState{
					vectors: map[Reg]uint64{source: ^uint64(0), destination: ^uint64(0)},
					masks:   map[Reg]bool{"K1": true},
					flags:   x86ByteFlagsAll,
				}
			}
			check := func(state *x86FixedLocalState, accepted bool) {
				t.Helper()
				known, err := fixedLocalConversionStep(&ins, state, &x86FixedLocalProof{}, 0)
				if !known || accepted && err != nil || !accepted && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("conversion effect accepted=%t: known=%t, %v", accepted, known, err)
				}
			}
			for missing := 0; missing < 64; missing++ {
				state := fresh()
				state.vectors[source] &^= uint64(1) << uint(missing)
				check(&state, missing >= row.input)
			}
			for missing := 0; missing < 64; missing++ {
				state := fresh()
				state.vectors[destination] &^= uint64(1) << uint(missing)
				accepted := !row.mask || row.zero || missing >= row.active
				check(&state, accepted)
				if !accepted {
					continue
				}
				want := ^uint64(0)
				if row.legacy && missing >= 16 {
					want &^= uint64(1) << uint(missing)
				}
				if state.vectors[destination] != want || state.flags != x86ByteFlagsAll {
					t.Fatalf("byte %d: alias/zero padding/FLAGS changed: %+v", missing, state)
				}
			}
			if row.mask {
				state := fresh()
				state.masks["K1"] = false
				check(&state, false)
			}
		})
	}
}

func TestGoAMD64FixedLocalConversionExactMemoryTuples(t *testing.T) {
	for _, row := range []struct {
		instruction string
		width       int
		aligned     bool
	}{
		{"CVTPL2PD (BP),X1", 8, false},
		{"CVTPL2PS (BP),X1", 16, true},
		{"CVTPS2PL (BP),X1", 16, true},
		{"CVTPD2PL (BP),X1", 16, true},
		{"VCVTDQ2PD (BP),X1", 8, false},
		{"VCVTDQ2PD (BP),Y1", 16, false},
		{"VCVTDQ2PD (BP),Z1", 32, false},
		{"VCVTDQ2PS (BP),Z1", 64, false},
		{"VCVTDQ2PD.BCST.Z (BP),K1,Z1", 4, false},
		{"VCVTPD2DQX (BP),X1", 16, false},
		{"VCVTPD2DQY (BP),X1", 32, false},
		{"VCVTPD2DQ (BP),Y1", 64, false},
		{"VCVTPS2QQ.BCST.Z (BP),K1,Z1", 4, false},
		{"VCVTUQQ2PS.BCST.Z (BP),K1,Y1", 8, false},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT value(SB),4,$128-0\n"+row.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			original := file.Funcs[0].Instrs[1]
			destination := x86CallerVectorRoot(original.Args[len(original.Args)-1].Reg)
			check := func(missing, offset int, accepted bool) {
				t.Helper()
				ins := original
				state := x86FixedLocalState{
					pointers: map[Reg]int64{BP: int64(offset)},
					vectors:  map[Reg]uint64{destination: ^uint64(0)},
					masks:    map[Reg]bool{"K1": true},
					bytes:    newFixedLocalByteSet(128),
				}
				for index := 0; index < 128; index++ {
					state.bytes.set(int64(index), index != missing)
				}
				proof := &x86FixedLocalProof{frame: 128}
				known, err := fixedLocalConversionStep(&ins, &state, proof, 0)
				if !known || accepted && err != nil || !accepted && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("byte=%d offset=%d accepted=%t: known=%t, %v", missing, offset, accepted, known, err)
				}
				if accepted {
					access := ins.x86FixedLocalMemory[0]
					if access.owner != proof || access.width != int64(row.width) || access.write || state.flags != 0 {
						t.Fatal("wrong native memory tuple, write permission or invented FLAGS", access)
					}
				}
				if missing >= 0 && state.bytes.has(int64(missing)) {
					t.Fatal("conversion manufactured initialized memory")
				}
			}
			for missing := 0; missing < 128; missing++ {
				check(missing, 0, missing >= row.width)
			}
			check(-1, 1, !row.aligned)
			check(-1, 129-row.width, false)
		})
	}
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch00(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 0)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch01(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 1)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch02(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 2)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch03(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 3)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch04(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 4)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch05(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 5)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch06(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 6)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch07(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 7)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch08(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 8)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch09(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 9)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch10(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 10)
}

func TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch11(t *testing.T) {
	fixedLocalConversionActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu", 11)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch00(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 0)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch01(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 1)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch02(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 2)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch03(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 3)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch04(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 4)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch05(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 5)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch06(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 6)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch07(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 7)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch08(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 8)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch09(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 9)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch10(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 10)
}

func TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch11(t *testing.T) {
	fixedLocalConversionActualObjects(t, "darwin/amd64", "x86_64-apple-darwin", 11)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch00(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 0)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch01(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 1)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch02(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 2)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch03(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 3)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch04(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 4)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch05(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 5)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch06(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 6)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch07(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 7)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch08(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 8)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch09(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 9)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch10(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 10)
}

func TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch11(t *testing.T) {
	fixedLocalConversionActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc", 11)
}

func fixedLocalObjectBatchRange(total, batch int) (start, end int, ok bool) {
	const size = 64
	if total <= 0 || batch < 0 || batch >= (total+size-1)/size {
		return 0, 0, false
	}
	start, end = batch*size, (batch+1)*size
	if end > total {
		end = total
	}
	return start, end, true
}

func TestGoAMD64FixedLocalConversionObjectBatchPlan(t *testing.T) {
	rows := fixedLocalConversionOperations()
	if len(rows) != 741 {
		t.Fatal("complete independent conversion inventory changed", len(rows))
	}
	seen := make([]int, len(rows))
	for batch := 0; batch < 12; batch++ {
		start, end, ok := fixedLocalObjectBatchRange(len(rows), batch)
		if !ok || end-start > 64 || end <= start {
			t.Fatal("invalid independent conversion batch", batch, start, end, ok)
		}
		for index := start; index < end; index++ {
			seen[index]++
		}
	}
	// Scheduling remains twelve complete batches. Independent source captures
	// cover those same 741 functions exactly once in bounded 32-function units.
	chunks, sourceSeen := 0, make([]int, len(rows))
	for batch := 0; batch < 12; batch++ {
		start, end, _ := fixedLocalObjectBatchRange(len(rows), batch)
		for chunk := start; chunk < end; chunk += 32 {
			limit := fixedLocalConversionSourceEnd(chunk, end)
			if limit <= chunk || limit > end || limit-chunk > 32 {
				t.Fatal("invalid independently captured conversion source", chunk, limit, end)
			}
			for index := chunk; index < limit; index++ {
				sourceSeen[index]++
			}
			chunks++
		}
	}
	if chunks != 24 {
		t.Fatal("complete conversion source plan changed", chunks)
	}
	for index, count := range seen {
		if count != 1 || sourceSeen[index] != 1 {
			t.Fatal("missing or duplicated original conversion form", index, rows[index], count)
		}
	}
	for _, input := range [][2]int{{0, 0}, {741, -1}, {741, 12}} {
		if _, _, ok := fixedLocalObjectBatchRange(input[0], input[1]); ok {
			t.Fatal("invalid conversion batch accepted", input)
		}
	}
}

func fixedLocalConversionSourceEnd(start, end int) int {
	if end-start > 32 {
		return start + 32
	}
	return end
}

func fixedLocalConversionActualObjects(t *testing.T, target, triple string, batch int) {
	t.Helper()
	// Go 1.27 builds objdump into GOCACHE. Reuse this batch's test-owned
	// compiler cache, not its independent source, object or lifetime records.
	t.Setenv("GOCACHE", t.TempDir())
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	rows := fixedLocalConversionOperations()
	start, end, ok := fixedLocalObjectBatchRange(len(rows), batch)
	if !ok {
		t.Fatal("invalid complete conversion object batch", batch, len(rows))
	}
	// Keep the twelve complete scheduling owners, but give each independent
	// source proof at most 32 functions within its unchanged five-minute lease.
	for chunk := start; chunk < end; chunk += 32 {
		limit := fixedLocalConversionSourceEnd(chunk, end)
		t.Run(fmt.Sprintf("batch%d/source%d", batch, (chunk-start)/32), func(t *testing.T) {
			var assembly, declarations strings.Builder
			var names []string
			for index := chunk; index < limit; index++ {
				name := fmt.Sprintf("Value%d", index)
				body := fixedLocalPackedAssembly(fixedLocalConversionOperation(rows[index]))
				assembly.WriteString(strings.Replace(body, "·Value", "·"+name, 1))
				fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
				names = append(names, "example.invalid/framefixture."+name)
			}
			pkg, request, _, options := x86CMOVFixedLocalFixture(t,
				assembly.String(), declarations.String(), target, triple)
			fixedLocalConversionPrepareToolCache(t, request)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(ir, "fixed_local_native") || !strings.Contains(ir, "asm sideeffect") {
					t.Fatal("conversion did not consume native private backing")
				}
				for _, optimize := range []bool{false, true} {
					input := ir
					if optimize {
						input = x86MulDivRoundOptimize(t, ir)
					}
					x86CompactExpandRequireAllDefinitions(t, input, names)
					compileLLVMToObject(t, llc, triple, "frame-conversion.ll", "frame-conversion.o", input)
				}
			})
		})
	}
	t.Logf("%s batch%d: %d/%d forms, three LLVM APIs, O0/O2", target, batch, end-start, len(rows))
}

func TestGoAMD64FixedLocalConversionSharedCacheKeepsSourcesIndependent(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("GOCACHE", cache)
	for _, key := range []string{"GOPATH", "GOMODCACHE", "TMPDIR", "GOTMPDIR"} {
		t.Setenv(key, "")
	}
	const assembly = "TEXT ·Value(SB),4,$0-16\nMOVQ a+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
	first, a, _, _ := x86CMOVFixedLocalFixture(t, assembly, "func Value(a uint64) uint64",
		"linux/amd64", "x86_64-unknown-linux-gnu")
	second, b, _, _ := x86CMOVFixedLocalFixture(t, assembly, "func Value(a uint64) uint64",
		"linux/amd64", "x86_64-unknown-linux-gnu")
	values := func(request GoAMD64FrameCaptureRequest) map[string]string {
		environment := make(map[string]string)
		for _, entry := range request.Environment {
			key, value, _ := strings.Cut(entry, "=")
			environment[key] = value
		}
		return environment
	}
	left, right := values(a), values(b)
	if left["GOCACHE"] != cache || right["GOCACHE"] != cache {
		t.Fatal("batch fixtures did not inherit their parent's owned build cache")
	}
	for _, key := range []string{"GOPATH", "GOMODCACHE", "TMPDIR", "GOTMPDIR"} {
		if left[key] == "" || left[key] == right[key] || left[key] == cache || right[key] == cache {
			t.Fatal("independent source observations shared private state", key)
		}
	}
	if a.Directory == b.Directory || first.Types == second.Types {
		t.Fatal("sharing compiler artifacts reused an original source or typed package")
	}
}
