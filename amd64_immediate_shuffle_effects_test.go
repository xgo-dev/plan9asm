package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86ImmediateShuffleCompleteLegacyOriginalRows(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`\{A(PSHUFW|PSHUFL|PSHUFD|PSHUFHW|PSHUFLW), (\w+), (\w+), opBytes\{([^}]+)\}\}`)
	rows := pattern.FindAllStringSubmatch(string(source), -1)
	if len(rows) != 5 {
		t.Fatalf("complete legacy original shuffle denominator changed: %d", len(rows))
	}
	for _, row := range rows {
		prefix := map[string]string{"PSHUFW": "Pm", "PSHUFL": "Pq", "PSHUFD": "Pq", "PSHUFHW": "Pf3", "PSHUFLW": "Pf2"}[row[1]]
		table := "yxshuf"
		classes := "{Zibm_r,2,argList{Yu8,Yxm,Yxr}},"
		if row[1] == "PSHUFW" {
			table, classes = "ymshuf", "{Zibm_r,2,argList{Yi8,Ymm,Ymr}},"
		}
		definition := regexp.MustCompile(`(?s)var ` + table + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(source))
		if len(definition) != 2 || strings.Join(strings.Fields(definition[1]), "") != classes ||
			row[2] != table || row[3] != prefix || row[4] != "0x70, 00" && row[4] != "0x70, 0" {
			t.Fatal("unmodeled complete legacy prefix/operands/opcode", row)
		}
	}
}

func TestX86ImmediateShuffleByteKnowledgeAndUnaffectedState(t *testing.T) {
	for _, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		widths := []int{16}
		if strings.HasPrefix(op, "V") {
			widths = []int{16, 32, 64}
		}
		for _, width := range widths {
			for _, mode := range []string{"plain", "merge", "zero"} {
				if !strings.HasPrefix(op, "V") && mode != "plain" {
					continue
				}
				for _, alias := range []bool{false, true} {
					for _, immediate := range []int{0, 27, 228, 255} {
						bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
						destination := 1
						if alias {
							destination = 0
						}
						row := op
						if mode == "zero" {
							row += ".Z"
						}
						row += fmt.Sprintf(" $%d,%s0,", immediate, bank)
						if mode != "plain" {
							row += "K1,"
						}
						row += fmt.Sprint(bank, destination)
						t.Run(row, func(t *testing.T) {
							ins := x86YMMReadSource(t, row)
							for seed := 0; seed < 32; seed++ {
								initial := x86SourceStackState{
									bp: x86SourceStackAddress{original: true}, gOriginal: true, numericFlags: true,
									callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}}, known: map[Reg]uint8{AX: 0xff},
									vectors: map[Reg]uint64{"Z0": uint64(seed)*0x1937a73b15d94ca7 ^ 0x31c097642eaf859b,
										"Z1": uint64(seed)*0xf03755e989ab7361 ^ 0xae78f9234cbad619, "Z31": 0x55},
									masks: map[Reg]bool{"K1": true, "K0": false},
								}
								state, want := x86CloneCallerState(initial), x86CloneCallerState(initial)
								var expected uint64
								lane := 4
								if strings.Contains(op, "HW") || strings.Contains(op, "LW") {
									lane = 2
								}
								old := initial.vectors[Reg(fmt.Sprint("Z", destination))]
								for output := 0; output < 64; output++ {
									known := old>>uint(output)&1 != 0
									if output >= width {
										known = strings.HasPrefix(op, "V") || known
									} else {
										at := output
										if lane == 4 {
											at = output/16*16 + (immediate>>(2*(output%16/4))&3)*4 + output%4
										} else if word := output % 16 / 2; word < 4 && strings.Contains(op, "LW") || word >= 4 && strings.Contains(op, "HW") {
											half := 0
											if strings.Contains(op, "HW") {
												half = 8
											}
											at = output/16*16 + half + (immediate>>(2*(word%4))&3)*2 + output%2
										}
										known = initial.vectors["Z0"]>>uint(at)&1 != 0
										if mode == "merge" {
											known = known && old>>uint(output)&1 != 0
										}
									}
									if known {
										expected |= uint64(1) << uint(output)
									}
								}
								want.vectors[Reg(fmt.Sprint("Z", destination))] = expected
								// The independent result observer must consume the same
								// family, not reject it after correct caller/lowering work.
								result := x86ResultState{flags: 0x3f, fp: []bool{true, false}, auto: []bool{false, true}}
								result.gp[0], result.pointerGP[7], result.masks[1] = 0xff, true, true
								for _, index := range []int{0, 1, 31} {
									result.writeVector(index, 64, initial.vectors[Reg(fmt.Sprint("Z", index))], false)
								}
								wantResult := result.clone()
								wantResult.writeVector(destination, 64, expected, false)
								if !x86ResultTransfer(ins, &result, nil, 0, "amd64") || !reflect.DeepEqual(result, wantResult) {
									t.Fatalf("%s seed=%d lost result bytes or unrelated state: got=%+v want=%+v", row, seed, result, wantResult)
								}
								if !x86CallerVectorMoveStep(&ins, &state, nil) || !reflect.DeepEqual(state, want) {
									t.Fatalf("%s seed=%d changed byte dependencies or unrelated state: got=%+v want=%+v", row, seed, state, want)
								}
								state = x86CloneCallerState(initial)
								state.masks["K1"] = false
								before := x86CloneCallerState(state)
								if mode != "plain" && (x86CallerVectorMoveStep(&ins, &state, nil) || !reflect.DeepEqual(state, before)) {
									t.Fatal("unknown mask acquired data or mutated state")
								}
								result.masks[1] = false
								beforeResult := result.clone()
								if mode != "plain" && (x86ResultTransfer(ins, &result, nil, 0, "amd64") || !reflect.DeepEqual(result, beforeResult)) {
									t.Fatal("unknown result mask acquired data or mutated state")
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestX86ImmediateShuffleActualCallerThreeAPIs(t *testing.T) {
	var body strings.Builder
	rows := x86OfficialImmediateShuffleRows(t)
	for _, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW"} {
		rows = append(rows, op+" $255,X0,X1")
	}
	for _, row := range rows {
		destination := strings.Split(row, ",")
		vector := destination[len(destination)-1]
		index := vector[1:]
		fmt.Fprintf(&body, "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z%s\nKMOVQ AX,K1\n%s\nVMOVSS X%s,(DX)\n", index, row, index)
	}
	// Broadcast, full tuple, merge and zeroing use actual caller input regions.
	for _, row := range []string{"VPSHUFD.BCST.Z $255,(DI),K1,Z1", "VPSHUFHW.Z $0,(DI),K1,Z1", "VPSHUFLW $27,(DI),K1,Y1"} {
		fmt.Fprintf(&body, "VMOVUPS (SI),Z1\nKMOVQ AX,K1\n%s\nVMOVSS X1,(DX)\n", row)
	}
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body.String(), 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "immediate-shuffle-text.ll", "immediate-shuffle-text.o", ir)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "immediate-shuffle-module.ll", "immediate-shuffle-module.o", module.String())
			if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
				t.Fatal("actual selected caller failed", err)
			}
		})
	}
}

func TestX86ImmediateShufflePartialSourceActualCaller(t *testing.T) {
	for _, test := range []struct {
		name, body string
		accepted   bool
	}{
		{"only selected dword", "MOVSS (DI),X0\nVPSHUFD $0,X0,Y1", false},
		{"selected low dword", "MOVSS (DI),X2\nMOVSS X2,X0\nVPSHUFD $0,X0,X1", true},
		{"selected unknown dword", "MOVSS (DI),X2\nMOVSS X2,X0\nVPSHUFD $255,X0,X1", false},
		{"unused upper words", "MOVSS (DI),X2\nMOVSS X2,X0\nVPSHUFLW $0,X0,X1", true},
		{"whole unknown vector", "VPSHUFD $0,X0,X1", false},
		{"unknown mask", "VMOVUPS (DI),Z0\nVPSHUFD.Z $0,X0,K1,X1", false},
		{"merge unknown destination", "VMOVUPS (DI),Z0\nKMOVQ AX,K1\nVPSHUFD $0,X0,K1,X1", false},
		{"zeroing no old destination", "VMOVUPS (DI),Z0\nKMOVQ AX,K1\nVPSHUFD.Z $0,X0,K1,X1", true},
		{"legacy alignment unbound", "PSHUFL $0,(DI),X1", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			// The width-mismatch case is a syntax negative, not caller Context.
			if test.name == "only selected dword" {
				goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+test.body+"\nRET\n", "", false)
				if _, known, err := x86ImmediateShuffleProperties(x86YMMReadSource(t, "VPSHUFD $0,X0,Y1"), "amd64"); !known || err == nil {
					t.Fatal("width mismatch acquired shuffle grammar")
				}
				return
			}
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", test.body+"\nVMOVSS X1,(DX)", 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
			if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("partial caller accepted=%v got %v", test.accepted, err)
			}
		})
	}

	ins := x86YMMReadSource(t, "vpshufd $27,X0,X1")
	var output strings.Builder
	ctx := &amd64Ctx{goarch: "amd64", b: &output}
	if known, _, err := ctx.lowerPackedWordShuffle("VPSHUFHW", ins); !known || err == nil || output.Len() != 0 {
		t.Fatal("contradictory dispatch consumed source or emitted IR")
	}
}
