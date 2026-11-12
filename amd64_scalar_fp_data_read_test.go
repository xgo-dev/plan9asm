package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This directory intentionally crosses instruction families. The new input
// is an emitted same-file DATA object, not a CRC-specific opcode exception.
func x86ScalarResultDataReadBodies(arch string) map[string]string {
	bodies := map[string]string{
		"MOVD":      "MOVD table<>+16(SB),X1\n",
		"MOVL":      "MOVL table<>+16(SB),X1\n",
		"MOVQ":      "MOVQ table<>+16(SB),X1\n",
		"VMOVD":     "VMOVD table<>+16(SB),X1\n",
		"VMOVQ":     "VMOVQ table<>+16(SB),X1\n",
		"MOVSS":     "MOVSS table<>+16(SB),X1\n",
		"MOVSD":     "MOVSD table<>+16(SB),X1\n",
		"PXOR":      "PXOR X1,X1\nPXOR table<>+16(SB),X1\n",
		"PAND":      "PXOR X1,X1\nPAND table<>+16(SB),X1\n",
		"PADDB":     "PXOR X1,X1\nPADDB table<>+16(SB),X1\n",
		"PCLMULQDQ": "PXOR X1,X1\nPCLMULQDQ $17,table<>+16(SB),X1\n",
	}
	for _, name := range []string{"MOVOU", "MOVOA", "MOVO", "MOVUPS", "MOVAPS", "MOVUPD", "MOVAPD"} {
		bodies[name] = name + " table<>+16(SB),X1\n"
	}
	for _, pair := range [][2]string{
		{"PSRLW", "VPSRLW"}, {"PSRLL", "VPSRLD"}, {"PSRLQ", "VPSRLQ"},
		{"PSLLW", "VPSLLW"}, {"PSLLL", "VPSLLD"}, {"PSLLQ", "VPSLLQ"},
	} {
		bodies[pair[0]] = "PXOR X1,X1\n" + pair[0] + " table<>+16(SB),X1\n"
		bodies[pair[1]] = "PXOR X0,X0\n" + pair[1] + " table<>+16(SB),X0,X1\n"
	}
	if arch == "amd64" {
		bodies["VPCLMULQDQ"] = "PXOR X0,X0\nVPCLMULQDQ $17,table<>+16(SB),X0,X1\n"
	}
	return bodies
}

const x86ScalarResultDataTable = `DATA table<>+0(SB)/8,$0x0123456789abcdef
DATA table<>+16(SB)/8,$0xfedcba9876543210
DATA table<>+24(SB)/8,$0x1020304050607080
GLOBL table<>(SB),8,$32
`

func TestX86LoweredScalarDataWithoutLocalStorageDoesNotResolve(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, body := range []string{
			"MOVL value+0(FP),AX\nRET\n",
			"MOVOU external(SB),X1\nRET\n",
			"CALL ·callee(SB)\nRET\n",
		} {
			t.Run(arch+"/"+strings.Fields(body)[0], func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT ·view(SB),4,$0-8\n"+body)
				if err != nil {
					t.Fatal(err)
				}
				var calls []string
				resolve := func(symbol string) string {
					calls = append(calls, symbol)
					return strings.TrimPrefix(symbol, "·")
				}
				sigs := map[string]FuncSig{"view": {Name: "view", Ret: Void}, "callee": {Name: "callee", Ret: Void}}
				reads := x86LoweredScalarDataReads(file, resolve, sigs, arch)
				if reads != nil || len(calls) != 0 {
					t.Fatalf("without emitted storage there is no DATA directory or resolver work: reads=%v calls=%v", reads, calls)
				}
			})
		}
	}
}

func TestX86LoweredScalarResultSameFileDataMatrix(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for name, body := range x86ScalarResultDataReadBodies(target.arch) {
			t.Run(target.triple+"/"+name, func(t *testing.T) {
				source := x86ScalarResultDataTable + "TEXT ·view(SB),4,$0-4\n" + body +
					"PEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n"
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", target.arch, target.triple, api)
					if err != nil {
						t.Errorf("%s: emitted same-file DATA did not supply numerical input: %v", api, err)
						continue
					}
					compileLLVMToObject(t, llc, target.triple, "data-read.ll", "data-read.o", ir)
				}
			})
		}
	}
}

func TestX86LoweredScalarResultSameFileDataBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for name, source := range map[string]string{
			"external":        "MOVOU external(SB),X1\n",
			"negative offset": "MOVOU table<>-1(SB),X1\n",
			"beyond end":      "MOVOU table<>+17(SB),X1\n",
			"entirely beyond": "MOVOU table<>+32(SB),X1\n",
			"unknown index":   "MOVOU table<>+0(SB)(AX*1),X1\n",
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				source = x86ScalarResultDataTable + "TEXT ·view(SB),4,$0-4\n" + source +
					"PEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", arch, triple, api); err == nil || name != "unknown index" && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s did not reject missing DATA extent: %v", api, err)
					}
				}
			})
		}
		for _, size := range []int{4, 8, 15, 16} {
			t.Run(fmt.Sprintf("%s/extent-%d", arch, size), func(t *testing.T) {
				// An initialized allocation includes zero-filled holes. Width is
				// still the complete native read, not the selected result lane.
				for _, op := range []string{"MOVOU", "PSRLQ", "PSLLW"} {
					source := fmt.Sprintf("GLOBL table<>(SB),8,$%d\nTEXT ·view(SB),4,$0-4\nPXOR X1,X1\n%s table<>(SB),X1\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n", size, op)
					for _, api := range []string{"text", "module", "Go"} {
						_, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", arch, triple, api)
						if size < 16 && !errors.Is(err, ErrProbeNeedsContext) || size == 16 && err != nil {
							t.Fatalf("%s/%s size=%d: %v", op, api, size, err)
						}
					}
				}
			})
		}
	}
}

func TestX86LoweredScalarResultDataDoesNotGrantStandaloneProof(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for name, body := range x86ScalarResultDataReadBodies(arch) {
			_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() uint32",
				body+"PEXTRD $0,X1,AX\nMOVL AX,ret0+0(FP)\nRET")
			data, err := Parse(ArchAMD64, x86ScalarResultDataTable)
			if err != nil {
				t.Fatal(err)
			}
			file.Data, file.Globl = data.Data, data.Globl
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s/%s standalone query gained emitted storage: %v", arch, name, err)
				}
			}
		}
	}
}

func TestX86LoweredScalarResultDataRelocationRemainsContext(t *testing.T) {
	source := strings.Replace(x86ScalarResultDataTable, "$0xfedcba9876543210", "$·external(SB)", 1) +
		"TEXT ·view(SB),4,$0-4\nMOVOU table<>+16(SB),X1\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n"
	for _, api := range []string{"text", "module", "Go"} {
		if _, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s treated a linker pointer as a numerical constant: %v", api, err)
		}
	}
}

func TestX86LoweredScalarResultDataResolvedObjectIdentity(t *testing.T) {
	file, err := Parse(ArchAMD64, x86ScalarResultDataTable+
		"TEXT ·view(SB),4,$0-4\nMOVOU table<>+16(SB),X1\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string {
		if strings.TrimPrefix(sym, "·") == "alias<>" {
			return "table<>"
		}
		return strings.TrimPrefix(sym, "·")
	}
	address := x86StaticSBAddress{symbol: "table<>", offset: 16}
	if reads := x86LoweredScalarDataReads(file, resolve, nil, "amd64"); reads[address] != 16 {
		t.Fatal("actual resolved DATA object lost its complete range", reads)
	}
	for _, change := range []string{"alias relocation", "alias unresolved extent", "alias function", "signature symbol", "signature LLVM name"} {
		t.Run(change, func(t *testing.T) {
			mutated := *file
			mutated.Data = append([]DataStmt(nil), file.Data...)
			mutated.Globl = append([]GloblStmt(nil), file.Globl...)
			mutated.Funcs = append([]Func(nil), file.Funcs...)
			var sigs map[string]FuncSig
			switch change {
			case "alias relocation":
				mutated.Data = append(mutated.Data, DataStmt{Sym: "alias<>", Off: 0, Width: 8, Addr: "·external(SB)"})
			case "alias unresolved extent":
				mutated.Globl = append(mutated.Globl, GloblStmt{Sym: "alias<>", SizeRaw: "missing"})
			case "alias function":
				mutated.Funcs = append(mutated.Funcs, Func{Sym: "·alias<>"})
			case "signature symbol":
				sigs = map[string]FuncSig{"table<>": {Ret: Void}}
			case "signature LLVM name":
				sigs = map[string]FuncSig{"other": {Name: "table<>", Ret: Void}}
			}
			if reads := x86LoweredScalarDataReads(&mutated, resolve, sigs, "amd64"); len(reads) != 0 {
				t.Fatal("raw name bypassed complete resolved object validation", reads)
			}
		})
	}
}

func TestX86LoweredScalarResultDataReadScopeDoesNotEscape(t *testing.T) {
	state := x86ResultState{loweredStaticReads: map[x86StaticSBAddress]int64{{symbol: "table<>"}: 16}}
	read := Operand{Kind: OpSym, Sym: "table<>(SB)"}
	if !x86ResultRead(read, 16, &state, nil, "amd64") || x86ResultRead(read, 17, &state, nil, "amd64") {
		t.Fatal("ephemeral reader did not enforce exact complete width")
	}
	for _, copy := range []x86ResultState{state.clone(), state.intersect(state)} {
		if copy.loweredStaticReads != nil || x86ResultRead(read, 16, &copy, nil, "amd64") {
			t.Fatal("a reaching CFG state retained the temporary DATA reader")
		}
	}
	_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value() uint32",
		"MOVOU table<>(SB),X1\nPEXTRD $0,X1,AX\nMOVL AX,ret0+0(FP)\nRET")
	ctx := &amd64Ctx{fpScalarSource: file.Funcs[0], sig: sig, goarch: "amd64",
		fpScalarData: map[x86StaticSBAddress]int64{{symbol: "table<>"}: 16}}
	if err := ctx.checkLoweredScalarFPResultInitialization(); err != nil {
		t.Fatal("ephemeral DATA read did not close the lowering-only result", err)
	}
	if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("private lowering changed the standalone source query", err)
	}
}
