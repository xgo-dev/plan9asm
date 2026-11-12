package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86CallerUnpackOpcodes() []string {
	return []string{
		"PUNPCKLBW", "PUNPCKHBW", "PUNPCKLWL", "PUNPCKHWL",
		"PUNPCKLLQ", "PUNPCKHLQ", "PUNPCKLQDQ", "PUNPCKHQDQ",
		"UNPCKLPS", "UNPCKHPS", "UNPCKLPD", "UNPCKHPD",
		"VPUNPCKLBW", "VPUNPCKHBW", "VPUNPCKLWD", "VPUNPCKHWD",
		"VPUNPCKLDQ", "VPUNPCKHDQ", "VPUNPCKLQDQ", "VPUNPCKHQDQ",
		"VUNPCKLPS", "VUNPCKHPS", "VUNPCKLPD", "VUNPCKHPD",
	}
}

func TestX86GoCallerUnpackCompleteInitializedGrammar(t *testing.T) {
	for _, opcode := range x86CallerUnpackOpcodes() {
		for _, original := range x86UnpackAcceptedForms(opcode, "amd64") {
			t.Run(original, func(t *testing.T) {
				row := strings.NewReplacer("8(AX)", "8(DI)", "X15", "X2", "X31", "X2", "Y31", "Y2", "Z31", "Z2").Replace(original)
				body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\nKMOVQ AX,K1\nKMOVQ AX,K7\n" + row + "\nVMOVSS X2,(DX)"
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
				needsContext := strings.Contains(row, "M7") || !strings.HasPrefix(opcode, "V") && strings.Contains(row, "(DI)")
				if needsContext && !errors.Is(err, ErrProbeNeedsContext) || !needsContext && err != nil {
					t.Fatalf("Context=%t: %v", needsContext, err)
				}
			})
		}
	}
}

func TestX86GoCallerUnpackRetainsUnknownAndMemoryFailures(t *testing.T) {
	for name, body := range map[string]string{
		"unknown first":                       "VMOVUPS (DI),X1\nVPUNPCKLBW X0,X1,X2\nVMOVSS X2,(DX)",
		"unknown second":                      "VMOVUPS (DI),X0\nVPUNPCKLBW X0,X1,X2\nVMOVSS X2,(DX)",
		"unknown selected high bytes":         "MOVSS (DI),X0\nMOVSS X0,X1\nVUNPCKHPS X0,X1,X2\nVMOVSS X2,(DX)",
		"unknown destructive input":           "VMOVUPS (DI),X0\nPUNPCKLBW X0,X1\nVMOVSS X1,(DX)",
		"unknown merge":                       "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nKMOVQ AX,K1\nVPUNPCKLBW X0,X1,K1,X2\nVMOVSS X2,(DX)",
		"unknown mask":                        "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nVPUNPCKLBW.Z X0,X1,K1,X2\nVMOVSS X2,(DX)",
		"pointer mask":                        "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nKMOVQ DI,K1\nVPUNPCKLBW.Z X0,X1,K1,X2\nVMOVSS X2,(DX)",
		"zero mask still full E4NF read":      "VMOVUPS (DI),X0\nMOVL $0,AX\nKMOVQ AX,K1\nVPUNPCKLDQ.Z (DX),X0,K1,X1\nVMOVSS X1,(DX)",
		"zero mask broadcast still full read": "VMOVUPS (DI),X0\nMOVL $0,AX\nKMOVQ AX,K1\nVPUNPCKLQDQ.BCST.Z (DX),X0,K1,X1\nVMOVSS X1,(DX)",
		"legacy alignment absent":             "VMOVUPS (DI),X0\nPUNPCKLBW (DI),X0\nVMOVSS X0,(DX)",
		"private stack":                       "VMOVUPS (DI),X0\nVPUNPCKLBW (SP),X0,X0\nVMOVSS X0,(DX)",
		"unknown address":                     "VMOVUPS (DI),X0\nVPUNPCKLBW (BX),X0,X0\nVMOVSS X0,(DX)",
		"read beyond scalar length":           "VMOVUPS (DI),X0\nVPUNPCKLDQ (CX),X0,X0\nVMOVSS X0,(DX)",
		"source write":                        "VMOVUPS (DI),X0\nVPUNPCKLBW X0,X0,X0\nVMOVSS X0,(DI)",
		"wide result":                         "VMOVUPS (DI),X0\nVPUNPCKLBW X0,X0,X0\nVMOVUPS X0,(DX)",
		"undefined CFG join":                  "VMOVUPS (DI),X0\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),X1\njoined:\nVPUNPCKLBW X0,X1,X2\nVMOVSS X2,(DX)",
		"MMX is a separate bank":              "PUNPCKLBW M0,M1\nVMOVSS X1,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved interleave acquired caller permission: %v", err)
			}
		})
	}
}

func TestX86GoCallerUnpackIndependentByteKnowledge(t *testing.T) {
	for _, opcode := range x86CallerUnpackOpcodes() {
		widths := []int{16}
		if strings.HasPrefix(opcode, "V") {
			widths = []int{16, 32, 64}
		}
		for _, width := range widths {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, destination := range []int{0, 1, 2} {
				if !strings.HasPrefix(opcode, "V") && destination != 1 {
					continue
				}
				for _, mode := range []string{"unmasked", "merge", "zero"} {
					if !strings.HasPrefix(opcode, "V") && mode != "unmasked" {
						continue
					}
					row := opcode + " " + bank + "0," + bank + "1"
					if strings.HasPrefix(opcode, "V") {
						if mode != "unmasked" {
							row += ",K1"
						}
						row += fmt.Sprintf(",%s%d", bank, destination)
						if mode == "zero" {
							row = strings.Replace(row, opcode, opcode+".Z", 1)
						}
					}
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					form, recognized, err := x86PackedUnpackProperties(ins, "amd64")
					if !recognized || err != nil {
						t.Fatalf("%s: %v", row, err)
					}
					for seed := 0; seed < 64; seed++ {
						initial := []uint64{0x19ca786fe32a907b, 0xf6210c89d8ba3547, 0x4a3b27e806c591df}
						for index := range initial {
							initial[index] ^= uint64(seed+index) * 0x102030405060708
						}
						state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": initial[0], "Z1": initial[1], "Z2": initial[2]}, masks: map[Reg]bool{"K1": true}}
						if !x86CallerPackedUnpackStep(&ins, form, &state, nil) {
							t.Fatalf("register effect refused %s", row)
						}
						// Calculate each output byte from the source spelling and
						// Intel's independent per-128-bit interleave definition.
						var want uint64
						lane := x86UnpackTestLaneBytes(opcode)
						high := strings.Contains(opcode, "UNPCKH")
						for output := 0; output < 64; output++ {
							known := false
							if output >= width {
								known = strings.HasPrefix(opcode, "V") || initial[destination]>>uint(output)&1 != 0
							} else {
								pair := (output % 16) / (2 * lane)
								sourceByte := output/16*16 + pair*lane + output%lane
								if high {
									sourceByte += 8
								}
								sourceRegister := 1
								if output/lane%2 != 0 {
									sourceRegister = 0
								}
								known = initial[sourceRegister]>>uint(sourceByte)&1 != 0
								if mode == "merge" {
									known = known && initial[destination]>>uint(output)&1 != 0
								}
							}
							if known {
								want |= uint64(1) << uint(output)
							}
						}
						if got := state.vectors[Reg(fmt.Sprintf("Z%d", destination))]; got != want {
							t.Fatalf("%s seed=%d: byte knowledge %#x want %#x", row, seed, got, want)
						}
					}
				}
			}
		}
	}
}

func TestX86GoCallerUnpackCompleteFamilyThreeAPIs(t *testing.T) {
	var body strings.Builder
	body.WriteString("VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\n")
	for _, opcode := range x86CallerUnpackOpcodes() {
		if strings.HasPrefix(opcode, "V") {
			fmt.Fprintf(&body, "%s Z0,Z1,Z2\nVMOVSS X2,(DX)\n", opcode)
		} else {
			fmt.Fprintf(&body, "%s X0,X1\nVMOVSS X1,(DX)\n", opcode)
		}
	}
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body.String(), 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
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
			compileLLVMToObject(t, llc, triple, "unpack.ll", "unpack.o", ir)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			compileLLVMToObject(t, llc, triple, "unpack-module.ll", "unpack-module.o", module.String())
			if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerUnpackMemoryCertificatesBindFullE4NFSource(t *testing.T) {
	for _, row := range []string{"VPUNPCKLBW (DI),X0,X2", "VUNPCKHPD.BCST.Z (DI),Z0,K1,Z2"} {
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", "VMOVUPS (SI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n"+row+"\nVMOVSS X2,(DX)", 1)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizeX86RawFile(file, "amd64", Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ins := range normalized.Funcs[0].Instrs {
			form, recognized, err := x86PackedUnpackProperties(ins, "amd64")
			if !recognized || err != nil || form.memory < 0 {
				continue
			}
			found = true
			index := form.memory
			access, exists := ins.x86CallerMemory[index]
			if !exists || access.write || access.width != int64(form.memoryBytes) || !x86CallerMemoryCertified(ins, index) {
				t.Fatal("missing full-width native read certificate")
			}
			for _, change := range []string{"opcode", "width", "address", "destination", "direction", "broadcast", "mask"} {
				mutated := ins
				mutated.Args = append([]Operand(nil), ins.Args...)
				mutated.x86CallerMemory = map[int]x86CallerMemoryAccess{index: access}
				switch change {
				case "opcode":
					mutated.Op = "VPUNPCKHBW"
				case "width":
					access.width--
					mutated.x86CallerMemory[index] = access
				case "address":
					mutated.Args[index].Mem.Off++
				case "destination":
					mutated.Args[form.destination].Reg = "X3"
				case "direction":
					access.write = true
					mutated.x86CallerMemory[index] = access
				case "broadcast":
					mutated.Op = Op(string(mutated.Op) + ".BCST")
				case "mask":
					if form.mask >= 0 {
						mutated.Args[form.mask].Reg = "K2"
					} else {
						mutated.Args = append(mutated.Args, Operand{Kind: OpReg, Reg: "K2"})
					}
				}
				if x86CallerMemoryCertified(mutated, index) {
					t.Fatalf("%s mutation reused a stale interleave certificate", change)
				}
			}
		}
		if !found {
			t.Fatal("no interleave instruction consumed its caller proof")
		}
	}
}

func TestX86GoCallerUnpackCompleteFamilyOriginalSource(t *testing.T) {
	for _, opcode := range x86CallerUnpackOpcodes() {
		t.Run(opcode, func(t *testing.T) {
			operands, destination := "X0,X1", "X1"
			if strings.HasPrefix(opcode, "V") {
				operands, destination = "Y0,Y1,Y2", "X2"
			}
			body := fmt.Sprintf("VMOVUPS (DI),Y0\nVMOVUPS (SI),Y1\n%s %s\nVMOVSS %s,(DX)", opcode, operands, destination)
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
