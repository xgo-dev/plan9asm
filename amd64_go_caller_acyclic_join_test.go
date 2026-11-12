package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86CallerAcyclicJoinAssembly(body string) string {
	return strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
}

func TestX86GoCallerAcyclicJoinActualSourceInputs(t *testing.T) {
	for name, body := range map[string]string{
		"same input offsets":     "MOVQ (CX),AX\nCMPQ AX,$1\nJE other\nADDQ $4,DI\nCMPQ AX,$1\nother:\nMOVL (DI),AX\nMOVL AX,(DX)",
		"copy and affine range":  "MOVQ (CX),AX\nCMPQ AX,$1\nJE other\nADDQ $4,DI\nCMPQ AX,$1\nother:\nMOVQ DI,BX\nLEAQ 4(BX),R11\nSUBQ $4,R11\nMOVL (R11),AX\nMOVL AX,(DX)",
		"all path low GP bytes":  "MOVQ (CX),AX\nCMPQ AX,$1\nJE narrow\nMOVL $42,BX\nJMP joined\nnarrow:\nMOVB $42,BL\njoined:\nMOVB BL,(DX)",
		"unused SIMD definition": "VMOVUPS (DI),X0\nMOVQ (CX),AX\nCMPQ AX,$1\nJE joined\nVMOVUPS (SI),X1\njoined:\nVMOVSS X0,(DX)",
		"unused mask definition": "MOVQ (CX),AX\nCMPQ AX,$1\nJE joined\nKMOVQ AX,K1\njoined:\nMOVL AX,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := x86CallerAcyclicJoinAssembly(body)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatalf("complete actual source acyclic join %s: %v", triple, err)
				}
			}
		})
	}
}

func TestX86GoCallerCountedLoopOriginalBackedgeNeedsFiniteProof(t *testing.T) {
	// These are unchanged consecutive original directives and the actual
	// backedge in Weaviate dot_avx256_amd64.s. The acyclic mechanism still cannot
	// prove them; the new private finite replay proves only this bounded region,
	// not the complete external function or its later unbounded loops.
	body := `MOVQ (CX),R9
LONG $0xff418d45
LONG $0x03c1f641
JE done
WORD $0x8944; BYTE $0xc8
WORD $0xe083; BYTE $0x03
LONG $0xc057f8c5
WORD $0xc931
LBB0_4:
LONG $0x0f10fac5
LONG $0xb971e2c4; BYTE $0x06
LONG $0x04c78348
LONG $0x04c68348
LONG $0x01c18348
WORD $0xc839
JNE LBB0_4
done:
MOVL $7,AX
MOVL AX,(DX)`
	assembly := x86CallerAcyclicJoinAssembly(body)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeX86RawDirectives(file.Funcs[0], "amd64")
	if err != nil {
		t.Fatal(err)
	}
	var instructions []int
	labels := map[string]int{}
	for index, ins := range decoded.Instrs {
		if ins.Op == OpLABEL {
			labels[ins.Args[0].Sym] = len(instructions)
		} else {
			instructions = append(instructions, index)
		}
	}
	if x86CallerReachableAcyclic(decoded, instructions, labels) {
		t.Fatal("a natural backedge acquired DAG admission")
	}
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatalf("source-bound finite replay of only the first region: %v", err)
	}
	// Preserve the bounded but outside-budget variant as a real source Context,
	// without hiding its original directives or adding a wrapper length check.
	outsideBudget := strings.Replace(assembly, "WORD $0xe083; BYTE $0x03", "WORD $0xe083; BYTE $0x07", 1)
	unsafePkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, outsideBudget)
	if err := x86CallerCoreTranslate(t, unsafePkg, outsideBudget, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("bound outside finite mechanism admitted: %v", err)
	}
}

func TestX86GoCallerAcyclicJoinRetainsUnknownPermissions(t *testing.T) {
	for name, body := range map[string]string{
		"different base":                     "CMPQ AX,$0\nJE joined\nMOVQ SI,DI\njoined:\nMOVL (DI),AX\nMOVL AX,(DX)",
		"lost pointer":                       "CMPQ AX,$0\nJE joined\nMOVQ $0,DI\njoined:\nMOVL (DI),AX\nMOVL AX,(DX)",
		"readonly write":                     "CMPQ AX,$0\nJE joined\nADDQ $4,DI\nCMPQ AX,$0\njoined:\nMOVL AX,(DI)",
		"result offset":                      "CMPQ AX,$0\nJE joined\nADDQ $1,DX\nCMPQ AX,$0\njoined:\nMOVB AX,(DX)",
		"length offset":                      "CMPQ AX,$0\nJE joined\nADDQ $1,CX\nCMPQ AX,$0\njoined:\nMOVL (CX),AX\nMOVL AX,(DX)",
		"upper range cap":                    "CMPQ AX,$0\nJE joined\nADDQ $1048576,DI\nCMPQ AX,$0\njoined:\nLEAQ 1(DI),BX\nMOVL (BX),AX\nMOVL AX,(DX)",
		"partial pointer":                    "CMPQ AX,$0\nJE joined\nADDQ $4,DI\nCMPQ AX,$0\njoined:\nMOVW DI,BX\nMOVL (BX),AX\nMOVL AX,(DX)",
		"truncated pointer":                  "CMPQ AX,$0\nJE joined\nADDQ $4,DI\nCMPQ AX,$0\njoined:\nLEAL (DI),DI\nMOVL (DI),AX\nMOVL AX,(DX)",
		"stack escape":                       "CMPQ AX,$0\nJE joined\nADDQ $4,DI\nCMPQ AX,$0\njoined:\nMOVQ DI,SP\nMOVL AX,(DX)",
		"input escapes as data":              "CMPQ AX,$0\nJE joined\nADDQ $4,DI\nCMPQ AX,$0\njoined:\nMOVQ DI,(DX)",
		"unknown length":                     "MOVQ R11,AX\nCMPQ AX,$0\nJE joined\nADDQ $4,DI\njoined:\nMOVL AX,(DX)",
		"late unknown GP":                    "CMPQ AX,$0\nJE missing\nMOVQ $7,BX\nJMP joined\nmissing:\nMOVB $7,BL\njoined:\nMOVQ BX,AX\nMOVL AX,(DX)",
		"late unknown vector":                "CMPQ AX,$0\nJE missing\nVMOVUPS (DI),Y0\nJMP joined\nmissing:\nMOVSS (DI),X0\njoined:\nVEXTRACTF128 $1,Y0,X1\nVMOVSS X1,(DX)",
		"late unknown mask":                  "VMOVUPS (DI),Z0\nCMPQ AX,$0\nJE joined\nKMOVQ AX,K1\njoined:\nVPADDD.Z Z0,Z0,K1,Z1\nVMOVSS X1,(DX)",
		"mask0 cannot grant source":          "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nCMPQ AX,$0\nJE joined\nADDQ $4,DI\nCMPQ AX,$0\njoined:\nVPADDD.Z (DX),Z0,K1,Z1\nVMOVSS X1,(DX)",
		"stale address flags":                "CMPQ AX,$0\nJE joined\nADDQ $4,DI\njoined:\nMOVL (DI),AX\nMOVL AX,(DX)",
		"same state loop cannot borrow span": "CMPQ AX,$0\nJE joined\nADDQ $4,DI\nCMPQ AX,$0\njoined:\nCMPQ AX,$0\nJNE joined\nMOVL (DI),AX\nMOVL AX,(DX)",
		"unknown dead instruction":           "JMP joined\nRDTSC\njoined:\nMOVL (DI),AX\nMOVL AX,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := x86CallerAcyclicJoinAssembly(body)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown permission acquired a finite input span: %v", err)
			}
		})
	}
}

func TestX86GoCallerAcyclicJoinRevokesProvisionalCertificatesForLateUnknown(t *testing.T) {
	// The short predecessor can reach and certify the input load before the
	// other predecessor arrives. A longer path then removes numerical bytes;
	// neither the early certificate nor arrival order may admit the function.
	for _, knownFirst := range []bool{true, false} {
		fast, slow := "MOVQ $7,BX", "MOVB $7,BL"
		if !knownFirst {
			fast, slow = slow, fast
		}
		body := "CMPQ AX,$0\nJE slow\n" + fast + "\nJMP joined\nslow:\n" +
			"MOVL $1,R10\nMOVL $2,R10\nMOVL $3,R10\nMOVL $4,R10\n" + slow +
			"\njoined:\nMOVL (DI),AX\nMOVQ BX,AX\nMOVL AX,(DX)"
		assembly := x86CallerAcyclicJoinAssembly(body)
		requireX86GoAssemblerResult(t, "amd64", assembly, true)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeX86RawDirectives(file.Funcs[0], "amd64")
		if err != nil {
			t.Fatal(err)
		}
		normalized := normalizeX86RawReturnSourceStack(decoded, Options{
			Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs,
		}, true, file.Funcs[0])
		if normalized.x86SourceStack != nil || !strings.Contains(normalized.x86SourceStackFailure, "unproved caller-region effect: MOVQ") {
			t.Fatalf("late unknown path acquired source permission: %s", normalized.x86SourceStackFailure)
		}
		for _, ins := range normalized.Instrs {
			if len(ins.x86CallerMemory) != 0 || len(ins.x86SourceStackFP) != 0 {
				t.Fatal("failed final source proof leaked a provisional instruction certificate")
			}
		}
		if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("late unknown predecessor was hidden by a prior proof: %v", err)
		}
	}
}

func TestX86GoCallerAcyclicJoinFinalCertificatesAndSourceMutations(t *testing.T) {
	body := "MOVQ (CX),AX\nCMPQ AX,$1\nJE joined\nADDQ $4,DI\nCMPQ AX,$1\njoined:\nMOVL (DI),AX\nMOVL AX,(DX)"
	for _, change := range []string{"none", "access width", "operand", "missing caller", "actual caller bytes"} {
		t.Run(change, func(t *testing.T) {
			assembly := x86CallerAcyclicJoinAssembly(body)
			pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
			normalized, err := normalizeX86RawFile(file, "amd64", options)
			if err != nil || normalized.Funcs[0].x86SourceStack == nil {
				t.Fatalf("complete final source proof: %v", err)
			}
			found := false
			for index := range normalized.Funcs[0].Instrs {
				ins := &normalized.Funcs[0].Instrs[index]
				if ins.Op != "MOVL" || len(ins.Args) != 2 || ins.Args[0].Kind != OpMem {
					continue
				}
				found = true
				if !x86CallerMemoryCertified(*ins, 0) {
					t.Fatal("final merged input read lacks a recomputed complete-width certificate")
				}
				if change == "access width" {
					access := ins.x86CallerMemory[0]
					access.width++
					ins.x86CallerMemory[0] = access
					if x86CallerMemoryCertified(*ins, 0) || x86RawReturnMemoryBound(normalized.Funcs[0], normalized, options, true) {
						t.Fatal("changed provisional access acquired final admission")
					}
					// Editing a private certificate also invalidates the sealed
					// normalized snapshot; recapture must start from original source.
				} else if change == "operand" {
					ins.Args[0].Mem.Base = DX
				}
			}
			if !found {
				t.Fatal("missing final original input load")
			}
			if change == "missing caller" {
				sig := sigs["caller.kernel"]
				sig.x86CallerRegions = nil
				sigs[sig.Name] = sig
			}
			if change == "actual caller bytes" {
				pkg.SourceSelection.GoSources["caller.go"] = []byte(x86CallerFixtureSource + "\nvar exposed = kernel\n")
				if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("changed producer caller source retained its original permission: %v", err)
				}
				return
			}
			_, err = Translate(normalized, options)
			if change == "none" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("edited %s acquired a final caller proof: %v", change, err)
			}
			if change == "access width" {
				fresh, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(fresh, options); err != nil {
					t.Fatalf("recapture from unchanged original source: %v", err)
				}
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				if err := x86CallerCoreTranslate(t, pkg, assembly, options.TargetTriple); err != nil {
					t.Fatalf("fresh actual caller source and LLVM object: %v", err)
				}
			}
		})
	}
}

func TestX86GoCallerAcyclicJoinFiveTargetsRetain386Boundary(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			if target.arch == "amd64" {
				assembly := x86CallerAcyclicJoinAssembly("CMPQ AX,$0\nJE joined\nADDQ $4,DI\nCMPQ AX,$0\njoined:\nMOVL (DI),AX\nMOVL AX,(DX)")
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, target.triple); err != nil {
					t.Fatal(err)
				}
				return
			}
			// The actual caller producer remains AMD64-only. A 386 object is
			// the existing independent scalar ABI0 control, not a copied span.
			pkg, selected, fn, sig := x86CallerFixture(t, x86CallerFixtureSource)
			if proof, err := deriveX86GoCallerRegions(pkg, selected, fn, sig, "386"); !errors.Is(err, ErrProbeNeedsContext) || proof != nil {
				t.Fatal("AMD64 input-origin proof was borrowed by mode32")
			}
			source, scalarSig, _ := x86SourceStackNumericalFixture("386", "@MOV @WORD(SP),AX\nCMPL AX,$0\nJE done\nADDL $7,AX\ndone:\n@MOV AX,@RESULT(SP)\nBYTE $0xc3")
			requireX86GoAssemblerResult(t, "386", source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, x86SourceStackOptions("386", target.triple, scalarSig))
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "mode32-control.ll", "mode32-control.o", module.String())
		})
	}
}
