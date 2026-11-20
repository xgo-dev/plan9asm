package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86FloatAddSubPhysicalAliasesAndInactiveMemory(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires amd64 runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang missing")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	var prefix []string
	if crossRosetta {
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	for _, fixture := range []struct {
		name, body, checks string
	}{
		{"packed upper aliases", "VADDPS X1,X0,X2", "for(int i=0;i<16;i++) if(out[i]!=(i<4?5.0f:0.0f)) return 11;"},
		{"scalar second-source passthrough", "VSUBSS X1,X0,X2", "for(int i=0;i<16;i++) if(out[i]!=(i==0?-1.0f:i<4?2.0f:0.0f)) return 12;"},
		{"inactive memory", "MOVQ $0,DX\nKMOVQ DX,K1\nVADDPS.Z (CX),X0,K1,X2", "for(int i=0;i<16;i++) if(out[i]!=0.0f) return 13;"},
		{"inactive scalar memory", "MOVQ $0,DX\nKMOVQ DX,K1\nVSUBSD.Z (CX),X0,K1,X2", "for(int i=0;i<16;i++) if(out[i]!=(i<2?0.0f:i<4?2.0f:0.0f)) return 14;"},
		{"inactive broadcast memory", "MOVQ $0,DX\nKMOVQ DX,K1\nVADDPD.BCST.Z (CX),Z0,K1,Z2", "for(int i=0;i<16;i++) if(out[i]!=0.0f) return 15;"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			source := "TEXT addsub(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nVMOVUPS (BX),Z0\nVMOVUPS (BX),Z2\n"
			if !strings.HasPrefix(fixture.name, "inactive") {
				source += "VMOVUPS (CX),Z1\n"
			}
			source += fixture.body + "\nVMOVUPS Z2,(AX)\nRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{
				"addsub": {Name: "addsub", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			argument := "b"
			if strings.HasPrefix(fixture.name, "inactive") {
				argument = "0"
			}
			main := fmt.Sprintf("extern void addsub(float*,const float*,const float*);\nint main(void){float a[16],b[16],out[16]; for(int i=0;i<16;i++){a[i]=2;b[i]=3;} addsub(out,a,%s); %s return 0;}\n", argument, fixture.checks)
			compileAndRunRuntimeTestForTarget(t, llc, clang, "addsub-alias", triple, ir, strings.TrimSpace(main), prefix)
		})
	}
}

func TestX86FloatAddSubFixedRoundingIgnoresAmbientMode(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires amd64 runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang missing")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	var prefix []string
	if crossRosetta {
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for mode, suffix := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
		name := fmt.Sprintf("roundadd%d", mode)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVSS (BX),X0\nMOVSS (CX),X1\nVADDSS.%s X1,X0,X2\nMOVSS X2,(AX)\nRET\n", name, suffix)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(uint32_t*,const uint32_t*,const uint32_t*);\n", name)
		expected := uint32(0x3f800000)
		if mode == 2 {
			expected++
		}
		fmt.Fprintf(&checks, "for(int ambient=0;ambient<4;ambient++){if(fesetround(modes[ambient]))return 2; uint32_t a=0x3f800000,b=0x33800000,out=0; %s(&out,&a,&b); if(out!=0x%x)return %d;}\n", name, expected, mode+10)
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <fenv.h>\n" + declarations.String() + "int main(void){const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};\n" + checks.String() + "return fesetround(FE_TONEAREST)!=0;}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "addsub-fixed-ambient", triple, ir, main, prefix)
}
