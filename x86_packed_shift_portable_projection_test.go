package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// This test-only projection removes exactly the original functions' checked
// ISA selection attributes. Their integer operations, guarded volatile accesses,
// aliases and control flow remain unchanged. It is not native x86 execution.
func x86PackedShiftPortableIR(source, ir string) (string, error) {
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	file, err = normalizeX86RawFile(file, "amd64")
	if err != nil {
		return "", err
	}
	profiles := make(map[string]string)
	for _, function := range file.Funcs {
		name := strings.TrimPrefix(function.Sym, "·")
		if _, duplicate := profiles[name]; duplicate || len(function.Instrs) == 0 ||
			function.Instrs[0].Op != OpTEXT || len(function.X86RawText) != 0 {
			return "", fmt.Errorf("portable packed-shift source lost its unique ordinary function: %s", name)
		}
		shifts := 0
		for ordinal, instruction := range function.Instrs {
			switch instruction.Op {
			case OpTEXT:
				// Parse binds this sole header to function.Sym. It is not an
				// executable body operation or a general directive exemption.
				if ordinal != 0 || len(instruction.Args) != 0 {
					return "", fmt.Errorf("portable packed-shift TEXT is not its associated first header: %s", name)
				}
				continue
			case "MOVQ", "KMOVQ", "VMOVUPS", "RET":
				continue
			}
			form, recognized, formErr := x86PackedShiftProperties(instruction.Op, instruction, "amd64")
			if !recognized || formErr != nil || form.legacy || x86PackedShiftHasNativeCount(form) {
				return "", fmt.Errorf("portable packed-shift source contains an unobserved operation: %s", instruction.Raw)
			}
			shifts++
		}
		if shifts != 1 {
			return "", fmt.Errorf("portable packed-shift function lost its single original operation: %s/%d", name, shifts)
		}
		profiles[name] = inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", function)
	}
	return x86PackedShiftPortableFeatureProjection(ir, profiles)
}

func x86PackedShiftPortableFeatureProjection(ir string, profiles map[string]string) (string, error) {
	if len(profiles) == 0 {
		return "", fmt.Errorf("portable packed-shift IR has no owned functions")
	}
	// The production prelude declares native intrinsics even when no function
	// uses them. Observe complete, singly referenced declarations without
	// removing any bytes from the actual projected IR. A body use is native.
	view, declarationGroups, err := x86PackedShiftInertDeclarations(ir)
	if err != nil {
		return "", err
	}
	if native := regexp.MustCompile(`\basm\b|@llvm\.(?:x86|aarch64|arm|wasm|ppc|riscv)\.|@"|"target-cpu"`).FindStringIndex(view); native != nil {
		start := strings.LastIndex(view[:native[0]], "\n") + 1
		end := strings.IndexByte(view[native[1]:], '\n')
		if end < 0 {
			end = len(view)
		} else {
			end += native[1]
		}
		attributes := regexp.MustCompile(`(?m)^attributes [^\r\n]*`).FindAllString(ir, -1)
		return "", fmt.Errorf("portable packed-shift native guard: token=%q line=%q complete attribute inventory=%q", view[native[0]:native[1]], view[start:end], attributes)
	}
	groupPattern := regexp.MustCompile(`(?m)^attributes (#[0-9]+) = \{ "target-features"="([^"]+)" \}\r?\n`)
	groups := groupPattern.FindAllStringSubmatch(ir, -1)
	byProfile, byGroup := make(map[string]string), make(map[string]string)
	for _, group := range groups {
		if byProfile[group[2]] != "" || byGroup[group[1]] != "" {
			return "", fmt.Errorf("duplicate portable packed-shift feature group")
		}
		byProfile[group[2]], byGroup[group[1]] = group[1], group[2]
	}
	genericGroups, err := x86PackedShiftInertDeclarationAttributes(ir, declarationGroups, byGroup)
	if err != nil {
		return "", err
	}
	if strings.Count(ir, "target-features") != len(groups) {
		return "", fmt.Errorf("unobserved portable packed-shift attribute group")
	}
	definitionPattern := regexp.MustCompile(`(?m)^define [^\r\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\([^\r\n]*\)[^\r\n]*\{`)
	definitions := definitionPattern.FindAllStringSubmatch(ir, -1)
	if len(definitions) != len(profiles) {
		return "", fmt.Errorf("portable packed-shift definition inventory changed: %d/%d", len(definitions), len(profiles))
	}
	seen, uses := make(map[string]bool), make(map[string]int)
	referencePattern := regexp.MustCompile(`#[0-9]+\b`)
	for _, definition := range definitions {
		name := definition[1]
		profile, found := profiles[name]
		if !found || seen[name] {
			return "", fmt.Errorf("unowned or duplicate portable packed-shift definition: %s", name)
		}
		seen[name] = true
		references := referencePattern.FindAllString(definition[0], -1)
		if profile == "" {
			if len(references) != 0 {
				return "", fmt.Errorf("feature-free portable packed-shift function gained an attribute: %s", name)
			}
			continue
		}
		group := byProfile[profile]
		if group == "" || len(references) != 1 || references[0] != group {
			return "", fmt.Errorf("portable packed-shift function lost exact ISA ownership: %s", name)
		}
		uses[group]++
	}
	for _, group := range groups {
		// Count exact numeric tokens, not prefixes such as #20 and #200.
		references := regexp.MustCompile(regexp.QuoteMeta(group[1])+`\b`).FindAllString(ir, -1)
		if uses[group[1]] == 0 || len(references) != uses[group[1]]+1 {
			return "", fmt.Errorf("portable packed-shift feature group has missing or foreign references: %s", group[1])
		}
	}
	// Only the checked group lines and corresponding definition-header tokens
	// change. In particular, no memory access or branch can be dropped here.
	projected := groupPattern.ReplaceAllString(ir, "")
	projected = definitionPattern.ReplaceAllStringFunc(projected, func(header string) string {
		return regexp.MustCompile(` #[0-9]+\b`).ReplaceAllString(header, "")
	})
	if strings.Contains(projected, "target-features") {
		return "", fmt.Errorf("portable packed-shift IR retains an unchecked ISA reference")
	}
	for _, reference := range referencePattern.FindAllString(projected, -1) {
		if !genericGroups[reference] {
			return "", fmt.Errorf("portable packed-shift IR retains an unowned declaration attribute: %s", reference)
		}
	}
	return projected, nil
}

func x86PackedShiftInertDeclarations(ir string) (string, map[string]int, error) {
	declarations := regexp.MustCompile(`(?m)^declare [^@\r\n]+(@[A-Za-z_][A-Za-z0-9_.$]*)\(([^@\r\n]*)\)(?: (#[0-9]+))?\r?$`)
	symbols := regexp.MustCompile(`@[A-Za-z_][A-Za-z0-9_.$]*`).FindAllString(ir, -1)
	uses := make(map[string]int)
	for _, symbol := range symbols {
		uses[symbol]++
	}
	groups := make(map[string]int)
	native := regexp.MustCompile(`^@llvm\.(?:x86|aarch64|arm|wasm|ppc|riscv)\.`)
	var failure error
	view := declarations.ReplaceAllStringFunc(ir, func(line string) string {
		parts := declarations.FindStringSubmatch(line)
		depth := 0
		for _, character := range parts[2] {
			switch character {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth < 0 {
				break
			}
		}
		if depth != 0 {
			failure = fmt.Errorf("portable packed-shift declaration has incomplete parameters: %s", line)
			return line
		}
		if parts[3] != "" {
			groups[parts[3]]++
		}
		if native.MatchString(parts[1]) {
			if uses[parts[1]] != 1 {
				failure = fmt.Errorf("portable packed-shift native intrinsic is not an inert unique declaration: %s", parts[1])
				return line
			}
			return ""
		}
		return line
	})
	return view, groups, failure
}

func x86PackedShiftInertDeclarationAttributes(ir string, declarationGroups map[string]int, featureGroups map[string]string) (map[string]bool, error) {
	pattern := regexp.MustCompile(`(?m)^attributes (#[0-9]+) = \{ ([^\r\n]*) \}\r?\n`)
	groups := pattern.FindAllStringSubmatch(ir, -1)
	if len(regexp.MustCompile(`(?m)^attributes `).FindAllString(ir, -1)) != len(groups) {
		return nil, fmt.Errorf("portable packed-shift IR has an incomplete attribute group")
	}
	seen, generic := make(map[string]bool), make(map[string]bool)
	for _, group := range groups {
		if seen[group[1]] {
			return nil, fmt.Errorf("portable packed-shift IR has a duplicate attribute identity: %s", group[1])
		}
		seen[group[1]] = true
		if _, feature := featureGroups[group[1]]; feature {
			continue
		}
		// LLVM22 attaches these generic properties to prelude declarations.
		// The declaration itself must own every reference; no function body or
		// definition can borrow this group, and no target attribute is accepted.
		properties := regexp.MustCompile(`memory\((?:none|read|write|readwrite|(?:argmem|inaccessiblemem):[ \t]*(?:read|write|readwrite)(?:,[ \t]*(?:argmem|inaccessiblemem):[ \t]*(?:read|write|readwrite))*)\)`).ReplaceAllString(group[2], "")
		for _, property := range strings.Fields(properties) {
			switch property {
			case "nocallback", "nofree", "nosync", "nounwind", "speculatable", "willreturn", "nocreateundeforpoison", "strictfp":
			default:
				return nil, fmt.Errorf("portable packed-shift declaration gained an unobserved attribute: %s", property)
			}
		}
		references := regexp.MustCompile(regexp.QuoteMeta(group[1])+`\b`).FindAllString(ir, -1)
		if declarationGroups[group[1]] == 0 || len(references) != declarationGroups[group[1]]+1 {
			return nil, fmt.Errorf("portable packed-shift generic attribute is not owned only by declarations: %s", group[1])
		}
		generic[group[1]] = true
	}
	return generic, nil
}

func TestX86PackedShiftPortableUnusedDeclarationsStayInert(t *testing.T) {
	const declaration = "declare i32 @llvm.x86.rdpid() #0\n"
	const attributes = "attributes #0 = { nocallback nofree nosync nounwind willreturn }\n"
	const body = "define void @A(ptr %p) {\n  %v = load volatile i8, ptr %p, align 1\n" +
		"  store volatile i8 %v, ptr %p, align 1\n  ret void\n}\n"
	input := declaration + body + attributes
	profiles := map[string]string{"A": ""}
	if projected, err := x86PackedShiftPortableFeatureProjection(input, profiles); err != nil || projected != input {
		t.Error("single unused native declaration and its own generic attributes must remain byte-for-byte inert", err)
	}
	shared := input + "declare i32 @llvm.x86.rdpid.extension() #0\n"
	if projected, err := x86PackedShiftPortableFeatureProjection(shared, profiles); err != nil || projected != shared {
		t.Error("inert declarations may share their exact generic group without confusing symbol prefixes", err)
	}
	for name, changed := range map[string]string{
		"called-native":          strings.Replace(input, "  ret void", "  %native = call i32 @llvm.x86.rdpid()\n  ret void", 1),
		"native-address":         input + "@escape = global ptr @llvm.x86.rdpid\n",
		"duplicate-declaration":  input + declaration,
		"incomplete-declaration": strings.Replace(input, "@llvm.x86.rdpid() #0", "@llvm.x86.rdpid( #0", 1),
		"trailing-body":          strings.Replace(input, "@llvm.x86.rdpid() #0", "@llvm.x86.rdpid() #0 call i32 @llvm.x86.rdpid()", 1),
		"foreign-attribute":      input + "attributes #7 = { nounwind }\n",
		"definition-attribute":   strings.Replace(input, "@A(ptr %p) {", "@A(ptr %p) #0 {", 1),
		"native-attribute":       strings.Replace(input, "nocallback nofree nosync nounwind willreturn", `"target-cpu"="skylake-avx512"`, 1),
		"native-inline-asm":      strings.Replace(input, "  ret void", `  call void asm sideeffect "nop", ""()`+"\n  ret void", 1),
		"quoted-native-address":  input + "@escape = global ptr @\"llvm.x86.rdpid\"\n",
		"escaped-native-address": input + "@escape = global ptr @\"llvm\\2Ex86\\2Erdpid\"\n",
		"native-prefix-call":     strings.Replace(input, "  ret void", "  %native = call i32 @llvm.x86.rdpid.extension()\n  ret void", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if projected, err := x86PackedShiftPortableFeatureProjection(changed, profiles); err == nil || projected != "" {
				t.Fatal("unused-declaration policy accepted a native body, address or unrelated attribute", err)
			}
		})
	}
}

func TestX86PackedShiftPortableProjectionConsumesNormalizedProductionIR(t *testing.T) {
	const prefix = "TEXT ·Shift(SB),4,$0-32\nMOVQ data+0(FP),AX\nMOVQ counts+8(FP),BX\n" +
		"MOVQ out+16(FP),DI\nVMOVUPS (AX),Z0\nVMOVUPS (AX),Z2\nKMOVQ mask+24(FP),K1\n"
	const suffix = "VMOVUPS Z2,(DI)\nVMOVUPS Y2,64(DI)\nVMOVUPS X2,96(DI)\nRET\n"
	const declaration = "func Shift(data,counts,out *byte,mask uint64)"
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprint("raw_", raw), func(t *testing.T) {
			operation := "VPSLLVW.Z (BX),X0,K1,X2\n"
			if raw {
				operation = x86RawDisplacementDirectives([]byte{0x62, 0xf2, 0xfd, 0x89, 0x12, 0x13})
			}
			source := prefix + operation + suffix
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, "amd64")
			if err != nil || len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 12 || file.Funcs[0].Instrs[0].Op != OpTEXT {
				t.Fatal("real normalized source lost the associated parser header or complete operation", err)
			}
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", "Go")
			if err != nil || ir == "" {
				t.Fatal("initialized source lost its actual public production consumer", err)
			}
			projected, err := x86PackedShiftPortableIR(source, ir)
			if err != nil || projected != ir || !strings.Contains(projected, "load volatile") || !strings.Contains(projected, "store volatile") {
				t.Fatal("already portable production IR lost a body effect at its parser header", err)
			}
			for name, changed := range map[string]string{
				"unknown-body":            strings.Replace(source, operation, "CPUID\n"+operation, 1),
				"other-function":          source + "TEXT ·Other(SB),4,$0-0\nRET\n",
				"wrong-associated-symbol": strings.Replace(source, "·Shift(SB)", "·Other(SB)", 1),
			} {
				t.Run(name, func(t *testing.T) {
					if output, err := x86PackedShiftPortableIR(changed, ir); err == nil || output != "" {
						t.Fatal("parser header exemption accepted an unknown body or foreign function", err)
					}
				})
			}
		})
	}
}

func TestX86PackedShiftPortableProjectionOwnsEveryFunctionAndEffect(t *testing.T) {
	const body = "entry:\n  %v = load volatile i8, ptr %p, align 1\n  br label %done\ndone:\n  store volatile i8 %v, ptr %p, align 1\n  ret void\n}\n"
	input := "define void @A(ptr %p) #20 {\n" + body +
		"define void @B(ptr %p) {\n" + body + "define void @C(ptr %p) #200 {\n" + body +
		"attributes #20 = { \"target-features\"=\"+avx\" }\n" +
		"attributes #200 = { \"target-features\"=\"+avx2\" }\n"
	profiles := map[string]string{"A": "+avx", "B": "", "C": "+avx2"}
	want := "define void @A(ptr %p) {\n" + body + "define void @B(ptr %p) {\n" + body +
		"define void @C(ptr %p) {\n" + body
	if actual, err := x86PackedShiftPortableFeatureProjection(input, profiles); err != nil || actual != want {
		t.Fatal("portable projection changed an access, branch or function instead of exact ISA attributes", err, actual)
	}
	for name, changed := range map[string]string{
		"missing-group":                 strings.Replace(input, "attributes #20 = { \"target-features\"=\"+avx\" }\n", "", 1),
		"duplicate-group":               input + "attributes #20 = { \"target-features\"=\"+avx\" }\n",
		"wrong-function-reference":      strings.Replace(input, "@A(ptr %p) #20", "@A(ptr %p) #200", 1),
		"unexpected-function-reference": strings.Replace(input, "@B(ptr %p) {", "@B(ptr %p) #20 {", 1),
		"foreign-reference":             input + "; foreign #20\n",
		"missing-function":              strings.Replace(input, "@B(ptr %p)", "@Unknown(ptr %p)", 1),
		"extra-definition":              input + "define void @D() {\nret void\n}\n",
		"native-asm":                    strings.Replace(input, "ret void", `call void asm sideeffect "nop", ""()`, 1),
		// The independent b6ef80f8a RED proves that a declaration alone is
		// inert. This negative must contain an actual native body operation.
		"native-intrinsic": strings.Replace(input, "ret void", "call void @llvm.x86.sse.pause()\n  ret void", 1) +
			"declare void @llvm.x86.sse.pause()\n",
		"extra-attribute": input + "attributes #3 = { nounwind }\n",
	} {
		t.Run(name, func(t *testing.T) {
			if actual, err := x86PackedShiftPortableFeatureProjection(changed, profiles); err == nil || actual != "" {
				t.Fatal("invalid portable inventory returned partially projected IR", err)
			}
		})
	}
	withoutFeatures := "define void @B(ptr %p) {\n" + body
	if actual, err := x86PackedShiftPortableFeatureProjection(withoutFeatures, map[string]string{"B": ""}); err != nil || actual != withoutFeatures {
		t.Fatal("already portable production IR must remain byte-for-byte unchanged", err)
	}
}
