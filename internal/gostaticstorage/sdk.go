package gostaticstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

const SDKCPUProtocol = "actual_go_sdk_cpu_numeric_storage_prototype_v1"

// gcToolchain.asm (gc.go:416) maps each selected SFile, in order, to its
// actual .o member. Bind that SDK rule as well as the observed asm route; the
// filename suffix by itself is not a source-to-object certificate.
var sdkCPUFormatSources = map[string]string{
	"src/cmd/go/internal/work/gc.go":     "13359b8707e78300e8e0ec880b9a8d1af4bafdf32140b56df5f041a52fbc1325",
	"src/cmd/go/internal/work/init.go":   "cd86d5c8fecb90d9db58ed3c98d0869ff6b5220c445025051d366818859a0963",
	"src/internal/platform/supported.go": "b2ee50eb1857a0dfd98cbfbd0c8a6c78f3a3e334cfc56557a24c8517681bc442",
	"src/cmd/compile/internal/gc/obj.go": "dfed5fe0bee6e0dab23e3fd3c1327c12273895cf8141ad4b896cef8bc73269f2",
	"src/cmd/link/internal/ld/go.go":     "1035a2c6ca034d8a47ae6ee3a4be530e0b32170120d527d75fc46df29be68c84",
}

// CaptureSDKCPU observes only the original selected Go 1.27.1 internal/cpu
// owner. Standard or Module=nil alone are never evidence of SDK ownership.
// This separate producer does not grant SB/native-entry/translation permission.
func CaptureSDKCPU(ctx context.Context, request Request) (*Observation, error) {
	return capture(ctx, request, true)
}

func sdkCPUArguments() []string {
	return []string{"list", "-deps", "-json", "-compiled", "-export", "-a", "-p=1", "internal/cpu"}
}

func sdkCPUTarget(target string) bool {
	if X86SDKTarget(target) {
		return true
	}
	switch target {
	case "linux/arm", "linux/arm64", "js/wasm":
		return true
	}
	return false
}

func sdkCPUProfile(target string) map[string]string {
	profile := map[string]string{"GO386": "", "GOARM": "", "GOARM64": "", "GOWASM": ""}
	switch target {
	case "linux/386", "windows/386":
		profile["GO386"] = "sse2"
	case "linux/arm":
		profile["GOARM"] = "7,hardfloat"
	case "linux/arm64":
		profile["GOARM64"] = "v8.0"
	}
	return profile
}

// Original files, including ignored/test/assembly files, are pinned to the
// selected stock SDK, not inferred from the directory or package spelling.
// Only this bounded owner is supported; this is not a general stdlib loader.
var sdkCPUSources = map[string]string{
	"cpu.go":                   "9af4310772f84d92f2a98e9f16e6553fdbefc4ce6286e0f508121e6c8819faf7",
	"cpu.s":                    "39594514f3cb069cecfc6782f81385cbb3570a2ca1b0f3028db1dfa75fd5837e",
	"cpu_arm.go":               "909650fdeab24972e89f702b663732297e00f12078339defb3da4b9e2d6e6159",
	"cpu_arm64.go":             "5b156522fb27d47992d4ab013779c6d24c87e002a1a83550042cbd1d1d641538",
	"cpu_arm64.s":              "90803105802e7e92084aeabb2985b3b770ebfe9ab045e997790ade7eabe3a6b4",
	"cpu_arm64_android.go":     "8b7f051aa72bd245b71fe2e2462069ae05e30df5b104b61875d9f207be0e9913",
	"cpu_arm64_darwin.go":      "83d95025242aca57e8258aa1fbb1c84a976717db1977c5200c5e8c41daecb099",
	"cpu_arm64_freebsd.go":     "a128fa45e38c0f2975d1eeb4287463361fe2ceabb1060a04b1aae8e01719757e",
	"cpu_arm64_hwcap.go":       "4e38722a3a8970e66ba2aa9aaf4eded7a46d8e57443b9fed16e05c56f23994b2",
	"cpu_arm64_linux.go":       "92a9f87d05a0c080cddd9f4ea8af606e57f43d1fa5bd48ce7db2048b693402bf",
	"cpu_arm64_openbsd.go":     "06ade8fe6706a137cbcecc895b7af08b80a6a9e9e4b1e626060e36ec40d627dc",
	"cpu_arm64_other.go":       "810f3fed4a62636bc78b5896eccdcc46ba78129b13f4fe200ffa7285042cf0ba",
	"cpu_arm64_windows.go":     "cd0dd8a3102d59d039a6ff9f236c2e18d91c19424a873241f23d6270baddfa9b",
	"cpu_darwin.go":            "5c9dafb5c15b5cb405520aa711230231111de33601eb732922991fe008ae2384",
	"cpu_loong64.go":           "ee25ebaec6b9365bff35b6c7b19b93bc5848ec2ec5897e1d7a25362eeca30d62",
	"cpu_loong64.s":            "b5ad39be941a89a31481d0321c36baf80ecc80ca91e8b0c0f668c7f18820aa03",
	"cpu_loong64_hwcap.go":     "5a91f8bf23674f1e97869a50686ef2d25ce97d17f75399437f5eda65a4902374",
	"cpu_loong64_linux.go":     "8c24d8a08fe921cca8ffa555bf2d186ad6d3c645345fe997fddb0da95f13f4ff",
	"cpu_mips.go":              "e29c18ecf33b490fb974604d690007e9aaf1c4a6a4c253100405613d1f636e87",
	"cpu_mips64x.go":           "6ed64689241f6dbd3f79975a6c073f541045c62f5e7b9cafea7a8f4f0663e5bc",
	"cpu_mipsle.go":            "e29c18ecf33b490fb974604d690007e9aaf1c4a6a4c253100405613d1f636e87",
	"cpu_no_name.go":           "8215f72c7d9df7b7b3b53f1d6a5df311816e57cf6e5a06f21f7be50097ca79cc",
	"cpu_ppc64x.go":            "5a7a1ceaf9b5f43addcdddb9ea5e8b430cac94d7e27fbf63962cceb4836f190d",
	"cpu_ppc64x_aix.go":        "9f25df3971d54401d69de9e289946837f34a0be07a4263f94a252938478e23ca",
	"cpu_ppc64x_linux.go":      "3e4ecc7e14ca82f767642fd2e48753d470ccb94c90c60dc5789664244530c129",
	"cpu_ppc64x_other.go":      "cfd68633c11ced7cedcb93b1a71a4b02fe15835970ffbcc6dc78aeeadf0cc461",
	"cpu_riscv64.go":           "d127180a261f61f485eb6448ab95575bd4a2b8a8f27ff60e6ad7ecc4d28ae3a3",
	"cpu_riscv64_linux.go":     "26a08d2184a041108c255d1df2afe84c34a0c8798aa379356ad94f9af034ec1c",
	"cpu_riscv64_other.go":     "9a8423e00805e1e95a1b3d6d218eaefe1442c1060d2ca9b51b9e18250ab62e96",
	"cpu_s390x.go":             "da56587ea0fcdadfaeae80c57a96b6044260ef3965c9e893af18f655cb98cfac",
	"cpu_s390x.s":              "c0a535dc06b98e14ee72277e800a61f412b58d0ca10db50780c498f40c4e41cc",
	"cpu_s390x_test.go":        "1eb3d6fe149aae62104c6ebd9742e977916abad1d15e0c020c27090d24d5c2fb",
	"cpu_test.go":              "2bbd71d724a24a17009b8b4b3b38b4057db57e5751697a8a7cbd58a88a0da7f0",
	"cpu_wasm.go":              "22f9de4a9088c0dff432817ec066451b6e35aafecf2328063ed3d87c9883db56",
	"cpu_windows.go":           "41eaf49d064a01655c3c7b7af2c5152151fd9d5462b7c708aad8d9c298abff3f",
	"cpu_windows_test.go":      "6064d216bc3134406d4cd3d39eabfceac8c88292cfdfd6ae55a6783ddd7152b6",
	"cpu_x86.go":               "395ce0d3004df63df376585519bc1b46303b206415c1915ab80b7bead155e26a",
	"cpu_x86.s":                "ee4dca9916b29475e600d85f71f0dfd134496d153c77d20a643b139cc6e18fed",
	"cpu_x86_darwin.go":        "036050c7259aa9282697b31603c3e5c8eb1ce234a1bbf26f9a326635a9645040",
	"cpu_x86_netbsd.go":        "680675d11b22c292cd57425c573e206377238e2671ab5dc15f74307300a96eaf",
	"cpu_x86_other.go":         "f24c84fc53bb2b8b067fdb462d6ac56594c371163527fba998f45c0f65c0c2f9",
	"cpu_x86_test.go":          "2c6198efdfa141f25bbe984d59c38c40acb17bca3e1b90c5e23497cf1245df2a",
	"datacache_unsupported.go": "1ee1b485113109cb851e7141c072ad31493414c963fd469f398fc0ea2b385a9c",
	"datacache_x86.go":         "bbd50f64070d9497f062de27710a17d1aead867054d7dd9143bf063cdcd4fbea",
	"datacache_x86_test.go":    "5b6c2963fed1a9fc4d260b6bd0ce83f921ab6571a7cc3b0dc6c6a2c2944f5256",
	"export_test.go":           "6ae4785c9b482cfaadb490f2cb06a42cf5e9c796dcc8e3460f7f25fd41bd8dcd",
	"export_x86_test.go":       "c9179504d2f6041efc0afe3a8a4bd56e66866fefce9dfb8377c47d074fde4455",
}

func sdkCPUSource(source map[string][]byte) error {
	if len(source) != len(sdkCPUSources) {
		return contextError("original SDK CPU source inventory differs")
	}
	for name, expected := range sdkCPUSources {
		if digest(source[name]) != expected {
			return contextError("original SDK CPU source bytes differ")
		}
	}
	return nil
}

func sdkCPUPackages(report Report) (map[string]Package, error) {
	root := report.Environment["GOROOT"]
	dir := filepath.Join(root, "src", "internal", "cpu")
	if !sdkCPUTarget(report.Target) || report.PackagePath != "internal/cpu" || report.CommandDirectory != dir ||
		report.CommandBinary != filepath.Join(root, "bin", gotoolchain.HostExecutable("go")) || sdkCPUSource(report.Source) != nil {
		return nil, contextError("unbound original SDK CPU owner/target/source role")
	}
	decoder := json.NewDecoder(bytes.NewReader(report.RawSelection))
	packages := make(map[string]Package)
	unsafeSeen := false
	for count := 0; ; count++ {
		var pkg Package
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil || count >= 2 || !pkg.Standard || !pkg.Goroot || pkg.Root != root || pkg.Module != nil ||
			pkg.ForTest != "" || len(pkg.Error) != 0 && string(pkg.Error) != "null" || len(pkg.DepsErrors) != 0 {
			return nil, contextError("incomplete, foreign or nonoriginal SDK selection")
		}
		if pkg.ImportPath == "unsafe" {
			if unsafeSeen || pkg.Name != "unsafe" || pkg.Dir != filepath.Join(root, "src", "unsafe") ||
				pkg.Export != "" || !reflect.DeepEqual(pkg.GoFiles, []string{"unsafe.go"}) || len(pkg.Imports) != 0 ||
				len(pkg.ImportMap) != 0 || len(pkg.SFiles) != 0 {
				return nil, contextError("unbound builtin SDK unsafe owner")
			}
			unsafeSeen = true
			continue
		}
		if pkg.ImportPath != "internal/cpu" || pkg.Name != "cpu" || pkg.Dir != dir || packages[pkg.ImportPath].ImportPath != "" ||
			!filepath.IsAbs(pkg.Export) || !within(report.Environment["GOCACHE"], pkg.Export) || len(pkg.GoFiles) == 0 ||
			!reflect.DeepEqual(pkg.Imports, []string{"unsafe"}) || len(pkg.ImportMap) != 0 {
			return nil, contextError("requested SDK CPU identity/import/archive differs")
		}
		for _, files := range [][]string{pkg.CgoFiles, pkg.EmbedFiles, pkg.EmbedPatterns, pkg.CFiles, pkg.CXXFiles, pkg.MFiles,
			pkg.FFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles} {
			if len(files) != 0 {
				return nil, contextError("foreign/generated SDK role outside prototype")
			}
		}
		seen := map[string]bool{}
		expected := []string{}
		for _, name := range pkg.GoFiles {
			if filepath.Base(name) != name || !strings.HasSuffix(name, ".go") || seen[name] || report.Source[name] == nil {
				return nil, contextError("unbound selected original SDK Go source")
			}
			seen[name] = true
			expected = append(expected, filepath.Join(dir, name))
		}
		actual := append([]string(nil), pkg.CompiledGoFiles...)
		for i, name := range actual {
			if !filepath.IsAbs(name) {
				if filepath.Base(name) != name {
					return nil, contextError("unbound SDK compiled source")
				}
				actual[i] = filepath.Join(dir, name)
			}
		}
		sort.Strings(expected)
		sort.Strings(actual)
		if !reflect.DeepEqual(expected, actual) {
			return nil, contextError("SDK compiled source differs from originals")
		}
		for _, name := range pkg.SFiles {
			if filepath.Base(name) != name || !strings.HasSuffix(name, ".s") || seen[name] || report.Source[name] == nil {
				return nil, contextError("unbound selected original SDK assembly source")
			}
			seen[name] = true
		}
		pkg.CompiledGoFiles = actual
		packages[pkg.ImportPath] = pkg
	}
	if !unsafeSeen || len(packages) != 1 {
		return nil, contextError("missing exact SDK CPU dependency inventory")
	}
	return packages, nil
}

// Every member is decoded and structurally checked. Assembly is inventoried,
// never used as a requested storage definition or a native entry certificate.
func readSDKCPUArchive(data []byte, target string, sources []string) (map[string]dataRecord, error) {
	if !sdkCPUTarget(target) {
		return nil, contextError("unobserved SDK CPU archive target")
	}
	// Keep ABI/index identity until after structural validation. Go's Darwin
	// compiler emits same-named ABI0/ABIInternal TEXT wrappers; neither can
	// supply a Go variable. CPU assembly storage remains expressly forbidden.
	return readSDKCompilerStorageArchive(data, target, sources, true)
}
