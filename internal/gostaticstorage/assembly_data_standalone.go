package gostaticstorage

import "strings"

// AMD64AssemblyData is a complete standalone object/source observation. It is
// not an SDK role or a certificate for storage, reads, addresses or native ABI.
type AMD64AssemblyData struct {
	Member    ASMDataMember
	Layouts   []ASMGlobalLayout
	TextOrder []ASMSourceText
}

// ObserveAMD64AssemblyData reuses the same typed DATA grammar and complete
// object decoder as the SDK observer without borrowing SDK provenance. The
// live caller must retain the actual producer, expanded source and object.
func ObserveAMD64AssemblyData(source, object, builtin []byte, packagePath, target string) (AMD64AssemblyData, error) {
	var result AMD64AssemblyData
	if target != "linux/amd64" && target != "darwin/amd64" && target != "windows/amd64" ||
		packagePath == "" || len(packagePath) > 4096 || strings.ContainsAny(packagePath, "\x00\r\n") ||
		len(object) == 0 || len(object) > archiveLimit || len(source)+len(object)+len(builtin) > 64<<20 {
		return result, contextError("standalone AMD64 DATA has an unobserved target or unbounded input")
	}
	// All three targets have the same AMD64 pointer-width DATA grammar. The
	// object itself is still checked against its exact physical OS/architecture.
	states, err := parseASMDataSource(source, packagePath, "linux/amd64")
	if err != nil {
		return result, err
	}
	result.Member, err = observeASMDataObject(object, builtin, target, 4, nil)
	if err != nil {
		return AMD64AssemblyData{}, err
	}
	result.TextOrder, err = ASMSourceTextOrder(source, packagePath, result.Member)
	if err != nil {
		return AMD64AssemblyData{}, err
	}
	result.Layouts, err = joinASMDataLayouts(states, result.Member)
	if err != nil {
		return AMD64AssemblyData{}, err
	}
	return result, nil
}
