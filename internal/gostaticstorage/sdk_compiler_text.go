package gostaticstorage

// ObserveX86SDKCompilerText observes the complete two-member archive emitted
// by the existing SDK header compiler. It is offline object metadata only;
// neither this function nor a returned record supplies a declaration or ABI.
func ObserveX86SDKCompilerText(data, builtin []byte, target string, referenced map[string]SDKReferencedArchive) ([]TextRecord, error) {
	if !X86SDKTarget(target) {
		return nil, contextError("unobserved SDK compiler TEXT target")
	}
	members, err := archiveMembers(data)
	if err != nil {
		return nil, err
	}
	if len(members) != 2 || members[0].name != "__.PKGDEF" || members[1].name != "_go_.o" {
		return nil, contextError("SDK compiler TEXT lacks its complete two-member archive")
	}
	symbols, err := sdkReferencedArchiveSymbols(referenced, target)
	if err != nil {
		return nil, err
	}
	member, err := observeASMDataObject(members[1].data, builtin, target, sdkCompilerObjectFlags(target), symbols)
	if err != nil {
		return nil, err
	}
	return member.Texts, nil
}
