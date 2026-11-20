package gotoolprofile

import (
	"fmt"
	"strconv"
	"strings"
)

// This finite renderer is bound to the complete Go 1.27.1/1.27.2 shell.go,
// gc.go and buildid.go registrations in InstrumentationExportEnvironment.
// It models updateBuildID's cache-copy display as well as runOut's
// joinUnambiguously, fmtCmd and ShowCmd, not a shell parser or normalizer for
// arbitrary observed commands. Only a whole exact rendered marker trace may
// be projected into the existing portable routing protocol.
type instrumentationExportTracePaths struct {
	work, marker, compile, asm, include, archive string
	separator                                    string
}

func instrumentationExportPhysicalTracePaths(work, root, marker, archive string, tools *InstrumentationToolState) (instrumentationExportTracePaths, error) {
	if tools == nil || !validDiscoveryFeatureToolDirectory(tools.Directory) {
		return instrumentationExportTracePaths{}, fmt.Errorf("export display lacks the actual SDK host tool directory")
	}
	separator, suffix := "/", ""
	if strings.HasPrefix(strings.TrimPrefix(tools.Directory, "pkg/tool/"), "windows_") {
		separator, suffix = `\`, ".exe"
	}
	for _, value := range []string{work, root, marker, archive} {
		if !instrumentationExportHostAbsolutePath(value, separator) {
			return instrumentationExportTracePaths{}, fmt.Errorf("export display lacks an absolute actual host path")
		}
	}
	paths := instrumentationExportTracePaths{work: work, marker: marker, archive: archive, separator: separator}
	for _, item := range []struct {
		name string
		out  *string
	}{{"compile", &paths.compile}, {"asm", &paths.asm}} {
		origin := "goroot/" + tools.Directory + "/" + item.name + suffix
		if tools.BinaryOrigins[item.name] != origin {
			return instrumentationExportTracePaths{}, fmt.Errorf("export display has an unbound actual %s host route", item.name)
		}
		*item.out = strings.TrimSuffix(root, separator) + separator + strings.ReplaceAll(strings.TrimPrefix(origin, "goroot/"), "/", separator)
	}
	paths.include = strings.TrimSuffix(root, separator) + separator + "pkg" + separator + "include"
	return paths, nil
}

// The producer's file/tool observers already resolve physical paths. This
// check recognizes the bound host spelling without using the target GOOS or
// this reader's host filepath parser. Relative and drive-relative paths fail.
func instrumentationExportHostAbsolutePath(value, separator string) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	if separator == "/" {
		return strings.HasPrefix(value, "/")
	}
	if len(value) >= 3 && value[1] == ':' && value[2] == '\\' &&
		(value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') {
		return true
	}
	if strings.HasPrefix(value, `\\`) {
		parts := strings.Split(strings.TrimPrefix(value, `\\`), `\`)
		return len(parts) >= 2 && parts[0] != "" && parts[0] != "." && parts[0] != "?" && parts[1] != ""
	}
	return false
}

func instrumentationRenderedExportTrace(plan *InstrumentationBuildPlan, defines []string, concurrency int, environment []string, paths instrumentationExportTracePaths) string {
	mode := string(plan.Mode)
	objdir := strings.TrimSuffix(paths.work, paths.separator) + paths.separator + "b001" + paths.separator
	trimpath := strings.TrimSuffix(objdir, paths.separator) + "=>"
	asm := []string{paths.asm, "-p", instrumentationExportModule, "-trimpath", trimpath, "-I", objdir, "-I", paths.include}
	for _, define := range defines[:2] {
		asm = append(asm, "-D", define)
	}
	asm = append(asm, plan.CodegenFlags...)
	for _, define := range defines[2:] {
		asm = append(asm, "-D", define)
	}
	installSuffix := mode
	if plan.InstrumentAdjustedBuildMode == "pie" && len(plan.CodegenFlags) == 1 {
		installSuffix += "_" + strings.TrimPrefix(plan.CodegenFlags[0], "-")
	}
	compile := []string{paths.compile, "-o", objdir + "_pkg_.a", "-trimpath", trimpath, "-p", instrumentationExportModule,
		"-lang=go1.20", "-installsuffix", installSuffix, "-buildid", "@action/@action", "-goversion", plan.GoVersion,
		"-symabis", objdir + "symabis"}
	if concurrency > 1 {
		compile = append(compile, "-c="+strconv.Itoa(concurrency))
	}
	compile = append(compile, plan.CodegenFlags...)
	compile = append(compile, "-"+mode, "-nolocalimports", "-importcfg", objdir+"importcfg", "-pack", "-asmhdr", objdir+"go_asm.h",
		paths.marker+paths.separator+"base.go", paths.marker+paths.separator+"mode_"+mode+".go")
	assembly := paths.marker + paths.separator + "mode_" + mode + ".s"
	symabis := append(append([]string(nil), asm...), "-gensymabis", "-o", objdir+"symabis", assembly)
	object := append(append([]string(nil), asm...), "-o", objdir+"mode_"+mode+".o", assembly)

	var lines []string
	lines = append(lines, "WORK="+paths.work)
	scriptDir := ""
	show := func(dir, command string) {
		command = instrumentationExportDisplayWORK(command, paths.work)
		if dir != "" {
			if dir != scriptDir {
				lines = append(lines, "cd "+instrumentationExportDisplayWORK(dir, paths.work))
				scriptDir = dir
			}
			dot := " ."
			if strings.HasSuffix(dir, paths.separator) {
				dot += paths.separator
			}
			command = strings.ReplaceAll(" "+command, " "+dir, dot)[1:]
		}
		lines = append(lines, command)
	}
	show("", "mkdir -p "+objdir)
	show("", "echo -n > "+objdir+"go_asm.h # internal")
	show(paths.marker, instrumentationExportCommandPrefix(environment)+instrumentationExportDisplayArgs(symabis))
	show("", "echo '# import config' > "+objdir+"importcfg # internal")
	show(paths.marker, instrumentationExportCommandPrefix(environment)+instrumentationExportDisplayArgs(compile))
	show(paths.marker, instrumentationExportCommandPrefix(environment)+instrumentationExportDisplayArgs(object))
	show(paths.marker, instrumentationExportDisplayArgs([]string{"go", "tool", "pack", "r", objdir + "_pkg_.a", objdir + "mode_" + mode + ".o"})+" # internal")
	show("", instrumentationExportDisplayArgs([]string{"go", "tool", "buildid", "-w", objdir + "_pkg_.a"})+" # internal")
	show("", instrumentationExportDisplayArgs([]string{"cp", objdir + "_pkg_.a", paths.archive})+" # internal")
	return strings.Join(lines, "\n") + "\n"
}

func instrumentationExportDisplayWORK(command, work string) string {
	command = strings.ReplaceAll(command, work, "$WORK")
	escaped := strconv.Quote(work)
	escaped = escaped[1 : len(escaped)-1]
	if escaped != work {
		command = strings.ReplaceAll(command, escaped, "$WORK")
	}
	return command
}

func instrumentationExportDisplayArgs(args []string) string {
	var values []string
	for _, value := range args {
		quoted := strconv.Quote(value)
		if value == "" || strings.ContainsAny(value, " ()>;") || len(quoted) > len(value)+2 {
			values = append(values, quoted)
		} else {
			values = append(values, value)
		}
	}
	return strings.Join(values, " ")
}
