package plan9asm

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCIModuleSuitesKeepExhaustiveUnixAndWindowsRoles(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile("scripts/test-module-ci.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		job, flags string
		parts      int
	}{
		{"test", "test) timeout=45m", 16},
		{"race", "race) timeout=60m; flags=(-race); root_partitions=32; shards=64", 32},
		{"coverage", "coverage) timeout=45m; flags=(-coverprofile=coverage-root.out)", 16},
	} {
		job, found := ciWorkflowJob(string(data), item.job)
		command := "bash scripts/test-module-ci.sh " + item.job + " execute ${{ matrix.module-owner }} ${{ matrix.root-partition }}"
		if !found || !strings.Contains(job, command) || !strings.Contains(string(script), item.flags) {
			t.Errorf("%s must keep the complete actual module inventory/flags using bounded partition ownership", item.job)
		}
		var roles []string
		for part := 0; part < item.parts; part++ {
			roles = append(roles, fmt.Sprintf("root-%d", part))
		}
		roles = append(roles, "profile", "other")
		normalizedJob := strings.Join(strings.Fields(job), " ")
		for _, required := range []string{"module-role: [" + strings.Join(roles, ", ") + "]", "fail-fast: false", "actions/upload-artifact@v6"} {
			if !strings.Contains(normalizedJob, required) {
				t.Errorf("%s missing exhaustive scheduling/artifact requirement %q", item.job, required)
			}
		}
		if strings.Contains(job, "module-owner: [") || strings.Contains(job, "max-parallel:") || strings.Contains(job, "continue-on-error:") {
			t.Errorf("%s repeats package owners or masks/limits scheduling", item.job)
		}
	}
	aggregate, found := ciWorkflowJob(string(data), "module-completion")
	if !found || !strings.Contains(aggregate, "needs: [test, nested-cli, race, coverage, nested-cli-coverage]") || !strings.Contains(aggregate, "!cancelled()") ||
		!strings.Contains(aggregate, "owner-0000") || !strings.Contains(aggregate, "owner-0001") || !strings.Contains(aggregate, "owner-0002") {
		t.Error("missing mandatory complete cross-owner readback")
	}
	for part := 0; part < 32; part++ {
		if !strings.Contains(aggregate, fmt.Sprintf("Download root part %d", part)) ||
			!strings.Contains(aggregate, fmt.Sprintf("-owners/owner-0000/part-%04d", part)) {
			t.Errorf("missing exact root part %d download", part)
		}
		marker := fmt.Sprintf("      - name: Download root part %d\n", part)
		_, download, ok := strings.Cut(aggregate, marker)
		if !ok {
			continue
		}
		download, _, _ = strings.Cut(download, "\n      - name:")
		if part < 16 {
			if strings.Contains(download, "matrix.flavor ==") ||
				(part != 0 && !strings.Contains(download, "if: ${{ !cancelled() }}")) {
				t.Errorf("every flavor requires original root part %d even after another owner fails", part)
			}
		} else if !strings.Contains(download, "if: ${{ !cancelled() && matrix.flavor == 'race' }}") {
			t.Errorf("only race owns global root part %d", part)
		}
	}
	for _, required := range []string{"-module -out=", "-shards=$shards -workers=2", "root_partitions=16", "shards=32", "-module-root-partitions=$root_partitions", "-verify-module=_out/module-$flavor-owners", "go run ./cmd/plan9asmtest"} {
		if !strings.Contains(string(script), required) {
			t.Errorf("module driver changed complete inventory/scheduling: %s", required)
		}
	}
	test, _ := ciWorkflowJob(string(data), "test")
	windows, found := ciWorkflowJob(string(data), "windows-module")
	if !found || !strings.Contains(windows, "needs: ci_policy") ||
		!strings.Contains(windows, "module: [root, plan9asm, plan9asmll]") ||
		!strings.Contains(windows, "uses: ./.github/workflows/windows-module.yml") ||
		!strings.Contains(windows, "fail-fast: false") {
		t.Error("all Windows modules need independent exhaustive partition/aggregate workflows")
	}
	if strings.Contains(test, "os: windows-latest") || strings.Contains(windows, "continue-on-error:") {
		t.Error("Windows complete module roles must not duplicate direct suites or hide failures")
	}
	if !strings.Contains(test, "| grep -Fx 'TestAMD64DownloadedFixedLocalLLVM22Numerical'") {
		t.Error("required numerical inventory must use the provisioned fixed-line filter, not optional ripgrep")
	}
	nested, found := ciWorkflowJob(string(data), "nested-cli")
	if !found || !strings.Contains(nested, "needs: ci_policy") ||
		!strings.Contains(nested, "go-version: ['1.24.x', '1.25.x', '1.26.x', '1.27.2']") ||
		!strings.Contains(nested, "module: [plan9asm, plan9asmll]") ||
		!strings.Contains(nested, "uses: ./.github/workflows/linux-cli-module.yml") ||
		!strings.Contains(nested, "module: ${{ matrix.module }}") ||
		!strings.Contains(nested, "go-version: ${{ matrix.go-version }}") ||
		!strings.Contains(nested, "flavor: test") || !strings.Contains(nested, "fail-fast: false") {
		t.Error("both complete nested CLIs need independent exhaustive SDK/module partition workflows")
	}
	if strings.Contains(test, "nested_modules") || strings.Contains(test, "working-directory: cmd/plan9asm") ||
		strings.Contains(nested, "module-owner") || strings.Contains(nested, "max-parallel:") ||
		strings.Contains(nested, "continue-on-error:") || strings.Contains(nested, "if:") {
		t.Error("nested CLI jobs must remain independent of other module failures without skipped or hidden outcomes")
	}
	coverage, _ := ciWorkflowJob(string(data), "coverage")
	if strings.Contains(coverage, "codecov/codecov-action") || !strings.Contains(aggregate, "files: ./coverage-root.out") {
		t.Error("coverage upload must use complete module union, never one owner's partial file")
	}
	nestedCoverage, found := ciWorkflowJob(string(data), "nested-cli-coverage")
	for _, required := range []string{
		"needs: ci_policy", "go-version: '1.27.2'", "module: [plan9asm, plan9asmll]",
		"fail-fast: false", "uses: ./.github/workflows/linux-cli-module.yml",
		"module: ${{ matrix.module }}", "flavor: coverage",
	} {
		if !found || !strings.Contains(nestedCoverage, required) {
			t.Errorf("complete CLI coverage needs independent original budgets and command: %s", required)
		}
	}
	if strings.Contains(coverage, "working-directory: cmd/") || strings.Contains(nestedCoverage, "module-owner") ||
		strings.Contains(nestedCoverage, "max-parallel:") || strings.Contains(nestedCoverage, "continue-on-error:") ||
		strings.Contains(nestedCoverage, "if:") {
		t.Error("complete CLI coverage cannot share remaining-package budgets or mask outcomes")
	}
	if !strings.Contains(aggregate, "if: ${{ !cancelled() && matrix.flavor == 'coverage' }}") ||
		!strings.Contains(aggregate, "run: test '${{ needs['nested-cli-coverage'].result }}' = success") {
		t.Error("failed CLI coverage must fail completion after original main-module evidence collection")
	}
}

func TestCILinuxCLIModulesKeepCompleteRolesAndBudgets(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/linux-cli-module.yml")
	if err != nil {
		t.Fatal(err)
	}
	roots, found := ciWorkflowJob(string(data), "root-parts")
	if !found || !strings.Contains(roots, "part: [0, 1, 2, 3]") ||
		!strings.Contains(roots, "timeout-minutes: 60") || !strings.Contains(roots, "fail-fast: false") {
		t.Fatal("Linux CLI requires four independently budgeted exhaustive root parts")
	}
	for _, required := range []string{
		"execute 0 ${{ matrix.part }}", "execute 1 -1", "execute 2 -1",
		"!cancelled() && matrix.part == 0", "always() && matrix.part == 0",
		"-owner-1/", "-owner-2/", "actions/upload-artifact@v6",
	} {
		if !strings.Contains(roots, required) {
			t.Errorf("Linux CLI root part zero must retain actual other-owner protocol: %s", required)
		}
	}
	complete, found := ciWorkflowJob(string(data), "complete")
	if !found || !strings.Contains(complete, "needs: root-parts") ||
		!strings.Contains(complete, "if: ${{ !cancelled() }}") ||
		!strings.Contains(complete, "test '${{ needs.root-parts.result }}' = success") {
		t.Fatal("Linux CLI complete reader must collect all evidence and reject failed owners")
	}
	for _, required := range []string{"owner-0001", "owner-0002", "part-0000", "part-0001", "part-0002", "part-0003",
		"Verify complete CLI module", "inputs.flavor == 'coverage'",
		"go tool cover -func=coverage-${{ inputs.module }}.out | tail -n 1"} {
		if !strings.Contains(complete, required) {
			t.Errorf("complete CLI union/coverage lost %s", required)
		}
	}
	driver, err := os.ReadFile("scripts/test-linux-cli-module-ci.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"-module", "-dir=cmd/$module", "-shards=8", "-workers=2",
		"-timeout=30m", "-module-root-partitions=4", "-verify-module=", "GOMAXPROCS=2",
		"test) flags=()", "coverage) flags=(\"-coverprofile=coverage-$module.out\")"} {
		if !strings.Contains(string(driver), required) {
			t.Errorf("Linux CLI driver changed exhaustive scope/budget: %s", required)
		}
	}
}

func TestCIWindowsModulesKeepCompleteCoverageAndBudgets(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/windows-module.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root-parts", "other-owners", "complete"} {
		job, found := ciWorkflowJob(string(data), name)
		if !found || !strings.Contains(job, "runs-on: windows-latest") ||
			!strings.Contains(job, "uses: ./.github/actions/setup-windows-llvm22") ||
			!strings.Contains(job, "uses: ./.github/actions/setup-node22") || !strings.Contains(job, "timeout-minutes: 10") {
			t.Fatalf("Windows %s must retain identical native tool/runtime setup", name)
		}
		if strings.Contains(job, "max-parallel:") || strings.Contains(job, "continue-on-error:") {
			t.Fatalf("Windows %s masks or throttles required execution", name)
		}
	}
	complete, _ := ciWorkflowJob(string(data), "complete")
	if !strings.Contains(complete, "needs: [root-parts, other-owners]") ||
		!strings.Contains(complete, "if: ${{ !cancelled() }}") ||
		!strings.Contains(complete, "test-windows-module-ci.sh ${{ inputs.module }} complete") {
		t.Fatal("Windows completion must independently reject missing/failed owners")
	}
	for part := 0; part < 8; part++ {
		if !strings.Contains(complete, fmt.Sprintf("-owners/owner-0000/part-%04d", part)) {
			t.Fatalf("missing Windows root part %d artifact", part)
		}
	}
	for _, owner := range []string{"owner-0001", "owner-0002"} {
		if !strings.Contains(complete, "-owners/"+owner) {
			t.Fatalf("missing Windows %s artifact", owner)
		}
	}
	script, err := os.ReadFile("scripts/test-windows-module-ci.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"-module", "-timeout=30m", "-workers=2", "-module-root-partitions=$parts", "-tags=byollvm", "-verify-module="} {
		if !strings.Contains(string(script), required) {
			t.Fatalf("Windows module driver lost %s", required)
		}
	}
}
